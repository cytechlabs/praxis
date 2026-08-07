"""
Alert service for sending external notifications via Slack webhooks and
generic webhooks (PRA-41 + PRA-125).

PRA-125 hardening:
- HMAC-SHA256 signing (X-Praxis-Signature) when AlertConfig.secret is set
- httpx sync client replaces urllib.request
- Retry queue with exponential backoff, persisted on AlertHistory rows
- dead_letter status after max attempts exhausted
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from ..db.models import AlertConfig, AlertHistory
from . import outbound_http_guard

logger = logging.getLogger(__name__)

# All supported event types
SUPPORTED_EVENT_TYPES: List[str] = [
    "job_completed",
    "job_failed",
    "job_cancelled",
    "job_rollback",
    "system_unreachable",
    "system_recovered",
    "security_updates",
    # PRA-156 #3e-b: replaces ``eol_warning`` (vestigial slot, never
    # had an emitter). The lifecycle emitter in #3e-c fires
    # ``host_eol_approaching`` once per (system, threshold) for the
    # 90/30/7-day buckets and ``host_eol_reached`` once per
    # (system, effective_eol_date) — see lifecycle_service for the
    # boundary semantics.
    "host_eol_approaching",
    "host_eol_reached",
    "host_key_changed",
    "package_scan_complete",
    "credential_change",
    "system_added",
    "system_removed",
    "bulk_operation_complete",
    "audit_event",
    "fleet_operation_complete",
    # PRA-157 #2b: mirror engine alerts. ``mirror_sync_failed`` fires
    # on engine/promotion/manifest failure (24h cooldown);
    # ``mirror_sync_completed`` fires once on the failed→ok recovery
    # transition (no cooldown — gated at the orchestrator);
    # ``mirror_disk_pressure`` fires on free-space gate refusal (24h
    # cooldown). All three target the ``mirrors`` content-plane
    # surface; ``system_id`` is null on these events.
    "mirror_sync_failed",
    "mirror_sync_completed",
    "mirror_disk_pressure",
    # PRA-158 #4b: pre-sync upstream-verify gate. Fires when
    # mirror_repos.verify_upstream_signature=true and the upstream
    # Release.gpg / InRelease / repomd.xml.asc fails verification
    # against the keyring built from mirror_upstream_keys.
    "mirror_upstream_signature_invalid",
    # PRA-178 Slice 3: patch / compliance / remediation lifecycle
    # notifications. Each event flows through the existing notification
    # service + alert delivery path (preference disable, scope filter,
    # retry behavior). Emission hooks live beside the existing audit
    # emits at the matching service-level state transitions; see
    # ``notification_events.py`` for the bounded helpers.
    "patch.executed",
    "patch.reboot_required",
    "patch.reboot_completed",
    "patch.rollback_started",
    "patch.rollback_completed",
    "compliance.evaluated",
    "remediation.requested",
    "remediation.ready",
    "remediation.executed",
    "remediation.failed",
]

# Severity to Slack colour mapping
SEVERITY_COLORS: Dict[str, str] = {
    "info": "#36a64f",
    "warning": "#ff9900",
    "error": "#dc3545",
    "critical": "#7b0000",
}

# Retry backoff in seconds, indexed by attempt number that just failed (1-based).
# Attempt 1 failed → wait BACKOFF_SECONDS[0] before attempt 2, etc.
BACKOFF_SECONDS: List[int] = [30, 120, 600, 1800]
MAX_ATTEMPTS: int = len(BACKOFF_SECONDS) + 1  # 5 attempts total


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


def _build_payload(
    config: AlertConfig,
    event_type: str,
    title: str,
    message: str,
    severity: str,
) -> Dict[str, Any]:
    """Return the JSON body to POST for the given config's alert type."""
    if config.alert_type == "slack":
        color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": title[:150],
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": message},
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": (
                                        f"*Severity:* {severity}  |  *Event:* "
                                        f"{event_type}  |  *Time:* "
                                        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                                    ),
                                }
                            ],
                        },
                    ],
                }
            ]
        }
    # Generic webhook
    return {
        "event_type": event_type,
        "title": title,
        "message": message,
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def sign_payload(secret: str, body: bytes) -> str:
    """Return hex HMAC-SHA256 of body, prefixed with 'sha256='."""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _post(url: str, body: bytes, secret: Optional[str]) -> tuple[int, Optional[str]]:
    """POST body to url; return (status_code, error_message). Raises nothing.

    If *secret* is set, attaches an X-Praxis-Signature header (HMAC-SHA256).
    """
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Praxis-Signature"] = sign_payload(secret, body)
    try:
        # SSRF guard: validate + pin to a public target and disable redirects at
        # delivery time (blocks DNS rebinding). Internal targets are blocked
        # unless the dedicated ALERT_ALLOW_PRIVATE_TARGETS hatch is set (the
        # audit-sink override does not apply). Timeout/HMAC behavior unchanged.
        resp = outbound_http_guard.post(
            url,
            content=body,
            headers=headers,
            timeout=10.0,
            allow_private=outbound_http_guard.alert_allow_private_targets(),
        )
        if resp.status_code >= 400:
            # Record the status only; never persist the target's response body
            # (it can leak internal-service bytes into alert history).
            return resp.status_code, f"HTTP {resp.status_code}"
        return resp.status_code, None
    except outbound_http_guard.SsrfBlocked as e:
        return 0, f"Blocked outbound target: {e}"
    except httpx.TimeoutException:
        return 0, "Timeout contacting webhook target"
    except httpx.HTTPError as e:
        return 0, f"Delivery error: {type(e).__name__}"
    except Exception as e:  # pylint: disable=broad-except
        return 0, f"Delivery error: {type(e).__name__}"


# ---------------------------------------------------------------------------
# Delivery + retry orchestration
# ---------------------------------------------------------------------------


def _schedule_retry(row: AlertHistory) -> None:
    """Mutate *row* to schedule the next retry, or mark it dead_letter."""
    if row.attempt_count >= MAX_ATTEMPTS:
        row.status = "dead_letter"
        row.next_retry_at = None
        return
    backoff = BACKOFF_SECONDS[row.attempt_count - 1]
    row.status = "failed"
    row.next_retry_at = datetime.utcnow() + timedelta(seconds=backoff)


def _attempt_delivery(db: Session, row: AlertHistory, config: AlertConfig) -> None:
    """Perform one delivery attempt and update *row* accordingly."""
    now = datetime.utcnow()
    row.last_attempted_at = now

    try:
        body = (row.payload or "").encode("utf-8")
        if not body:
            row.status = "failed"
            row.error_message = "Empty payload"
            row.next_retry_at = None
            return

        status_code, error = _post(config.destination, body, config.secret)
        row.response_code = status_code or None

        if error is None:
            row.status = "sent"
            row.sent_at = now
            row.error_message = None
            row.next_retry_at = None
        else:
            row.error_message = error
            _schedule_retry(row)
    finally:
        try:
            db.commit()
        except Exception as e:  # pylint: disable=broad-except
            logger.error("alert_history commit failed: %s", e)
            db.rollback()


def send_alert(
    db: Session,
    event_type: str,
    title: str,
    message: str,
    severity: str = "info",
    system_id: Optional[int] = None,
) -> None:
    """Enqueue and attempt delivery for every matching AlertConfig.

    If ``system_id`` is provided, configs with a ``scope_smart_group_id`` only
    dispatch when that system is a member of the scoped smart group (PRA-126).
    Configs without a scope always dispatch.
    """
    try:
        configs = (
            db.query(AlertConfig)
            .filter(AlertConfig.enabled == True)  # noqa: E712
            .all()
        )

        for config in configs:
            try:
                events = json.loads(config.events)
            except (json.JSONDecodeError, TypeError):
                events = []

            if event_type not in events:
                continue

            # PRA-126: smart-group scope filter
            if config.scope_smart_group_id:
                if system_id is None:
                    continue
                from .smart_group_service import is_member

                if not is_member(db, config.scope_smart_group_id, system_id):
                    continue

            if config.alert_type not in ("slack", "webhook"):
                logger.warning(
                    "Skipping alert config %d: unsupported type %s",
                    config.id,
                    config.alert_type,
                )
                continue

            payload = _build_payload(config, event_type, title, message, severity)
            row = AlertHistory(
                alert_config_id=config.id,
                event_type=event_type,
                message=f"{title}: {message}",
                sent_at=datetime.utcnow(),
                status="pending",
                payload=json.dumps(payload),
                attempt_count=1,
            )
            db.add(row)
            db.commit()
            db.refresh(row)

            _attempt_delivery(db, row, config)
    except Exception as e:  # pylint: disable=broad-except
        logger.error("send_alert error: %s", e)
        db.rollback()


def retry_pending_deliveries(db: Session, limit: int = 50) -> int:
    """Sweeper: pick failed rows whose next_retry_at is due and retry.

    Returns number of rows processed.
    """
    now = datetime.utcnow()
    rows = (
        db.query(AlertHistory)
        .filter(
            AlertHistory.status == "failed",
            AlertHistory.next_retry_at.isnot(None),
            AlertHistory.next_retry_at <= now,
        )
        .order_by(AlertHistory.next_retry_at.asc())
        .limit(limit)
        .all()
    )

    processed = 0
    for row in rows:
        config = (
            db.query(AlertConfig).filter(AlertConfig.id == row.alert_config_id).first()
        )
        if not config or not config.enabled:
            row.status = "dead_letter"
            row.next_retry_at = None
            db.commit()
            processed += 1
            continue

        row.attempt_count += 1
        _attempt_delivery(db, row, config)
        processed += 1

    return processed


def force_retry(db: Session, history_id: int) -> Dict[str, Any]:
    """Manually retry a dead_letter or failed row (admin action)."""
    row = db.query(AlertHistory).filter(AlertHistory.id == history_id).first()
    if not row:
        return {"status": "error", "message": "Delivery record not found"}
    if row.status == "sent":
        return {"status": "error", "message": "Already delivered"}

    config = db.query(AlertConfig).filter(AlertConfig.id == row.alert_config_id).first()
    if not config:
        return {"status": "error", "message": "Alert config missing"}

    row.attempt_count = 1  # reset the counter for a manual retry cycle
    _attempt_delivery(db, row, config)
    return {
        "status": row.status,
        "response_code": row.response_code,
        "error_message": row.error_message,
    }


# ---------------------------------------------------------------------------
# Test fire
# ---------------------------------------------------------------------------


def send_test_alert(db: Session, config_id: int) -> Dict[str, Any]:
    """Send a test alert synchronously to verify a webhook URL works."""
    config = db.query(AlertConfig).filter(AlertConfig.id == config_id).first()
    if not config:
        return {"status": "error", "message": "Alert config not found"}

    title = "Praxis Test Alert"
    message = f"This is a test alert from Praxis for config '{config.name}'."
    severity = "info"

    payload = _build_payload(config, "test", title, message, severity)
    row = AlertHistory(
        alert_config_id=config.id,
        event_type="test",
        message=f"{title}: {message}",
        sent_at=datetime.utcnow(),
        status="pending",
        payload=json.dumps(payload),
        attempt_count=1,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    _attempt_delivery(db, row, config)

    return {
        "status": row.status,
        "message": row.error_message or "Test alert sent successfully",
        "response_code": row.response_code,
    }
