"""Structured audit event service + pluggable external sinks (PRA-143).

Every security-relevant action in the app calls ``emit(...)``, which:

    1. Persists an AuditEvent row (always — the in-app audit log is the
       source of truth).
    2. Fans out to every enabled AuditSink as pending
       ``AuditSinkDelivery`` rows.
    3. A scheduler worker drains pending deliveries through the right
       transport (syslog / http / file) with retry + dead-letter after
       ``MAX_ATTEMPTS``.

Sink transports:

    * ``file``: append the event JSON to a newline-delimited file on local
      disk. ``target`` is a relative path beneath the operator-approved
      audit file sink root; absolute paths, traversal, and symlinked path
      components are rejected at create/update and again at delivery.
    * ``syslog`` — RFC 5424 over TCP (``target`` is ``host:port``). Chosen
      over UDP so operators get a delivery signal.
    * ``http``  — POST the event JSON to ``target``. Optional HMAC-SHA256
      signature in the ``X-Praxis-Signature`` header when ``hmac_secret``
      is set; same pattern M10 webhooks use.

Event shape (stable):

    {
      "schema_version": 1,
      "event_uuid": "...",
      "timestamp": "2026-04-22T00:00:00Z",
      "action": "session.open",
      "outcome": "success" | "failure" | "denied",
      "actor": {"user_id": 1, "username": "alice", "ip": "10.0.0.5"},
      "target": {"kind": "system", "system_id": 42, "id": "42"},
      "context": { per-action payload }
    }

See docs/audit-schema.md for the full action vocabulary + per-action
context shape.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
import ssl
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from urllib.error import URLError

import httpx
from sqlalchemy.orm import Session as DbSession

from ..db.access_models import AuditEvent, AuditSink, AuditSinkDelivery
from ..db.session import SessionLocal
from . import audit_file_sink_guard, outbound_http_guard

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
MAX_ATTEMPTS = 6
RETRY_BACKOFF_S = [5, 15, 60, 300, 900, 3600]  # index by attempt count
HTTP_TIMEOUT_S = 10
SYSLOG_TIMEOUT_S = 5


class AuditError(RuntimeError):
    """Audit emission / dispatch failure."""


# ---------------------------------------------------------------- emit


def emit(
    db: DbSession,
    *,
    action: str,
    outcome: str = "success",
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    target_system_id: Optional[int] = None,
    target_kind: Optional[str] = None,
    target_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """Persist an event and enqueue one delivery per enabled sink."""
    if not action or "." not in action:
        raise AuditError(f"action must be dotted (got {action!r})")

    row = AuditEvent(
        schema_version=SCHEMA_VERSION,
        event_uuid=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        action=action,
        outcome=outcome,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_system_id=target_system_id,
        target_kind=target_kind,
        target_id=str(target_id) if target_id is not None else None,
        context_json=json.dumps(context or {}, separators=(",", ":")),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # Enqueue deliveries for each enabled sink (best-effort — a broken sink
    # config must not block event persistence).
    try:
        sinks = db.query(AuditSink).filter(AuditSink.enabled.is_(True)).all()
        for sink in sinks:
            db.add(
                AuditSinkDelivery(
                    sink_id=sink.id,
                    event_id=row.id,
                    status="pending",
                    attempts=0,
                    next_attempt_at=datetime.utcnow(),
                )
            )
        if sinks:
            db.commit()
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("audit sink enqueue failed: %s", e)
        try:
            db.rollback()
        except Exception:  # pylint: disable=broad-except
            pass
    return row


def event_to_dict(row: AuditEvent) -> Dict[str, Any]:
    """Stable JSON shape — the wire format sinks send out."""
    try:
        context = json.loads(row.context_json or "{}")
    except ValueError:
        context = {}
    return {
        "schema_version": row.schema_version,
        "event_uuid": row.event_uuid,
        "timestamp": row.timestamp.isoformat() + "Z" if row.timestamp else None,
        "action": row.action,
        "outcome": row.outcome,
        "actor": {
            "user_id": row.actor_user_id,
            "username": row.actor_username,
            "ip": row.actor_ip,
        },
        "target": {
            "kind": row.target_kind,
            "system_id": row.target_system_id,
            "id": row.target_id,
        },
        "context": context,
    }


# --------------------------------------------------------------- transports


def _send_file(sink: AuditSink, payload: str) -> None:
    # ``target`` is a relative path under the audit file sink root. Append-only,
    # newline-delimited JSON. The guard re-reads the root and re-validates the
    # target on every delivery, then pins each traversed directory, so a target
    # that was valid when the sink was saved cannot be redirected later by a
    # symlink or a changed root. A stored target that predates the confinement
    # rules is never rewritten or redirected: it fails here with an actionable
    # error and follows the normal retry / dead-letter path.
    try:
        audit_file_sink_guard.append_line(sink.target, payload)
    except audit_file_sink_guard.FileSinkTargetError as exc:
        raise AuditError(f"file sink target rejected: {exc}") from exc


def _send_syslog(sink: AuditSink, payload: str) -> None:
    # RFC 5424 framing: ``<PRI>1 TIMESTAMP HOST APP PROCID MSGID STRUCTURED MSG``
    host, _, port = sink.target.partition(":")
    port_i = int(port) if port else 6514
    cfg = json.loads(sink.config_json or "{}")
    facility = int(cfg.get("facility", 1))  # user-level messages
    severity = int(cfg.get("severity", 6))  # informational
    pri = facility * 8 + severity
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    frame = f"<{pri}>1 {ts} praxis praxis - - - {payload}".encode("utf-8")
    use_tls = bool(cfg.get("tls", True))
    sock = socket.create_connection((host, port_i), timeout=SYSLOG_TIMEOUT_S)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        # Octet-counting framing (RFC 6587) — size-prefixed.
        prefix = f"{len(frame)} ".encode("ascii")
        sock.sendall(prefix + frame)
    finally:
        try:
            sock.close()
        except Exception:  # pylint: disable=broad-except
            pass


def _send_http(sink: AuditSink, payload: str) -> None:
    cfg = json.loads(sink.config_json or "{}")
    body = payload.encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Praxis-Audit/1.0",
    }
    headers.update(cfg.get("headers") or {})
    if sink.hmac_secret:
        sig = hmac.new(
            sink.hmac_secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        headers["X-Praxis-Signature"] = f"sha256={sig}"
    # SSRF guard: validate + resolve DNS + pin the connection to a validated IP
    # and disable redirects at delivery time (blocks rebinding/redirect bypass).
    # ``require_https`` preserves the existing non-local-must-use-TLS policy; the
    # AUDIT_SINK_ALLOW_PRIVATE_TARGETS override still allows an internal collector.
    try:
        resp = outbound_http_guard.post(
            sink.target,
            content=body,
            headers=headers,
            timeout=HTTP_TIMEOUT_S,
            allow_private=outbound_http_guard.allow_private_targets(),
            require_https=True,
        )
    except outbound_http_guard.SsrfBlocked as exc:
        raise AuditError(f"http sink target blocked: {exc}") from exc
    except httpx.HTTPError as exc:
        raise AuditError(f"http sink delivery error: {type(exc).__name__}") from exc
    if resp.status_code >= 400:
        raise AuditError(f"http sink returned {resp.status_code}")


_TRANSPORTS = {
    "file": _send_file,
    "syslog": _send_syslog,
    "http": _send_http,
}


def _deliver_one(db: DbSession, delivery: AuditSinkDelivery) -> None:
    sink = db.query(AuditSink).filter(AuditSink.id == delivery.sink_id).first()
    event = db.query(AuditEvent).filter(AuditEvent.id == delivery.event_id).first()
    if sink is None or event is None or not sink.enabled:
        # Drop — sink disabled or rows pruned. Mark failed rather than loop.
        delivery.status = "failed"
        delivery.last_error = "sink or event missing"
        delivery.delivered_at = datetime.utcnow()
        db.commit()
        return

    transport = _TRANSPORTS.get(sink.kind)
    if transport is None:
        delivery.status = "failed"
        delivery.last_error = f"unknown sink kind: {sink.kind}"
        db.commit()
        return

    payload = json.dumps(
        event_to_dict(event), separators=(",", ":"), ensure_ascii=False
    )
    try:
        transport(sink, payload)
    except (AuditError, URLError, OSError, ssl.SSLError) as e:
        delivery.attempts += 1
        delivery.last_error = str(e)[:2000]
        if delivery.attempts >= MAX_ATTEMPTS:
            delivery.status = "dead_letter"
        else:
            delivery.status = "pending"
            backoff = RETRY_BACKOFF_S[
                min(delivery.attempts - 1, len(RETRY_BACKOFF_S) - 1)
            ]
            delivery.next_attempt_at = datetime.utcnow() + timedelta(seconds=backoff)
        db.commit()
        return

    delivery.status = "delivered"
    delivery.attempts += 1
    delivery.delivered_at = datetime.utcnow()
    delivery.last_error = None
    db.commit()


# --------------------------------------------------------------- sweeper


def run_delivery_sweep(batch: int = 100) -> Dict[str, int]:
    """Drain pending deliveries whose next_attempt_at has passed."""
    db = SessionLocal()
    counts = {"delivered": 0, "retried": 0, "dead_letter": 0}
    try:
        now = datetime.utcnow()
        rows = (
            db.query(AuditSinkDelivery)
            .filter(
                AuditSinkDelivery.status == "pending",
                (AuditSinkDelivery.next_attempt_at == None)  # noqa: E711
                | (AuditSinkDelivery.next_attempt_at <= now),
            )
            .order_by(AuditSinkDelivery.id.asc())
            .limit(batch)
            .all()
        )
        for d in rows:
            before = d.status
            _deliver_one(db, d)
            if d.status == "delivered":
                counts["delivered"] += 1
            elif d.status == "dead_letter":
                counts["dead_letter"] += 1
            else:
                counts["retried"] += 1
    finally:
        db.close()
    return counts


def retry_dead_letter(db: DbSession, delivery_id: int) -> AuditSinkDelivery:
    """Reset a dead-lettered delivery to pending so the sweeper re-tries."""
    d = db.query(AuditSinkDelivery).filter(AuditSinkDelivery.id == delivery_id).first()
    if d is None:
        raise AuditError(f"delivery {delivery_id} not found")
    if d.status != "dead_letter":
        raise AuditError(f"delivery not in dead_letter state ({d.status})")
    d.status = "pending"
    d.attempts = 0
    d.next_attempt_at = datetime.utcnow()
    d.last_error = None
    db.commit()
    db.refresh(d)
    return d


# ----------------------------------------------------------- convenience


def safe_emit(**kwargs: Any) -> None:
    """Emit without raising. Callers in hot paths (command exec, session
    open) shouldn't have audit failures propagate up as user-visible errors.
    """
    db = kwargs.pop("db", None)
    own = db is None
    if own:
        db = SessionLocal()
    try:
        emit(db, **kwargs)
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("audit emit failed: %s", e)
    finally:
        if own:
            db.close()


def emit_user_cert_sign(
    db: Optional[DbSession],
    *,
    actor_user_id: Optional[int],
    actor_username: Optional[str],
    login: str,
    ttl_s: int,
    key_id: str,
    actor_ip: Optional[str] = None,
    system_id: Optional[int] = None,
    purpose: str = "session",
) -> None:
    """Audit issuance of a short-lived SSH *user* certificate (PRA-219).

    Fires at the moment Vault signs the cert — independent of whether the
    subsequent SSH connection succeeds — so every minted user cert is recorded
    in the unified audit stream. The signature deliberately accepts only
    non-secret identifiers (``login`` principal, ``ttl_s``, ``key_id`` =
    cert serial, ``purpose``); the signed certificate and the ephemeral private
    key are never passed in, so they can never reach the event context.

    Note: backend-initiated SSH that reuses the pooled connection helper
    (e.g. command execution) has no single user actor at the mint point; that
    host access is audited via its parent ``command.exec`` event instead.
    """
    safe_emit(
        db=db,
        action="ssh.user_cert.sign",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_system_id=system_id,
        target_kind="system" if system_id is not None else "ssh_user_cert",
        target_id=str(system_id) if system_id is not None else None,
        context={
            "login": login,
            "ttl_s": ttl_s,
            "cert_serial": key_id,
            "purpose": purpose,
        },
    )
