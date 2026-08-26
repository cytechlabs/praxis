"""PRA-178 Slice 3 — patch / compliance / remediation notification events.

Defines the new notification event vocabulary required by the
PRA-178 Linear acceptance criterion ("notification settings expose
the new event types and respect existing routing/disable behavior")
and wires bounded helper emitters that the existing services can call
beside their existing audit emits.

Hard boundaries (slice locks):

* No scheduler, worker, queue, broker, or recurring delivery.
* No delivery retry behavior changes (the existing
  ``alert_service`` retry shape is reused unchanged).
* No host mutation, package/remediation execution, reboot, rollback,
  OpenSCAP, facts refresh, package scan, raw SSH, subprocess, or new
  compliance probe kinds.

Each emitter is a thin wrapper around
:func:`notification_service.create_notification` so the existing
per-user disable, per-fleet routing, and alert-delivery retry path
all apply unchanged. The helper functions never raise — failures are
logged and swallowed so an audit event always wins precedence over
a notification side-effect (mirrors the ``safe_emit`` posture).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from . import notification_service

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Event name constants — mirror the vocabularies in
# ``alert_service.SUPPORTED_EVENT_TYPES`` and
# ``notification_preferences.ALL_EVENT_TYPES``.
# ---------------------------------------------------------------------------

EVENT_PATCH_EXECUTED = "patch.executed"
EVENT_PATCH_REBOOT_REQUIRED = "patch.reboot_required"
EVENT_PATCH_REBOOT_COMPLETED = "patch.reboot_completed"
EVENT_PATCH_ROLLBACK_STARTED = "patch.rollback_started"
EVENT_PATCH_ROLLBACK_COMPLETED = "patch.rollback_completed"
EVENT_COMPLIANCE_EVALUATED = "compliance.evaluated"
EVENT_REMEDIATION_REQUESTED = "remediation.requested"
EVENT_REMEDIATION_READY = "remediation.ready"
EVENT_REMEDIATION_EXECUTED = "remediation.executed"
EVENT_REMEDIATION_FAILED = "remediation.failed"


PRA178_EVENT_TYPES: tuple[str, ...] = (
    EVENT_PATCH_EXECUTED,
    EVENT_PATCH_REBOOT_REQUIRED,
    EVENT_PATCH_REBOOT_COMPLETED,
    EVENT_PATCH_ROLLBACK_STARTED,
    EVENT_PATCH_ROLLBACK_COMPLETED,
    EVENT_COMPLIANCE_EVALUATED,
    EVENT_REMEDIATION_REQUESTED,
    EVENT_REMEDIATION_READY,
    EVENT_REMEDIATION_EXECUTED,
    EVENT_REMEDIATION_FAILED,
)


# Bounded title / message length so a malformed snapshot value cannot
# blow up the notification row. Mirrors the bound the existing
# ``alert_service.send_alert`` would accept without truncation.
MAX_TITLE_CHARS = 160
MAX_MESSAGE_CHARS = 1024


def _safe_str(value: Any, *, fallback: str = "") -> str:
    if value is None:
        return fallback
    try:
        return str(value)
    except Exception:  # pylint: disable=broad-except
        return fallback


def _bounded_title(value: str) -> str:
    if len(value) <= MAX_TITLE_CHARS:
        return value
    return value[: MAX_TITLE_CHARS - 1] + "…"


def _bounded_message(value: str) -> str:
    if len(value) <= MAX_MESSAGE_CHARS:
        return value
    return value[: MAX_MESSAGE_CHARS - 1] + "…"


def _safe_emit(
    db: Session,
    *,
    event_type: str,
    title: str,
    message: str,
    severity: str,
    user_id: Optional[int] = None,
    system_id: Optional[int] = None,
) -> None:
    """Emit one notification without raising.

    Wraps :func:`notification_service.create_notification` so a
    notification or alert-delivery failure cannot break the calling
    service's commit. Mirrors the ``safe_emit`` posture used for audit
    events.

    ``system_id`` is threaded through to
    :func:`alert_service.send_alert` so smart-group scoped alert
    configs (``scope_smart_group_id``) match host-scoped events.
    Host-scoped emitters MUST pass it; execution-scoped emitters
    (e.g. ``patch.executed`` which spans multiple hosts) may leave
    it ``None`` so non-scoped configs still receive the event.
    """
    try:
        notification_service.create_notification(
            db,
            type=event_type,
            title=_bounded_title(title),
            message=_bounded_message(message),
            severity=severity,
            user_id=user_id,
            system_id=system_id,
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "PRA-178 notification emit failed: event=%s err=%s",
            event_type,
            exc,
        )


# ---------------------------------------------------------------------------
# Patch lifecycle emitters
# ---------------------------------------------------------------------------


def emit_patch_executed(
    db: Session,
    *,
    execution_id: int,
    plan_id: int,
    plan_name: Optional[str],
    state: str,
    progress: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit when a patch update execution reaches a terminal state.

    ``state`` is the execution's final ``state`` (``succeeded`` /
    ``failed`` / ``canceled``). Severity maps:
    succeeded -> ``info``, canceled -> ``warning``, anything else
    -> ``error``. The progress dict is the same JSONB ``progress_summary``
    snapshot already persisted on ``PatchUpdateExecution``; only a
    bounded subset is rendered into the message.
    """
    severity = (
        "info"
        if state == "succeeded"
        else ("warning" if state == "canceled" else "error")
    )
    plan_label = plan_name or f"plan #{plan_id}"
    counts = (progress or {}).get("host_counts_by_state") or {}
    host_summary = (
        " / ".join(
            f"{k}={int(counts.get(k, 0) or 0)}"
            for k in ("succeeded", "failed", "skipped", "canceled")
        )
        if isinstance(counts, dict)
        else ""
    )
    title = f"Patch execution {state}: {plan_label}"
    message = (
        f"Patch update execution #{execution_id} for {plan_label} reached "
        f"state '{state}'."
    )
    if host_summary:
        message += f" Hosts: {host_summary}."
    _safe_emit(
        db,
        event_type=EVENT_PATCH_EXECUTED,
        title=title,
        message=message,
        severity=severity,
    )


def emit_patch_reboot_required(
    db: Session,
    *,
    execution_id: int,
    system_id: Optional[int],
    system_hostname: Optional[str],
    evidence_unknown: bool = False,
) -> None:
    """Emit when a patch execution row materializes a ``pending``
    reboot for one host (i.e. the reboot reconcile gate added a row
    that requires operator action).

    ``evidence_unknown`` distinguishes a host queued because it was
    observed to need a reboot from one queued because its state could
    not be established. Both need operator action, but only the second
    asks the operator to find out why the host could not answer.
    """
    host_label = system_hostname or (
        f"system #{system_id}" if system_id is not None else "unknown host"
    )
    if evidence_unknown:
        title = f"Reboot state unknown: {host_label}"
        message = (
            f"Patch update execution #{execution_id} could not establish "
            f"whether {host_label} needs a reboot. The host stays queued for "
            "a reboot decision and dependent waves remain blocked until it "
            "is resolved."
        )
    else:
        title = f"Reboot required: {host_label}"
        message = (
            f"Patch update execution #{execution_id} requires a reboot on "
            f"{host_label} for the patches to take effect."
        )
    _safe_emit(
        db,
        event_type=EVENT_PATCH_REBOOT_REQUIRED,
        title=title,
        message=message,
        severity="warning",
        system_id=system_id,
    )


def emit_patch_reboot_reconcile_failed(
    db: Session,
    *,
    execution_id: int,
    plan_id: Optional[int],
    reason: Optional[str] = None,
) -> None:
    """Emit when the reboot queue for an execution could not be built.

    A failed reconcile leaves the execution without a trustworthy
    answer about which hosts still need rebooting, so it is reported
    at ``error`` severity rather than left to a log line.
    """
    plan_label = f"plan #{plan_id}" if plan_id is not None else "unknown plan"
    message = (
        f"Patch update execution #{execution_id} ({plan_label}) could not "
        "build its reboot queue, so outstanding reboots for this run are "
        "unknown. Re-run the reboot reconcile for this execution."
    )
    detail = _safe_str(reason).strip()
    if detail:
        message += f" Reason: {detail}"
    _safe_emit(
        db,
        event_type=EVENT_PATCH_REBOOT_REQUIRED,
        title=f"Reboot queue incomplete: execution #{execution_id}",
        message=message,
        severity="error",
    )


def emit_patch_reboot_completed(
    db: Session,
    *,
    execution_id: int,
    system_id: Optional[int],
    system_hostname: Optional[str],
    state: str,
) -> None:
    """Emit when a patch reboot row transitions to a terminal state
    (``healthy`` -> ``info``; ``failed`` -> ``error``).
    """
    severity = "info" if state == "healthy" else "error"
    host_label = system_hostname or (
        f"system #{system_id}" if system_id is not None else "unknown host"
    )
    _safe_emit(
        db,
        event_type=EVENT_PATCH_REBOOT_COMPLETED,
        title=f"Reboot {state}: {host_label}",
        message=(
            f"Patch update execution #{execution_id} reboot on {host_label} "
            f"reached state '{state}'."
        ),
        severity=severity,
        system_id=system_id,
    )


def emit_patch_rollback_started(
    db: Session,
    *,
    execution_id: int,
    plan_id: Optional[int],
) -> None:
    """Emit when an operator-approved rollback dispatch begins."""
    plan_label = f"plan #{plan_id}" if plan_id is not None else "unknown plan"
    _safe_emit(
        db,
        event_type=EVENT_PATCH_ROLLBACK_STARTED,
        title=f"Rollback started: execution #{execution_id}",
        message=(
            f"Rollback dispatch started for patch execution #{execution_id} "
            f"({plan_label})."
        ),
        severity="warning",
    )


def emit_patch_rollback_completed(
    db: Session,
    *,
    execution_id: int,
    plan_id: Optional[int],
    state: str,
) -> None:
    """Emit when a rollback dispatch run finalizes
    (``succeeded`` / ``failed`` / ``canceled``)."""
    severity = (
        "info"
        if state == "succeeded"
        else ("warning" if state == "canceled" else "error")
    )
    plan_label = f"plan #{plan_id}" if plan_id is not None else "unknown plan"
    _safe_emit(
        db,
        event_type=EVENT_PATCH_ROLLBACK_COMPLETED,
        title=f"Rollback {state}: execution #{execution_id}",
        message=(
            f"Rollback dispatch for patch execution #{execution_id} "
            f"({plan_label}) reached state '{state}'."
        ),
        severity=severity,
    )


# ---------------------------------------------------------------------------
# Compliance / remediation lifecycle emitters
# ---------------------------------------------------------------------------


def emit_compliance_evaluated(
    db: Session,
    *,
    policy_id: int,
    policy_slug: str,
    system_id: int,
    verdict: str,
) -> None:
    """Emit when a compliance probe finishes for one (policy, host).

    Severity tracks the verdict: ``pass`` -> ``info``,
    ``fail`` -> ``warning``, ``error`` -> ``error``. The operator gets
    one notification per (system, policy) verdict transition; this is
    the same cadence the existing compliance evidence row records.
    """
    severity = {"pass": "info", "fail": "warning", "error": "error"}.get(
        verdict, "info"
    )
    _safe_emit(
        db,
        event_type=EVENT_COMPLIANCE_EVALUATED,
        title=f"Compliance verdict {verdict}: {policy_slug}",
        message=(
            f"Compliance policy '{policy_slug}' (id={policy_id}) evaluated "
            f"system #{system_id} with verdict '{verdict}'."
        ),
        severity=severity,
        system_id=system_id,
    )


def emit_remediation_requested(
    db: Session,
    *,
    request_id: int,
    policy_slug: str,
    check_slug: str,
    system_id: int,
    requested_by: Optional[int],
) -> None:
    """Emit when an operator opens a remediation request against a
    failing evidence row."""
    actor = f"user #{requested_by}" if requested_by is not None else "an operator"
    _safe_emit(
        db,
        event_type=EVENT_REMEDIATION_REQUESTED,
        title=(
            f"Remediation requested: {policy_slug}/{check_slug} "
            f"(system #{system_id})"
        ),
        message=(
            f"{actor} opened remediation request #{request_id} for compliance "
            f"check '{check_slug}' under policy '{policy_slug}' on "
            f"system #{system_id}."
        ),
        severity="warning",
        system_id=system_id,
    )


def emit_remediation_ready(
    db: Session,
    *,
    request_id: int,
    plan_id: int,
    policy_slug: str,
    check_slug: str,
    system_id: int,
) -> None:
    """Emit when an acknowledged remediation plan becomes
    ``ready_for_execution`` so admins can dispatch it. Fires once per
    plan acknowledgement that flips the readiness flag."""
    _safe_emit(
        db,
        event_type=EVENT_REMEDIATION_READY,
        title=(
            f"Remediation plan ready: {policy_slug}/{check_slug} "
            f"(system #{system_id})"
        ),
        message=(
            f"Remediation plan #{plan_id} for request #{request_id} "
            f"({policy_slug}/{check_slug} on system #{system_id}) was "
            f"acknowledged and is ready for execution."
        ),
        severity="info",
        system_id=system_id,
    )


def emit_remediation_executed(
    db: Session,
    *,
    attempt_id: int,
    request_id: int,
    plan_id: Optional[int],
    policy_slug: str,
    check_slug: str,
    system_id: int,
) -> None:
    """Emit when a remediation execution attempt dispatches to
    ``succeeded``."""
    plan_label = f"plan #{plan_id}" if plan_id is not None else "plan"
    _safe_emit(
        db,
        event_type=EVENT_REMEDIATION_EXECUTED,
        title=(
            f"Remediation succeeded: {policy_slug}/{check_slug} "
            f"(system #{system_id})"
        ),
        message=(
            f"Remediation attempt #{attempt_id} for request #{request_id} "
            f"({plan_label}, {policy_slug}/{check_slug}, system #{system_id}) "
            f"succeeded."
        ),
        severity="info",
        system_id=system_id,
    )


def emit_remediation_failed(
    db: Session,
    *,
    attempt_id: int,
    request_id: int,
    plan_id: Optional[int],
    policy_slug: str,
    check_slug: str,
    system_id: int,
    failure_reason: Optional[str] = None,
) -> None:
    """Emit when a remediation execution attempt terminates in
    ``failed`` (transport error, package-manager exit != 0, refusal,
    etc.). ``failure_reason`` is the bounded service-layer failure
    code."""
    plan_label = f"plan #{plan_id}" if plan_id is not None else "plan"
    reason = f" Reason: {_safe_str(failure_reason)}." if failure_reason else ""
    _safe_emit(
        db,
        event_type=EVENT_REMEDIATION_FAILED,
        title=(
            f"Remediation failed: {policy_slug}/{check_slug} " f"(system #{system_id})"
        ),
        message=(
            f"Remediation attempt #{attempt_id} for request #{request_id} "
            f"({plan_label}, {policy_slug}/{check_slug}, system #{system_id}) "
            f"failed.{reason}"
        ),
        severity="error",
        system_id=system_id,
    )
