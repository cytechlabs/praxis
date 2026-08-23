"""Patch reboot verification service (PRA-172 slice 4).

Post-reboot health verification on top of the Slice 1-3 reboot
queue substrate. Walks ``rebooting`` rows whose dispatch
``started_at`` is at least a configured grace period in the past
and runs a bounded SSH health probe to prove the host actually
came back. Successful verification flips the row from
``rebooting`` to ``healthy``; terminal verification failures flip
to ``failed`` with structured reason codes.

Slice 4 deliberately stops before dependent-wave continuation,
rollback / power-cycle fallback, agent-transport verification,
and background scheduling daemons.

Health probe (SSH-only by spec lock; mocked in tests):

1. **Reachability** — issues a benign ``true`` command via
   :class:`SSHTransport` to confirm the host accepts SSH sessions
   again. Failures here are mapped to ``reachability_failed``
   (transport unavailable / connection refused) or
   ``probe_timeout`` (asyncio.TimeoutError) or
   ``transport_error`` (other ``TransportError`` from the SSH
   layer).
2. **Reboot evidence** — refreshes host facts where the SSH
   reachability probe was successful, and compares
   ``uptime_seconds`` / ``kernel_version`` against the pre-reboot
   snapshot the Slice 3 dispatcher recorded in
   ``dispatch_details.pre_reboot_facts``. Successful evidence
   means either ``post_reboot_uptime < pre_reboot_uptime`` (the
   uptime counter reset) or ``kernel_version`` differs (a
   kernel-update reboot). Absent reboot evidence is
   ``no_reboot_evidence`` — failure, not silent.

PRA-172 Slice 4a: reachability alone is NOT proof of
reboot. The verifier requires explicit reboot evidence
(``uptime_seconds`` reset OR ``kernel_version`` change) to mark
a row ``healthy``. Missing pre-reboot facts baseline → structured
``no_baseline`` failure; reachable + matching post-reboot facts
→ structured ``no_reboot_evidence`` failure. An approved policy
override that allows reachability-only verification is reserved
for a later slice.

Audit events: reuses the Slice 3 reserved codes
``patch_update_execution_reboot.verification_passed`` and
``.verification_failed``. Both emit via ``safe_emit`` no ``db=``
per ``feedback_safe_emit_session_boundary``.

Reboot-wave failure threshold: applies to verification failures
within a single batch using the execution's
``failure_threshold_percent`` — matches Slice 3 dispatch-pause
semantics.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from ..db.models import (
    HostFacts,
    PatchUpdateExecution,
    PatchUpdateExecutionReboot,
    System,
)
from .audit_event_service import safe_emit
from .patch_execution_service import TERMINAL_EXECUTION_STATES
from .patch_reboot_dispatch_service import (
    AUDIT_REBOOT_VERIFICATION_FAILED,
    AUDIT_REBOOT_VERIFICATION_PASSED,
    _resolve_failure_threshold,
    _threshold_breach_context,
)
from .patch_reboot_service import (
    REBOOT_STATE_FAILED,
    REBOOT_STATE_HEALTHY,
    REBOOT_STATE_REBOOTING,
    REBOOT_STATE_VERIFYING,
    PatchUpdateRebootError,
    utc_iso,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Verification reason vocabulary (mirrors the values the service
# writes into ``verification_details.reason``).
# ---------------------------------------------------------------------------

VERIFY_REASON_REACHABILITY_FAILED = "reachability_failed"
VERIFY_REASON_NO_REBOOT_EVIDENCE = "no_reboot_evidence"
VERIFY_REASON_PROBE_TIMEOUT = "probe_timeout"
VERIFY_REASON_TRANSPORT_ERROR = "transport_error"
VERIFY_REASON_SYSTEM_DELETED = "system_deleted"
VERIFY_REASON_UPTIME_RESET = "uptime_reset"
VERIFY_REASON_KERNEL_CHANGED = "kernel_changed"
# PRA-172 Slice 4a: missing pre-reboot facts baseline
# is a structured FAILURE, not a success. Reachability alone is
# not proof the host actually rebooted — if the dispatcher
# couldn't snapshot pre-reboot facts (no HostFacts row at
# dispatch time), the verifier has no way to prove evidence and
# must record the gap as a terminal failure so operators can
# investigate / re-establish the facts baseline.
VERIFY_REASON_NO_BASELINE = "no_baseline"


# Default grace period between dispatch start and verification
# probe. A reboot needs at least a few seconds for sshd to die,
# the kernel to come back up, and the host's sshd to listen again.
# 60 seconds is a conservative default that operator policy can
# override in a later slice; the verifier currently sources this
# from the Slice 4 default rather than a per-policy column to keep
# the slice scoped.
DEFAULT_GRACE_SECONDS = 60


PAUSE_REASON_REBOOT_VERIFY_THRESHOLD_EXCEEDED = (
    "reboot_verify_failure_threshold_exceeded"
)


# ---------------------------------------------------------------------------
# Probe seam — tests pass a fake to avoid real SSH.
# ---------------------------------------------------------------------------


@dataclass
class RebootHealthProbeResult:
    """Outcome of one SSH-only reboot health probe.

    ``reachable`` indicates the SSH session reached the host and
    returned a benign command (i.e. ``transport.run_command(["true"])``
    succeeded). ``post_reboot_facts`` carries the fresh facts the
    verifier compares against the pre-reboot snapshot; the dict
    keys match :func:`patch_reboot_dispatch_service._capture_pre_reboot_facts`.
    A probe that hit the host but couldn't refresh facts returns
    ``reachable=True`` with ``post_reboot_facts={}``.

    ``reason`` carries a structured failure code when ``reachable``
    is False; ``error`` carries the underlying error message for
    operator-UI display.
    """

    reachable: bool
    post_reboot_facts: Dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None
    error: Optional[str] = None
    attempts: int = 1


# Sync callable: takes (System ORM row, pre_reboot_facts dict) and
# returns a ``RebootHealthProbeResult``. Tests pass fakes; the
# default implementation bridges to the async SSH transport.
RebootHealthProbeCallable = Callable[[System, Dict[str, Any]], RebootHealthProbeResult]


def default_reboot_health_probe(
    db: Session, system: System, pre_reboot_facts: Dict[str, Any]
) -> RebootHealthProbeResult:
    """Default reboot health probe. SSH-only by spec lock.

    Runs ``true`` over SSH to confirm reachability. If the
    reachability check passes, refreshes ``host_facts`` for the
    system (best-effort) so the caller can compare uptime/kernel
    against the pre-reboot baseline. Per the Slice 3 +
    Slice 4 review locks this never goes through the generic
    transport factory — agent reboot verification is reserved for
    a later slice.
    """
    from .ssh_service import SSHService
    from .transport import TransportError
    from .transport.ssh import SSHTransport

    async def _run() -> RebootHealthProbeResult:
        ssh_service = SSHService(db)
        try:
            await asyncio.to_thread(lambda: ssh_service.get_connection(system.id))
        except Exception as exc:  # pylint: disable=broad-except
            ssh_service.close_all_connections()
            return RebootHealthProbeResult(
                reachable=False,
                reason=VERIFY_REASON_REACHABILITY_FAILED,
                error=str(exc),
            )

        transport = SSHTransport(system, ssh_service)
        try:
            try:
                await transport.run_command(["true"])
            except asyncio.TimeoutError as exc:
                return RebootHealthProbeResult(
                    reachable=False,
                    reason=VERIFY_REASON_PROBE_TIMEOUT,
                    error=str(exc),
                )
            except TransportError as exc:
                return RebootHealthProbeResult(
                    reachable=False,
                    reason=VERIFY_REASON_TRANSPORT_ERROR,
                    error=str(exc),
                )

            # Reachable. Refresh facts opportunistically; the
            # default path here does not invoke the live facts
            # collector — that's beyond Slice 4 transport scope.
            # Slice 4 just reads the most-recent ``host_facts`` row
            # and lets the caller decide whether the data is fresh
            # enough. A later slice that wires PRA-155 facts
            # refresh can replace this read.
            facts = db.query(HostFacts).filter(HostFacts.system_id == system.id).first()
            post_facts: Dict[str, Any] = {}
            if facts is not None:
                post_facts = {
                    "system_id": system.id,
                    "uptime_seconds": facts.uptime_seconds,
                    "kernel_version": facts.kernel_version,
                    "collected_at": utc_iso(facts.collected_at),
                }
            return RebootHealthProbeResult(reachable=True, post_reboot_facts=post_facts)
        finally:
            ssh_service.close_all_connections()

    # Reuse PRA-171's sync↔async bridge.
    from .patch_execution_dispatch_service import _run_async_from_sync

    return _run_async_from_sync(_run())


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class RebootVerifyHostOutcome:
    """One per-row outcome inside a verify-due batch result."""

    execution_reboot_id: int
    execution_host_id: int
    system_id: Optional[int]
    state: str  # ``healthy`` on success; ``failed`` on verification failure
    reason: Optional[str] = None


@dataclass
class RebootVerifyBatchSummary:
    """Result of one ``POST /reboots/verify-due`` invocation."""

    execution_id: int
    verified_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    not_due_count: int = 0
    no_due: bool = False
    pause_reason: Optional[str] = None
    threshold_pause: Optional[Dict[str, Any]] = None
    host_outcomes: List[RebootVerifyHostOutcome] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Evidence evaluation
# ---------------------------------------------------------------------------


def _evaluate_reboot_evidence(
    pre: Dict[str, Any], post: Dict[str, Any]
) -> Dict[str, Any]:
    """Compare pre- and post-reboot fact snapshots.

    Returns a dict with at minimum ``rebooted`` (bool) and
    ``reason`` (code). Reboot evidence requires PROOF — not just
    reachability:

    * ``uptime_seconds`` reset: post < pre indicates the uptime
      counter restarted (i.e. host rebooted).
    * ``kernel_version`` changed: the host loaded a different
      kernel, which only happens on reboot.

    Absent baseline (no pre-reboot facts captured) → returns
    ``rebooted=False`` with ``no_baseline`` reason. PRA-172
    Slice 4a: reachability alone is NOT proof of
    reboot — a host that never actually rebooted would still
    accept SSH sessions, so without a baseline to compare we
    cannot mark the row ``healthy``. The verifier records the
    missing-baseline gap as a structured failure so operators
    can investigate / re-establish the facts baseline.

    Missing post-reboot facts despite a baseline → returns
    ``rebooted=False`` with ``no_reboot_evidence``.
    """
    pre_uptime = pre.get("uptime_seconds") if pre else None
    pre_kernel = pre.get("kernel_version") if pre else None
    post_uptime = post.get("uptime_seconds") if post else None
    post_kernel = post.get("kernel_version") if post else None

    # No baseline at all: structured failure. Reachability alone
    # is not proof of reboot.
    if not pre or (pre_uptime is None and pre_kernel is None):
        return {
            "rebooted": False,
            "reason": VERIFY_REASON_NO_BASELINE,
            "pre_uptime_seconds": pre_uptime,
            "post_uptime_seconds": post_uptime,
            "pre_kernel_version": pre_kernel,
            "post_kernel_version": post_kernel,
        }

    # Baseline present but post-reboot facts missing entirely.
    if not post:
        return {
            "rebooted": False,
            "reason": VERIFY_REASON_NO_REBOOT_EVIDENCE,
            "pre_uptime_seconds": pre_uptime,
            "post_uptime_seconds": None,
            "pre_kernel_version": pre_kernel,
            "post_kernel_version": None,
        }

    # Kernel change is unambiguous reboot evidence.
    if (
        pre_kernel
        and post_kernel
        and isinstance(pre_kernel, str)
        and isinstance(post_kernel, str)
        and pre_kernel != post_kernel
    ):
        return {
            "rebooted": True,
            "reason": VERIFY_REASON_KERNEL_CHANGED,
            "pre_uptime_seconds": pre_uptime,
            "post_uptime_seconds": post_uptime,
            "pre_kernel_version": pre_kernel,
            "post_kernel_version": post_kernel,
        }

    # Uptime reset: post < pre means the counter restarted.
    if (
        isinstance(pre_uptime, int)
        and isinstance(post_uptime, int)
        and post_uptime < pre_uptime
    ):
        return {
            "rebooted": True,
            "reason": VERIFY_REASON_UPTIME_RESET,
            "pre_uptime_seconds": pre_uptime,
            "post_uptime_seconds": post_uptime,
            "pre_kernel_version": pre_kernel,
            "post_kernel_version": post_kernel,
        }

    # No evidence the host rebooted.
    return {
        "rebooted": False,
        "reason": VERIFY_REASON_NO_REBOOT_EVIDENCE,
        "pre_uptime_seconds": pre_uptime,
        "post_uptime_seconds": post_uptime,
        "pre_kernel_version": pre_kernel,
        "post_kernel_version": post_kernel,
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def _emit_audit(
    *,
    action: str,
    row: PatchUpdateExecutionReboot,
    actor_user_id: Optional[int],
    actor_username: Optional[str],
    actor_ip: Optional[str],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    context: Dict[str, Any] = {
        "execution_id": row.execution_id,
        "execution_host_id": row.execution_host_id,
        "plan_id": row.plan_id_snapshot,
        "system_id": row.system_id_snapshot,
        "wave_index": row.wave_index,
        "state": row.state,
        "started_at": utc_iso(row.started_at),
        "verified_at": utc_iso(row.verified_at),
    }
    if extra:
        context.update(extra)
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_system_id=row.system_id_snapshot,
        target_kind="patch_update_execution_reboot",
        target_id=str(row.id),
        context=context,
    )


# ---------------------------------------------------------------------------
# Public API — verify_due_reboots
# ---------------------------------------------------------------------------


def _due_rebooting_rows(
    db: Session,
    execution_id: int,
    *,
    now: datetime,
    grace_seconds: int,
) -> List[PatchUpdateExecutionReboot]:
    cutoff = now - timedelta(seconds=grace_seconds)
    return (
        db.query(PatchUpdateExecutionReboot)
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution_id,
            PatchUpdateExecutionReboot.state == REBOOT_STATE_REBOOTING,
            PatchUpdateExecutionReboot.started_at <= cutoff,
        )
        .order_by(
            PatchUpdateExecutionReboot.wave_index.asc(),
            PatchUpdateExecutionReboot.started_at.asc().nullsfirst(),
            PatchUpdateExecutionReboot.id.asc(),
        )
        .all()
    )


def _not_due_rebooting_count(
    db: Session,
    execution_id: int,
    *,
    now: datetime,
    grace_seconds: int,
) -> int:
    cutoff = now - timedelta(seconds=grace_seconds)
    return (
        db.query(PatchUpdateExecutionReboot)
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution_id,
            PatchUpdateExecutionReboot.state == REBOOT_STATE_REBOOTING,
            PatchUpdateExecutionReboot.started_at > cutoff,
        )
        .count()
    )


def _resolve_probe(
    db: Session,
    override: Optional[RebootHealthProbeCallable],
) -> RebootHealthProbeCallable:
    if override is not None:
        return override

    def _impl(system: System, pre: Dict[str, Any]) -> RebootHealthProbeResult:
        return default_reboot_health_probe(db, system, pre)

    return _impl


def verify_due_reboots(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    now: Optional[datetime] = None,
    grace_seconds: int = DEFAULT_GRACE_SECONDS,
    health_check_callable: Optional[RebootHealthProbeCallable] = None,
    max_verify: Optional[int] = None,
) -> RebootVerifyBatchSummary:
    """Verify one bounded batch of due ``rebooting`` reboot rows.

    Walks rows in state ``rebooting`` whose ``started_at`` is at
    least ``grace_seconds`` in the past, atomically claims each
    via ``rebooting`` → ``verifying``, runs the SSH health probe,
    and transitions to ``healthy`` (success) or ``failed`` (terminal
    verification failure). Failures count against the reboot-wave
    failure threshold; on breach the batch stops mid-verify and
    the summary carries the structured ``threshold_pause`` context.

    The parent execution must be in a terminal state (the reboot
    queue is only populated by Slice 2's auto-reconcile hook
    after the execution finalizes).
    """
    execution = (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.id == execution_id)
        .first()
    )
    if execution is None:
        raise PatchUpdateRebootError(
            f"patch update execution id={execution_id} not found"
        )
    if execution.state not in TERMINAL_EXECUTION_STATES:
        raise PatchUpdateRebootError(
            f"execution {execution_id} is in state {execution.state!r}; only "
            f"terminal executions can verify reboots"
        )

    current_now = now or datetime.utcnow()
    summary = RebootVerifyBatchSummary(execution_id=execution_id)

    due_rows = _due_rebooting_rows(
        db, execution_id, now=current_now, grace_seconds=grace_seconds
    )
    summary.not_due_count = _not_due_rebooting_count(
        db, execution_id, now=current_now, grace_seconds=grace_seconds
    )
    if not due_rows:
        summary.no_due = True
        return summary

    bound = (
        max_verify
        if max_verify is not None
        else (execution.max_parallel_per_wave or len(due_rows))
    )
    batch = due_rows[:bound]
    threshold_pct = _resolve_failure_threshold(execution)
    probe = _resolve_probe(db, health_check_callable)

    attempted = 0
    failed = 0

    for row in batch:
        # Atomic claim: ``rebooting`` → ``verifying``. Conditional
        # UPDATE ensures concurrent verify-due calls cannot
        # double-probe the same row. The first UPDATE that affects
        # 1 row wins; losing callers see 0 affected rows and skip.
        claimed = (
            db.query(PatchUpdateExecutionReboot)
            .filter(
                PatchUpdateExecutionReboot.id == row.id,
                PatchUpdateExecutionReboot.state == REBOOT_STATE_REBOOTING,
            )
            .update(
                {PatchUpdateExecutionReboot.state: REBOOT_STATE_VERIFYING},
                synchronize_session=False,
            )
        )
        db.commit()
        if claimed == 0:
            continue
        db.refresh(row)

        attempted += 1
        pre_facts = (row.dispatch_details or {}).get("pre_reboot_facts") or {}

        # Fetch the System ORM row from the snapshot id. None means
        # the host was deleted after the reboot dispatch — that's
        # a structured failure, not a crash.
        system: Optional[System] = None
        if row.system_id_snapshot is not None:
            system = (
                db.query(System).filter(System.id == row.system_id_snapshot).first()
            )

        if system is None:
            probe_result = RebootHealthProbeResult(
                reachable=False,
                reason=VERIFY_REASON_SYSTEM_DELETED,
                error=f"system id={row.system_id_snapshot} no longer exists",
            )
        else:
            try:
                probe_result = probe(system, pre_facts)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning(
                    "reboot health_check_callable raised for row=%d: %s",
                    row.id,
                    exc,
                )
                probe_result = RebootHealthProbeResult(
                    reachable=False,
                    reason=VERIFY_REASON_TRANSPORT_ERROR,
                    error=str(exc),
                )

        # Build the structured verification result.
        if probe_result.reachable:
            evidence = _evaluate_reboot_evidence(
                pre_facts, probe_result.post_reboot_facts
            )
            rebooted = bool(evidence.get("rebooted"))
        else:
            rebooted = False
            evidence = {
                "rebooted": False,
                "reason": probe_result.reason or VERIFY_REASON_REACHABILITY_FAILED,
                "error": probe_result.error,
            }

        success = rebooted
        new_state = REBOOT_STATE_HEALTHY if success else REBOOT_STATE_FAILED
        row.state = new_state
        row.verified_at = current_now
        row.completed_at = current_now
        row.verification_details = {
            "reachable": probe_result.reachable,
            "attempts": probe_result.attempts,
            "verified_at": utc_iso(current_now),
            "reason": evidence.get("reason"),
            "evidence": evidence,
            "error": probe_result.error if not probe_result.reachable else None,
        }
        db.commit()

        if success:
            _emit_audit(
                action=AUDIT_REBOOT_VERIFICATION_PASSED,
                row=row,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                extra={"reason": evidence.get("reason")},
            )
            summary.succeeded_count += 1
        else:
            _emit_audit(
                action=AUDIT_REBOOT_VERIFICATION_FAILED,
                row=row,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                extra={"reason": evidence.get("reason")},
            )
            summary.failed_count += 1
            failed += 1
        # PRA-178 Slice 3: emit patch.reboot_completed beside the
        # verification audit. Fires once per row's terminal verify
        # transition (healthy or failed).
        from . import notification_events

        notification_events.emit_patch_reboot_completed(
            db,
            execution_id=row.execution_id,
            system_id=row.system_id_snapshot,
            system_hostname=row.system_hostname_snapshot,
            state=new_state,
        )

        summary.verified_count += 1
        summary.host_outcomes.append(
            RebootVerifyHostOutcome(
                execution_reboot_id=row.id,
                execution_host_id=row.execution_host_id,
                system_id=row.system_id_snapshot,
                state=new_state,
                reason=evidence.get("reason"),
            )
        )

        breach = _threshold_breach_context(threshold_pct, failed, attempted)
        if breach is not None:
            # Override the dispatch breach code with a verify-
            # specific marker so the operator UI can render the
            # right phase.
            breach = dict(breach)
            breach["code"] = PAUSE_REASON_REBOOT_VERIFY_THRESHOLD_EXCEEDED
            summary.pause_reason = PAUSE_REASON_REBOOT_VERIFY_THRESHOLD_EXCEEDED
            summary.threshold_pause = breach
            break

    return summary
