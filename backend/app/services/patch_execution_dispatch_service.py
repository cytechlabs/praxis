"""Patch execution dispatch service (PRA-171 slices 2 and 3).

Trigger-based per-host dispatcher that consumes one bounded batch
from a Slice 1 execution row, builds package-manager command
invocations from the PRA-164 selected-package snapshots, hands the
command to a small adapter seam (mockable in tests; default bridges
to the existing transport factory), captures per-host and
per-package results, transitions host state, emits host-level audit
events, and applies Slice 3 lifecycle hooks for wave completion,
execution completion, and threshold-driven auto-pause.

**Bounded batch only.** One ``POST /dispatch-next`` call dispatches
at most ``execution.max_parallel_per_wave`` pending hosts in the
lowest pending wave. There is NO long-lived background worker, NO
continuous scheduling loop, NO reboot, NO rollback, NO version
re-pin, NO mirror mutation, NO airgap behavior, and NO package
history mutation. Reboot/rollback/mirror/airgap work belongs to
later slices.

Adapter seam:

The dispatcher delegates the actual remote command execution to a
``DispatchCallable``: a sync ``(System, list[str]) -> DispatchResult``
function. Tests pass a fake. The default implementation
(``default_dispatch``) also receives the request database session so
the SSH fallback path can build the existing ``SSHService(db)``. It
bridges to the existing async transport factory using the same sync↔async pattern
``command_execution_service`` uses (`_run_async_from_sync`).

Per-package outcome derivation:

Slice 2 runs a single command per host (one apt or dnf invocation
covering all selected packages for that host). When the command
exits 0, every package row is marked ``succeeded``; when it exits
non-zero, every package row is marked ``failed`` with the same
structured error code. Per-package output parsing for partial
success is deferred to a later slice.

Audit events emitted (via ``safe_emit`` no ``db=`` per the
session-boundary lock):

- ``patch_update_execution.host_started`` — once per host before
  the dispatch attempt.
- ``patch_update_execution.host_succeeded`` — once per host whose
  dispatch returned exit 0.
- ``patch_update_execution.host_failed`` — once per host whose
  dispatch failed (non-zero exit, transport error, or unsupported
  family).
- ``patch_update_execution.wave_completed`` — once per completed wave.
- ``patch_update_execution.completed`` — once when the execution
  reaches ``succeeded`` or ``failed``.
- ``patch_update_execution.paused`` — reused when failure-threshold
  auto-pause trips.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import (
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdatePlanHost,
    PatchUpdatePlanPreflightSnapshot,
    PatchUpdatePlanSelectedPackage,
    System,
    User,
)
from .audit_event_service import safe_emit
from .patch_execution_service import (  # noqa: F401  (re-export friendliness)
    AUDIT_EXECUTION_CANCELED,
    AUDIT_EXECUTION_PAUSED,
    EXECUTION_HOST_STATE_CANCELED,
    EXECUTION_HOST_STATE_FAILED,
    EXECUTION_HOST_STATE_PENDING,
    EXECUTION_HOST_STATE_RUNNING,
    EXECUTION_HOST_STATE_SKIPPED,
    EXECUTION_HOST_STATE_SUCCEEDED,
    EXECUTION_STATE_FAILED,
    EXECUTION_STATE_PAUSED,
    EXECUTION_STATE_RUNNING,
    EXECUTION_STATE_SUCCEEDED,
    PatchUpdateExecutionError,
    _build_progress_summary,
)
from .patch_update_plan_service import (
    PACKAGE_MANAGER_FAMILY_APT,
    PACKAGE_MANAGER_FAMILY_DNF,
    PACKAGE_MANAGER_FAMILY_UNKNOWN,
    SELECTION_REASON_INVENTORY_MISSING,
    SELECTION_STATE_SELECTED,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Audit constants for the three new host-level events Slice 2 emits.
# Reserved-but-not-yet-emitted strings (`wave_completed`, `completed`)
# stay in later slices that own wave/plan completion semantics.
# ---------------------------------------------------------------------------

AUDIT_EXECUTION_HOST_STARTED = "patch_update_execution.host_started"
AUDIT_EXECUTION_HOST_SUCCEEDED = "patch_update_execution.host_succeeded"
AUDIT_EXECUTION_HOST_FAILED = "patch_update_execution.host_failed"

# Slice 3: lifecycle events emitted at most once per wave / per execution.
# Idempotency is enforced via ``progress_summary["completed_wave_indexes"]``
# and the execution's terminal state (running -> succeeded/failed flips
# at most once and refuses further dispatch by the existing 422 path).
AUDIT_EXECUTION_WAVE_COMPLETED = "patch_update_execution.wave_completed"
AUDIT_EXECUTION_COMPLETED = "patch_update_execution.completed"


# ---------------------------------------------------------------------------
# Slice 3: structured pause reason for failure-threshold auto-pause
# ---------------------------------------------------------------------------

PAUSE_REASON_THRESHOLD_EXCEEDED = "failure_threshold_exceeded"


# ---------------------------------------------------------------------------
# Per-package outcome vocabulary (mirrors DB CHECK)
# ---------------------------------------------------------------------------

PACKAGE_OUTCOME_SUCCEEDED = "succeeded"
PACKAGE_OUTCOME_FAILED = "failed"
PACKAGE_OUTCOME_SKIPPED = "skipped"
PACKAGE_OUTCOME_UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Host-level structured failure codes
# ---------------------------------------------------------------------------

ERROR_CODE_UNSUPPORTED_FAMILY = "unsupported_package_family"
ERROR_CODE_TRANSPORT_UNAVAILABLE = "transport_unavailable"
ERROR_CODE_TRANSPORT_ERROR = "transport_error"
ERROR_CODE_PACKAGE_MANAGER_FAILED = "package_manager_failed"
ERROR_CODE_NO_SELECTED_PACKAGES = "no_selected_packages"


# Cap stored stdout/stderr size so the result table doesn't grow
# pathologically on misbehaving package managers.
MAX_OUTPUT_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# DispatchResult + DispatchCallable adapter seam
# ---------------------------------------------------------------------------


@dataclass
class DispatchResult:
    """Outcome of one ``(system, command)`` dispatch.

    ``error`` carries a structured error-code string when the
    transport / adapter could not even produce an exit code (e.g.
    ``transport_unavailable``); otherwise it stays ``None`` and
    callers interpret the exit code.

    ``effective_argv`` (PRA-175 Slice 2) is the actual argv handed
    to the transport after :func:`dispatch_sudo.wrap_argv_for_sudo`
    applied any ``sudo -n`` / ``sudo -S`` prefix. ``None`` means
    the dispatcher did not record it (the wrap was a no-op or a
    test fake bypassed the default dispatcher). Orchestrators
    persist it into the existing JSONB evidence column alongside
    the planned argv. The password (when ``sudo_method=password``)
    is NEVER part of ``effective_argv`` — it travels through
    ``transport.run_command(stdin=...)`` and is not retained on
    the result.
    """

    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    transport_name: str = ""
    error: Optional[str] = None
    effective_argv: Optional[List[str]] = None


# Sync callable: takes (System ORM row, command argv list) and returns
# a DispatchResult. Tests pass a fake; default implementation bridges
# to the async transport factory.
DispatchCallable = Callable[[System, List[str]], DispatchResult]


def default_dispatch(db: Session, system: System, cmd: List[str]) -> DispatchResult:
    """Default DispatchCallable that bridges to the async transport
    factory. Uses the same sync↔async pattern command_execution_service
    uses so a FastAPI sync route handler can call us safely from
    within a parent event loop.

    The bridge owns its BrokerClient lifecycle so the httpx.AsyncClient
    is bound to the freshly-built loop and torn down before the loop
    closes (per ``feedback_async_broker_client.md``).

    PRA-175: resolves the system's credential at dispatch time and
    routes the planned ``cmd`` argv through :func:`wrap_argv_for_sudo`
    so the transport call honors ``credential.sudo_method``
    (``none`` keeps argv as-is, ``nopasswd`` prepends ``sudo -n``,
    ``password`` prepends ``sudo -S`` and pipes the Vault-stored
    sudo password to stdin). The fake-dispatcher test path
    (callers passing ``dispatch_callable=fake``) bypasses this
    function entirely, so existing dispatch tests that record raw
    planned argv remain accurate.
    """
    from .broker_client import BrokerClient
    from .dispatch_sudo import (
        SudoMethodError,
        resolve_system_credential,
        wrap_argv_for_sudo,
    )
    from .ssh_service import SSHService
    from .transport import TransportError, TransportUnavailable, get_transport

    credential = resolve_system_credential(db, system)
    try:
        effective_argv, sudo_stdin = wrap_argv_for_sudo(db, credential, cmd)
    except SudoMethodError as exc:
        # PRA-229 PATCH-03: a null/unknown credential sudo_method is a structured,
        # operator-actionable dispatch condition — record it on the row instead
        # of silently running the planned argv unescalated. Also covers rollback,
        # which dispatches through this same default_dispatch.
        return DispatchResult(
            exit_code=-1,
            error=exc.reason,
            stderr=exc.operator_message(),
            effective_argv=None,
        )

    async def _run() -> DispatchResult:
        broker_client = BrokerClient()
        ssh_service = SSHService(db)
        try:
            try:
                transport = await get_transport(
                    system,
                    broker_client,
                    ssh_service=ssh_service,
                )
            except TransportUnavailable as exc:
                # PRA-175 Slice 2: surface effective_argv on every
                # return path so the orchestrator can record what the
                # wrapper produced even when the transport never opened.
                return DispatchResult(
                    exit_code=-1,
                    error=ERROR_CODE_TRANSPORT_UNAVAILABLE,
                    stderr=str(exc),
                    effective_argv=list(effective_argv),
                )
            try:
                result = await transport.run_command(effective_argv, stdin=sudo_stdin)
            except TransportError as exc:
                return DispatchResult(
                    exit_code=-1,
                    error=ERROR_CODE_TRANSPORT_ERROR,
                    stderr=str(exc),
                    transport_name=transport.name,
                    effective_argv=list(effective_argv),
                )
            return DispatchResult(
                exit_code=int(result.exit_code),
                stdout=result.stdout.decode("utf-8", errors="replace"),
                stderr=result.stderr.decode("utf-8", errors="replace"),
                duration_ms=int(result.duration_ms),
                transport_name=transport.name,
                effective_argv=list(effective_argv),
            )
        finally:
            ssh_service.close_all_connections()
            await broker_client.__aexit__(None, None, None)

    return _run_async_from_sync(_run())


def _run_async_from_sync(coro: Awaitable) -> Any:
    """Mirror of command_execution_service._run_async_from_sync.

    Lets a sync caller invoke an async coroutine even if a parent
    event loop is already running in the current thread.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_actor(db: Session, actor_user_id: int) -> None:
    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchUpdateExecutionError(
            f"actor_user_id={actor_user_id} does not reference a user"
        )


def _require_execution(db: Session, execution_id: int) -> PatchUpdateExecution:
    execution = (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.id == execution_id)
        .first()
    )
    if execution is None:
        raise PatchUpdateExecutionError(
            f"patch update execution id={execution_id} not found"
        )
    return execution


def _truncate(text: str) -> str:
    if not text:
        return ""
    if len(text) <= MAX_OUTPUT_BYTES:
        return text
    return (
        text[:MAX_OUTPUT_BYTES] + f"...[truncated {len(text) - MAX_OUTPUT_BYTES} bytes]"
    )


def _select_lowest_pending_wave(db: Session, execution_id: int) -> Optional[int]:
    """Return the lowest wave_index that still has at least one
    ``pending`` host on this execution, or ``None`` when no wave
    has pending hosts left."""
    row = (
        db.query(PatchUpdateExecutionHost.wave_index)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.state == EXECUTION_HOST_STATE_PENDING,
        )
        .order_by(PatchUpdateExecutionHost.wave_index.asc())
        .first()
    )
    return row[0] if row else None


def _take_pending_hosts(
    db: Session, execution_id: int, wave_index: int, limit: int
) -> List[PatchUpdateExecutionHost]:
    """Take up to ``limit`` pending hosts from a specific wave,
    ordered by id for determinism."""
    return (
        db.query(PatchUpdateExecutionHost)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.wave_index == wave_index,
            PatchUpdateExecutionHost.state == EXECUTION_HOST_STATE_PENDING,
        )
        .order_by(PatchUpdateExecutionHost.id.asc())
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Slice 3 lifecycle helpers — wave/plan completion + threshold auto-pause
# ---------------------------------------------------------------------------

# Terminal host states: a host in any of these has reached an end state
# and will not be dispatched again. Slice 3 uses this set to decide
# wave/plan completion and to compute the failure-threshold ratio.
TERMINAL_HOST_STATES = frozenset(
    {
        EXECUTION_HOST_STATE_SUCCEEDED,
        EXECUTION_HOST_STATE_FAILED,
        EXECUTION_HOST_STATE_SKIPPED,
        EXECUTION_HOST_STATE_CANCELED,
    }
)


def _wave_indexes_for_execution(db: Session, execution_id: int) -> List[int]:
    """Distinct wave_index values present on this execution, ordered."""
    rows = (
        db.query(PatchUpdateExecutionHost.wave_index)
        .filter(PatchUpdateExecutionHost.execution_id == execution_id)
        .distinct()
        .order_by(PatchUpdateExecutionHost.wave_index.asc())
        .all()
    )
    return [r[0] for r in rows]


def _wave_is_complete(db: Session, execution_id: int, wave_index: int) -> bool:
    """A wave is complete when every host in that wave is in a terminal
    state (no remaining pending / running / paused host rows)."""
    non_terminal = (
        db.query(PatchUpdateExecutionHost.id)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.wave_index == wave_index,
            PatchUpdateExecutionHost.state.notin_(TERMINAL_HOST_STATES),
        )
        .first()
    )
    return non_terminal is None


def _execution_is_complete(db: Session, execution_id: int) -> bool:
    """Whole execution is complete when every host across every wave is
    terminal. Computed by looking for any non-terminal row."""
    non_terminal = (
        db.query(PatchUpdateExecutionHost.id)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.state.notin_(TERMINAL_HOST_STATES),
        )
        .first()
    )
    return non_terminal is None


def _terminal_host_counts(db: Session, execution_id: int) -> Tuple[int, int]:
    """Return ``(failed_terminal_count, total_terminal_count)`` for the
    execution. Used by the failure-threshold check.

    Terminal hosts include succeeded / failed / skipped / canceled.
    A ``skipped`` host is NOT counted as a failure for threshold
    purposes (it never dispatched). A ``canceled`` host similarly
    never produced a real failure result.
    """
    rows = (
        db.query(
            PatchUpdateExecutionHost.state,
        )
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.state.in_(TERMINAL_HOST_STATES),
        )
        .all()
    )
    failed = sum(1 for (s,) in rows if s == EXECUTION_HOST_STATE_FAILED)
    return failed, len(rows)


def _threshold_breach_context(
    execution: PatchUpdateExecution, failed: int, total: int
) -> Optional[Dict[str, Any]]:
    """Return a structured breach-context dict when the execution's
    ``failure_threshold_percent`` is set and the current failure rate
    exceeds it; ``None`` otherwise.

    Convention (per slice packet): breach when
    ``failed / total * 100 > threshold``. Threshold ``0`` means any
    failure breaches; threshold ``None`` means no auto-pause.
    """
    threshold = execution.failure_threshold_percent
    if threshold is None or total == 0:
        return None
    pct = (failed / total) * 100.0
    if pct <= threshold:
        return None
    return {
        "code": PAUSE_REASON_THRESHOLD_EXCEEDED,
        "failure_threshold_percent": threshold,
        "failed_terminal_hosts": failed,
        "terminal_hosts": total,
        "failure_percent": round(pct, 2),
    }


def _completed_wave_indexes(execution: PatchUpdateExecution) -> List[int]:
    """Read the JSONB list of waves whose ``wave_completed`` audit
    event has already been emitted. Stored in ``progress_summary``
    so a re-call cannot duplicate the event."""
    summary = execution.progress_summary or {}
    raw = summary.get("completed_wave_indexes") or []
    return [int(x) for x in raw]


def _record_completed_wave(execution: PatchUpdateExecution, wave_index: int) -> None:
    """Append ``wave_index`` to the JSONB completed-waves list in
    ``progress_summary`` (idempotent)."""
    summary = dict(execution.progress_summary or {})
    existing = list(summary.get("completed_wave_indexes") or [])
    if wave_index not in existing:
        existing.append(wave_index)
        existing.sort()
        summary["completed_wave_indexes"] = existing
        execution.progress_summary = summary


def _record_threshold_pause(
    execution: PatchUpdateExecution, breach_context: Dict[str, Any]
) -> None:
    """Stash the breach context inside ``progress_summary`` so the
    operator UI can render the threshold-pause callout without parsing
    the freeform pause_reason text."""
    summary = dict(execution.progress_summary or {})
    summary["threshold_pause"] = breach_context
    execution.progress_summary = summary


def _emit_lifecycle_audit(
    *,
    action: str,
    execution: PatchUpdateExecution,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    context: Dict[str, Any] = {
        "execution_id": execution.id,
        "plan_id": execution.plan_id,
    }
    if extra:
        context.update(extra)
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution",
        target_id=str(execution.id),
        context=context,
    )


def _emit_unrecorded_wave_completions(
    db: Session,
    *,
    execution: PatchUpdateExecution,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
) -> List[int]:
    """Walk all wave indexes on this execution; for any wave that is
    complete and whose index is not yet in
    ``progress_summary.completed_wave_indexes``, emit
    ``patch_update_execution.wave_completed`` and record the index.

    Returns the list of newly-emitted wave indexes for the caller to
    surface in the dispatch summary.
    """
    newly_completed: List[int] = []
    already_recorded = set(_completed_wave_indexes(execution))
    for wave_index in _wave_indexes_for_execution(db, execution.id):
        if wave_index in already_recorded:
            continue
        if not _wave_is_complete(db, execution.id, wave_index):
            continue
        # Aggregate counts for the audit event context.
        wave_rows = (
            db.query(PatchUpdateExecutionHost.state)
            .filter(
                PatchUpdateExecutionHost.execution_id == execution.id,
                PatchUpdateExecutionHost.wave_index == wave_index,
            )
            .all()
        )
        wave_counts: Dict[str, int] = {}
        for (s,) in wave_rows:
            wave_counts[s] = wave_counts.get(s, 0) + 1
        _record_completed_wave(execution, wave_index)
        already_recorded.add(wave_index)
        newly_completed.append(wave_index)
        _emit_lifecycle_audit(
            action=AUDIT_EXECUTION_WAVE_COMPLETED,
            execution=execution,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={
                "wave_index": wave_index,
                "host_count": len(wave_rows),
                "host_counts_by_state": wave_counts,
            },
        )

        # PRA-172 Slice 5: as each wave completes, reconcile the
        # reboot queue rows for THAT wave's hosts so the
        # dependent-wave gate has rows to inspect before the
        # next wave can dispatch. The execution stays in
        # ``running`` here — the per-wave reconcile entry point
        # gates on the wave being complete, not the whole
        # execution. Best-effort: a reboot-queue failure must
        # not roll back the just-emitted ``wave_completed``
        # audit. Lazy import to avoid a circular reference.
        try:
            from . import patch_reboot_service

            existing_reboot_ids = {
                r.id
                for r in db.query(patch_reboot_service.PatchUpdateExecutionReboot.id)
                .filter(
                    patch_reboot_service.PatchUpdateExecutionReboot.execution_id
                    == execution.id,
                    patch_reboot_service.PatchUpdateExecutionReboot.wave_index
                    == wave_index,
                )
                .all()
            }
            wave_reboot_rows = patch_reboot_service.reconcile_wave_reboots(
                db, execution.id, wave_index
            )
            # Emit queued / skipped audits for any newly-created
            # reboot rows from this wave. ``scheduled`` rows aren't
            # produced here — promotion happens later in
            # ``auto_reconcile_on_terminal``.
            for row in wave_reboot_rows:
                if row.id in existing_reboot_ids:
                    continue
                if row.state == patch_reboot_service.REBOOT_STATE_PENDING:
                    patch_reboot_service._emit_reboot_audit(
                        action=patch_reboot_service.AUDIT_REBOOT_QUEUED,
                        row=row,
                        actor_user_id=actor_user_id,
                        actor_username=actor_username,
                        actor_ip=actor_ip,
                    )
                elif row.state == patch_reboot_service.REBOOT_STATE_SKIPPED:
                    patch_reboot_service._emit_reboot_audit(
                        action=patch_reboot_service.AUDIT_REBOOT_SKIPPED,
                        row=row,
                        actor_user_id=actor_user_id,
                        actor_username=actor_username,
                        actor_ip=actor_ip,
                    )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(
                "per-wave reboot reconcile failed for execution=%d wave=%d: %s",
                execution.id,
                wave_index,
                exc,
            )
            try:
                db.rollback()
            except Exception:  # pylint: disable=broad-except
                pass
    return newly_completed


def _maybe_finalize_execution(
    db: Session,
    *,
    execution: PatchUpdateExecution,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
) -> bool:
    """If every host across every wave is terminal and the execution
    is still ``running``, transition it to ``succeeded`` (no failed
    hosts) or ``failed`` (any failed host) and emit
    ``patch_update_execution.completed`` exactly once. Returns True
    on transition, False otherwise.

    Idempotency: the existing dispatch refusal path (`state != running`
    raises 422) prevents a re-call from re-running the finalize
    branch; the audit event therefore emits at most once.
    """
    if execution.state != EXECUTION_STATE_RUNNING:
        return False
    if not _execution_is_complete(db, execution.id):
        return False

    failed, total = _terminal_host_counts(db, execution.id)
    final_state = EXECUTION_STATE_FAILED if failed > 0 else EXECUTION_STATE_SUCCEEDED
    now = datetime.utcnow()
    execution.state = final_state
    execution.completed_at = now
    db.flush()

    _emit_lifecycle_audit(
        action=AUDIT_EXECUTION_COMPLETED,
        execution=execution,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        extra={
            "final_state": final_state,
            "failed_terminal_hosts": failed,
            "terminal_hosts": total,
            "completed_at": now.isoformat(),
        },
    )

    # PRA-178 Slice 3: emit the patch.executed notification beside the
    # existing audit event. Best-effort — a notification/alert delivery
    # failure must not unwind the just-committed terminal state.
    from . import notification_events

    plan_name = None
    if execution.plan is not None:
        plan_name = getattr(execution.plan, "name", None)
    notification_events.emit_patch_executed(
        db,
        execution_id=execution.id,
        plan_id=execution.plan_id,
        plan_name=plan_name,
        state=final_state,
        progress=dict(execution.progress_summary or {}),
    )

    # PRA-172 Slice 2: auto-reconcile the reboot queue after a terminal
    # state. Commit the terminal state first so reconcile reads from
    # stable state (the call shares this session). Best-effort — a
    # reboot-queue failure does NOT roll back the just-emitted
    # ``completed`` audit. Lazy import to avoid a circular reference
    # (the reboot service imports from this dispatch module's sibling
    # execution module).
    db.commit()
    from . import patch_reboot_service

    patch_reboot_service.auto_reconcile_on_terminal(
        db,
        execution.id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    return True


def _maybe_threshold_auto_pause(
    db: Session,
    *,
    execution: PatchUpdateExecution,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Check the failure threshold against current terminal-host
    counts. If breached and the execution is still ``running``,
    auto-pause the execution (state -> paused, paused_at, structured
    pause_reason text, threshold context recorded in
    progress_summary), emit ``patch_update_execution.paused`` with
    the breach context, and return the breach context dict.

    Returns ``None`` when no breach (or the threshold is null /
    nothing terminal yet).
    """
    if execution.state != EXECUTION_STATE_RUNNING:
        return None
    failed, total = _terminal_host_counts(db, execution.id)
    breach = _threshold_breach_context(execution, failed, total)
    if breach is None:
        return None
    now = datetime.utcnow()
    execution.state = EXECUTION_STATE_PAUSED
    execution.paused_at = now
    execution.pause_reason = PAUSE_REASON_THRESHOLD_EXCEEDED
    _record_threshold_pause(execution, breach)
    db.flush()

    _emit_lifecycle_audit(
        action=AUDIT_EXECUTION_PAUSED,
        execution=execution,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        extra={
            "pause_reason": PAUSE_REASON_THRESHOLD_EXCEEDED,
            "auto": True,
            **breach,
        },
    )
    return breach


def _selected_packages_for_host(
    db: Session, plan_host_id: int
) -> List[PatchUpdatePlanSelectedPackage]:
    """Selected-state, non-inventory-missing packages for a plan
    host, ordered by package_name for command determinism."""
    return (
        db.query(PatchUpdatePlanSelectedPackage)
        .filter(
            PatchUpdatePlanSelectedPackage.plan_host_id == plan_host_id,
            PatchUpdatePlanSelectedPackage.state == SELECTION_STATE_SELECTED,
            PatchUpdatePlanSelectedPackage.selection_reason
            != SELECTION_REASON_INVENTORY_MISSING,
        )
        .order_by(
            PatchUpdatePlanSelectedPackage.package_name.asc(),
            PatchUpdatePlanSelectedPackage.id.asc(),
        )
        .all()
    )


def _resolve_package_family(db: Session, plan_host_id: int) -> str:
    """Derive the package-manager family for a host from its
    Slice-3 preflight snapshot rows. All preflight rows for one
    host share the same family snapshot (it's host-derived); we
    take the first one. Returns ``unknown`` when there are no
    preflight rows (host had no selected packages or preflight
    skipped)."""
    row = (
        db.query(PatchUpdatePlanPreflightSnapshot.package_manager_family_snapshot)
        .filter(PatchUpdatePlanPreflightSnapshot.plan_host_id == plan_host_id)
        .first()
    )
    if row is None:
        return PACKAGE_MANAGER_FAMILY_UNKNOWN
    return row[0]


# ---------------------------------------------------------------------------
# Command builders (pure; unit-tested separately)
# ---------------------------------------------------------------------------


def build_apt_command(package_specs: List[Tuple[str, Optional[str]]]) -> List[str]:
    """Build a single apt-get install argv for a list of
    ``(name, version)`` package specs. Pins each package to its
    requested version when version is non-None
    (``name=version`` per apt(8)), otherwise installs the candidate.

    Uses ``-y --no-install-recommends`` to avoid prompts and
    incidental installs. The dispatcher invokes the result via the
    transport's ``run_command(list[str], ...)`` so each argv member
    is preserved as a separate token without shell interpretation.
    """
    args = ["apt-get", "install", "-y", "--no-install-recommends"]
    for name, version in package_specs:
        if version:
            args.append(f"{name}={version}")
        else:
            args.append(name)
    return args


def build_dnf_command(package_specs: List[Tuple[str, Optional[str]]]) -> List[str]:
    """Build a single dnf install argv for a list of
    ``(name, version)`` package specs. Pins to the requested
    version when non-None (``name-version`` per dnf(8)).

    Uses ``-y`` for non-interactive operation. Same argv-style
    invocation as the apt path.
    """
    args = ["dnf", "install", "-y"]
    for name, version in package_specs:
        if version:
            args.append(f"{name}-{version}")
        else:
            args.append(name)
    return args


def build_command_for_family(
    family: str, package_specs: List[Tuple[str, Optional[str]]]
) -> List[str]:
    """Family-dispatch helper. Raises ``PatchUpdateExecutionError``
    for unknown/unsupported families so the dispatcher can map it
    to the structured ``unsupported_package_family`` host failure."""
    if family == PACKAGE_MANAGER_FAMILY_APT:
        return build_apt_command(package_specs)
    if family == PACKAGE_MANAGER_FAMILY_DNF:
        return build_dnf_command(package_specs)
    raise PatchUpdateExecutionError(f"unsupported package family: {family!r}")


def build_apt_remove_command(package_names: List[str]) -> List[str]:
    """Build a single ``apt-get remove`` argv for a list of package
    names. ``-y`` for non-interactive operation; explicit ``remove``
    rather than ``purge`` so configuration files survive (the
    compliance check we're satisfying targets package presence, not
    configuration state). Same argv-style invocation as the install
    path — no shell interpretation.
    """
    args = ["apt-get", "remove", "-y"]
    args.extend(package_names)
    return args


def build_dnf_remove_command(package_names: List[str]) -> List[str]:
    """Build a single ``dnf remove`` argv for a list of package
    names. ``-y`` for non-interactive operation.
    """
    args = ["dnf", "remove", "-y"]
    args.extend(package_names)
    return args


def build_remove_command_for_family(family: str, package_names: List[str]) -> List[str]:
    """Family-dispatch helper for removals. Raises
    ``PatchUpdateExecutionError`` for unknown/unsupported families
    so callers can map it to a structured failure code.
    """
    if family == PACKAGE_MANAGER_FAMILY_APT:
        return build_apt_remove_command(package_names)
    if family == PACKAGE_MANAGER_FAMILY_DNF:
        return build_dnf_remove_command(package_names)
    raise PatchUpdateExecutionError(f"unsupported package family: {family!r}")


# ---------------------------------------------------------------------------
# Dispatch core
# ---------------------------------------------------------------------------


@dataclass
class DispatchBatchSummary:
    """Result envelope returned by ``dispatch_next_batch``."""

    execution_id: int
    wave_index: Optional[int]
    dispatched_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    no_pending: bool = False
    pause_reason: Optional[str] = None
    host_outcomes: List[Dict[str, Any]] = field(default_factory=list)
    # Slice 3: wave indexes that emitted ``wave_completed`` during this
    # call. Empty when no wave completed (or the only completions were
    # already-recorded waves from a previous call).
    completed_wave_indexes: List[int] = field(default_factory=list)
    # Slice 3: structured context recorded when the dispatcher
    # auto-paused due to ``failure_threshold_percent`` breach. Null
    # otherwise. Mirrors ``progress_summary["threshold_pause"]``.
    threshold_pause: Optional[Dict[str, Any]] = None
    # Slice 3: terminal state the execution flipped to during this
    # call (``succeeded`` / ``failed``), or null when the execution
    # is not yet complete.
    finalized_state: Optional[str] = None


def _record_per_package_outcomes(
    db: Session,
    *,
    execution_host: PatchUpdateExecutionHost,
    selected_packages: List[PatchUpdatePlanSelectedPackage],
    package_family: str,
    outcome: str,
    error_code: Optional[str],
    preflight_versions: Dict[str, Optional[str]],
) -> None:
    """Persist one row per attempted package. Called once per host
    after the bundle command returns. ``outcome`` applies to every
    package in this slice (per-package output parsing is deferred)."""
    for sp in selected_packages:
        db.add(
            PatchUpdateExecutionHostPackage(
                execution_host_id=execution_host.id,
                package_name=sp.package_name,
                requested_version_snapshot=sp.available_version_snapshot,
                installed_version_before=preflight_versions.get(sp.package_name)
                or sp.installed_version_snapshot,
                installed_version_after=None,
                package_manager_family_snapshot=package_family,
                outcome=outcome,
                error_code=error_code,
                details={},
            )
        )
    db.flush()


def _emit_host_audit(
    *,
    action: str,
    execution: PatchUpdateExecution,
    execution_host: PatchUpdateExecutionHost,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    context: Dict[str, Any] = {
        "execution_id": execution.id,
        "plan_id": execution.plan_id,
        "wave_index": execution_host.wave_index,
        "system_id": execution_host.system_id_snapshot,
        "system_hostname": execution_host.system_hostname_snapshot,
    }
    if extra:
        context.update(extra)
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution_host",
        target_id=str(execution_host.id),
        context=context,
    )


def _preflight_versions_for_host(
    db: Session, plan_host_id: int
) -> Dict[str, Optional[str]]:
    rows = (
        db.query(
            PatchUpdatePlanPreflightSnapshot.package_name,
            PatchUpdatePlanPreflightSnapshot.installed_version_at_preflight,
        )
        .filter(PatchUpdatePlanPreflightSnapshot.plan_host_id == plan_host_id)
        .all()
    )
    return {pkg: ver for pkg, ver in rows}


# PRA-180 PATCH-01: outcome sentinel returned by ``_process_host`` when it lost
# the atomic claim race for a host (another concurrent dispatcher already flipped
# it to ``running``). The dispatch loop skips these without counting or
# re-dispatching them.
OUTCOME_SKIPPED_CLAIM = "skipped_claim"


def _process_host(
    db: Session,
    *,
    execution: PatchUpdateExecution,
    execution_host: PatchUpdateExecutionHost,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    dispatch_callable: DispatchCallable,
) -> Dict[str, Any]:
    """Dispatch a single host. Updates host state + per-package
    rows + emits audit events. Returns a summary dict for the
    batch result envelope."""
    plan_host_id = execution_host.plan_host_id

    # PRA-180 PATCH-01: atomically claim the host before doing any
    # dispatch work. The previous ``state = RUNNING`` + ``flush`` let
    # two concurrent ``dispatch_next_batch`` calls (operator
    # double-click, or a scheduler tick overlapping an operator action
    # across the prod uvicorn workers) both observe the same ``pending``
    # row from ``_take_pending_hosts`` and both dispatch the package
    # command. The conditional UPDATE flips ``pending -> running`` only
    # if the row is still pending; the loser's UPDATE matches 0 rows and
    # we return a ``skipped_claim`` sentinel so the caller neither issues
    # the command nor double-counts the host. Mirrors the reboot
    # dispatcher's atomic-claim pattern.
    now_started = datetime.utcnow()
    claimed = (
        db.query(PatchUpdateExecutionHost)
        .filter(
            PatchUpdateExecutionHost.id == execution_host.id,
            PatchUpdateExecutionHost.state == EXECUTION_HOST_STATE_PENDING,
        )
        .update(
            {
                PatchUpdateExecutionHost.state: EXECUTION_HOST_STATE_RUNNING,
                PatchUpdateExecutionHost.started_at: now_started,
            },
            synchronize_session=False,
        )
    )
    db.flush()
    if claimed == 0:
        # Lost the race: another dispatcher already claimed this host.
        # synchronize_session=False left the in-Python row stale; refresh
        # so callers/logging see the real (running) state.
        db.refresh(execution_host)
        return {
            "execution_host_id": execution_host.id,
            "system_id": execution_host.system_id_snapshot,
            "outcome": OUTCOME_SKIPPED_CLAIM,
        }
    # Won the claim. Refresh the stale ORM row (synchronize_session=False)
    # so the rest of this function operates on the running state.
    db.refresh(execution_host)

    selected_packages = _selected_packages_for_host(db, plan_host_id)
    package_family = _resolve_package_family(db, plan_host_id)

    # Audit the host start BEFORE the dispatch call so the audit row is
    # in place even if the transport call hangs and we abort.
    _emit_host_audit(
        action=AUDIT_EXECUTION_HOST_STARTED,
        execution=execution,
        execution_host=execution_host,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        extra={
            "package_family": package_family,
            "selected_package_count": len(selected_packages),
        },
    )

    # Defensive: a planned host with zero selected packages should
    # never have reached `pending` (Slice 1 marks it `skipped`),
    # but guard the dispatcher path anyway.
    if not selected_packages:
        execution_host.state = EXECUTION_HOST_STATE_FAILED
        execution_host.completed_at = datetime.utcnow()
        execution_host.error_details = {
            "code": ERROR_CODE_NO_SELECTED_PACKAGES,
            "message": "host has no selected packages to dispatch",
        }
        db.flush()
        _emit_host_audit(
            action=AUDIT_EXECUTION_HOST_FAILED,
            execution=execution,
            execution_host=execution_host,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={"error_code": ERROR_CODE_NO_SELECTED_PACKAGES},
        )
        return {
            "execution_host_id": execution_host.id,
            "system_id": execution_host.system_id_snapshot,
            "outcome": "failed",
            "error_code": ERROR_CODE_NO_SELECTED_PACKAGES,
        }

    if package_family == PACKAGE_MANAGER_FAMILY_UNKNOWN:
        execution_host.state = EXECUTION_HOST_STATE_FAILED
        execution_host.completed_at = datetime.utcnow()
        execution_host.error_details = {
            "code": ERROR_CODE_UNSUPPORTED_FAMILY,
            "package_family": package_family,
            "message": "host package-manager family is 'unknown'; refuse to dispatch",
        }
        _record_per_package_outcomes(
            db,
            execution_host=execution_host,
            selected_packages=selected_packages,
            package_family=package_family,
            outcome=PACKAGE_OUTCOME_FAILED,
            error_code=ERROR_CODE_UNSUPPORTED_FAMILY,
            preflight_versions=_preflight_versions_for_host(db, plan_host_id),
        )
        db.flush()
        _emit_host_audit(
            action=AUDIT_EXECUTION_HOST_FAILED,
            execution=execution,
            execution_host=execution_host,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={"error_code": ERROR_CODE_UNSUPPORTED_FAMILY},
        )
        return {
            "execution_host_id": execution_host.id,
            "system_id": execution_host.system_id_snapshot,
            "outcome": "failed",
            "error_code": ERROR_CODE_UNSUPPORTED_FAMILY,
        }

    package_specs: List[Tuple[str, Optional[str]]] = [
        (sp.package_name, sp.available_version_snapshot) for sp in selected_packages
    ]
    cmd = build_command_for_family(package_family, package_specs)

    # Resolve the System ORM row for the dispatch call. Slice 1
    # tolerates `system_id_snapshot is None` (host was deleted) but
    # those rows land as `skipped` at materialization time, not
    # `pending`. Defensive: if we somehow reached here without a
    # system_id, fail with a structured error.
    system: Optional[System] = None
    if execution_host.system_id_snapshot is not None:
        system = (
            db.query(System)
            .filter(System.id == execution_host.system_id_snapshot)
            .first()
        )
    if system is None:
        execution_host.state = EXECUTION_HOST_STATE_FAILED
        execution_host.completed_at = datetime.utcnow()
        execution_host.error_details = {
            "code": ERROR_CODE_TRANSPORT_UNAVAILABLE,
            "message": "system row not found at dispatch time",
            "system_id_snapshot": execution_host.system_id_snapshot,
        }
        _record_per_package_outcomes(
            db,
            execution_host=execution_host,
            selected_packages=selected_packages,
            package_family=package_family,
            outcome=PACKAGE_OUTCOME_FAILED,
            error_code=ERROR_CODE_TRANSPORT_UNAVAILABLE,
            preflight_versions=_preflight_versions_for_host(db, plan_host_id),
        )
        db.flush()
        _emit_host_audit(
            action=AUDIT_EXECUTION_HOST_FAILED,
            execution=execution,
            execution_host=execution_host,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={"error_code": ERROR_CODE_TRANSPORT_UNAVAILABLE},
        )
        return {
            "execution_host_id": execution_host.id,
            "system_id": execution_host.system_id_snapshot,
            "outcome": "failed",
            "error_code": ERROR_CODE_TRANSPORT_UNAVAILABLE,
        }

    # Hand off to the adapter. Catch broad exceptions defensively so
    # one host's transport blowup cannot crash the rest of the batch.
    try:
        result = dispatch_callable(system, cmd)
    except Exception as exc:  # pragma: no cover - defensive
        result = DispatchResult(
            exit_code=-1,
            error=ERROR_CODE_TRANSPORT_ERROR,
            stderr=f"adapter raised: {exc}",
        )

    preflight_versions = _preflight_versions_for_host(db, plan_host_id)

    if result.error or result.exit_code != 0:
        host_outcome = "failed"
        error_code = result.error or ERROR_CODE_PACKAGE_MANAGER_FAILED
        execution_host.state = EXECUTION_HOST_STATE_FAILED
        execution_host.completed_at = datetime.utcnow()
        # PRA-175 Slice 2: ``command`` is the planned/raw argv (the
        # apt-get / dnf invocation the dispatcher built);
        # ``effective_argv`` (when the default dispatcher ran)
        # records the post-wrap argv actually sent to the transport
        # so operators see e.g. ``sudo -n apt-get install -y …``
        # without recomputing it from ``credential.sudo_method``.
        # The sudo password (password mode) never appears in
        # ``effective_argv`` — it travels through ``stdin`` and is
        # never persisted.
        execution_host.error_details = {
            "code": error_code,
            "exit_code": result.exit_code,
            "stdout": _truncate(result.stdout),
            "stderr": _truncate(result.stderr),
            "duration_ms": result.duration_ms,
            "transport": result.transport_name,
            "command": " ".join(shlex.quote(c) for c in cmd),
            "effective_argv": (
                list(result.effective_argv)
                if result.effective_argv is not None
                else None
            ),
        }
        _record_per_package_outcomes(
            db,
            execution_host=execution_host,
            selected_packages=selected_packages,
            package_family=package_family,
            outcome=PACKAGE_OUTCOME_FAILED,
            error_code=error_code,
            preflight_versions=preflight_versions,
        )
        db.flush()
        _emit_host_audit(
            action=AUDIT_EXECUTION_HOST_FAILED,
            execution=execution,
            execution_host=execution_host,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={
                "error_code": error_code,
                "exit_code": result.exit_code,
                "transport": result.transport_name,
            },
        )
    else:
        host_outcome = "succeeded"
        execution_host.state = EXECUTION_HOST_STATE_SUCCEEDED
        execution_host.completed_at = datetime.utcnow()
        execution_host.error_details = {
            "stdout": _truncate(result.stdout),
            "stderr": _truncate(result.stderr),
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "transport": result.transport_name,
            "command": " ".join(shlex.quote(c) for c in cmd),
            "effective_argv": (
                list(result.effective_argv)
                if result.effective_argv is not None
                else None
            ),
        }
        _record_per_package_outcomes(
            db,
            execution_host=execution_host,
            selected_packages=selected_packages,
            package_family=package_family,
            outcome=PACKAGE_OUTCOME_SUCCEEDED,
            error_code=None,
            preflight_versions=preflight_versions,
        )
        db.flush()
        _emit_host_audit(
            action=AUDIT_EXECUTION_HOST_SUCCEEDED,
            execution=execution,
            execution_host=execution_host,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={
                "exit_code": result.exit_code,
                "transport": result.transport_name,
                "duration_ms": result.duration_ms,
            },
        )

    return {
        "execution_host_id": execution_host.id,
        "system_id": execution_host.system_id_snapshot,
        "outcome": host_outcome,
        "exit_code": result.exit_code,
        "transport": result.transport_name,
    }


def dispatch_next_batch(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    dispatch_callable: Optional[DispatchCallable] = None,
) -> DispatchBatchSummary:
    """Dispatch the next eligible batch of pending hosts for an
    execution.

    * Refuses unknown executions (404 via "not found" message).
    * Refuses non-`running` executions (`pending` / `paused` /
      `succeeded` / `failed` / `canceled`) with structured 422.
    * Picks the lowest wave_index that has at least one `pending`
      host. Returns ``no_pending=True`` when no wave has pending
      hosts left.
    * Dispatches at most ``execution.max_parallel_per_wave`` hosts
      from that wave, ordered by id for determinism.
    * Per host: see ``_process_host``.

    Slice 3 lifecycle hooks (run after each per-host commit):

    * Reconcile any newly-completed waves and emit
      ``patch_update_execution.wave_completed`` for waves that
      haven't yet been recorded.
    * If every host across every wave is terminal, transition the
      execution to ``succeeded`` / ``failed``, set ``completed_at``,
      emit ``patch_update_execution.completed``, and stop.
    * Otherwise, evaluate ``failure_threshold_percent``; if breached,
      auto-pause the execution with a structured
      ``failure_threshold_exceeded`` reason, emit
      ``patch_update_execution.paused`` with the breach context,
      and stop. Unprocessed hosts remain ``pending``.

    Refreshes ``execution.progress_summary`` after the batch (the
    summary now also carries ``completed_wave_indexes`` and
    ``threshold_pause`` from the lifecycle hooks).
    """
    _require_actor(db, actor_user_id)
    execution = _require_execution(db, execution_id)
    if execution.state != EXECUTION_STATE_RUNNING:
        raise PatchUpdateExecutionError(
            f"execution {execution_id} is in state {execution.state!r}; only "
            f"'{EXECUTION_STATE_RUNNING}' executions may dispatch"
        )

    if dispatch_callable is None:
        dispatch_callable = lambda system, cmd: default_dispatch(db, system, cmd)

    wave_index = _select_lowest_pending_wave(db, execution.id)
    if wave_index is None:
        # Nothing left to dispatch in any wave. Run a final
        # reconciliation pass so any waves that completed earlier
        # without a dispatch call (e.g. all-skipped waves recorded at
        # materialization time) get their wave_completed event, and
        # so the execution transitions to its terminal state if every
        # host is terminal.
        summary = DispatchBatchSummary(
            execution_id=execution.id,
            wave_index=None,
            no_pending=True,
        )
        summary.completed_wave_indexes = _emit_unrecorded_wave_completions(
            db,
            execution=execution,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
        )
        if _maybe_finalize_execution(
            db,
            execution=execution,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
        ):
            summary.finalized_state = execution.state
        execution.progress_summary = _build_progress_summary(db, execution.id)
        db.commit()
        db.refresh(execution)
        return summary

    # PRA-172 Slice 5: dependent-wave reboot gate. Before
    # dispatching wave_index, check that all earlier waves' reboot
    # rows are in safe states (``not_required`` / ``healthy`` /
    # ``skipped``). If any earlier wave still has rows in
    # ``pending`` / ``scheduled`` / ``rebooting`` / ``verifying``
    # OR has rows in ``failed`` (terminal verification failure),
    # refuse to advance. Remaining wave_index hosts stay
    # ``pending`` so a subsequent dispatch call can retry once
    # operators drive the reboot queue forward. Lazy import to
    # avoid a circular reference.
    from . import patch_reboot_service

    gate_blocker = patch_reboot_service.is_wave_blocked_by_reboot_gate(
        db, execution.id, wave_index
    )
    if gate_blocker is not None:
        summary = DispatchBatchSummary(
            execution_id=execution.id,
            wave_index=wave_index,
            dispatched_count=0,
            no_pending=False,
            pause_reason="reboot_gate_pending",
            threshold_pause=gate_blocker,
        )
        # Refresh progress_summary so the read API surfaces the
        # blocker context.
        execution.progress_summary = {
            **(execution.progress_summary or {}),
            "wave_reboot_gate_blocker": gate_blocker,
        }
        db.commit()
        db.refresh(execution)
        return summary

    # No gate block: clear any stale blocker context the previous
    # call may have recorded.
    if (execution.progress_summary or {}).get("wave_reboot_gate_blocker") is not None:
        updated_summary = dict(execution.progress_summary or {})
        updated_summary.pop("wave_reboot_gate_blocker", None)
        execution.progress_summary = updated_summary
        db.commit()
        db.refresh(execution)

    hosts = _take_pending_hosts(
        db, execution.id, wave_index, execution.max_parallel_per_wave
    )

    summary = DispatchBatchSummary(
        execution_id=execution.id,
        wave_index=wave_index,
        dispatched_count=len(hosts),
    )

    for host_row in hosts:
        # Re-check execution state inside the loop so a concurrent
        # pause/cancel halts the batch cleanly. (Slice 1 transitions
        # are metadata-only so this is the dispatcher's only check.)
        db.refresh(execution)
        if execution.state != EXECUTION_STATE_RUNNING:
            summary.pause_reason = (
                f"execution transitioned to {execution.state!r} mid-batch"
            )
            break
        host_summary = _process_host(
            db,
            execution=execution,
            execution_host=host_row,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            dispatch_callable=dispatch_callable,
        )
        if host_summary["outcome"] == OUTCOME_SKIPPED_CLAIM:
            # PRA-180 PATCH-01: a concurrent dispatcher claimed this host
            # between the batch SELECT and our claim. It was not dispatched
            # here, so don't record or count it.
            summary.dispatched_count -= 1
            continue
        summary.host_outcomes.append(host_summary)
        if host_summary["outcome"] == "succeeded":
            summary.succeeded_count += 1
        else:
            summary.failed_count += 1

        # Slice 3 lifecycle hooks. Order matters:
        # 1. Wave-completion: emit wave_completed for any waves that
        #    just became fully terminal (idempotent via
        #    progress_summary.completed_wave_indexes).
        # 2. Plan-completion: if every host is terminal, finalize
        #    succeeded/failed and stop the loop.
        # 3. Threshold auto-pause: if not finalized, check the
        #    failure-threshold and pause if breached.
        newly_done = _emit_unrecorded_wave_completions(
            db,
            execution=execution,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
        )
        for w in newly_done:
            if w not in summary.completed_wave_indexes:
                summary.completed_wave_indexes.append(w)

        if _maybe_finalize_execution(
            db,
            execution=execution,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
        ):
            summary.finalized_state = execution.state
            break

        breach = _maybe_threshold_auto_pause(
            db,
            execution=execution,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
        )
        if breach is not None:
            summary.threshold_pause = breach
            summary.pause_reason = PAUSE_REASON_THRESHOLD_EXCEEDED
            break

    execution.progress_summary = _build_progress_summary(db, execution.id)
    db.commit()
    db.refresh(execution)
    return summary


# ---------------------------------------------------------------------------
# Read helper for routes / UI per-package drill-down
# ---------------------------------------------------------------------------


def list_host_packages(
    db: Session, execution_host_id: int
) -> List[PatchUpdateExecutionHostPackage]:
    """Per-package result rows for one execution host, ordered by
    ``(outcome, package_name, id)`` for stable rendering."""
    if (
        db.query(PatchUpdateExecutionHost.id)
        .filter(PatchUpdateExecutionHost.id == execution_host_id)
        .first()
        is None
    ):
        raise PatchUpdateExecutionError(
            f"patch update execution host id={execution_host_id} not found"
        )
    return (
        db.query(PatchUpdateExecutionHostPackage)
        .filter(PatchUpdateExecutionHostPackage.execution_host_id == execution_host_id)
        .order_by(
            PatchUpdateExecutionHostPackage.outcome.asc(),
            PatchUpdateExecutionHostPackage.package_name.asc(),
            PatchUpdateExecutionHostPackage.id.asc(),
        )
        .all()
    )
