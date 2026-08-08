"""Patch reboot dispatch service (PRA-172 slice 3).

First transport-bound reboot dispatch primitive on top of the
Slice 1+2 reboot queue substrate. Walks ``scheduled`` rows whose
``scheduled_for_at`` is due, transitions them to ``rebooting``
(or ``failed`` on dispatch failure), and records the structured
per-row dispatch outcome.

Slice 3 deliberately stops before post-reboot verification. A row
that lands in ``rebooting`` waits there until a later Slice 4
verification pass moves it to ``verifying`` / ``healthy`` /
``failed``. The dispatcher itself does NOT poll the host, refresh
facts, compare uptime/kernel, or gate dependent waves on reboot
health.

Transport posture:

* SSH-only via the existing PRA-171 transport abstraction (mirrors
  PRA-171 dispatch). Agent transport is reserved for a later slice
  when the agent exposes a reboot primitive.
* Tests pass a fake ``RebootDispatchCallable`` so no test ever
  issues a real ``systemctl reboot`` / ``shutdown`` call.

Special exit-signal handling:

A reboot command is unusual because the SSH session dies mid-
command when the kernel takes the host down. The default reboot
dispatcher recognises this as the ``connection_lost_clean`` exit
signal and treats it as dispatch SUCCESS (the host accepted the
reboot command and is now in the process of rebooting). The full
exit-signal vocabulary:

* ``exit_zero`` — command returned exit 0 before the connection
  closed (typical when systemd defers the reboot far enough). Success.
* ``connection_lost_clean`` — transport raised a ``TransportError``
  after the run-command call started; the host accepted the
  command and the session died because the kernel is rebooting.
  Success.
* ``non_zero`` — command returned a non-zero exit code. Failure
  (permission denied, command not found, etc.).
* ``timeout`` — transport raised ``asyncio.TimeoutError``. Failure.
* ``transport_error`` — transport raised a generic
  ``TransportError`` BEFORE the run-command call. Failure.
* ``transport_unavailable`` — transport factory could not open a
  session at all. Failure.

Audit events (via ``safe_emit`` no ``db=`` per the established
session-boundary lock):

* ``patch_update_execution_reboot.started`` — emitted on every
  ``scheduled`` → ``rebooting`` transition (dispatch success).
* ``patch_update_execution_reboot.dispatch_failed`` — emitted on
  every ``scheduled`` → ``failed`` transition (dispatch failure).
  Reserved separately from ``.verification_failed`` (Slice 4) so
  the audit code identifies the lifecycle phase that failed.

Reboot-wave threshold pause:

The service consumes the execution's ``failure_threshold_percent``
to bound how many dispatch failures it tolerates within a single
batch. On breach the dispatcher stops mid-batch, leaving the
remaining due rows in ``scheduled`` state; the batch summary
returns the structured ``threshold_pause`` context so the operator
UI can render a "paused / N% failure threshold breached" surface.
No execution-level state change happens — the parent execution is
already terminal at this point, and the reboot queue carries its
own per-row state.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from dataclasses import dataclass, field
from datetime import datetime
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
from .patch_reboot_service import (
    REBOOT_STATE_FAILED,
    REBOOT_STATE_REBOOTING,
    REBOOT_STATE_SCHEDULED,
    PatchUpdateRebootError,
    utc_iso,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exit-signal vocabulary (mirrors the DB CHECK constraint added in
# migration ``pra172_reboot_dispatch``).
# ---------------------------------------------------------------------------

EXIT_SIGNAL_EXIT_ZERO = "exit_zero"
EXIT_SIGNAL_CONNECTION_LOST_CLEAN = "connection_lost_clean"
EXIT_SIGNAL_NON_ZERO = "non_zero"
EXIT_SIGNAL_TIMEOUT = "timeout"
EXIT_SIGNAL_TRANSPORT_ERROR = "transport_error"
EXIT_SIGNAL_TRANSPORT_UNAVAILABLE = "transport_unavailable"
# PRA-229 PATCH-03: the credential's sudo_method was null/blank or unrecognized,
# so the reboot was never dispatched. Not a SUCCESS signal → row goes to failed
# with a structured, operator-actionable reason instead of an unescalated try.
EXIT_SIGNAL_SUDO_METHOD_INVALID = "sudo_method_invalid"

VALID_EXIT_SIGNALS = frozenset(
    {
        EXIT_SIGNAL_EXIT_ZERO,
        EXIT_SIGNAL_CONNECTION_LOST_CLEAN,
        EXIT_SIGNAL_NON_ZERO,
        EXIT_SIGNAL_TIMEOUT,
        EXIT_SIGNAL_TRANSPORT_ERROR,
        EXIT_SIGNAL_TRANSPORT_UNAVAILABLE,
    }
)

# Success signals — host accepted the reboot command. The row
# transitions to ``rebooting`` and waits for a future verification
# pass.
SUCCESS_EXIT_SIGNALS = frozenset(
    {EXIT_SIGNAL_EXIT_ZERO, EXIT_SIGNAL_CONNECTION_LOST_CLEAN}
)

# Transport vocab. Slice 3 only writes ``ssh``; ``agent`` is
# reserved for a later slice when the agent exposes a reboot
# primitive.
TRANSPORT_KIND_SSH = "ssh"


# ---------------------------------------------------------------------------
# Audit constants. Slice 3 emits ``.started`` (success) and
# ``.dispatch_failed`` (failure); ``.verification_passed`` and
# ``.verification_failed`` are reserved for Slice 4 so the audit
# vocabulary doesn't churn route/read schemas.
# ---------------------------------------------------------------------------

AUDIT_REBOOT_STARTED = "patch_update_execution_reboot.started"
AUDIT_REBOOT_DISPATCH_FAILED = "patch_update_execution_reboot.dispatch_failed"

# Reserved for Slice 4; declared here so the operator UI / external
# consumers can hardcode the full vocabulary now.
AUDIT_REBOOT_VERIFICATION_PASSED = "patch_update_execution_reboot.verification_passed"
AUDIT_REBOOT_VERIFICATION_FAILED = "patch_update_execution_reboot.verification_failed"


# ---------------------------------------------------------------------------
# Default reboot command. A future slice can promote this to a
# policy-configurable snapshot per ``reboot_policy``; Slice 3 keeps
# the command behind a single helper so the operator UI / tests
# have one stable place to mock.
#
# PRA-175: this is the *planned* argv. Privilege escalation is
# applied at dispatch time by ``default_reboot_dispatch`` via
# ``dispatch_sudo.wrap_argv_for_sudo`` so the effective command
# matches the host credential's ``sudo_method`` (``none`` runs the
# argv as-is, ``nopasswd`` prepends ``sudo -n``, ``password``
# prepends ``sudo -S`` + pipes the Vault-stored sudo password to
# stdin). Pre-PRA-175 the command was hardcoded as
# ``["sudo", "systemctl", "reboot"]``, which ignored the credential
# intent and failed for the ``password`` mode (hung on the password
# prompt) and was redundant for ``nopasswd``.
# ---------------------------------------------------------------------------

DEFAULT_REBOOT_COMMAND = ["systemctl", "reboot"]

# Default reboot-wave failure threshold cap if the execution
# snapshot has no explicit value. Conservative: any failure breaches
# a threshold of zero by spec, so callers that want a permissive
# default should set the execution-level
# ``failure_threshold_percent`` explicitly.
DEFAULT_FAILURE_THRESHOLD_PERCENT = None  # None == no auto-pause


PAUSE_REASON_REBOOT_THRESHOLD_EXCEEDED = "reboot_failure_threshold_exceeded"


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class RebootDispatchResult:
    """Outcome of one ``(system, reboot_command)`` dispatch call.

    ``exit_signal_kind`` is the canonical success/failure indicator
    — see module docstring for the full vocabulary. ``exit_code``
    stays ``None`` for connection-lost / transport-unavailable
    paths where the command never reported an exit.

    ``effective_argv`` (PRA-175 Slice 2) is the actual argv handed
    to the SSH transport after :func:`dispatch_sudo.wrap_argv_for_sudo`
    applied any ``sudo -n`` / ``sudo -S`` prefix. ``None`` means
    the dispatcher did not record it (a test fake bypassed the
    default dispatcher). The orchestrator persists it into
    ``PatchUpdateExecutionReboot.dispatch_details`` alongside the
    planned ``command_snapshot``. The sudo password (password
    mode) is NEVER part of ``effective_argv`` — it flows through
    ``transport.run_command(stdin=...)`` and is not retained.
    """

    exit_signal_kind: str
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    transport_name: str = ""
    error: Optional[str] = None
    effective_argv: Optional[List[str]] = None


RebootDispatchCallable = Callable[[System, List[str]], RebootDispatchResult]


@dataclass
class RebootDispatchHostOutcome:
    """One host-row summary inside a dispatch-due batch result."""

    execution_reboot_id: int
    execution_host_id: int
    system_id: Optional[int]
    state: str  # ``rebooting`` on success; ``failed`` on dispatch failure
    exit_signal_kind: str
    transport_kind: str
    exit_code: Optional[int] = None
    error_code: Optional[str] = None


@dataclass
class RebootDispatchBatchSummary:
    """Result of one ``POST /reboots/dispatch-due`` invocation."""

    execution_id: int
    dispatched_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    not_due_count: int = 0
    no_due: bool = False
    pause_reason: Optional[str] = None
    threshold_pause: Optional[Dict[str, Any]] = None
    host_outcomes: List[RebootDispatchHostOutcome] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Default reboot transport — bridges to the PRA-171 async transport
# factory but recognises mid-command transport errors as the
# ``connection_lost_clean`` success signal.
# ---------------------------------------------------------------------------


def default_reboot_dispatch(
    db: Session, system: System, cmd: List[str]
) -> RebootDispatchResult:
    """Default reboot transport. Issues ``cmd`` over SSH **only**.

    Slice 3 is SSH-only by spec lock. The generic
    ``get_transport(...)`` factory can return an
    :class:`AgentTransport` for systems whose
    ``transport_preference`` is ``agent`` or ``auto``-with-healthy-
    tunnel, which would route a reboot command through the agent
    path — out of scope for this slice. We bind directly to
    :class:`SSHTransport(system, ssh_service)` so the agent path is
    never selected here. Agent-backed reboot dispatch is reserved
    for a later slice when the agent exposes a reboot primitive.

    Failure-path mapping:

    * ``ssh_service.get_connection`` raising at transport-init time
      → ``transport_unavailable`` (failure — we never opened a session).
    * ``transport.run_command`` raising ``asyncio.TimeoutError`` →
      ``timeout`` (failure — operator should investigate).
    * ``transport.run_command`` raising any other ``TransportError``
      → ``transport_error`` (failure). The PRA-171 SSH transport
      cannot currently distinguish "exec_command failed pre-
      acceptance" from "socket dropped post-acceptance"; per the
      Slice 3 acceptance criterion, connection loss is treated as
      dispatch success ONLY when the command was accepted. Since
      the current transport cannot prove command acceptance, we
      surface the structured failure rather than risk persisting
      ``rebooting`` for a host that never accepted the command. A
      later slice that refines the SSH transport to surface command-
      acceptance separately can promote the post-acceptance case
      to ``connection_lost_clean`` (the enum value is preserved
      for that future path and is still exercised by test fakes).
    * Otherwise, the exit code is honored: 0 → ``exit_zero``
      (success), non-zero → ``non_zero`` (failure).
    """
    from .dispatch_sudo import (
        SudoMethodError,
        resolve_system_credential,
        wrap_argv_for_sudo,
    )
    from .ssh_service import SSHService
    from .transport import TransportError
    from .transport.ssh import SSHTransport

    # PRA-175: wrap the planned reboot argv per the credential's
    # ``sudo_method`` so the actual SSH exec honors privilege
    # intent. ``none`` keeps argv as-is, ``nopasswd`` prepends
    # ``sudo -n``, ``password`` prepends ``sudo -S`` and pipes the
    # Vault-stored sudo password into stdin so the prompt is
    # consumed on the first read instead of hanging the session.
    credential = resolve_system_credential(db, system)
    try:
        effective_argv, sudo_stdin = wrap_argv_for_sudo(db, credential, cmd)
    except SudoMethodError as exc:
        # PRA-229 PATCH-03: a null/unknown credential sudo_method is a structured
        # dispatch-failed condition — record it on the reboot row rather than
        # attempting an unescalated reboot that would fail opaquely as non-root.
        return RebootDispatchResult(
            exit_signal_kind=EXIT_SIGNAL_SUDO_METHOD_INVALID,
            error=exc.reason,
            stderr=exc.operator_message(),
            effective_argv=None,
        )

    async def _run() -> RebootDispatchResult:
        ssh_service = SSHService(db)
        # Probe the pooled SSH connection up front so we can map a
        # connection-init failure to ``transport_unavailable``
        # (failure — never opened a session) and never get there
        # mid-command.
        try:
            await asyncio.to_thread(lambda: ssh_service.get_connection(system.id))
        except Exception as exc:  # pylint: disable=broad-except
            ssh_service.close_all_connections()
            # PRA-175 Slice 2: surface effective_argv on every
            # return path so the orchestrator can persist the
            # post-wrap argv even when the transport never opened.
            return RebootDispatchResult(
                exit_signal_kind=EXIT_SIGNAL_TRANSPORT_UNAVAILABLE,
                error="transport_unavailable",
                stderr=str(exc),
                effective_argv=list(effective_argv),
            )

        transport = SSHTransport(system, ssh_service)
        try:
            try:
                result = await transport.run_command(effective_argv, stdin=sudo_stdin)
            except asyncio.TimeoutError as exc:
                return RebootDispatchResult(
                    exit_signal_kind=EXIT_SIGNAL_TIMEOUT,
                    error="timeout",
                    stderr=str(exc),
                    transport_name=transport.name,
                    effective_argv=list(effective_argv),
                )
            except TransportError as exc:
                # Pre-acceptance failures and post-acceptance socket
                # drops both surface as ``TransportError`` from the
                # current SSH transport — we cannot distinguish, so
                # we treat every TransportError as a structured
                # transport_error failure. The acceptance criterion
                # remains satisfied in spirit: ``connection_lost_clean``
                # is still the success signal a future, more granular
                # SSH transport can use; this slice just never reaches
                # it from the default dispatcher.
                return RebootDispatchResult(
                    exit_signal_kind=EXIT_SIGNAL_TRANSPORT_ERROR,
                    error="transport_error",
                    stderr=str(exc),
                    transport_name=transport.name,
                    effective_argv=list(effective_argv),
                )

            exit_code = int(result.exit_code)
            signal = EXIT_SIGNAL_EXIT_ZERO if exit_code == 0 else EXIT_SIGNAL_NON_ZERO
            return RebootDispatchResult(
                exit_signal_kind=signal,
                exit_code=exit_code,
                stdout=result.stdout.decode("utf-8", errors="replace"),
                stderr=result.stderr.decode("utf-8", errors="replace"),
                duration_ms=int(result.duration_ms),
                transport_name=transport.name,
                effective_argv=list(effective_argv),
            )
        finally:
            ssh_service.close_all_connections()

    # Reuse PRA-171's sync↔async bridge so a sync FastAPI route can
    # call us safely even from within a parent event loop.
    from .patch_execution_dispatch_service import _run_async_from_sync

    return _run_async_from_sync(_run())


# ---------------------------------------------------------------------------
# Threshold helpers
# ---------------------------------------------------------------------------


def _resolve_failure_threshold(execution: PatchUpdateExecution) -> Optional[int]:
    """Resolve the reboot-wave failure threshold from the
    execution's ``failure_threshold_percent`` snapshot.

    Slice 3 reuses the parent execution's threshold so operators
    have one place to tune fleet failure tolerance. A later slice
    could introduce a reboot-specific override.
    """
    value = getattr(execution, "failure_threshold_percent", None)
    if value is None:
        return DEFAULT_FAILURE_THRESHOLD_PERCENT
    if isinstance(value, bool) or not isinstance(value, int):
        return DEFAULT_FAILURE_THRESHOLD_PERCENT
    if value < 0 or value > 100:
        return DEFAULT_FAILURE_THRESHOLD_PERCENT
    return value


def _threshold_breach_context(
    threshold_pct: Optional[int],
    failed_count: int,
    attempted_count: int,
) -> Optional[Dict[str, Any]]:
    """Return a structured breach context when the threshold is
    exceeded, or ``None`` when no breach. Uses strict greater-than
    so a threshold of ``0`` breaches on the first failure (matches
    PRA-171's existing threshold semantics)."""
    if threshold_pct is None:
        return None
    if attempted_count == 0:
        return None
    failure_pct = (failed_count * 100) // attempted_count
    if failure_pct <= threshold_pct:
        return None
    return {
        "code": PAUSE_REASON_REBOOT_THRESHOLD_EXCEEDED,
        "failure_threshold_percent": threshold_pct,
        "failed_count": failed_count,
        "attempted_count": attempted_count,
        "observed_failure_percent": failure_pct,
    }


# ---------------------------------------------------------------------------
# Audit emission
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
        "transport_kind": row.transport_kind,
        "command_snapshot": row.command_snapshot,
        "exit_signal_kind": row.exit_signal_kind,
        "started_at": utc_iso(row.started_at),
        "completed_at": utc_iso(row.completed_at),
    }
    if extra:
        context.update(extra)
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution_reboot",
        target_id=str(row.id),
        context=context,
    )


# ---------------------------------------------------------------------------
# Public API — dispatch_due_reboots
# ---------------------------------------------------------------------------


def _capture_pre_reboot_facts(db: Session, system_id: Optional[int]) -> Dict[str, Any]:
    """Snapshot the pre-reboot host facts the verifier needs to
    prove the host actually rebooted.

    The Slice 4 verifier compares post-reboot ``uptime_seconds``
    against this snapshot: if the post-reboot value is less than
    the pre-reboot value (or the kernel version changed), that's
    evidence of reboot success. Missing facts (deleted host, no
    HostFacts row yet) are surfaced as ``null`` rather than
    silently omitted so the verifier can decide whether to fall
    back to reachability-only.
    """
    if system_id is None:
        return {"system_id": None, "uptime_seconds": None, "kernel_version": None}
    facts = db.query(HostFacts).filter(HostFacts.system_id == system_id).first()
    if facts is None:
        return {
            "system_id": system_id,
            "uptime_seconds": None,
            "kernel_version": None,
        }
    return {
        "system_id": system_id,
        "uptime_seconds": facts.uptime_seconds,
        "kernel_version": facts.kernel_version,
        "collected_at": utc_iso(facts.collected_at),
    }


def _due_scheduled_rows(
    db: Session, execution_id: int, *, now: datetime
) -> List[PatchUpdateExecutionReboot]:
    return (
        db.query(PatchUpdateExecutionReboot)
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution_id,
            PatchUpdateExecutionReboot.state == REBOOT_STATE_SCHEDULED,
            PatchUpdateExecutionReboot.scheduled_for_at <= now,
        )
        .order_by(
            PatchUpdateExecutionReboot.wave_index.asc(),
            PatchUpdateExecutionReboot.scheduled_for_at.asc().nullsfirst(),
            PatchUpdateExecutionReboot.id.asc(),
        )
        .all()
    )


def _not_due_scheduled_count(db: Session, execution_id: int, *, now: datetime) -> int:
    return (
        db.query(PatchUpdateExecutionReboot)
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution_id,
            PatchUpdateExecutionReboot.state == REBOOT_STATE_SCHEDULED,
            PatchUpdateExecutionReboot.scheduled_for_at > now,
        )
        .count()
    )


def _resolve_dispatch_callable(
    db: Session,
    override: Optional[RebootDispatchCallable],
) -> RebootDispatchCallable:
    if override is not None:
        return override

    def _impl(system: System, cmd: List[str]) -> RebootDispatchResult:
        return default_reboot_dispatch(db, system, cmd)

    return _impl


def dispatch_due_reboots(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    now: Optional[datetime] = None,
    dispatch_callable: Optional[RebootDispatchCallable] = None,
    max_dispatch: Optional[int] = None,
) -> RebootDispatchBatchSummary:
    """Dispatch one bounded batch of due scheduled reboot rows.

    Walks rows in state ``scheduled`` with
    ``scheduled_for_at <= now``, transitions each to ``rebooting``
    (or ``failed`` on dispatch failure), records the structured
    per-row dispatch outcome, and emits the matching reboot audit
    event. The batch is bounded by ``max_dispatch`` (defaults to the
    execution's ``max_parallel_per_wave``); the parent execution
    must be in a terminal state (the reboot queue is only populated
    by the Slice 2 auto-reconcile hook after the execution
    finalizes).

    Reboot-wave threshold pause: failures within the batch are
    tracked against the execution's
    ``failure_threshold_percent``. On breach the batch stops mid-
    dispatch, leaves remaining due rows in ``scheduled`` state,
    and returns the structured ``threshold_pause`` context in the
    summary so the operator UI can render a paused state.

    No real reboot is issued by tests — they pass a fake
    ``dispatch_callable`` so the transport is mocked.
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
            f"terminal executions can dispatch reboots"
        )

    current_now = now or datetime.utcnow()
    summary = RebootDispatchBatchSummary(execution_id=execution_id)

    due_rows = _due_scheduled_rows(db, execution_id, now=current_now)
    summary.not_due_count = _not_due_scheduled_count(db, execution_id, now=current_now)
    if not due_rows:
        summary.no_due = True
        return summary

    bound = (
        max_dispatch
        if max_dispatch is not None
        else (execution.max_parallel_per_wave or len(due_rows))
    )
    batch = due_rows[:bound]
    threshold_pct = _resolve_failure_threshold(execution)
    dispatcher = _resolve_dispatch_callable(db, dispatch_callable)

    attempted = 0
    failed = 0

    for row in batch:
        # Atomic claim: conditional UPDATE flips the row from
        # ``scheduled`` to ``rebooting`` only if no other dispatcher
        # has already claimed it. Two concurrent ``dispatch-due``
        # calls would both observe the row as ``scheduled`` in the
        # initial batch fetch; the first UPDATE that affects 1 row
        # wins the claim, every other UPDATE affects 0 rows and the
        # losing caller skips this row without ever issuing the
        # reboot command. The claim is durable via the immediate
        # ``db.commit()`` so a crash between claim and transport
        # leaves a stable ``rebooting`` row (Slice 4 verification
        # will reconcile stale claims).
        cmd = list(DEFAULT_REBOOT_COMMAND)
        command_snapshot = shlex.join(cmd)
        claimed = (
            db.query(PatchUpdateExecutionReboot)
            .filter(
                PatchUpdateExecutionReboot.id == row.id,
                PatchUpdateExecutionReboot.state == REBOOT_STATE_SCHEDULED,
            )
            .update(
                {
                    PatchUpdateExecutionReboot.state: REBOOT_STATE_REBOOTING,
                    PatchUpdateExecutionReboot.started_at: current_now,
                    PatchUpdateExecutionReboot.transport_kind: TRANSPORT_KIND_SSH,
                    PatchUpdateExecutionReboot.command_snapshot: command_snapshot,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        if claimed == 0:
            # Another worker claimed this row first; skip without
            # incrementing ``attempted`` / sending the command.
            continue
        db.refresh(row)

        # Fetch the System ORM row from the snapshot id. None means
        # the host was deleted after Slice 2 scheduling — treat as
        # transport_unavailable so the failure is structured, not
        # silent.
        system: Optional[System] = None
        if row.system_id_snapshot is not None:
            system = (
                db.query(System).filter(System.id == row.system_id_snapshot).first()
            )

        attempted += 1

        if system is None:
            # Skip the transport call entirely — there is no host.
            result = RebootDispatchResult(
                exit_signal_kind=EXIT_SIGNAL_TRANSPORT_UNAVAILABLE,
                error="system_deleted",
                stderr=(f"system id={row.system_id_snapshot} no longer exists"),
            )
        else:
            try:
                result = dispatcher(system, cmd)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning(
                    "reboot dispatch_callable raised for row=%d: %s",
                    row.id,
                    exc,
                )
                result = RebootDispatchResult(
                    exit_signal_kind=EXIT_SIGNAL_TRANSPORT_ERROR,
                    error="dispatch_callable_error",
                    stderr=str(exc),
                )

        if result.exit_signal_kind not in VALID_EXIT_SIGNALS:
            # Defensive: any unknown signal becomes a structured
            # transport_error so the CHECK constraint never trips.
            logger.warning(
                "reboot dispatcher returned unknown exit_signal_kind=%r "
                "for row=%d; coercing to transport_error",
                result.exit_signal_kind,
                row.id,
            )
            result = RebootDispatchResult(
                exit_signal_kind=EXIT_SIGNAL_TRANSPORT_ERROR,
                error="unknown_exit_signal",
                stderr=str(result.exit_signal_kind),
            )

        # Persist the dispatch outcome on the row.
        success = result.exit_signal_kind in SUCCESS_EXIT_SIGNALS
        new_state = REBOOT_STATE_REBOOTING if success else REBOOT_STATE_FAILED
        completed_at = None if success else current_now

        row.state = new_state
        row.started_at = current_now
        row.completed_at = completed_at
        row.transport_kind = TRANSPORT_KIND_SSH
        row.command_snapshot = command_snapshot
        row.exit_signal_kind = result.exit_signal_kind
        # PRA-172 Slice 4 evidence baseline: capture the
        # pre-reboot host facts (uptime + kernel) at dispatch
        # time so the verifier has a reference point for proving
        # the host actually rebooted. Missing facts are
        # represented as ``null`` rather than silently omitted so
        # the verifier can decide to fall back to reachability-only.
        pre_reboot_facts = _capture_pre_reboot_facts(db, row.system_id_snapshot)
        row.dispatch_details = {
            "exit_code": result.exit_code,
            "stderr": (result.stderr or "")[:4096],
            "stdout_truncated": bool(result.stdout),
            "duration_ms": result.duration_ms,
            "transport_name": result.transport_name,
            "error": result.error,
            "dispatched_at": utc_iso(current_now),
            "pre_reboot_facts": pre_reboot_facts,
            # PRA-175 Slice 2: planned argv lives in
            # ``command_snapshot`` (e.g. ``systemctl reboot``);
            # ``effective_argv`` is the post-sudo-wrap argv
            # actually sent to SSH (e.g.
            # ``["sudo", "-n", "systemctl", "reboot"]``), recorded
            # when the default dispatcher ran. ``None`` for test
            # fakes that bypass the wrap. The sudo password is
            # never present here — it travels via stdin and is
            # not retained.
            "effective_argv": (
                list(result.effective_argv)
                if result.effective_argv is not None
                else None
            ),
        }
        db.commit()

        # Audit emit (safe_emit no db= — opens own session).
        if success:
            _emit_audit(
                action=AUDIT_REBOOT_STARTED,
                row=row,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
            )
            summary.succeeded_count += 1
        else:
            _emit_audit(
                action=AUDIT_REBOOT_DISPATCH_FAILED,
                row=row,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                extra={"error": result.error},
            )
            summary.failed_count += 1
            failed += 1

        summary.dispatched_count += 1
        summary.host_outcomes.append(
            RebootDispatchHostOutcome(
                execution_reboot_id=row.id,
                execution_host_id=row.execution_host_id,
                system_id=row.system_id_snapshot,
                state=new_state,
                exit_signal_kind=result.exit_signal_kind,
                transport_kind=TRANSPORT_KIND_SSH,
                exit_code=result.exit_code,
                error_code=result.error,
            )
        )

        # Threshold check after each row. On breach, stop and
        # return the pause context; remaining rows in ``batch`` stay
        # in ``scheduled`` state for a later operator-triggered
        # dispatch call.
        breach = _threshold_breach_context(threshold_pct, failed, attempted)
        if breach is not None:
            summary.pause_reason = PAUSE_REASON_REBOOT_THRESHOLD_EXCEEDED
            summary.threshold_pause = breach
            break

    return summary
