"""Patch rollback dispatch service (PRA-173 slice 3).

Trigger-based per-host rollback dispatcher that consumes the PRA-173
Slice 2 *frozen* approval snapshot — not the live ``command_plan``
columns — and runs the recorded ``argv`` sequences through the same
sync↔async transport seam :mod:`patch_execution_dispatch_service`
uses. Slice 3 is the first PRA-173 slice that actually runs
rollback commands, and only after explicit operator action while
the rollback approval is ``approved``.

**Bounded batch only.** One ``POST /rollback/dispatch-next`` call
dispatches at most ``run.max_parallel`` pending hosts. There is
NO long-lived background worker, NO continuous loop, NO automatic
rollback on failure, NO package-history mutation, NO re-scan or
verification loop, NO mirror/airgap behavior. Re-scan +
PackageHistory writes belong to Slice 4; UI to closeout.

Adapter seam:

The dispatcher delegates the actual remote command execution to a
``DispatchCallable`` — the same alias the PRA-171 dispatch service
exposes (``(System, list[str]) -> DispatchResult``). Tests pass a
fake. The default implementation bridges to the existing async
transport factory through
``patch_execution_dispatch_service.default_dispatch``.

Per-host command sequence:

The frozen plan snapshot carries, per feasible package, a
``command_plan`` JSONB blob shaped by Slice 2's
``_render_command_plan``. Slice 3 dispatch processes a host by:

1. **Pre-steps**: every package's ``held_package_handling.pre_steps``
   and ``versionlock_handling.pre_steps``, in package-name order.
   For apt-with-held: ``apt-mark unhold <pkg>``. For dnf-with-
   versionlock: future-slice — current frozen plans record
   ``versionlock_handling.supported = false`` and an empty
   ``pre_steps`` list.
2. **Primary commands**: every package's ``primary_command.argv``,
   in package-name order. Per-package outcome is recorded from
   each invocation's exit code.
3. **Post-steps**: every package's ``held_package_handling.post_steps``
   and ``versionlock_handling.post_steps``, in reverse package-
   name order so a hold restored on the way out matches the
   unhold released on the way in.

Audit events (via ``safe_emit`` no ``db=`` per the session-
boundary lock):

- ``patch_rollback.started`` — once per ``start_rollback_execution``.
- ``patch_rollback.host_succeeded`` — once per host whose every
  package returned exit 0.
- ``patch_rollback.host_failed`` — once per host whose dispatch
  encountered any non-zero exit / transport error.
- ``patch_rollback.completed`` — once when every host on the
  dispatch run reaches a terminal state.

Slice 3 *does not* finalize the parent rollback artifact or the
parent ``patch_update_executions`` row; it is a separate per-
execution dispatch artifact whose lifecycle mirrors PRA-171's.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import (
    PatchApproval,
    PatchRollbackDispatchHost,
    PatchRollbackDispatchHostPackage,
    PatchRollbackDispatchRun,
    PatchUpdateExecution,
    PatchUpdateExecutionRollback,
    PatchUpdateExecutionRollbackApproval,
    System,
    User,
)
from . import patch_approval_service
from .audit_event_service import safe_emit
from .patch_execution_dispatch_service import (
    ERROR_CODE_PACKAGE_MANAGER_FAILED,
    ERROR_CODE_TRANSPORT_ERROR,
    ERROR_CODE_TRANSPORT_UNAVAILABLE,
    MAX_OUTPUT_BYTES,
    DispatchCallable,
    DispatchResult,
    default_dispatch,
)
from .patch_rollback_service import (
    ROLLBACK_PLAN_STATE_EVALUATED,
    PatchUpdateRollbackError,
    _latest_rollback_approval_link,
    utc_iso,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabulary (mirrors DB CHECK constraints)
# ---------------------------------------------------------------------------

RUN_STATE_PENDING = "pending"
RUN_STATE_RUNNING = "running"
RUN_STATE_PAUSED = "paused"
RUN_STATE_SUCCEEDED = "succeeded"
RUN_STATE_FAILED = "failed"
RUN_STATE_CANCELED = "canceled"

VALID_RUN_STATES = frozenset(
    {
        RUN_STATE_PENDING,
        RUN_STATE_RUNNING,
        RUN_STATE_PAUSED,
        RUN_STATE_SUCCEEDED,
        RUN_STATE_FAILED,
        RUN_STATE_CANCELED,
    }
)
NON_TERMINAL_RUN_STATES = frozenset(
    {RUN_STATE_PENDING, RUN_STATE_RUNNING, RUN_STATE_PAUSED}
)
TERMINAL_RUN_STATES = frozenset(
    {RUN_STATE_SUCCEEDED, RUN_STATE_FAILED, RUN_STATE_CANCELED}
)
CANCEL_FROM_STATES = NON_TERMINAL_RUN_STATES

HOST_STATE_PENDING = "pending"
HOST_STATE_RUNNING = "running"
HOST_STATE_SUCCEEDED = "succeeded"
HOST_STATE_FAILED = "failed"
HOST_STATE_SKIPPED = "skipped"
HOST_STATE_CANCELED = "canceled"

VALID_HOST_STATES = frozenset(
    {
        HOST_STATE_PENDING,
        HOST_STATE_RUNNING,
        HOST_STATE_SUCCEEDED,
        HOST_STATE_FAILED,
        HOST_STATE_SKIPPED,
        HOST_STATE_CANCELED,
    }
)

PACKAGE_OUTCOME_PENDING = "pending"
PACKAGE_OUTCOME_SUCCEEDED = "succeeded"
PACKAGE_OUTCOME_FAILED = "failed"
PACKAGE_OUTCOME_SKIPPED = "skipped"
PACKAGE_OUTCOME_UNKNOWN = "unknown"

VALID_PACKAGE_OUTCOMES = frozenset(
    {
        PACKAGE_OUTCOME_PENDING,
        PACKAGE_OUTCOME_SUCCEEDED,
        PACKAGE_OUTCOME_FAILED,
        PACKAGE_OUTCOME_SKIPPED,
        PACKAGE_OUTCOME_UNKNOWN,
    }
)


# Refusal codes for start/cancel/dispatch.
REFUSAL_APPROVAL_NOT_APPROVED = "approval_not_approved"
REFUSAL_NO_FROZEN_SNAPSHOT = "no_frozen_plan_snapshot"
REFUSAL_LIVE_DISPATCH_EXISTS = "live_dispatch_exists"
REFUSAL_ROLLBACK_NOT_EVALUATED = "rollback_not_evaluated"


# Audit actions emitted from this service (via safe_emit no db= per
# the session-boundary lock).
AUDIT_ROLLBACK_STARTED = "patch_rollback.started"
AUDIT_ROLLBACK_HOST_SUCCEEDED = "patch_rollback.host_succeeded"
AUDIT_ROLLBACK_HOST_FAILED = "patch_rollback.host_failed"
AUDIT_ROLLBACK_COMPLETED = "patch_rollback.completed"


DEFAULT_MAX_PARALLEL = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_user(db: Session, user_id: int) -> None:
    if not db.query(User.id).filter(User.id == user_id).first():
        raise PatchUpdateRollbackError(
            f"actor_user_id={user_id} does not reference a user"
        )


def _require_execution(db: Session, execution_id: int) -> PatchUpdateExecution:
    execution = (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.id == execution_id)
        .first()
    )
    if execution is None:
        raise PatchUpdateRollbackError(
            f"patch update execution id={execution_id} not found"
        )
    return execution


def _require_run(db: Session, run_id: int) -> PatchRollbackDispatchRun:
    run = (
        db.query(PatchRollbackDispatchRun)
        .filter(PatchRollbackDispatchRun.id == run_id)
        .first()
    )
    if run is None:
        raise PatchUpdateRollbackError(
            f"patch rollback dispatch run id={run_id} not found"
        )
    return run


def _truncate(text: str) -> str:
    if not text:
        return ""
    if len(text) <= MAX_OUTPUT_BYTES:
        return text
    return (
        text[:MAX_OUTPUT_BYTES] + f"...[truncated {len(text) - MAX_OUTPUT_BYTES} bytes]"
    )


def _command_to_string(argv: List[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


def _normalize_max_parallel(value: Optional[int]) -> int:
    if value is None:
        return DEFAULT_MAX_PARALLEL
    if isinstance(value, bool) or not isinstance(value, int):
        raise PatchUpdateRollbackError("max_parallel must be a positive integer")
    if value < 1:
        raise PatchUpdateRollbackError("max_parallel must be >= 1")
    return value


def _emit_run_audit(
    *,
    action: str,
    run: PatchRollbackDispatchRun,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    context: Dict[str, Any] = {
        "rollback_id": run.rollback_id,
        "rollback_approval_link_id": run.rollback_approval_link_id,
        "rollback_dispatch_run_id": run.id,
        "max_parallel": run.max_parallel,
    }
    if extra:
        context.update(extra)
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_rollback_dispatch_run",
        target_id=str(run.id),
        context=context,
    )


def _emit_host_audit(
    *,
    action: str,
    run: PatchRollbackDispatchRun,
    host_row: PatchRollbackDispatchHost,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    context: Dict[str, Any] = {
        "rollback_id": run.rollback_id,
        "rollback_dispatch_run_id": run.id,
        "rollback_dispatch_host_id": host_row.id,
        "rollback_host_id": host_row.rollback_host_id,
        "system_id": host_row.system_id_snapshot,
        "system_hostname": host_row.system_hostname_snapshot,
    }
    if extra:
        context.update(extra)
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_rollback_dispatch_host",
        target_id=str(host_row.id),
        context=context,
    )


# ---------------------------------------------------------------------------
# Result envelope
# ---------------------------------------------------------------------------


@dataclass
class RollbackDispatchHostOutcome:
    """One per-host outcome returned by ``dispatch_next_batch``."""

    rollback_dispatch_host_id: int
    rollback_host_id: int
    system_id: Optional[int]
    state: str
    succeeded_package_count: int = 0
    failed_package_count: int = 0
    skipped_package_count: int = 0
    error_code: Optional[str] = None


@dataclass
class RollbackDispatchBatchSummary:
    """Result envelope returned by ``dispatch_next_batch``."""

    rollback_dispatch_run_id: int
    dispatched_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    no_pending: bool = False
    finalized_state: Optional[str] = None
    host_outcomes: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------


def _resolve_approved_link(
    db: Session, rollback_row: PatchUpdateExecutionRollback
) -> PatchUpdateExecutionRollbackApproval:
    """Return the rollback's most-recent approval link if and only if
    the underlying ``PatchApproval`` row is ``approved``. Otherwise
    raise with a structured refusal reason."""
    link = _latest_rollback_approval_link(db, rollback_row.id)
    if link is None:
        raise PatchUpdateRollbackError(
            f"rollback {rollback_row.id} has no approval link; call "
            "request_rollback_approval first"
        )
    approval = (
        db.query(PatchApproval).filter(PatchApproval.id == link.approval_id).first()
    )
    if approval is None:
        raise PatchUpdateRollbackError(
            f"rollback approval link {link.id} references missing "
            f"approval row {link.approval_id}"
        )
    if approval.status != patch_approval_service.STATUS_APPROVED:
        raise PatchUpdateRollbackError(
            f"cannot start rollback dispatch: {REFUSAL_APPROVAL_NOT_APPROVED}: "
            f"latest approval status is {approval.status!r}"
        )
    snapshot = link.frozen_plan_snapshot or {}
    if not snapshot or not snapshot.get("hosts"):
        raise PatchUpdateRollbackError(
            f"cannot start rollback dispatch: {REFUSAL_NO_FROZEN_SNAPSHOT}: "
            f"approval link {link.id} has no frozen plan snapshot"
        )
    return link


def _live_dispatch_run(
    db: Session, rollback_id: int
) -> Optional[PatchRollbackDispatchRun]:
    """Return the still-non-terminal dispatch run for this rollback,
    if one exists. The DB partial-unique index already prevents
    creating a second one; this is the readable refusal path."""
    return (
        db.query(PatchRollbackDispatchRun)
        .filter(
            PatchRollbackDispatchRun.rollback_id == rollback_id,
            PatchRollbackDispatchRun.state.in_(NON_TERMINAL_RUN_STATES),
        )
        .first()
    )


def _materialize_dispatch_hosts(
    db: Session,
    *,
    run: PatchRollbackDispatchRun,
    snapshot: Dict[str, Any],
) -> List[PatchRollbackDispatchHost]:
    """Build one dispatch-host row + per-package rows from each
    snapshot host. Pending state by default; the dispatcher
    transitions each row through ``running`` / ``succeeded`` /
    ``failed`` as it processes the host.

    Hosts that the snapshot describes but with zero feasible
    packages land as ``skipped`` immediately (defensive — the
    request-approval guard already refuses zero-feasible
    rollbacks, but the snapshot may carry hosts whose only
    feasible row was archived between request and start).
    """
    rows: List[PatchRollbackDispatchHost] = []
    for host_entry in snapshot.get("hosts") or []:
        feasible_packages = host_entry.get("feasible_packages") or []
        host_state = HOST_STATE_PENDING if feasible_packages else HOST_STATE_SKIPPED
        host_row = PatchRollbackDispatchHost(
            rollback_dispatch_run_id=run.id,
            rollback_host_id=host_entry["rollback_host_id"],
            system_id_snapshot=host_entry.get("system_id_snapshot"),
            system_hostname_snapshot=host_entry.get("system_hostname_snapshot"),
            state=host_state,
            error_details=(
                {"reason": "no_feasible_packages_in_snapshot"}
                if not feasible_packages
                else {}
            ),
            completed_at=(datetime.utcnow() if not feasible_packages else None),
        )
        db.add(host_row)
        db.flush()
        for pkg in feasible_packages:
            db.add(
                PatchRollbackDispatchHostPackage(
                    rollback_dispatch_host_id=host_row.id,
                    rollback_package_id=pkg.get("rollback_package_id"),
                    package_name=pkg["package_name"],
                    package_manager_family_snapshot=(
                        pkg.get("package_manager_family")
                        or pkg.get("command_plan", {}).get("family")
                        or "unknown"
                    ),
                    target_rollback_version_snapshot=pkg.get("target_rollback_version"),
                    outcome=PACKAGE_OUTCOME_PENDING,
                    error_code=None,
                    details={},
                )
            )
        rows.append(host_row)
    db.flush()
    return rows


def _build_progress_summary(db: Session, run_id: int) -> Dict[str, Any]:
    """Per-run rollup of host + package state counts. Stable
    ordering for polling responses."""
    host_counts: Dict[str, int] = {s: 0 for s in sorted(VALID_HOST_STATES)}
    pkg_counts: Dict[str, int] = {s: 0 for s in sorted(VALID_PACKAGE_OUTCOMES)}
    hosts = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run_id)
        .all()
    )
    for host in hosts:
        host_counts[host.state] = host_counts.get(host.state, 0) + 1
    pkg_rows = (
        db.query(PatchRollbackDispatchHostPackage.outcome)
        .join(
            PatchRollbackDispatchHost,
            PatchRollbackDispatchHost.id
            == PatchRollbackDispatchHostPackage.rollback_dispatch_host_id,
        )
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run_id)
        .all()
    )
    for (outcome,) in pkg_rows:
        pkg_counts[outcome] = pkg_counts.get(outcome, 0) + 1
    return {
        "host_count": len(hosts),
        "host_counts_by_state": host_counts,
        "package_count": len(pkg_rows),
        "package_counts_by_outcome": pkg_counts,
    }


def start_rollback_execution(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    max_parallel: Optional[int] = None,
) -> PatchRollbackDispatchRun:
    """Materialize a new rollback dispatch run for an execution.

    Refuses (route 422) when:

    * the parent execution does not exist (404 wording);
    * no rollback feasibility artifact exists yet
      (``rollback_not_evaluated``);
    * the rollback header is ``refused``;
    * the rollback's latest approval is not ``approved``;
    * the approval link's ``frozen_plan_snapshot`` is empty;
    * a non-terminal dispatch run already exists for this rollback
      (DB-level partial unique index + readable 422 message).

    Emits :data:`AUDIT_ROLLBACK_STARTED` via ``safe_emit`` no
    ``db=`` once the row + per-host rows are committed.
    """
    _require_user(db, actor_user_id)
    execution = _require_execution(db, execution_id)
    resolved_max_parallel = _normalize_max_parallel(max_parallel)

    rollback_row = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id == execution.id)
        .first()
    )
    if rollback_row is None:
        raise PatchUpdateRollbackError(
            f"cannot start rollback dispatch: {REFUSAL_ROLLBACK_NOT_EVALUATED}: "
            f"execution {execution_id} has no rollback feasibility artifact"
        )
    if rollback_row.state != ROLLBACK_PLAN_STATE_EVALUATED:
        raise PatchUpdateRollbackError(
            f"cannot start rollback dispatch: rollback {rollback_row.id} is in "
            f"state {rollback_row.state!r}; only "
            f"{ROLLBACK_PLAN_STATE_EVALUATED!r} rollbacks may dispatch"
        )

    existing = _live_dispatch_run(db, rollback_row.id)
    if existing is not None:
        raise PatchUpdateRollbackError(
            f"cannot start rollback dispatch: {REFUSAL_LIVE_DISPATCH_EXISTS}: "
            f"dispatch run {existing.id} is in state {existing.state!r}"
        )

    link = _resolve_approved_link(db, rollback_row)
    snapshot = dict(link.frozen_plan_snapshot or {})

    now = datetime.utcnow()
    run = PatchRollbackDispatchRun(
        rollback_id=rollback_row.id,
        rollback_approval_link_id=link.id,
        state=RUN_STATE_RUNNING,
        started_by=actor_user_id,
        started_at=now,
        max_parallel=resolved_max_parallel,
        progress_summary={},
    )
    db.add(run)
    db.flush()

    _materialize_dispatch_hosts(db, run=run, snapshot=snapshot)
    run.progress_summary = _build_progress_summary(db, run.id)
    db.commit()
    db.refresh(run)

    _emit_run_audit(
        action=AUDIT_ROLLBACK_STARTED,
        run=run,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        extra={
            "execution_id": execution.id,
            "plan_id": execution.plan_id,
            "approval_id": link.approval_id,
            "host_count": run.progress_summary.get("host_count"),
            "started_at": utc_iso(now),
        },
    )
    # PRA-178 Slice 3: emit patch.rollback_started beside the audit.
    from . import notification_events

    notification_events.emit_patch_rollback_started(
        db,
        execution_id=execution.id,
        plan_id=execution.plan_id,
    )
    return run


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def _frozen_packages_for_host(
    db: Session, host_row: PatchRollbackDispatchHost
) -> List[Dict[str, Any]]:
    """Return the frozen-plan package entries for one dispatch host.

    Reads from the dispatch run's approval-link snapshot
    (``link.frozen_plan_snapshot.hosts[*]``) rather than the live
    rollback package rows so dispatch consumes the bytes operators
    voted on. Falls back to an empty list when the snapshot has no
    entry for this host (defensive — the start path already
    materialized rows from the snapshot).
    """
    run = (
        db.query(PatchRollbackDispatchRun)
        .filter(PatchRollbackDispatchRun.id == host_row.rollback_dispatch_run_id)
        .first()
    )
    if run is None:
        return []
    link = (
        db.query(PatchUpdateExecutionRollbackApproval)
        .filter(
            PatchUpdateExecutionRollbackApproval.id == run.rollback_approval_link_id
        )
        .first()
    )
    if link is None:
        return []
    snapshot = link.frozen_plan_snapshot or {}
    for host_entry in snapshot.get("hosts") or []:
        if int(host_entry.get("rollback_host_id") or -1) == int(
            host_row.rollback_host_id
        ):
            return list(host_entry.get("feasible_packages") or [])
    return []


def _record_package_outcome(
    db: Session,
    host_row: PatchRollbackDispatchHost,
    package_name: str,
    *,
    outcome: str,
    error_code: Optional[str] = None,
    installed_version_before: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Upsert the per-package outcome row by ``(host_id, package_name)``.
    Slice 3 mirrors PRA-171: ``installed_version_after`` is NOT
    populated by the dispatcher; Slice 4 re-scan owns that column."""
    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_row.id,
            PatchRollbackDispatchHostPackage.package_name == package_name,
        )
        .first()
    )
    if pkg_row is None:
        # Should never happen — the start path materializes every
        # feasible package row. Defensive insert keeps the audit
        # complete even on the unlikely race.
        pkg_row = PatchRollbackDispatchHostPackage(
            rollback_dispatch_host_id=host_row.id,
            rollback_package_id=None,
            package_name=package_name,
            package_manager_family_snapshot="unknown",
            target_rollback_version_snapshot=None,
            outcome=outcome,
            error_code=error_code,
            installed_version_before=installed_version_before,
            details=details or {},
        )
        db.add(pkg_row)
    else:
        pkg_row.outcome = outcome
        pkg_row.error_code = error_code
        if installed_version_before is not None:
            pkg_row.installed_version_before = installed_version_before
        if details is not None:
            pkg_row.details = details
    db.flush()


def _build_pre_post_steps(
    feasible_packages: List[Dict[str, Any]],
) -> Tuple[List[Tuple[str, List[str]]], List[Tuple[str, List[str]]]]:
    """Pull every package's pre/post-step ``argv`` lists out of the
    frozen plan in deterministic order.

    Returns ``(pre_steps, post_steps)`` where each entry is
    ``(package_name, argv)``. Pre-steps run in package-name order
    (unhold before primary); post-steps run in reverse package-name
    order (rehold after primary in mirror order) so the
    unhold→primary→rehold pairing is preserved when multiple
    packages are mixed.
    """
    pre: List[Tuple[str, List[str]]] = []
    post: List[Tuple[str, List[str]]] = []
    sorted_pkgs = sorted(feasible_packages, key=lambda p: p["package_name"])
    for pkg in sorted_pkgs:
        plan = pkg.get("command_plan") or {}
        for step in (plan.get("held_package_handling") or {}).get("pre_steps") or []:
            argv = step.get("argv") or []
            if argv:
                pre.append((pkg["package_name"], list(argv)))
        for step in (plan.get("versionlock_handling") or {}).get("pre_steps") or []:
            argv = step.get("argv") or []
            if argv:
                pre.append((pkg["package_name"], list(argv)))
    for pkg in reversed(sorted_pkgs):
        plan = pkg.get("command_plan") or {}
        for step in (plan.get("held_package_handling") or {}).get("post_steps") or []:
            argv = step.get("argv") or []
            if argv:
                post.append((pkg["package_name"], list(argv)))
        for step in (plan.get("versionlock_handling") or {}).get("post_steps") or []:
            argv = step.get("argv") or []
            if argv:
                post.append((pkg["package_name"], list(argv)))
    return pre, post


def _resolve_system(db: Session, system_id: Optional[int]) -> Optional[System]:
    if system_id is None:
        return None
    return db.query(System).filter(System.id == system_id).first()


def _take_pending_hosts(
    db: Session, run_id: int, limit: int
) -> List[PatchRollbackDispatchHost]:
    rows = (
        db.query(PatchRollbackDispatchHost)
        .filter(
            PatchRollbackDispatchHost.rollback_dispatch_run_id == run_id,
            PatchRollbackDispatchHost.state == HOST_STATE_PENDING,
        )
        .order_by(PatchRollbackDispatchHost.id.asc())
        .limit(limit)
        .all()
    )
    return rows


# PRA-180 ROLLBACK-01: outcome sentinel returned by ``_process_host`` when it
# lost the atomic claim race for a host. The dispatch loop skips these without
# counting or re-dispatching them. Mirrors the patch-execution dispatcher.
OUTCOME_SKIPPED_CLAIM = "skipped_claim"


def _process_host(
    db: Session,
    *,
    run: PatchRollbackDispatchRun,
    host_row: PatchRollbackDispatchHost,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    dispatch_callable: DispatchCallable,
) -> Dict[str, Any]:
    """Dispatch a single host. Mirrors the PRA-171 ``_process_host``
    contract: state -> running + audit BEFORE the first command,
    fail-closed on any non-zero exit / transport error, emit
    host_succeeded / host_failed on completion."""
    # PRA-180 ROLLBACK-01: atomically claim the host before dispatching.
    # Same race as PATCH-01 on the patch path — two concurrent
    # ``dispatch_next_batch`` calls could both observe a ``pending`` row
    # and re-issue the (idempotent) downgrade. The conditional UPDATE
    # flips ``pending -> running`` only if still pending; the loser
    # matches 0 rows and we return a ``skipped_claim`` sentinel so the
    # caller neither dispatches nor double-counts the host.
    claimed = (
        db.query(PatchRollbackDispatchHost)
        .filter(
            PatchRollbackDispatchHost.id == host_row.id,
            PatchRollbackDispatchHost.state == HOST_STATE_PENDING,
        )
        .update(
            {
                PatchRollbackDispatchHost.state: HOST_STATE_RUNNING,
                PatchRollbackDispatchHost.started_at: datetime.utcnow(),
            },
            synchronize_session=False,
        )
    )
    db.flush()
    if claimed == 0:
        db.refresh(host_row)
        return {
            "rollback_dispatch_host_id": host_row.id,
            "rollback_host_id": host_row.rollback_host_id,
            "system_id": host_row.system_id_snapshot,
            "state": OUTCOME_SKIPPED_CLAIM,
        }
    # Won the claim; refresh the stale ORM row (synchronize_session=False).
    db.refresh(host_row)

    feasible_packages = _frozen_packages_for_host(db, host_row)
    _emit_host_audit(
        action="patch_rollback.host_started",  # reserved-not-yet-required
        run=run,
        host_row=host_row,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        extra={"package_count": len(feasible_packages)},
    )

    if not feasible_packages:
        host_row.state = HOST_STATE_SKIPPED
        host_row.completed_at = datetime.utcnow()
        host_row.error_details = {
            "reason": "no_feasible_packages_in_snapshot",
        }
        db.flush()
        _emit_host_audit(
            action=AUDIT_ROLLBACK_HOST_FAILED,
            run=run,
            host_row=host_row,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={"error_code": "no_feasible_packages_in_snapshot"},
        )
        return {
            "rollback_dispatch_host_id": host_row.id,
            "rollback_host_id": host_row.rollback_host_id,
            "system_id": host_row.system_id_snapshot,
            "state": host_row.state,
            "succeeded_package_count": 0,
            "failed_package_count": 0,
            "skipped_package_count": len(feasible_packages),
        }

    system = _resolve_system(db, host_row.system_id_snapshot)
    if system is None:
        host_row.state = HOST_STATE_FAILED
        host_row.completed_at = datetime.utcnow()
        host_row.error_details = {
            "code": ERROR_CODE_TRANSPORT_UNAVAILABLE,
            "message": "system row not found at dispatch time",
            "system_id_snapshot": host_row.system_id_snapshot,
        }
        for pkg in feasible_packages:
            _record_package_outcome(
                db,
                host_row,
                pkg["package_name"],
                outcome=PACKAGE_OUTCOME_FAILED,
                error_code=ERROR_CODE_TRANSPORT_UNAVAILABLE,
            )
        db.flush()
        _emit_host_audit(
            action=AUDIT_ROLLBACK_HOST_FAILED,
            run=run,
            host_row=host_row,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={"error_code": ERROR_CODE_TRANSPORT_UNAVAILABLE},
        )
        return {
            "rollback_dispatch_host_id": host_row.id,
            "rollback_host_id": host_row.rollback_host_id,
            "system_id": host_row.system_id_snapshot,
            "state": host_row.state,
            "succeeded_package_count": 0,
            "failed_package_count": len(feasible_packages),
            "skipped_package_count": 0,
            "error_code": ERROR_CODE_TRANSPORT_UNAVAILABLE,
        }

    pre_steps, post_steps = _build_pre_post_steps(feasible_packages)

    # Track per-package primary outcome and remaining-pkgs-to-skip.
    succeeded = 0
    failed = 0
    skipped = 0
    host_error_code: Optional[str] = None
    command_log: List[Dict[str, Any]] = []
    host_failed = False

    # Pre-steps. Failure of a pre-step fails the *associated*
    # package's primary but does not abort the whole host.
    pre_step_failed_packages: set = set()
    for pkg_name, argv in pre_steps:
        try:
            result = dispatch_callable(system, argv)
        except Exception as exc:  # pragma: no cover - defensive
            result = DispatchResult(
                exit_code=-1,
                error=ERROR_CODE_TRANSPORT_ERROR,
                stderr=f"adapter raised: {exc}",
            )
        command_log.append(
            {
                "phase": "pre",
                "package_name": pkg_name,
                # PRA-175 Slice 2: ``argv`` is the frozen plan
                # argv (preserved per the rollback frozen-snapshot
                # lock); ``effective_argv`` is the post-sudo-wrap
                # argv actually sent to the transport, recorded
                # only when the default dispatcher ran (``None``
                # for test fakes that bypass the wrap).
                "argv": argv,
                "effective_argv": (
                    list(result.effective_argv)
                    if result.effective_argv is not None
                    else None
                ),
                "command_string": _command_to_string(argv),
                "exit_code": result.exit_code,
                "transport": result.transport_name,
                "duration_ms": result.duration_ms,
                "error": result.error,
            }
        )
        if result.error or result.exit_code != 0:
            pre_step_failed_packages.add(pkg_name)
            host_failed = True
            host_error_code = host_error_code or (
                result.error or ERROR_CODE_PACKAGE_MANAGER_FAILED
            )

    # Primary commands. Skip any package whose pre-step failed.
    for pkg in sorted(feasible_packages, key=lambda p: p["package_name"]):
        pkg_name = pkg["package_name"]
        plan = pkg.get("command_plan") or {}
        primary = plan.get("primary_command") or {}
        argv = primary.get("argv") or []
        if pkg_name in pre_step_failed_packages or not argv:
            skipped += 1
            _record_package_outcome(
                db,
                host_row,
                pkg_name,
                outcome=PACKAGE_OUTCOME_SKIPPED,
                error_code="pre_step_failed"
                if pkg_name in pre_step_failed_packages
                else "missing_primary_command",
                details={"phase": "primary", "argv": list(argv)},
            )
            continue
        try:
            result = dispatch_callable(system, argv)
        except Exception as exc:  # pragma: no cover - defensive
            result = DispatchResult(
                exit_code=-1,
                error=ERROR_CODE_TRANSPORT_ERROR,
                stderr=f"adapter raised: {exc}",
            )
        effective_argv_snapshot = (
            list(result.effective_argv) if result.effective_argv is not None else None
        )
        command_log.append(
            {
                "phase": "primary",
                "package_name": pkg_name,
                "argv": argv,
                "effective_argv": effective_argv_snapshot,
                "command_string": _command_to_string(argv),
                "exit_code": result.exit_code,
                "transport": result.transport_name,
                "duration_ms": result.duration_ms,
                "error": result.error,
            }
        )
        if result.error or result.exit_code != 0:
            failed += 1
            host_failed = True
            error_code = result.error or ERROR_CODE_PACKAGE_MANAGER_FAILED
            host_error_code = host_error_code or error_code
            _record_package_outcome(
                db,
                host_row,
                pkg_name,
                outcome=PACKAGE_OUTCOME_FAILED,
                error_code=error_code,
                details={
                    "phase": "primary",
                    "argv": list(argv),
                    "effective_argv": effective_argv_snapshot,
                    "exit_code": result.exit_code,
                    "stdout": _truncate(result.stdout),
                    "stderr": _truncate(result.stderr),
                    "duration_ms": result.duration_ms,
                    "transport": result.transport_name,
                },
            )
        else:
            succeeded += 1
            _record_package_outcome(
                db,
                host_row,
                pkg_name,
                outcome=PACKAGE_OUTCOME_SUCCEEDED,
                error_code=None,
                details={
                    "phase": "primary",
                    "argv": list(argv),
                    "effective_argv": effective_argv_snapshot,
                    "exit_code": result.exit_code,
                    "stdout": _truncate(result.stdout),
                    "stderr": _truncate(result.stderr),
                    "duration_ms": result.duration_ms,
                    "transport": result.transport_name,
                },
            )

    # Post-steps. We run these regardless of primary outcome so a
    # rehold that wraps a failed unhold/primary pair still gets a
    # best-effort restore. Any post-step failure does NOT downgrade
    # an otherwise-succeeded package row, but it does flip the host
    # to failed so operators see the gap.
    for pkg_name, argv in post_steps:
        try:
            result = dispatch_callable(system, argv)
        except Exception as exc:  # pragma: no cover - defensive
            result = DispatchResult(
                exit_code=-1,
                error=ERROR_CODE_TRANSPORT_ERROR,
                stderr=f"adapter raised: {exc}",
            )
        command_log.append(
            {
                "phase": "post",
                "package_name": pkg_name,
                "argv": argv,
                "effective_argv": (
                    list(result.effective_argv)
                    if result.effective_argv is not None
                    else None
                ),
                "command_string": _command_to_string(argv),
                "exit_code": result.exit_code,
                "transport": result.transport_name,
                "duration_ms": result.duration_ms,
                "error": result.error,
            }
        )
        if result.error or result.exit_code != 0:
            host_failed = True
            host_error_code = host_error_code or (
                result.error or ERROR_CODE_PACKAGE_MANAGER_FAILED
            )

    host_row.completed_at = datetime.utcnow()
    host_row.error_details = {
        "command_log": command_log,
        "succeeded_package_count": succeeded,
        "failed_package_count": failed,
        "skipped_package_count": skipped,
    }
    if host_failed:
        host_row.state = HOST_STATE_FAILED
        host_row.error_details["code"] = (
            host_error_code or ERROR_CODE_PACKAGE_MANAGER_FAILED
        )
        emit_action = AUDIT_ROLLBACK_HOST_FAILED
    else:
        host_row.state = HOST_STATE_SUCCEEDED
        emit_action = AUDIT_ROLLBACK_HOST_SUCCEEDED

    db.flush()
    _emit_host_audit(
        action=emit_action,
        run=run,
        host_row=host_row,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        extra={
            "succeeded_package_count": succeeded,
            "failed_package_count": failed,
            "skipped_package_count": skipped,
            "error_code": host_error_code,
        },
    )

    return {
        "rollback_dispatch_host_id": host_row.id,
        "rollback_host_id": host_row.rollback_host_id,
        "system_id": host_row.system_id_snapshot,
        "state": host_row.state,
        "succeeded_package_count": succeeded,
        "failed_package_count": failed,
        "skipped_package_count": skipped,
        "error_code": host_error_code,
    }


def _maybe_finalize_run(
    db: Session,
    *,
    run: PatchRollbackDispatchRun,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
) -> bool:
    """Transition the run to ``succeeded`` / ``failed`` when every
    host has a terminal state. Idempotent — only fires once."""
    if run.state not in {RUN_STATE_RUNNING, RUN_STATE_PAUSED}:
        return False
    host_states = [
        s
        for (s,) in db.query(PatchRollbackDispatchHost.state)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .all()
    ]
    if not host_states:
        return False
    if any(s in {HOST_STATE_PENDING, HOST_STATE_RUNNING} for s in host_states):
        return False
    any_failed = any(s == HOST_STATE_FAILED for s in host_states)
    run.state = RUN_STATE_FAILED if any_failed else RUN_STATE_SUCCEEDED
    run.completed_at = datetime.utcnow()
    db.flush()
    _emit_run_audit(
        action=AUDIT_ROLLBACK_COMPLETED,
        run=run,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        extra={
            "final_state": run.state,
            "completed_at": utc_iso(run.completed_at),
        },
    )
    # PRA-178 Slice 3: emit patch.rollback_completed beside the audit.
    # The parent execution is resolved through the rollback row so the
    # notification carries operator-readable identifiers.
    from . import notification_events

    rollback = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.id == run.rollback_id)
        .first()
    )
    notification_events.emit_patch_rollback_completed(
        db,
        execution_id=rollback.execution_id if rollback else 0,
        plan_id=rollback.plan_id_snapshot if rollback else None,
        state=run.state,
    )
    return True


def dispatch_next_batch(
    db: Session,
    run_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    dispatch_callable: Optional[DispatchCallable] = None,
) -> RollbackDispatchBatchSummary:
    """Dispatch the next bounded batch of pending hosts for a
    rollback dispatch run. One bounded batch per call.

    Refuses (route 422) when the run is not ``running``. Returns
    ``no_pending=True`` when every host is already terminal /
    skipped (the run may be finalized as a side-effect)."""
    _require_user(db, actor_user_id)
    run = _require_run(db, run_id)
    if run.state != RUN_STATE_RUNNING:
        raise PatchUpdateRollbackError(
            f"rollback dispatch run {run.id} is in state {run.state!r}; "
            f"only '{RUN_STATE_RUNNING}' runs may dispatch"
        )

    if dispatch_callable is None:
        dispatch_callable = lambda system, cmd: default_dispatch(db, system, cmd)

    pending = _take_pending_hosts(db, run.id, run.max_parallel)
    summary = RollbackDispatchBatchSummary(
        rollback_dispatch_run_id=run.id,
        dispatched_count=len(pending),
    )

    if not pending:
        summary.no_pending = True
        if _maybe_finalize_run(
            db,
            run=run,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
        ):
            summary.finalized_state = run.state
        run.progress_summary = _build_progress_summary(db, run.id)
        db.commit()
        db.refresh(run)
        return summary

    for host_row in pending:
        db.refresh(run)
        if run.state != RUN_STATE_RUNNING:
            break
        result = _process_host(
            db,
            run=run,
            host_row=host_row,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            dispatch_callable=dispatch_callable,
        )
        if result["state"] == OUTCOME_SKIPPED_CLAIM:
            # PRA-180 ROLLBACK-01: a concurrent dispatcher claimed this host
            # first; it was not dispatched here.
            summary.dispatched_count -= 1
            continue
        summary.host_outcomes.append(result)
        if result["state"] == HOST_STATE_SUCCEEDED:
            summary.succeeded_count += 1
        elif result["state"] == HOST_STATE_FAILED:
            summary.failed_count += 1

    if _maybe_finalize_run(
        db,
        run=run,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    ):
        summary.finalized_state = run.state

    run.progress_summary = _build_progress_summary(db, run.id)
    db.commit()
    db.refresh(run)
    return summary


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------


def cancel_rollback_execution(
    db: Session,
    run_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    cancel_reason: Optional[str] = None,
) -> PatchRollbackDispatchRun:
    """Metadata-only cancel: pending hosts flip to ``canceled``,
    succeeded / failed rows preserved.

    Refuses with 422 when the run is already terminal.
    """
    _require_user(db, actor_user_id)
    run = _require_run(db, run_id)
    if run.state not in CANCEL_FROM_STATES:
        raise PatchUpdateRollbackError(
            f"rollback dispatch run {run.id} is in state {run.state!r}; "
            f"only {sorted(CANCEL_FROM_STATES)} runs may be canceled"
        )

    now = datetime.utcnow()
    run.state = RUN_STATE_CANCELED
    run.canceled_at = now
    run.completed_at = now
    run.cancel_reason = cancel_reason

    pending_hosts = (
        db.query(PatchRollbackDispatchHost)
        .filter(
            PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id,
            PatchRollbackDispatchHost.state == HOST_STATE_PENDING,
        )
        .all()
    )
    for host in pending_hosts:
        host.state = HOST_STATE_CANCELED
        host.completed_at = now

    db.flush()
    run.progress_summary = _build_progress_summary(db, run.id)
    db.commit()
    db.refresh(run)

    _emit_run_audit(
        action=AUDIT_ROLLBACK_COMPLETED,
        run=run,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        extra={
            "final_state": run.state,
            "cancel_reason": cancel_reason,
            "completed_at": utc_iso(now),
        },
    )
    return run


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def get_latest_dispatch_for_execution(
    db: Session, execution_id: int
) -> Tuple[
    PatchUpdateExecution,
    Optional[PatchRollbackDispatchRun],
    List[PatchRollbackDispatchHost],
    Dict[int, List[PatchRollbackDispatchHostPackage]],
]:
    """Return ``(execution, run_or_none, host_rows, packages_by_host_row_id)``
    for the per-execution dispatch read endpoint.

    Returns ``None`` for the run when no dispatch has been started.
    Raises with "not found" wording when the execution does not
    exist."""
    execution = _require_execution(db, execution_id)
    rollback_row = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id == execution.id)
        .first()
    )
    if rollback_row is None:
        return execution, None, [], {}
    run = (
        db.query(PatchRollbackDispatchRun)
        .filter(PatchRollbackDispatchRun.rollback_id == rollback_row.id)
        .order_by(
            PatchRollbackDispatchRun.started_at.desc(),
            PatchRollbackDispatchRun.id.desc(),
        )
        .first()
    )
    if run is None:
        return execution, None, [], {}
    hosts = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .order_by(PatchRollbackDispatchHost.id.asc())
        .all()
    )
    host_ids = [h.id for h in hosts]
    packages_by_host: Dict[int, List[PatchRollbackDispatchHostPackage]] = {
        hid: [] for hid in host_ids
    }
    if host_ids:
        for pkg in (
            db.query(PatchRollbackDispatchHostPackage)
            .filter(
                PatchRollbackDispatchHostPackage.rollback_dispatch_host_id.in_(host_ids)
            )
            .order_by(
                PatchRollbackDispatchHostPackage.rollback_dispatch_host_id.asc(),
                PatchRollbackDispatchHostPackage.package_name.asc(),
            )
            .all()
        ):
            packages_by_host.setdefault(pkg.rollback_dispatch_host_id, []).append(pkg)
    return execution, run, hosts, packages_by_host
