"""Patch update execution service (PRA-171 slice 1).

Substrate that consumes an approved/scheduled :class:`PatchUpdatePlan`
and materializes a durable execution-run row plus per-host execution
rows. **No package execution.** Slice 1 deliberately stops before
package-manager dispatch, SSH/agent operations, package-history
mutation, or any of the live execution machinery PRA-171 will own in
later slices.

Slice 1 responsibilities:

* enforce the start gate (plan exists, plan state, approval context,
  block reasons, materializable hosts, scheduled-start-at conservatism)
* materialize ``patch_update_executions`` + ``patch_update_execution_hosts``
  rows from the existing PRA-164 plan artifact (no target invention)
* expose metadata-only controls (start / pause / resume / cancel)
* aggregate progress: per-execution / per-wave host-state counts,
  selected-package counts, skip counts
* emit four audit events (started / paused / resumed / canceled) via
  ``safe_emit`` no ``db=`` per the established session-boundary lock

Out of scope (later slices / efforts):

* package-manager dispatch (apt/dnf/yum/dpkg/rpm/...)
* SSH execution, agent execution, broker operation dispatch
* mutating ``Package`` / ``PackageUpdate`` / ``PackageHistory``
* capturing real stdout/stderr/exit codes / before-after versions
* advancing hosts to ``running`` / ``succeeded`` / ``failed`` from
  real execution results
* wave worker loops, async background workers, retry queues
* reboot orchestration, post-reboot health verification, probes,
  rollback, downgrade, version re-pin
* mirror sync, mirror rebuild/re-sign, airgap export/import
* approval creation or approval-state changes (Slice 1 only consumes
  already-approved/scheduled plan state)
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import (
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    PatchUpdatePlanSelectedPackage,
    User,
)
from . import patch_update_plan_service
from .audit_event_service import safe_emit
from .patch_update_plan_service import (
    BLOCK_APPROVAL_REJECTED,
    PLAN_HOST_STATE_BLOCKED,
    PLAN_HOST_STATE_PLANNED,
    PLAN_STATE_APPROVED,
    PLAN_STATE_SCHEDULED,
    SELECTION_REASON_INVENTORY_MISSING,
    SELECTION_STATE_SELECTED,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local exception class — independent from patch_update_plan / patch_approval
# surfaces (M16 implementation lock #3 carry-forward).
# ---------------------------------------------------------------------------


class PatchUpdateExecutionError(ValueError):
    """Raised when an execution start / control / read is rejected for
    semantic reasons (unknown id, bad plan state, bad transition,
    request shape error, etc.).

    Subclasses ``ValueError`` so route layers can map the family to
    HTTP 422; "not found" wording maps to 404 by the same disambiguation
    convention used in PRA-161 / PRA-162 / PRA-164 routes.
    """


# ---------------------------------------------------------------------------
# Vocabulary constants (mirror the DB CHECKs)
# ---------------------------------------------------------------------------

EXECUTION_STATE_PENDING = "pending"
EXECUTION_STATE_RUNNING = "running"
EXECUTION_STATE_PAUSED = "paused"
EXECUTION_STATE_SUCCEEDED = "succeeded"
EXECUTION_STATE_FAILED = "failed"
EXECUTION_STATE_CANCELED = "canceled"

VALID_EXECUTION_STATES = frozenset(
    {
        EXECUTION_STATE_PENDING,
        EXECUTION_STATE_RUNNING,
        EXECUTION_STATE_PAUSED,
        EXECUTION_STATE_SUCCEEDED,
        EXECUTION_STATE_FAILED,
        EXECUTION_STATE_CANCELED,
    }
)

# Slice 1 transitions: pause requires running; resume requires paused;
# cancel allowed from any non-terminal state.
PAUSE_FROM_STATES = frozenset({EXECUTION_STATE_RUNNING})
RESUME_FROM_STATES = frozenset({EXECUTION_STATE_PAUSED})
CANCEL_FROM_STATES = frozenset(
    {
        EXECUTION_STATE_PENDING,
        EXECUTION_STATE_RUNNING,
        EXECUTION_STATE_PAUSED,
    }
)
TERMINAL_EXECUTION_STATES = frozenset(
    {
        EXECUTION_STATE_SUCCEEDED,
        EXECUTION_STATE_FAILED,
        EXECUTION_STATE_CANCELED,
    }
)
NON_TERMINAL_EXECUTION_STATES = frozenset(
    {
        EXECUTION_STATE_PENDING,
        EXECUTION_STATE_RUNNING,
        EXECUTION_STATE_PAUSED,
    }
)

# Plan states that are eligible to start an execution. Matches the
# Slice 1 spec: only ``approved`` or ``scheduled`` plans may execute;
# ``draft`` / ``awaiting_approval`` / ``blocked`` / ``superseded`` /
# ``canceled`` must be refused with structured 422 errors.
EXECUTABLE_PLAN_STATES = frozenset({PLAN_STATE_APPROVED, PLAN_STATE_SCHEDULED})

EXECUTION_HOST_STATE_PENDING = "pending"
EXECUTION_HOST_STATE_RUNNING = "running"
EXECUTION_HOST_STATE_SUCCEEDED = "succeeded"
EXECUTION_HOST_STATE_FAILED = "failed"
EXECUTION_HOST_STATE_SKIPPED = "skipped"
EXECUTION_HOST_STATE_PAUSED = "paused"
EXECUTION_HOST_STATE_CANCELED = "canceled"

VALID_EXECUTION_HOST_STATES = frozenset(
    {
        EXECUTION_HOST_STATE_PENDING,
        EXECUTION_HOST_STATE_RUNNING,
        EXECUTION_HOST_STATE_SUCCEEDED,
        EXECUTION_HOST_STATE_FAILED,
        EXECUTION_HOST_STATE_SKIPPED,
        EXECUTION_HOST_STATE_PAUSED,
        EXECUTION_HOST_STATE_CANCELED,
    }
)

# Skip-reason codes (structured ``[{"code": "...", "details": {...}}]``)
SKIP_REASON_PLAN_HOST_BLOCKED = "plan_host_blocked"
SKIP_REASON_PLAN_HOST_TARGETLESS = "plan_host_targetless"
SKIP_REASON_NO_SELECTED_PACKAGES = "no_selected_packages"

# Start-gate refusal codes (raised as PatchUpdateExecutionError messages
# starting with "cannot start execution: ..." — the route layer maps the
# whole family to 422 via the standard error-to-HTTP helper).
START_REFUSAL_PLAN_NOT_FOUND = "plan_not_found"
START_REFUSAL_PLAN_STATE = "plan_state_not_executable"
START_REFUSAL_PLAN_BLOCKED = "plan_block_reasons_present"
START_REFUSAL_APPROVAL_REQUIRED = "approval_required_not_satisfied"
START_REFUSAL_NO_HOSTS = "no_materializable_hosts"
START_REFUSAL_FUTURE_SCHEDULE = "scheduled_start_at_in_future"
START_REFUSAL_ACTIVE_EXECUTION_EXISTS = "active_execution_exists"


# ---------------------------------------------------------------------------
# Audit constants — Slice 1 emits four events.
# Reserved-but-not-yet-emitted strings (host_started/host_succeeded/
# host_failed/wave_completed/completed) live in later slices that own
# real execution.
# ---------------------------------------------------------------------------

AUDIT_EXECUTION_STARTED = "patch_update_execution.started"
AUDIT_EXECUTION_PAUSED = "patch_update_execution.paused"
AUDIT_EXECUTION_RESUMED = "patch_update_execution.resumed"
AUDIT_EXECUTION_CANCELED = "patch_update_execution.canceled"


DEFAULT_MAX_PARALLEL_PER_WAVE = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_actor(db: Session, actor_user_id: int) -> None:
    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchUpdateExecutionError(
            f"actor_user_id={actor_user_id} does not reference a user"
        )


def _require_plan(db: Session, plan_id: int) -> PatchUpdatePlan:
    plan = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()
    if plan is None:
        raise PatchUpdateExecutionError(f"patch update plan id={plan_id} not found")
    return plan


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


def _normalize_max_parallel(
    requested: Optional[int], policy_snapshot: Dict[str, Any]
) -> int:
    """Resolve the ``max_parallel_per_wave`` for a new execution.

    Operator-supplied wins; otherwise pull from the plan's policy
    snapshot (``max_parallel_per_wave`` or ``concurrency`` if present);
    otherwise fall back to ``DEFAULT_MAX_PARALLEL_PER_WAVE`` (1) so
    later slices have a conservative default. Negative / zero / bool
    values are rejected.
    """
    if requested is not None:
        if isinstance(requested, bool) or not isinstance(requested, int):
            raise PatchUpdateExecutionError(
                "max_parallel_per_wave must be a positive integer"
            )
        if requested < 1:
            raise PatchUpdateExecutionError("max_parallel_per_wave must be >= 1")
        return requested
    candidate = policy_snapshot.get("max_parallel_per_wave") or policy_snapshot.get(
        "concurrency"
    )
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        return DEFAULT_MAX_PARALLEL_PER_WAVE
    if candidate < 1:
        return DEFAULT_MAX_PARALLEL_PER_WAVE
    return candidate


def _normalize_failure_threshold(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise PatchUpdateExecutionError(
            "failure_threshold_percent must be an integer 0-100 or null"
        )
    if value < 0 or value > 100:
        raise PatchUpdateExecutionError(
            "failure_threshold_percent must be between 0 and 100 inclusive"
        )
    return value


def _selected_package_counts(db: Session, plan_host_ids: List[int]) -> Dict[int, int]:
    """Return a mapping ``plan_host_id -> count of selected_packages with
    state='selected'``. Inventory-missing placeholder rows
    (``package_name == ''``) are NOT counted as selected packages.
    """
    if not plan_host_ids:
        return {}
    rows = (
        db.query(
            PatchUpdatePlanSelectedPackage.plan_host_id,
            PatchUpdatePlanSelectedPackage.state,
            PatchUpdatePlanSelectedPackage.selection_reason,
        )
        .filter(
            PatchUpdatePlanSelectedPackage.plan_host_id.in_(plan_host_ids),
        )
        .all()
    )
    counts: Dict[int, int] = {pid: 0 for pid in plan_host_ids}
    for plan_host_id, state, reason in rows:
        if state != SELECTION_STATE_SELECTED:
            continue
        if reason == SELECTION_REASON_INVENTORY_MISSING:
            continue
        counts[plan_host_id] = counts.get(plan_host_id, 0) + 1
    return counts


def _has_active_execution(db: Session, plan_id: int) -> Optional[PatchUpdateExecution]:
    return (
        db.query(PatchUpdateExecution)
        .filter(
            PatchUpdateExecution.plan_id == plan_id,
            PatchUpdateExecution.state.in_(NON_TERMINAL_EXECUTION_STATES),
        )
        .first()
    )


# ---------------------------------------------------------------------------
# Start gate
# ---------------------------------------------------------------------------


def _evaluate_approval_gate(
    db: Session, plan: PatchUpdatePlan
) -> Optional[Dict[str, Any]]:
    """Return None when the approval gate passes, or a refusal-detail
    dict when it does not. Slice 1 keeps the policy contract:

    * if ``policy_snapshot.requires_approval`` is True, the plan's
      most recent approval link must report ``status=approved``
    * if ``policy_snapshot.requires_approval`` is False, the gate is
      satisfied automatically (the plan's own state machine already
      enforced ``approve_directly`` to reach ``approved`` /
      ``scheduled``)
    """
    requires_approval = bool(
        (plan.policy_snapshot or {}).get("requires_approval", False)
    )
    if not requires_approval:
        return None
    approval = patch_update_plan_service.get_plan_approval(db, plan)
    if approval is None:
        return {
            "code": START_REFUSAL_APPROVAL_REQUIRED,
            "details": {"reason": "no approval row exists for plan"},
        }
    if approval.get("status") != "approved":
        return {
            "code": START_REFUSAL_APPROVAL_REQUIRED,
            "details": {
                "reason": "approval not in 'approved' status",
                "approval_status": approval.get("status"),
            },
        }
    return None


def _evaluate_schedule_gate(
    plan: PatchUpdatePlan, *, now: datetime
) -> Optional[Dict[str, Any]]:
    """Reject starts whose ``scheduled_start_at`` is meaningfully in
    the future. Slice 1 stays conservative — the plan's own contract
    is that ``scheduled`` plans should not run until their start
    timestamp. PRA-171 will revisit when wiring the live executor.

    Returns ``None`` when the gate passes (no scheduled_start_at or
    the time has already arrived) or a refusal dict otherwise.
    """
    if plan.scheduled_start_at is None:
        return None
    if plan.scheduled_start_at <= now:
        return None
    return {
        "code": START_REFUSAL_FUTURE_SCHEDULE,
        "details": {
            "scheduled_start_at": plan.scheduled_start_at.isoformat(),
            "now": now.isoformat(),
        },
    }


def _evaluate_start_gate(
    db: Session, plan: PatchUpdatePlan, *, now: datetime
) -> Optional[Dict[str, Any]]:
    """Slice 1 start gate. Returns None on pass, or a dict
    ``{"code": ..., "details": {...}}`` on refusal.

    Order matters — earlier checks short-circuit so the operator sees
    the most actionable refusal first:

    1. plan state must be approved/scheduled
    2. plan must have no plan-level block_reasons
    3. approval gate (only enforced when policy requires_approval)
    4. plan must have at least one ``planned`` host
    5. scheduled_start_at must not be in the future
    6. no other non-terminal execution may exist for this plan
    """
    if plan.state not in EXECUTABLE_PLAN_STATES:
        return {
            "code": START_REFUSAL_PLAN_STATE,
            "details": {
                "plan_state": plan.state,
                "executable_states": sorted(EXECUTABLE_PLAN_STATES),
            },
        }

    block_reasons = list(plan.block_reasons or [])
    # Ignore approval_rejected because it is a terminal block at the plan
    # layer — schedule_plan / approve_directly cannot reach "approved" /
    # "scheduled" while it is set, so a plan with this code AND state
    # in EXECUTABLE_PLAN_STATES would already be impossible. Any other
    # code (block_reasons from selection / preflight / etc.) refuses.
    structural_blocks = [
        r for r in block_reasons if r.get("code") != BLOCK_APPROVAL_REJECTED
    ]
    if structural_blocks:
        return {
            "code": START_REFUSAL_PLAN_BLOCKED,
            "details": {"block_reasons": structural_blocks},
        }

    approval_refusal = _evaluate_approval_gate(db, plan)
    if approval_refusal is not None:
        return approval_refusal

    planned_count = (
        db.query(PatchUpdatePlanHost)
        .filter(
            PatchUpdatePlanHost.plan_id == plan.id,
            PatchUpdatePlanHost.state == PLAN_HOST_STATE_PLANNED,
        )
        .count()
    )
    if planned_count == 0:
        return {
            "code": START_REFUSAL_NO_HOSTS,
            "details": {"reason": "plan has zero planned hosts"},
        }

    schedule_refusal = _evaluate_schedule_gate(plan, now=now)
    if schedule_refusal is not None:
        return schedule_refusal

    active = _has_active_execution(db, plan.id)
    if active is not None:
        return {
            "code": START_REFUSAL_ACTIVE_EXECUTION_EXISTS,
            "details": {
                "execution_id": active.id,
                "execution_state": active.state,
            },
        }

    return None


# ---------------------------------------------------------------------------
# Materialization
# ---------------------------------------------------------------------------


def _materialize_execution_hosts(
    db: Session,
    *,
    execution: PatchUpdateExecution,
    plan_hosts: List[PatchUpdatePlanHost],
) -> List[PatchUpdateExecutionHost]:
    """Initialize per-host execution rows from the plan host artifact.

    * ``planned`` plan hosts whose system is still attached -> ``pending``
    * ``planned`` plan hosts whose Slice 2 selection produced zero
      selected packages -> ``skipped`` with ``no_selected_packages``
    * ``planned`` plan hosts whose system was deleted -> ``skipped``
      with ``plan_host_targetless``
    * ``blocked`` plan hosts -> ``skipped`` with ``plan_host_blocked``
      (block reasons copied from the plan host so the audit trail is
      self-contained)
    """
    plan_host_ids = [h.id for h in plan_hosts]
    selected_counts = _selected_package_counts(db, plan_host_ids)

    rows: List[PatchUpdateExecutionHost] = []
    for plan_host in plan_hosts:
        skip_reasons: List[Dict[str, Any]] = []
        state = EXECUTION_HOST_STATE_PENDING
        selected_count = selected_counts.get(plan_host.id, 0)

        if plan_host.state == PLAN_HOST_STATE_BLOCKED:
            state = EXECUTION_HOST_STATE_SKIPPED
            skip_reasons.append(
                {
                    "code": SKIP_REASON_PLAN_HOST_BLOCKED,
                    "details": {
                        "plan_host_block_reasons": list(plan_host.block_reasons or []),
                    },
                }
            )
        elif plan_host.system_id is None:
            state = EXECUTION_HOST_STATE_SKIPPED
            skip_reasons.append(
                {
                    "code": SKIP_REASON_PLAN_HOST_TARGETLESS,
                    "details": {
                        "system_hostname_snapshot": (
                            plan_host.system_hostname_snapshot
                        ),
                    },
                }
            )
        elif selected_count == 0:
            state = EXECUTION_HOST_STATE_SKIPPED
            skip_reasons.append(
                {
                    "code": SKIP_REASON_NO_SELECTED_PACKAGES,
                    "details": {
                        "selection_summary": (
                            dict(plan_host.selection_summary)
                            if plan_host.selection_summary
                            else None
                        ),
                    },
                }
            )

        row = PatchUpdateExecutionHost(
            execution_id=execution.id,
            plan_host_id=plan_host.id,
            system_id_snapshot=plan_host.system_id,
            system_hostname_snapshot=plan_host.system_hostname_snapshot,
            wave_index=plan_host.wave_index,
            state=state,
            selected_package_count=selected_count,
            skip_reasons=skip_reasons,
            error_details={},
        )
        db.add(row)
        rows.append(row)

    db.flush()
    return rows


def _build_progress_summary(db: Session, execution_id: int) -> Dict[str, Any]:
    """Aggregate per-execution + per-wave host-state counts and selected
    package totals from the per-host rows. Stable ordering so the
    operator UI can render polling responses without diff churn.

    Slice 2 extends the rollup with per-package outcome counts
    (succeeded / failed / skipped / unknown) sourced from the
    Slice-2 ``patch_update_execution_host_packages`` table when
    rows exist; the four counts are zero before the first
    dispatch-next call writes any rows.

    Slice 3 preserves the lifecycle keys
    (``completed_wave_indexes``, ``threshold_pause``) the
    dispatch service writes into ``progress_summary`` so a rebuild
    by this aggregator does not drop them. Those keys are emission/
    pause tracking state that the dispatcher persists explicitly;
    they cannot be re-derived from current host rows alone.
    """
    # Snapshot the lifecycle keys from the existing summary so they
    # survive the rebuild below.
    existing_summary = (
        db.query(PatchUpdateExecution.progress_summary)
        .filter(PatchUpdateExecution.id == execution_id)
        .scalar()
    ) or {}
    preserved_completed_waves = list(
        existing_summary.get("completed_wave_indexes") or []
    )
    preserved_threshold_pause = existing_summary.get("threshold_pause")

    rows: List[PatchUpdateExecutionHost] = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution_id)
        .order_by(
            PatchUpdateExecutionHost.wave_index.asc(),
            PatchUpdateExecutionHost.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionHost.id.asc(),
        )
        .all()
    )
    host_counts: Dict[str, int] = {s: 0 for s in sorted(VALID_EXECUTION_HOST_STATES)}
    waves: Dict[int, Dict[str, Any]] = {}
    selected_total = 0
    for row in rows:
        host_counts[row.state] = host_counts.get(row.state, 0) + 1
        selected_total += int(row.selected_package_count or 0)
        wave = waves.setdefault(
            row.wave_index,
            {
                "wave_index": row.wave_index,
                "host_count": 0,
                "selected_package_count": 0,
                "host_counts_by_state": {
                    s: 0 for s in sorted(VALID_EXECUTION_HOST_STATES)
                },
            },
        )
        wave["host_count"] += 1
        wave["selected_package_count"] += int(row.selected_package_count or 0)
        wave["host_counts_by_state"][row.state] = (
            wave["host_counts_by_state"].get(row.state, 0) + 1
        )

    # Slice 2: per-package outcome rollup from
    # patch_update_execution_host_packages. Local import to avoid the
    # circular module reference (dispatch service imports from this
    # module).
    from ..db.models import PatchUpdateExecutionHostPackage

    package_counts: Dict[str, int] = {
        "succeeded": 0,
        "failed": 0,
        "skipped": 0,
        "unknown": 0,
    }
    pkg_rows = (
        db.query(
            PatchUpdateExecutionHostPackage.outcome,
        )
        .join(
            PatchUpdateExecutionHost,
            PatchUpdateExecutionHost.id
            == PatchUpdateExecutionHostPackage.execution_host_id,
        )
        .filter(PatchUpdateExecutionHost.execution_id == execution_id)
        .all()
    )
    for (outcome,) in pkg_rows:
        package_counts[outcome] = package_counts.get(outcome, 0) + 1

    return {
        "host_count": len(rows),
        "host_counts_by_state": host_counts,
        "selected_package_count": selected_total,
        "package_outcome_counts": package_counts,
        "waves": [waves[k] for k in sorted(waves.keys())],
        # Slice 3 lifecycle tracking — preserved from the dispatcher's
        # explicit writes; not re-derivable from host rows alone.
        "completed_wave_indexes": sorted(
            set(int(x) for x in preserved_completed_waves)
        ),
        "threshold_pause": preserved_threshold_pause,
    }


# ---------------------------------------------------------------------------
# Public API — start
# ---------------------------------------------------------------------------


def start_execution(
    db: Session,
    *,
    plan_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    max_parallel_per_wave: Optional[int] = None,
    failure_threshold_percent: Optional[int] = None,
    now: Optional[datetime] = None,
) -> PatchUpdateExecution:
    """Materialize an execution-run from an approved/scheduled plan.

    Slice 1: writes the ``patch_update_executions`` row in state
    ``running`` plus per-host ``patch_update_execution_hosts`` rows
    initialized from the plan-host artifact. Does NOT dispatch any
    package-manager work — that is later-slice scope.
    """
    _require_actor(db, actor_user_id)
    plan = _require_plan(db, plan_id)
    current_now = now or datetime.utcnow()

    refusal = _evaluate_start_gate(db, plan, now=current_now)
    if refusal is not None:
        raise PatchUpdateExecutionError(
            f"cannot start execution: {refusal['code']}: {refusal['details']}"
        )

    plan_hosts: List[PatchUpdatePlanHost] = (
        db.query(PatchUpdatePlanHost)
        .filter(PatchUpdatePlanHost.plan_id == plan.id)
        .order_by(
            PatchUpdatePlanHost.wave_index.asc(),
            PatchUpdatePlanHost.system_id.asc().nullsfirst(),
            PatchUpdatePlanHost.id.asc(),
        )
        .all()
    )

    policy_snapshot = dict(plan.policy_snapshot or {})
    resolved_max_parallel = _normalize_max_parallel(
        max_parallel_per_wave, policy_snapshot
    )
    resolved_threshold = _normalize_failure_threshold(failure_threshold_percent)

    execution_config_snapshot: Dict[str, Any] = {
        "max_parallel_per_wave": resolved_max_parallel,
        "failure_threshold_percent": resolved_threshold,
        "max_parallel_source": (
            "request"
            if max_parallel_per_wave is not None
            else (
                "policy_snapshot"
                if policy_snapshot.get("max_parallel_per_wave")
                or policy_snapshot.get("concurrency")
                else "default"
            )
        ),
        "scheduled_start_at": (
            plan.scheduled_start_at.isoformat()
            if plan.scheduled_start_at is not None
            else None
        ),
    }

    execution = PatchUpdateExecution(
        plan_id=plan.id,
        state=EXECUTION_STATE_RUNNING,
        started_by=actor_user_id,
        started_at=current_now,
        max_parallel_per_wave=resolved_max_parallel,
        failure_threshold_percent=resolved_threshold,
        plan_state_snapshot=plan.state,
        policy_snapshot=policy_snapshot,
        execution_config_snapshot=execution_config_snapshot,
        progress_summary={},
    )
    db.add(execution)
    db.flush()

    _materialize_execution_hosts(db, execution=execution, plan_hosts=plan_hosts)
    execution.progress_summary = _build_progress_summary(db, execution.id)
    db.commit()
    db.refresh(execution)

    policy_slug = (
        db.query(PatchPolicy.slug).filter(PatchPolicy.id == plan.policy_id).scalar()
    )
    safe_emit(
        action=AUDIT_EXECUTION_STARTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution",
        target_id=str(execution.id),
        context={
            "plan_id": plan.id,
            "policy_id": plan.policy_id,
            "policy_slug": policy_slug,
            "plan_state_snapshot": execution.plan_state_snapshot,
            "max_parallel_per_wave": execution.max_parallel_per_wave,
            "failure_threshold_percent": execution.failure_threshold_percent,
            "host_count": execution.progress_summary.get("host_count"),
        },
    )
    return execution


# ---------------------------------------------------------------------------
# Public API — pause / resume / cancel (metadata-only)
# ---------------------------------------------------------------------------


def pause_execution(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    pause_reason: Optional[str] = None,
) -> PatchUpdateExecution:
    """Metadata-only pause: ``running`` -> ``paused``. Slice 1 does NOT
    interrupt any in-flight work because no work is dispatched yet."""
    _require_actor(db, actor_user_id)
    execution = _require_execution(db, execution_id)
    if execution.state not in PAUSE_FROM_STATES:
        raise PatchUpdateExecutionError(
            f"execution {execution_id} is in state {execution.state!r}; only "
            f"{sorted(PAUSE_FROM_STATES)} executions may be paused"
        )
    now = datetime.utcnow()
    execution.state = EXECUTION_STATE_PAUSED
    execution.paused_at = now
    execution.pause_reason = pause_reason
    db.commit()
    db.refresh(execution)

    safe_emit(
        action=AUDIT_EXECUTION_PAUSED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution",
        target_id=str(execution.id),
        context={
            "plan_id": execution.plan_id,
            "pause_reason": pause_reason,
        },
    )
    return execution


def resume_execution(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchUpdateExecution:
    """Metadata-only resume: ``paused`` -> ``running``."""
    _require_actor(db, actor_user_id)
    execution = _require_execution(db, execution_id)
    if execution.state not in RESUME_FROM_STATES:
        raise PatchUpdateExecutionError(
            f"execution {execution_id} is in state {execution.state!r}; only "
            f"{sorted(RESUME_FROM_STATES)} executions may be resumed"
        )
    execution.state = EXECUTION_STATE_RUNNING
    execution.paused_at = None
    execution.pause_reason = None
    db.commit()
    db.refresh(execution)

    safe_emit(
        action=AUDIT_EXECUTION_RESUMED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution",
        target_id=str(execution.id),
        context={"plan_id": execution.plan_id},
    )
    return execution


def cancel_execution(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    cancel_reason: Optional[str] = None,
) -> PatchUpdateExecution:
    """Metadata-only cancel: any non-terminal execution state ->
    ``canceled``. Still-``pending`` host rows are flipped to
    ``canceled`` so the progress rollup is accurate; ``skipped`` rows
    keep their state because they were never going to dispatch.

    Slice 4: after the pending-host flip, reuse the Slice 3
    wave-completion reconciliation helper from
    ``patch_execution_dispatch_service`` so any wave that just
    became fully terminal (because its in-flight ``pending`` hosts
    were canceled) emits ``patch_update_execution.wave_completed``.
    Idempotent via ``progress_summary.completed_wave_indexes``.

    Cancel intentionally does NOT emit
    ``patch_update_execution.completed`` — Slice 3's contract is
    that ``completed`` flips state to ``succeeded`` / ``failed``
    via ``_maybe_finalize_execution`` from the dispatch path.
    Cancel is its own terminal event; the cancel audit row remains
    the operator-facing terminal marker.
    """
    _require_actor(db, actor_user_id)
    execution = _require_execution(db, execution_id)
    if execution.state not in CANCEL_FROM_STATES:
        raise PatchUpdateExecutionError(
            f"execution {execution_id} is in state {execution.state!r}; only "
            f"{sorted(CANCEL_FROM_STATES)} executions may be canceled"
        )

    now = datetime.utcnow()
    prior_state = execution.state
    execution.state = EXECUTION_STATE_CANCELED
    execution.canceled_at = now
    execution.completed_at = now
    execution.cancel_reason = cancel_reason

    # Flip pending host rows to canceled; leave skipped/running/etc. alone.
    pending_hosts: List[PatchUpdateExecutionHost] = (
        db.query(PatchUpdateExecutionHost)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution.id,
            PatchUpdateExecutionHost.state == EXECUTION_HOST_STATE_PENDING,
        )
        .all()
    )
    for host_row in pending_hosts:
        host_row.state = EXECUTION_HOST_STATE_CANCELED
        host_row.completed_at = now
    db.flush()

    # Slice 4: wave-completion reconciliation pass.
    # Lazy import to avoid the circular reference (dispatch service
    # imports from this module). The helper records newly-completed
    # waves into ``execution.progress_summary.completed_wave_indexes``
    # and emits ``patch_update_execution.wave_completed`` via
    # ``safe_emit`` no ``db=`` per the established session-boundary
    # lock. Idempotent across calls (already-recorded wave indexes
    # are skipped).
    from . import patch_execution_dispatch_service

    patch_execution_dispatch_service._emit_unrecorded_wave_completions(
        db,
        execution=execution,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    # Note: cancel does NOT call _maybe_finalize_execution. Slice 3's
    # finalize transitions state to succeeded/failed; cancel owns
    # the canceled terminal state and emits the cancel audit row
    # below. Mixing them would double-emit terminal events.

    execution.progress_summary = _build_progress_summary(db, execution.id)
    db.commit()
    db.refresh(execution)

    safe_emit(
        action=AUDIT_EXECUTION_CANCELED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution",
        target_id=str(execution.id),
        context={
            "plan_id": execution.plan_id,
            "prior_state": prior_state,
            "canceled_host_count": len(pending_hosts),
            "cancel_reason": cancel_reason,
        },
    )

    # PRA-172 Slice 2: auto-reconcile the reboot queue after the cancel
    # commits and the cancel audit emits. Shares this session; the
    # call is best-effort so a reboot-queue failure does NOT
    # retroactively roll back the cancel. Lazy import to avoid a
    # circular reference (patch_reboot_service imports vocab constants
    # from this module).
    from . import patch_reboot_service

    patch_reboot_service.auto_reconcile_on_terminal(
        db,
        execution.id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    return execution


# ---------------------------------------------------------------------------
# Public API — read
# ---------------------------------------------------------------------------


def get_execution(db: Session, execution_id: int) -> Optional[PatchUpdateExecution]:
    return (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.id == execution_id)
        .first()
    )


def list_execution_hosts(
    db: Session, execution_id: int
) -> List[PatchUpdateExecutionHost]:
    """Return the per-host rows for an execution ordered by
    ``(wave_index, system_id_snapshot NULLS FIRST, id)`` for stable
    rendering."""
    if (
        db.query(PatchUpdateExecution.id)
        .filter(PatchUpdateExecution.id == execution_id)
        .first()
        is None
    ):
        raise PatchUpdateExecutionError(
            f"patch update execution id={execution_id} not found"
        )
    return (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution_id)
        .order_by(
            PatchUpdateExecutionHost.wave_index.asc(),
            PatchUpdateExecutionHost.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionHost.id.asc(),
        )
        .all()
    )


def latest_execution_for_plan(
    db: Session, plan_id: int
) -> Optional[PatchUpdateExecution]:
    """Return the most recent execution row for a plan, or None when no
    execution has ever been started. Used by the by-plan route lookup
    + the operator UI's plan-detail "current execution" panel."""
    if (
        db.query(PatchUpdatePlan.id).filter(PatchUpdatePlan.id == plan_id).first()
        is None
    ):
        raise PatchUpdateExecutionError(f"patch update plan id={plan_id} not found")
    return (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.plan_id == plan_id)
        .order_by(PatchUpdateExecution.id.desc())
        .first()
    )


def build_progress(db: Session, execution: PatchUpdateExecution) -> Dict[str, Any]:
    """Return the canonical progress payload for an execution. Recomputes
    the per-execution + per-wave rollup from current host rows so the
    response is always live (the persisted ``progress_summary`` JSONB
    is a snapshot from the last write — handy for reads without an
    extra query but the route surface re-aggregates so paused/cancel
    state changes show up immediately)."""
    summary = _build_progress_summary(db, execution.id)
    hosts = list_execution_hosts(db, execution.id)
    return {
        "execution": execution,
        "summary": summary,
        "hosts": hosts,
    }


# ---------------------------------------------------------------------------
# Helpers exposed for tests / route serialization layer
# ---------------------------------------------------------------------------


def execution_with_progress(
    db: Session, execution: PatchUpdateExecution
) -> Tuple[PatchUpdateExecution, Dict[str, Any], List[PatchUpdateExecutionHost]]:
    summary = _build_progress_summary(db, execution.id)
    hosts = list_execution_hosts(db, execution.id)
    return execution, summary, hosts
