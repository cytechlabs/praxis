"""Patch update reboot service (PRA-172 slice 1).

Builds and maintains the reboot queue that sits on top of a
PRA-171 :class:`PatchUpdateExecution`. Slice 1 ships *only* the
storage substrate and read surface: it computes per-host reboot
eligibility from the execution's policy snapshot and the host's
already-modeled facts, persists one
:class:`PatchUpdateExecutionReboot` row per execution-host, and
exposes idempotent reconcile/read APIs the route layer consumes.

Slice 1 deliberately stops before any real reboot work. There is
NO scheduling, NO transport-level reboot dispatch (SSH or agent),
NO post-reboot health verification, NO dependent-wave gating.
Those land in later PRA-172 slices.

Initialization is explicit (the route layer calls
:func:`reconcile_reboot_queue` once the parent execution reaches a
terminal state); this slice does not introduce a background
daemon. The reconcile pass is idempotent: re-running it after a
prior run does NOT overwrite scheduling / runtime fields (which
only later slices write), it only refreshes the Slice-1 decision
columns (``state``, ``decision_code``, ``decision_details``,
``reboot_required_fact``, ``reboot_policy_snapshot``,
``reboot_window_id_snapshot``, ``system_id_snapshot``,
``system_hostname_snapshot``, ``wave_index``).

The decision logic:

* If the execution-host did not succeed (state is anything other
  than ``succeeded``) -> ``skipped``, decision
  ``host_did_not_succeed``.
* Otherwise if the policy is ``never`` -> ``skipped``, decision
  ``policy_never``.
* Otherwise if the policy is ``always`` -> ``pending``, decision
  ``policy_always``.
* Otherwise if the policy is ``if_required``:
    * if ``host_facts.reboot_required`` is True -> ``pending``,
      decision ``host_fact_reboot_required``.
    * otherwise -> ``not_required``, decision
      ``fact_not_required``. (Null facts are NOT treated as
      requiring a reboot — silence is "no signal", not "yes". A
      later slice may re-evaluate after refreshing facts.)
* If the policy snapshot is missing -> ``skipped``, decision
  ``policy_missing``. If the policy snapshot is present but the
  value is not one of {never, if_required, always} -> ``skipped``,
  decision ``policy_invalid``.

Reboot-window context (``reboot_window_id`` from the policy
snapshot or the plan's own ``reboot_window_id`` override) is
recorded on every row, including ``pending`` rows whose window
context is null. The detail key ``reboot_window_status`` carries
``set`` / ``unset`` so the later slice that schedules into windows
can decide whether to fall back to maintenance-window context or
refuse the queue entry; this slice never silently fails — missing
window context is surfaced, never suppressed.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func as _sa_func
from sqlalchemy.orm import Session

func_count = _sa_func.count

from ..db.models import (
    HostFacts,
    MaintenanceWindow,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionReboot,
    PatchUpdatePlan,
)
from .audit_event_service import safe_emit
from .patch_execution_service import (
    EXECUTION_HOST_STATE_SUCCEEDED,
    TERMINAL_EXECUTION_STATES,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabularies (mirror the DB CHECK constraints).
# ---------------------------------------------------------------------------

REBOOT_STATE_NOT_REQUIRED = "not_required"
REBOOT_STATE_PENDING = "pending"
REBOOT_STATE_SCHEDULED = "scheduled"
REBOOT_STATE_REBOOTING = "rebooting"
REBOOT_STATE_VERIFYING = "verifying"
REBOOT_STATE_HEALTHY = "healthy"
REBOOT_STATE_FAILED = "failed"
REBOOT_STATE_SKIPPED = "skipped"

VALID_REBOOT_STATES = frozenset(
    {
        REBOOT_STATE_NOT_REQUIRED,
        REBOOT_STATE_PENDING,
        REBOOT_STATE_SCHEDULED,
        REBOOT_STATE_REBOOTING,
        REBOOT_STATE_VERIFYING,
        REBOOT_STATE_HEALTHY,
        REBOOT_STATE_FAILED,
        REBOOT_STATE_SKIPPED,
    }
)

# Slice 1 only writes these three states; the remainder are reserved
# for later PRA-172 slices.
SLICE1_REBOOT_STATES = frozenset(
    {
        REBOOT_STATE_NOT_REQUIRED,
        REBOOT_STATE_PENDING,
        REBOOT_STATE_SKIPPED,
    }
)

REBOOT_POLICY_NEVER = "never"
REBOOT_POLICY_IF_REQUIRED = "if_required"
REBOOT_POLICY_ALWAYS = "always"
REBOOT_POLICY_UNKNOWN = "unknown"

VALID_REBOOT_POLICY_INPUTS = frozenset(
    {REBOOT_POLICY_NEVER, REBOOT_POLICY_IF_REQUIRED, REBOOT_POLICY_ALWAYS}
)


# Decision codes carried on every queue row. Short, machine-readable;
# detail context lives in ``decision_details`` JSONB.
REBOOT_DECISION_HOST_FACT_REBOOT_REQUIRED = "host_fact_reboot_required"
REBOOT_DECISION_POLICY_ALWAYS = "policy_always"
REBOOT_DECISION_FACT_NOT_REQUIRED = "fact_not_required"
REBOOT_DECISION_POLICY_NEVER = "policy_never"
REBOOT_DECISION_HOST_DID_NOT_SUCCEED = "host_did_not_succeed"
REBOOT_DECISION_POLICY_INVALID = "policy_invalid"
REBOOT_DECISION_POLICY_MISSING = "policy_missing"

# Slice 2: scheduling-promotion outcomes, recorded under
# ``decision_details.scheduling`` so the operator UI can render the
# "why we picked / didn't pick this window" without parsing the
# row's history.
SCHEDULING_OUTCOME_SCHEDULED = "scheduled"
SCHEDULING_OUTCOME_WINDOW_UNSET = "window_unset"
SCHEDULING_OUTCOME_WINDOW_MISSING = "window_missing"
SCHEDULING_OUTCOME_WINDOW_DISABLED = "window_disabled"
SCHEDULING_OUTCOME_WINDOW_UNUSABLE = "window_unusable"


# Slice 2 audit-event actions. Emitted via ``safe_emit`` without
# ``db=`` per ``feedback_safe_emit_session_boundary``.
AUDIT_REBOOT_QUEUED = "patch_update_execution_reboot.queued"
AUDIT_REBOOT_SCHEDULED = "patch_update_execution_reboot.scheduled"
AUDIT_REBOOT_SKIPPED = "patch_update_execution_reboot.skipped"


# ---------------------------------------------------------------------------
# Local exception
# ---------------------------------------------------------------------------


class PatchUpdateRebootError(ValueError):
    """Raised when a reboot-queue read / reconcile is rejected for
    semantic reasons (unknown execution id, execution not in a
    terminal state, etc.). Route layer maps "not found" to 404 and
    everything else to 422 via the standard error-to-HTTP helper."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Serialize a datetime as an absolute-UTC ISO 8601 string.

    The patch-lifecycle DB convention is naive-UTC datetimes; this
    helper makes the wire shape unambiguous by appending ``Z`` for
    naive values and normalizing tz-aware values to ``...Z``. PRA-172
    review lock #2 requires persisted/detail/read payload timestamps
    to be absolute UTC so API consumers cannot mistake them for local
    time.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_execution(db: Session, execution_id: int) -> PatchUpdateExecution:
    execution = (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.id == execution_id)
        .first()
    )
    if execution is None:
        raise PatchUpdateRebootError(
            f"patch update execution id={execution_id} not found"
        )
    return execution


def _resolve_policy(
    policy_snapshot: Dict[str, Any],
) -> Tuple[str, Optional[str]]:
    """Return ``(snapshot_value_for_db, normalized_input_or_none)``.

    The DB column accepts ``never`` / ``if_required`` / ``always`` /
    ``unknown``. The normalized input is the same value when valid,
    or ``None`` when the policy snapshot is missing or malformed —
    so the caller can branch on validity without re-parsing.
    """
    raw = policy_snapshot.get("reboot_policy") if policy_snapshot else None
    if raw is None:
        return REBOOT_POLICY_UNKNOWN, None
    if not isinstance(raw, str):
        return REBOOT_POLICY_UNKNOWN, None
    if raw not in VALID_REBOOT_POLICY_INPUTS:
        return REBOOT_POLICY_UNKNOWN, None
    return raw, raw


def _resolve_reboot_window_id(
    execution: PatchUpdateExecution, plan: Optional[PatchUpdatePlan]
) -> Optional[int]:
    """Reboot-window context for the execution.

    Precedence:

    1. ``plan.reboot_window_id`` (the operator's plan-level override
       at plan-build time, also nullable).
    2. ``policy_snapshot.reboot_window_id`` (the policy snapshot the
       execution captured at start time).

    Either may be null; null is recorded as ``unset`` in the row's
    ``decision_details.reboot_window_status`` so downstream slices
    have a structured signal instead of silent absence.
    """
    if plan is not None and plan.reboot_window_id is not None:
        return int(plan.reboot_window_id)
    snapshot = execution.policy_snapshot or {}
    value = snapshot.get("reboot_window_id")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _fact_reboot_required(
    facts_by_system: Dict[int, Optional[bool]], system_id: Optional[int]
) -> Optional[bool]:
    if system_id is None:
        return None
    return facts_by_system.get(system_id)


def _decide(
    *,
    host_state: str,
    policy_value: Optional[str],
    reboot_required_fact: Optional[bool],
) -> Tuple[str, str, Dict[str, Any]]:
    """Return ``(queue_state, decision_code, decision_extras)``.

    ``decision_extras`` is merged into the row's ``decision_details``
    JSONB alongside the caller-supplied policy/window context — it
    carries only the decision-local context (e.g. the observed
    host facts).
    """
    if host_state != EXECUTION_HOST_STATE_SUCCEEDED:
        return (
            REBOOT_STATE_SKIPPED,
            REBOOT_DECISION_HOST_DID_NOT_SUCCEED,
            {"host_state": host_state},
        )

    if policy_value is None:
        # _resolve_policy returns None for both missing-from-snapshot
        # and malformed-value cases. The caller doesn't carry enough
        # info here to tell them apart, so we infer from policy_value
        # which is the original raw input — done in reconcile, not
        # here. Default to ``policy_missing``; reconcile overrides
        # to ``policy_invalid`` when the snapshot had a non-string
        # or out-of-vocab value.
        return (
            REBOOT_STATE_SKIPPED,
            REBOOT_DECISION_POLICY_MISSING,
            {},
        )

    if policy_value == REBOOT_POLICY_NEVER:
        return (
            REBOOT_STATE_SKIPPED,
            REBOOT_DECISION_POLICY_NEVER,
            {},
        )

    if policy_value == REBOOT_POLICY_ALWAYS:
        return (
            REBOOT_STATE_PENDING,
            REBOOT_DECISION_POLICY_ALWAYS,
            {"reboot_required_fact": reboot_required_fact},
        )

    # if_required
    if reboot_required_fact is True:
        return (
            REBOOT_STATE_PENDING,
            REBOOT_DECISION_HOST_FACT_REBOOT_REQUIRED,
            {"reboot_required_fact": True},
        )
    return (
        REBOOT_STATE_NOT_REQUIRED,
        REBOOT_DECISION_FACT_NOT_REQUIRED,
        {"reboot_required_fact": reboot_required_fact},
    )


def _facts_by_system(db: Session, system_ids: List[int]) -> Dict[int, Optional[bool]]:
    """Bulk-load ``host_facts.reboot_required`` for the given system
    ids. Returns ``{system_id: reboot_required_bool_or_none}``; ids
    without a HostFacts row are absent from the dict (the lookup
    falls back to ``None``, treated as "no signal")."""
    if not system_ids:
        return {}
    rows = (
        db.query(HostFacts.system_id, HostFacts.reboot_required)
        .filter(HostFacts.system_id.in_(system_ids))
        .all()
    )
    return {sid: bool(rb) if rb is not None else None for sid, rb in rows}


# ---------------------------------------------------------------------------
# Public API — reconcile
# ---------------------------------------------------------------------------


def _reconcile_hosts_into_reboot_rows(
    db: Session,
    execution: PatchUpdateExecution,
    plan: Optional[PatchUpdatePlan],
    hosts: List[PatchUpdateExecutionHost],
    *,
    now: datetime,
) -> List[PatchUpdateExecutionReboot]:
    """Shared per-host reconcile loop. Used by both the full
    ``reconcile_reboot_queue`` (Slice 1) and the per-wave
    ``reconcile_wave_reboots`` (Slice 5).

    Refreshes the Slice-1 decision columns on existing rows
    (matched by ``execution_host_id``) and creates new rows for
    hosts that don't have one yet. Never overwrites
    scheduling/runtime fields owned by later slices
    (``scheduled_for_at`` / ``started_at`` / ``completed_at`` /
    dispatch+verify columns).
    """
    policy_snapshot = dict(execution.policy_snapshot or {})
    policy_snapshot_value, policy_normalized = _resolve_policy(policy_snapshot)
    policy_raw = policy_snapshot.get("reboot_policy") if policy_snapshot else None
    reboot_window_id_snapshot = _resolve_reboot_window_id(execution, plan)

    host_ids = [h.id for h in hosts]
    succeeded_system_ids = [
        h.system_id_snapshot
        for h in hosts
        if h.state == EXECUTION_HOST_STATE_SUCCEEDED
        and h.system_id_snapshot is not None
    ]
    facts_by_system = _facts_by_system(db, succeeded_system_ids)

    existing_rows: Dict[int, PatchUpdateExecutionReboot] = {}
    if host_ids:
        existing_rows = {
            row.execution_host_id: row
            for row in db.query(PatchUpdateExecutionReboot)
            .filter(
                PatchUpdateExecutionReboot.execution_id == execution.id,
                PatchUpdateExecutionReboot.execution_host_id.in_(host_ids),
            )
            .all()
        }

    results: List[PatchUpdateExecutionReboot] = []

    for host in hosts:
        reboot_required_fact = _fact_reboot_required(
            facts_by_system, host.system_id_snapshot
        )

        state, decision_code, decision_extras = _decide(
            host_state=host.state,
            policy_value=policy_normalized,
            reboot_required_fact=reboot_required_fact,
        )

        # Distinguish missing vs invalid policy at the decision-code
        # level. _decide returns ``policy_missing`` whenever
        # ``policy_normalized`` is None; reconcile owns the raw
        # input so it can refine to ``policy_invalid`` when the raw
        # value was present but malformed.
        if decision_code == REBOOT_DECISION_POLICY_MISSING and policy_raw is not None:
            decision_code = REBOOT_DECISION_POLICY_INVALID

        decision_details: Dict[str, Any] = {
            "reboot_policy_raw": policy_raw,
            "reboot_window_status": (
                "set" if reboot_window_id_snapshot is not None else "unset"
            ),
            "evaluated_at": utc_iso(now),
        }
        decision_details.update(decision_extras)

        existing = existing_rows.get(host.id)
        if existing is None:
            row = PatchUpdateExecutionReboot(
                execution_id=execution.id,
                execution_host_id=host.id,
                plan_id_snapshot=execution.plan_id,
                system_id_snapshot=host.system_id_snapshot,
                system_hostname_snapshot=host.system_hostname_snapshot,
                wave_index=host.wave_index,
                state=state,
                reboot_policy_snapshot=policy_snapshot_value,
                reboot_window_id_snapshot=reboot_window_id_snapshot,
                reboot_required_fact=reboot_required_fact,
                decision_code=decision_code,
                decision_details=decision_details,
            )
            db.add(row)
            results.append(row)
        else:
            existing.plan_id_snapshot = execution.plan_id
            existing.system_id_snapshot = host.system_id_snapshot
            existing.system_hostname_snapshot = host.system_hostname_snapshot
            existing.wave_index = host.wave_index
            existing.state = state
            existing.reboot_policy_snapshot = policy_snapshot_value
            existing.reboot_window_id_snapshot = reboot_window_id_snapshot
            existing.reboot_required_fact = reboot_required_fact
            existing.decision_code = decision_code
            existing.decision_details = decision_details
            results.append(existing)

    db.flush()
    return results


def reconcile_reboot_queue(
    db: Session,
    execution_id: int,
    *,
    now: Optional[datetime] = None,
) -> List[PatchUpdateExecutionReboot]:
    """Initialize or refresh the reboot queue for a terminal execution.

    Idempotent: re-running after a prior call only refreshes the
    Slice-1 decision columns and never overwrites the
    scheduling/runtime fields (``scheduled_for_at`` / ``started_at``
    / ``completed_at``) that later slices own. Existing rows are
    looked up by ``(execution_id, execution_host_id)``.

    The execution must be in a terminal state (``succeeded`` /
    ``failed`` / ``canceled``). Non-terminal executions raise so a
    later slice doesn't accidentally queue reboots against a still-
    running plan.
    """
    execution = _require_execution(db, execution_id)
    if execution.state not in TERMINAL_EXECUTION_STATES:
        raise PatchUpdateRebootError(
            f"execution {execution_id} is in state {execution.state!r}; only "
            f"{sorted(TERMINAL_EXECUTION_STATES)} executions can have their "
            f"reboot queue reconciled"
        )

    plan = (
        db.query(PatchUpdatePlan)
        .filter(PatchUpdatePlan.id == execution.plan_id)
        .first()
    )

    hosts: List[PatchUpdateExecutionHost] = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution_id)
        .order_by(
            PatchUpdateExecutionHost.wave_index.asc(),
            PatchUpdateExecutionHost.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionHost.id.asc(),
        )
        .all()
    )

    current_now = now or datetime.utcnow()
    results = _reconcile_hosts_into_reboot_rows(
        db, execution, plan, hosts, now=current_now
    )
    db.commit()
    return results


def reconcile_wave_reboots(
    db: Session,
    execution_id: int,
    wave_index: int,
    *,
    now: Optional[datetime] = None,
) -> List[PatchUpdateExecutionReboot]:
    """PRA-172 Slice 5: per-wave reboot queue reconcile.

    Creates or refreshes the reboot queue rows for one specific
    wave's hosts on a still-running execution. Used by the
    dependent-wave gate: each wave's reboot rows must exist
    before the dispatcher can decide whether the next wave is
    safe to start.

    The wave must be fully complete (every host in
    ``terminal`` state). Non-complete waves raise so the gate
    can't false-positive. The parent execution is NOT required
    to be terminal — that's the whole point of this entry
    point vs. ``reconcile_reboot_queue``.

    Idempotent: like the full reconcile, re-running only
    refreshes Slice-1 decision columns on existing rows.
    """
    execution = _require_execution(db, execution_id)

    # Lazy-import the dispatcher helper to avoid a circular
    # reference at module-import time.
    from .patch_execution_dispatch_service import _wave_is_complete

    if not _wave_is_complete(db, execution_id, wave_index):
        raise PatchUpdateRebootError(
            f"execution {execution_id} wave={wave_index} is not complete; "
            f"per-wave reboot reconcile requires every host in the wave to "
            f"be in a terminal state"
        )

    plan = (
        db.query(PatchUpdatePlan)
        .filter(PatchUpdatePlan.id == execution.plan_id)
        .first()
    )

    hosts: List[PatchUpdateExecutionHost] = (
        db.query(PatchUpdateExecutionHost)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.wave_index == wave_index,
        )
        .order_by(
            PatchUpdateExecutionHost.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionHost.id.asc(),
        )
        .all()
    )

    current_now = now or datetime.utcnow()
    results = _reconcile_hosts_into_reboot_rows(
        db, execution, plan, hosts, now=current_now
    )
    db.commit()
    return results


# ---------------------------------------------------------------------------
# Slice 5: dependent-wave reboot gate
# ---------------------------------------------------------------------------

# Reboot-row states that are considered "safe" for the purposes of
# letting a dependent wave continue. Any other state on a prior-wave
# row blocks the next wave from starting.
WAVE_GATE_SAFE_STATES = frozenset(
    {
        REBOOT_STATE_NOT_REQUIRED,
        REBOOT_STATE_HEALTHY,
        REBOOT_STATE_SKIPPED,
    }
)

# Structured blocker codes the dispatcher records on the execution
# when the gate refuses to advance to a new wave.
WAVE_GATE_REASON_REBOOTS_IN_PROGRESS = "prior_wave_reboots_in_progress"
WAVE_GATE_REASON_REBOOT_FAILURES = "prior_wave_reboot_failures"
# PRA-172 Slice 5a: fail-closed reason when prior wave
# has execution hosts that should have produced reboot queue rows
# but the rows are missing — likely the per-wave reconcile hook
# rolled back due to a transient error. Treat as a blocker so a
# silent per-wave reconcile failure cannot let a dependent wave
# proceed without proving the prior wave's reboot health.
WAVE_GATE_REASON_REBOOT_ROWS_MISSING = "prior_wave_reboot_rows_missing"


def is_wave_blocked_by_reboot_gate(
    db: Session, execution_id: int, wave_index: int
) -> Optional[Dict[str, Any]]:
    """PRA-172 Slice 5: gate check before dispatching wave_index.

    Returns ``None`` when the wave is safe to start, or a
    structured blocker dict when any prior wave is NOT proven
    safe. Three blocker codes:

    * ``prior_wave_reboots_in_progress`` — at least one prior-
      wave row is in ``pending`` / ``scheduled`` / ``rebooting``
      / ``verifying``.
    * ``prior_wave_reboot_failures`` — at least one prior-wave
      row is ``failed``.
    * ``prior_wave_reboot_rows_missing`` — a prior wave has
      execution-host rows but is missing one or more reboot
      queue rows (per-wave reconcile likely rolled back or
      never ran). Fail-closed so a silent reconcile failure
      cannot let a dependent wave dispatch package work.

    Safe states: ``not_required`` / ``healthy`` / ``skipped``.

    The blocker dict is the structured pause context the
    dispatcher records on the batch summary so the operator UI
    can render the wait + the reason.
    """
    if wave_index <= 0:
        # Wave 0 has no prior wave; nothing to gate.
        return None

    # PRA-172 Slice 5a fail-closed coverage check: compare the
    # count of execution-host rows in each prior wave against the
    # count of reboot queue rows in that same wave. If any prior
    # wave has fewer reboot rows than execution-host rows, the
    # gate must NOT pass — per-wave reconcile likely failed (or
    # never ran), so we don't have a complete picture of the
    # prior wave's reboot health.
    host_counts_by_wave: Dict[int, int] = {}
    for wave, host_count in (
        db.query(
            PatchUpdateExecutionHost.wave_index,
            func_count(PatchUpdateExecutionHost.id),
        )
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.wave_index < wave_index,
        )
        .group_by(PatchUpdateExecutionHost.wave_index)
        .all()
    ):
        host_counts_by_wave[wave] = host_count

    row_counts_by_wave: Dict[int, int] = {}
    for wave, row_count in (
        db.query(
            PatchUpdateExecutionReboot.wave_index,
            func_count(PatchUpdateExecutionReboot.id),
        )
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution_id,
            PatchUpdateExecutionReboot.wave_index < wave_index,
        )
        .group_by(PatchUpdateExecutionReboot.wave_index)
        .all()
    ):
        row_counts_by_wave[wave] = row_count

    missing_by_wave: Dict[int, Dict[str, int]] = {}
    for wave, host_count in host_counts_by_wave.items():
        rebooted = row_counts_by_wave.get(wave, 0)
        if rebooted < host_count:
            missing_by_wave[wave] = {
                "host_count": host_count,
                "reboot_row_count": rebooted,
                "missing_row_count": host_count - rebooted,
            }

    if missing_by_wave:
        return {
            "reason": WAVE_GATE_REASON_REBOOT_ROWS_MISSING,
            "blocked_wave_index": wave_index,
            "missing_by_wave": missing_by_wave,
            "evaluated_at": utc_iso(datetime.utcnow()),
        }

    # Coverage is complete (or every prior wave is genuinely
    # empty). Aggregate the reboot-row states across prior waves
    # to decide whether to block on in-progress / failed rows.
    rows: List[Tuple[str, int]] = (
        db.query(
            PatchUpdateExecutionReboot.state,
            PatchUpdateExecutionReboot.id,
        )
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution_id,
            PatchUpdateExecutionReboot.wave_index < wave_index,
        )
        .all()
    )
    if not rows:
        # No prior-wave rows AND no prior-wave hosts (otherwise
        # missing_by_wave above would have caught it). Nothing
        # to gate on.
        return None

    state_counts: Dict[str, int] = {}
    failed_ids: List[int] = []
    in_progress_ids: List[int] = []
    for state, row_id in rows:
        state_counts[state] = state_counts.get(state, 0) + 1
        if state == REBOOT_STATE_FAILED:
            failed_ids.append(row_id)
        elif state in (
            REBOOT_STATE_PENDING,
            REBOOT_STATE_SCHEDULED,
            REBOOT_STATE_REBOOTING,
            REBOOT_STATE_VERIFYING,
        ):
            in_progress_ids.append(row_id)

    if not failed_ids and not in_progress_ids:
        # All prior-wave rows are safe.
        return None

    if failed_ids:
        reason = WAVE_GATE_REASON_REBOOT_FAILURES
    else:
        reason = WAVE_GATE_REASON_REBOOTS_IN_PROGRESS
    return {
        "reason": reason,
        "blocked_wave_index": wave_index,
        "prior_wave_state_counts": state_counts,
        "in_progress_row_count": len(in_progress_ids),
        "failed_row_count": len(failed_ids),
        "evaluated_at": utc_iso(datetime.utcnow()),
    }


# ---------------------------------------------------------------------------
# Public API — read
# ---------------------------------------------------------------------------


def list_reboot_rows_for_execution(
    db: Session, execution_id: int
) -> List[PatchUpdateExecutionReboot]:
    """Return the reboot queue rows for an execution, ordered by
    ``(wave_index, system_id_snapshot NULLS FIRST, id)``. Raises
    :class:`PatchUpdateRebootError` when the execution id does not
    exist (route layer maps to 404 via "not found" wording)."""
    if (
        db.query(PatchUpdateExecution.id)
        .filter(PatchUpdateExecution.id == execution_id)
        .first()
        is None
    ):
        raise PatchUpdateRebootError(
            f"patch update execution id={execution_id} not found"
        )
    return (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution_id)
        .order_by(
            PatchUpdateExecutionReboot.wave_index.asc(),
            PatchUpdateExecutionReboot.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionReboot.id.asc(),
        )
        .all()
    )


def build_reboot_summary(
    rows: List[PatchUpdateExecutionReboot],
) -> Dict[str, Any]:
    """Return the canonical summary payload for a reboot-queue read.

    Stable ordering so polling responses don't diff-churn; every
    Slice-1 state is included in ``state_counts`` even when zero so
    the operator UI doesn't have to defensively check for missing
    keys. The eight states reserved for later slices appear with
    zero counts too — the contract is "all eight DB-valid states
    are present in the rollup".
    """
    state_counts: Dict[str, int] = {s: 0 for s in sorted(VALID_REBOOT_STATES)}
    decision_counts: Dict[str, int] = {}
    for row in rows:
        state_counts[row.state] = state_counts.get(row.state, 0) + 1
        decision_counts[row.decision_code] = (
            decision_counts.get(row.decision_code, 0) + 1
        )
    return {
        "row_count": len(rows),
        "state_counts": state_counts,
        "decision_counts": dict(sorted(decision_counts.items())),
    }


def get_reboot_queue(
    db: Session, execution_id: int
) -> Tuple[PatchUpdateExecution, List[PatchUpdateExecutionReboot], Dict[str, Any]]:
    """Return ``(execution, rows, summary)`` for the read endpoint.

    Raises :class:`PatchUpdateRebootError` when the execution id
    does not exist.
    """
    execution = _require_execution(db, execution_id)
    rows = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution_id)
        .order_by(
            PatchUpdateExecutionReboot.wave_index.asc(),
            PatchUpdateExecutionReboot.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionReboot.id.asc(),
        )
        .all()
    )
    summary = build_reboot_summary(rows)
    return execution, rows, summary


def get_plan_reboot_queue(
    db: Session, plan_id: int
) -> Tuple[
    PatchUpdatePlan,
    List[PatchUpdateExecution],
    List[PatchUpdateExecutionReboot],
    Dict[str, Any],
]:
    """Return ``(plan, executions, rows, aggregate_summary)`` for the
    plan-scoped reboot read endpoint.

    Walks every :class:`PatchUpdateExecution` that has been started
    for ``plan_id`` and collects the union of queue rows. The
    aggregate summary rolls across every execution so the plan-detail
    UI can render one "reboots pending across the plan" number; the
    per-execution breakdown stays available via the returned
    ``executions`` list. Rows are ordered by
    ``(execution_id, wave_index, system_id_snapshot, id)`` for
    deterministic polling responses.

    Raises :class:`PatchUpdateRebootError` when the plan id does
    not exist; the route layer maps "not found" to 404. Empty plans
    (no executions, or executions with no reconciled queue rows)
    return zero-count summaries rather than refusing — the plan
    surface is read-only and must not require a reconcile to render.
    """
    plan = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()
    if plan is None:
        raise PatchUpdateRebootError(f"patch update plan id={plan_id} not found")

    executions: List[PatchUpdateExecution] = (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.plan_id == plan_id)
        .order_by(PatchUpdateExecution.id.asc())
        .all()
    )
    if not executions:
        return plan, [], [], build_reboot_summary([])

    execution_ids = [e.id for e in executions]
    rows: List[PatchUpdateExecutionReboot] = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id.in_(execution_ids))
        .order_by(
            PatchUpdateExecutionReboot.execution_id.asc(),
            PatchUpdateExecutionReboot.wave_index.asc(),
            PatchUpdateExecutionReboot.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionReboot.id.asc(),
        )
        .all()
    )
    aggregate_summary = build_reboot_summary(rows)
    return plan, executions, rows, aggregate_summary


# ---------------------------------------------------------------------------
# Slice 2 — window resolution + scheduling promotion + auto-reconcile.
#
# Slice 2 only moves the substrate one step further: eligible
# ``pending`` rows pick up a ``scheduled_for_at`` from the policy /
# plan reboot window and transition to ``scheduled``. No real reboot
# command is dispatched here; ``scheduled`` is metadata-only, not a
# transport authorization.
# ---------------------------------------------------------------------------


def _parse_window_schedule(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    """Parse a ``MaintenanceWindow.schedule`` JSON blob.

    Mirrors the parsing in ``maintenance_window_service._parse_schedule``;
    factored locally so PRA-172's narrow scheduling use case doesn't
    drag the full MW service surface into this module. A later slice
    can refactor both onto a shared evaluator (TODO: see also
    ``maintenance_window_service.get_next_window`` for the per-system
    variant)."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def next_window_start(
    window: MaintenanceWindow, *, now: datetime, days_ahead: int = 14
) -> Optional[datetime]:
    """Return the next naive-UTC datetime ``window`` opens after ``now``.

    Returns ``None`` when the window is disabled, has no parseable
    schedule, or has no opening within ``days_ahead`` days. The
    schedule shape mirrors the existing ``MaintenanceWindow``
    convention (``day_of_week: List[int]`` 0=Mon..6=Sun,
    ``start_time: "HH:MM"``).
    """
    if not window.enabled:
        return None
    schedule = _parse_window_schedule(window.schedule)
    if not schedule:
        return None
    day_of_week = schedule.get("day_of_week") or []
    if not day_of_week:
        return None
    start_time_str = schedule.get("start_time", "00:00")
    try:
        start_h, start_m = map(int, start_time_str.split(":"))
    except (ValueError, AttributeError):
        return None
    # Range-validate before handing to ``datetime.replace`` — operator-
    # edited schedules can carry out-of-range values like ``25:00`` or
    # ``00:75`` that would otherwise raise ``ValueError`` from
    # ``replace(hour=..., minute=...)``. The caller treats ``None``
    # here as ``window_unusable`` and surfaces the structured pending
    # outcome, so we must not let an out-of-range value crash the
    # reboot reconcile pass.
    if not (0 <= start_h <= 23 and 0 <= start_m <= 59):
        return None

    for offset in range(days_ahead + 1):
        candidate = now + timedelta(days=offset)
        if candidate.weekday() not in day_of_week:
            continue
        candidate_start = candidate.replace(
            hour=start_h, minute=start_m, second=0, microsecond=0
        )
        if candidate_start <= now:
            continue
        return candidate_start
    return None


def _resolve_window_for_row(
    db: Session, row: PatchUpdateExecutionReboot, *, now: datetime
) -> Tuple[Optional[datetime], str, Dict[str, Any]]:
    """Return ``(scheduled_for_at, outcome_code, context)`` for a row.

    Outcome codes:

    * ``window_unset`` — row's ``reboot_window_id_snapshot`` is null
      (the policy/plan never declared a reboot window). Row stays
      ``pending``; context is the unset signal.
    * ``window_missing`` — row points at a window id that no longer
      exists (later cleanup or DELETE). Row stays ``pending``;
      context names the missing id.
    * ``window_disabled`` — window exists but is disabled. Row stays
      ``pending``; context names the window id + reason.
    * ``window_unusable`` — schedule JSON unparseable / empty
      ``day_of_week`` / no opening in the search horizon. Row stays
      ``pending``; context preserves the schedule preview for the
      operator UI.
    * ``scheduled`` — found a valid next opening; row moves to
      ``scheduled`` with ``scheduled_for_at`` set.
    """
    window_id = row.reboot_window_id_snapshot
    if window_id is None:
        return None, SCHEDULING_OUTCOME_WINDOW_UNSET, {}

    window = (
        db.query(MaintenanceWindow).filter(MaintenanceWindow.id == window_id).first()
    )
    if window is None:
        return (
            None,
            SCHEDULING_OUTCOME_WINDOW_MISSING,
            {"window_id": window_id},
        )
    if not window.enabled:
        return (
            None,
            SCHEDULING_OUTCOME_WINDOW_DISABLED,
            {"window_id": window_id, "window_name": window.name},
        )

    next_start = next_window_start(window, now=now)
    if next_start is None:
        return (
            None,
            SCHEDULING_OUTCOME_WINDOW_UNUSABLE,
            {
                "window_id": window_id,
                "window_name": window.name,
            },
        )
    return (
        next_start,
        SCHEDULING_OUTCOME_SCHEDULED,
        {
            "window_id": window_id,
            "window_name": window.name,
        },
    )


def _emit_reboot_audit(
    *,
    action: str,
    row: PatchUpdateExecutionReboot,
    actor_user_id: Optional[int],
    actor_username: Optional[str],
    actor_ip: Optional[str],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit a reboot lifecycle audit via ``safe_emit`` no ``db=``.

    Session-boundary lock (``feedback_safe_emit_session_boundary``):
    the caller has already committed its own DB work, so safe_emit
    opens its own ``SessionLocal()`` and is independent of the
    reboot reconcile commit. We never pass ``db=`` here.
    """
    context: Dict[str, Any] = {
        "execution_id": row.execution_id,
        "execution_host_id": row.execution_host_id,
        "plan_id": row.plan_id_snapshot,
        "system_id": row.system_id_snapshot,
        "wave_index": row.wave_index,
        "state": row.state,
        "decision_code": row.decision_code,
        "reboot_policy_snapshot": row.reboot_policy_snapshot,
        "reboot_window_id_snapshot": row.reboot_window_id_snapshot,
        "scheduled_for_at": utc_iso(row.scheduled_for_at),
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


def promote_pending_to_scheduled(
    db: Session,
    execution_id: int,
    *,
    now: Optional[datetime] = None,
) -> List[PatchUpdateExecutionReboot]:
    """Promote eligible ``pending`` queue rows to ``scheduled``.

    For every row in ``pending`` state with a usable reboot window,
    set ``scheduled_for_at`` to the next opening (naive-UTC) and
    transition to ``scheduled``. Rows with no usable window stay
    ``pending`` and gain structured ``decision_details.scheduling``
    context so later slices / UI can render the "why no schedule"
    reason without re-querying.

    Returns the rows the call touched (both promoted-to-scheduled
    and pending-with-updated-scheduling-context); the caller decides
    which transitions to audit (this function does not emit audits
    directly, so callers can batch emission after their own commit
    via the session-boundary convention).
    """
    current_now = now or datetime.utcnow()
    rows: List[PatchUpdateExecutionReboot] = (
        db.query(PatchUpdateExecutionReboot)
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution_id,
            PatchUpdateExecutionReboot.state == REBOOT_STATE_PENDING,
        )
        .all()
    )
    touched: List[PatchUpdateExecutionReboot] = []
    for row in rows:
        scheduled_for_at, outcome, ctx = _resolve_window_for_row(
            db, row, now=current_now
        )
        scheduling_block: Dict[str, Any] = {
            "outcome": outcome,
            "evaluated_at": utc_iso(current_now),
        }
        scheduling_block.update(ctx)

        new_details = dict(row.decision_details or {})
        new_details["scheduling"] = scheduling_block
        row.decision_details = new_details

        if outcome == SCHEDULING_OUTCOME_SCHEDULED:
            row.state = REBOOT_STATE_SCHEDULED
            row.scheduled_for_at = scheduled_for_at
        touched.append(row)
    db.flush()
    return touched


def auto_reconcile_on_terminal(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: Optional[int],
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    """Reconcile + promote a terminal execution's reboot queue.

    Shares the caller's session. Per
    ``feedback_safe_emit_session_boundary``, the caller is expected
    to have committed its terminal-state change before invoking
    this so the queue work that follows operates on stable state.

    Best-effort: any internal exception is logged but does NOT
    propagate, so a reboot-queue failure cannot retroactively
    invalidate the just-committed terminal transition. On error
    the session is rolled back to discard any partial queue work
    (the caller's already-committed terminal state survives).

    After running, emits Slice 2 reboot-lifecycle audits for the
    rows that changed:

    * ``patch_update_execution_reboot.queued`` — newly-created
      ``pending`` rows.
    * ``patch_update_execution_reboot.scheduled`` — rows that just
      promoted from ``pending`` to ``scheduled``.
    * ``patch_update_execution_reboot.skipped`` — newly-created
      ``skipped`` rows.

    ``not_required`` rows are NOT audited individually (they are
    high-volume and represent absence of action); the operator UI
    still sees them via the queue read API.
    """
    try:
        execution = (
            db.query(PatchUpdateExecution)
            .filter(PatchUpdateExecution.id == execution_id)
            .first()
        )
        if execution is None:
            logger.warning(
                "auto_reconcile_on_terminal: execution id=%d not found",
                execution_id,
            )
            return
        if execution.state not in TERMINAL_EXECUTION_STATES:
            logger.warning(
                "auto_reconcile_on_terminal: execution id=%d state=%s is not terminal",
                execution_id,
                execution.state,
            )
            return

        # Snapshot existing row ids so we can tell newly-created rows
        # (queued / skipped audits) apart from pre-existing rows the
        # reconcile pass merely refreshed.
        existing_ids = {
            r.id
            for r in db.query(PatchUpdateExecutionReboot.id)
            .filter(PatchUpdateExecutionReboot.execution_id == execution_id)
            .all()
        }

        rows = reconcile_reboot_queue(db, execution_id)
        promoted = promote_pending_to_scheduled(db, execution_id)
        db.commit()

        promoted_ids = {r.id for r in promoted}
        for row in rows:
            if row.id in existing_ids and row.id not in promoted_ids:
                continue
            db.refresh(row)
            newly_created = row.id not in existing_ids

            # A newly-created row that the promote pass also touched
            # was pending at promote time (promote filters strictly by
            # state == pending). Emit ``queued`` first, then
            # ``scheduled`` so the audit trail mirrors the actual
            # lifecycle transitions even when they collapse into a
            # single auto-reconcile pass.
            if newly_created and (
                row.id in promoted_ids or row.state == REBOOT_STATE_PENDING
            ):
                _emit_reboot_audit(
                    action=AUDIT_REBOOT_QUEUED,
                    row=row,
                    actor_user_id=actor_user_id,
                    actor_username=actor_username,
                    actor_ip=actor_ip,
                )
                # PRA-178 Slice 3: emit patch.reboot_required beside the
                # ``queued`` audit so operators get one notification per
                # newly-queued host. Fires only for new rows so repeated
                # reconciles do not re-notify.
                from . import notification_events

                notification_events.emit_patch_reboot_required(
                    db,
                    execution_id=row.execution_id,
                    system_id=row.system_id_snapshot,
                    system_hostname=row.system_hostname_snapshot,
                )
            elif newly_created and row.state == REBOOT_STATE_SKIPPED:
                _emit_reboot_audit(
                    action=AUDIT_REBOOT_SKIPPED,
                    row=row,
                    actor_user_id=actor_user_id,
                    actor_username=actor_username,
                    actor_ip=actor_ip,
                )
            if row.id in promoted_ids and row.state == REBOOT_STATE_SCHEDULED:
                _emit_reboot_audit(
                    action=AUDIT_REBOOT_SCHEDULED,
                    row=row,
                    actor_user_id=actor_user_id,
                    actor_username=actor_username,
                    actor_ip=actor_ip,
                )
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "auto_reconcile_on_terminal failed for execution=%d: %s",
            execution_id,
            exc,
        )
        try:
            db.rollback()
        except Exception:  # pylint: disable=broad-except
            pass
