"""Pydantic schemas for patch update execution reboot queue (PRA-172 slice 1).

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md``).

Slice 1 ships the reboot-queue read surface only: a per-execution
queue listing plus the per-host decision details. No scheduling,
no real reboot dispatch, no verification fields.

**Timestamp wire shape:** All datetime-bearing fields are typed as
``str`` because the route serialization helper formats them through
``patch_reboot_service.utc_iso`` so wire payloads carry an explicit
``Z`` UTC suffix. PRA-172 review lock #2 requires read payload
timestamps to be absolute UTC so API consumers cannot mistake them
for local time. The DB layer keeps the patch-lifecycle naive-UTC
convention; the conversion happens at the serialization boundary
only.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class PatchUpdateExecutionRebootRowRead(BaseModel):
    """One reboot-queue row for an execution host.

    ``state`` is one of ``not_required`` / ``pending`` /
    ``scheduled`` / ``rebooting`` / ``verifying`` / ``healthy`` /
    ``failed`` / ``skipped``. Slice 1 only writes
    ``not_required`` / ``pending`` / ``skipped``; the other five
    are reserved for later PRA-172 slices.

    ``decision_code`` is a short machine-readable reason
    (``host_fact_reboot_required`` / ``policy_always`` /
    ``fact_not_required`` / ``reboot_evidence_unknown`` /
    ``policy_never`` / ``host_did_not_succeed`` / ``policy_invalid``
    / ``policy_missing``). ``decision_details`` is JSONB context that
    backs the operator UI's "why" display, including
    ``reboot_window_status`` (``set`` or ``unset``) so missing
    window context is explicit instead of silent, and
    ``reboot_evidence`` carrying the observation the decision was
    made from (value, source indicator, collection time, probe
    outcome).

    ``reboot_required_fact`` is the observed value and is null
    whenever the observation did not conclude. A null here with
    ``decision_code`` of ``reboot_evidence_unknown`` means the host's
    reboot state could not be established, never that no reboot is
    needed.
    """

    id: int
    execution_id: int
    execution_host_id: int
    plan_id_snapshot: int
    system_id_snapshot: Optional[int]
    system_hostname_snapshot: Optional[str]
    wave_index: int
    state: str
    reboot_policy_snapshot: str
    reboot_window_id_snapshot: Optional[int]
    reboot_required_fact: Optional[bool]
    decision_code: str
    decision_details: Dict[str, Any] = {}
    scheduled_for_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    # Slice 3 dispatch-result columns. Null until the row's
    # ``scheduled`` → ``rebooting`` / ``failed`` transition runs.
    transport_kind: Optional[str] = None
    command_snapshot: Optional[str] = None
    exit_signal_kind: Optional[str] = None
    dispatch_details: Dict[str, Any] = {}
    # Slice 4 verification-result columns. Null until the row's
    # ``rebooting`` → ``healthy`` / ``failed`` transition runs.
    verified_at: Optional[str] = None
    verification_details: Dict[str, Any] = {}
    created_at: str
    updated_at: str


class PatchUpdateExecutionRebootSummary(BaseModel):
    """Per-execution rollup over the reboot-queue rows.

    ``state_counts`` includes every DB-valid reboot state with zero
    counts when not present, so the operator UI doesn't need to
    defensively check for missing keys. ``decision_counts`` is keyed
    by the row decision codes that actually appear (sorted for
    deterministic polling responses).

    ``reconciliation`` reports whether the queue actually describes
    the whole run: ``status`` is ``ok``, ``incomplete`` (hosts that
    finished their package work have no queue row), or ``failed`` (a
    reconcile pass recorded a failure), and ``action_required`` is
    true for anything but ``ok``. The counts above cannot be read as
    "nothing outstanding" while ``action_required`` is set. It is
    null only where the scope has no execution to evaluate."""

    row_count: int
    state_counts: Dict[str, int]
    decision_counts: Dict[str, int]
    reconciliation: Optional[Dict[str, Any]] = None


class PatchUpdateExecutionRebootQueue(BaseModel):
    """Full reboot-queue read envelope for one execution.

    Returned by ``GET /patch/update-executions/{id}/reboots``. The
    ``execution_id`` / ``execution_state`` fields make it cheap for
    the operator UI to render the "execution must be terminal
    before reboots queue" message without a follow-up round-trip.
    """

    execution_id: int
    execution_state: str
    plan_id: int
    summary: PatchUpdateExecutionRebootSummary
    rows: List[PatchUpdateExecutionRebootRowRead] = []


class PatchUpdateExecutionRebootReconcileResponse(BaseModel):
    """Response body for ``POST /patch/update-executions/{id}/reboots/reconcile``."""

    execution_id: int
    execution_state: str
    plan_id: int
    summary: PatchUpdateExecutionRebootSummary
    rows: List[PatchUpdateExecutionRebootRowRead] = []


class PatchUpdatePlanRebootExecutionRef(BaseModel):
    """Per-execution rollup carried inside the plan-scoped read envelope.

    The plan-scoped read endpoint walks every execution that has been
    started for the plan and returns the reboot-queue rollup for each
    one. Execution timestamps are serialized as absolute UTC ISO
    strings via ``patch_reboot_service.utc_iso`` so wire shape matches
    the row-level fields.
    """

    execution_id: int
    execution_state: str
    started_at: str
    completed_at: Optional[str] = None
    summary: PatchUpdateExecutionRebootSummary


class PatchUpdatePlanRebootQueue(BaseModel):
    """Plan-scoped reboot queue read envelope.

    Returned by ``GET /patch/update-plans/{plan_id}/reboots``. The
    aggregate ``summary`` rolls across every execution row in
    ``executions`` so a plan-detail UI can render one "reboots
    pending across the plan" number; the ``executions`` array keeps
    the per-execution breakdown so the UI can drill into a specific
    run without a follow-up round-trip. ``rows`` is the union of
    queue rows across every execution, ordered by
    ``(execution_id, wave_index, system_id_snapshot, id)``.
    """

    plan_id: int
    plan_state: str
    summary: PatchUpdateExecutionRebootSummary
    executions: List[PatchUpdatePlanRebootExecutionRef] = []
    rows: List[PatchUpdateExecutionRebootRowRead] = []


# ---------------------------------------------------------------------------
# Slice 3: dispatch-due response shape.
# ---------------------------------------------------------------------------


class PatchUpdateExecutionRebootDispatchHostOutcome(BaseModel):
    """One per-row outcome inside a reboot dispatch-due batch."""

    execution_reboot_id: int
    execution_host_id: int
    system_id: Optional[int] = None
    state: str
    exit_signal_kind: str
    transport_kind: str
    exit_code: Optional[int] = None
    error_code: Optional[str] = None


class PatchUpdateExecutionRebootDispatchResult(BaseModel):
    """Response body for
    ``POST /patch/update-executions/{id}/reboots/dispatch-due``.

    Slice 3 contract: trigger-based, one bounded batch per call.
    ``no_due`` is true when nothing was scheduled and due (the
    operator has nothing left to dispatch on this execution).
    ``not_due_count`` reports how many ``scheduled`` rows are
    waiting on a future ``scheduled_for_at`` so the operator UI
    can render "N reboots queued for later" without a follow-up
    round-trip.

    Reboot-wave threshold pause:

    * ``pause_reason`` — structured code when the dispatcher
      stopped mid-batch (currently always
      ``reboot_failure_threshold_exceeded``).
    * ``threshold_pause`` — breach context dict the operator UI
      renders next to the paused affordance.
    """

    execution_id: int
    dispatched_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    not_due_count: int = 0
    no_due: bool = False
    pause_reason: Optional[str] = None
    threshold_pause: Optional[Dict[str, Any]] = None
    host_outcomes: List[PatchUpdateExecutionRebootDispatchHostOutcome] = []
    # The full queue post-dispatch so the UI doesn't need a separate
    # ``GET /reboots`` round-trip.
    queue: PatchUpdateExecutionRebootQueue


# ---------------------------------------------------------------------------
# Slice 4: verify-due response shape.
# ---------------------------------------------------------------------------


class PatchUpdateExecutionRebootVerifyHostOutcome(BaseModel):
    """One per-row outcome inside a reboot verify-due batch."""

    execution_reboot_id: int
    execution_host_id: int
    system_id: Optional[int] = None
    state: str
    reason: Optional[str] = None


class PatchUpdateExecutionRebootVerifyResult(BaseModel):
    """Response body for
    ``POST /patch/update-executions/{id}/reboots/verify-due``.

    Slice 4 contract: trigger-based, one bounded batch per call.
    ``no_due`` is true when nothing in ``rebooting`` is past the
    grace period (the operator has nothing left to verify on
    this execution). ``not_due_count`` reports how many
    ``rebooting`` rows are still inside the grace window.

    Reboot-wave verification-failure threshold pause:

    * ``pause_reason`` — structured code when the verifier
      stopped mid-batch (currently always
      ``reboot_verify_failure_threshold_exceeded``).
    * ``threshold_pause`` — breach context dict the operator UI
      renders next to the paused affordance.
    """

    execution_id: int
    verified_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    not_due_count: int = 0
    no_due: bool = False
    pause_reason: Optional[str] = None
    threshold_pause: Optional[Dict[str, Any]] = None
    host_outcomes: List[PatchUpdateExecutionRebootVerifyHostOutcome] = []
    # Full queue post-verify so the UI doesn't need a separate
    # ``GET /reboots`` round-trip.
    queue: PatchUpdateExecutionRebootQueue
