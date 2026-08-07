"""Pydantic schemas for patch update execution rollback feasibility
(PRA-173 slice 1).

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md``).

Slice 1 ships the rollback feasibility read surface only: a per-
execution feasibility envelope plus per-host / per-package
breakdown. No rollback command planning, no approval, no execution
or dispatch fields.

**Timestamp wire shape:** All datetime-bearing fields are typed as
``str`` (or ``Optional[str]``) because the route serialization
helper formats them through ``patch_rollback_service.utc_iso`` so
wire payloads carry an explicit ``Z`` UTC suffix. PRA-173 review
lock #2 (carry-forward from PRA-172) requires read payload
timestamps to be absolute UTC so API consumers cannot mistake them
for local time. The DB layer keeps the patch-lifecycle naive-UTC
convention; the conversion happens at the serialization boundary
only.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class PatchUpdateExecutionRollbackPackageRead(BaseModel):
    """One rollback feasibility row for a (host, package) candidate.

    ``state`` is one of ``feasible`` / ``infeasible``.
    ``refusal_reason`` is set on every ``infeasible`` row; null
    otherwise. ``target_rollback_version`` is set only on
    ``feasible`` rows (equal to ``installed_version_before_snapshot``)
    so the future rollback execution layer can read it directly.

    ``content_evidence`` records the channel/mirror/run records the
    feasibility check inspected: on feasible rows it lists the
    matching channels; on ``old_version_unavailable`` it lists the
    negative results. ``refusal_details`` carries refusal-specific
    structured context (the observed mismatched versions, the
    content-profile state, etc.).

    ``command_plan`` (PRA-173 slice 2) is the JSONB rollback command
    rendered at evaluation time for feasible rows: family-specific
    primary ``argv`` + ``command_string``, plus held-package /
    versionlock handling metadata. Null on infeasible rows so the
    read surface stays honest about which packages are dispatch-
    ready.
    """

    id: int
    rollback_host_id: int
    execution_host_package_id: Optional[int]
    package_name: str
    package_manager_family_snapshot: str
    installed_version_before_snapshot: Optional[str]
    installed_version_after_snapshot: Optional[str]
    requested_version_snapshot: Optional[str]
    target_rollback_version: Optional[str]
    package_outcome_snapshot: str
    state: str
    refusal_reason: Optional[str]
    refusal_details: Dict[str, Any] = {}
    content_evidence: Dict[str, Any] = {}
    command_plan: Optional[Dict[str, Any]] = None
    evaluated_at: str
    created_at: str
    updated_at: str


class PatchUpdateExecutionRollbackHostRead(BaseModel):
    """One rollback feasibility row for an execution host.

    ``state`` is one of ``feasible`` / ``partial_feasible`` /
    ``infeasible``. ``refusal_reason`` is set when the host-level
    refusal is structured (currently only ``host_not_succeeded``);
    null otherwise (per-package refusals live on the package rows).

    ``content_profile_snapshot`` mirrors the host's effective
    content-profile context at evaluation time. ``package_summary``
    is the per-host rollup (counts by state and by refusal reason)
    so polling UIs don't need to re-aggregate from the children.
    """

    id: int
    rollback_id: int
    execution_host_id: int
    plan_host_id_snapshot: int
    system_id_snapshot: Optional[int]
    system_hostname_snapshot: Optional[str]
    wave_index: int
    execution_host_state_snapshot: str
    state: str
    refusal_reason: Optional[str]
    refusal_details: Dict[str, Any] = {}
    content_profile_snapshot: Dict[str, Any] = {}
    package_summary: Dict[str, Any] = {}
    evaluated_at: str
    created_at: str
    updated_at: str


class PatchUpdateExecutionRollbackSummary(BaseModel):
    """Per-execution rollup over the rollback feasibility rows.

    ``host_counts_by_state`` and ``package_counts_by_state`` always
    include every DB-valid state with zero counts when absent, so the
    operator UI doesn't have to defensively check for missing keys.
    ``refusal_counts`` is keyed by the refusal reasons that actually
    appear (sorted for deterministic polling responses)."""

    host_count: int = 0
    host_counts_by_state: Dict[str, int] = {}
    package_count: int = 0
    package_counts_by_state: Dict[str, int] = {}
    refusal_counts: Dict[str, int] = {}


class PatchUpdateExecutionRollbackRead(BaseModel):
    """Header row + plan-level refusal context for one execution.

    ``state`` is one of ``evaluated`` / ``refused``. ``refused``
    records the plan-level refusal codes (e.g.
    ``execution_not_terminal``); ``evaluated`` rows carry the
    per-host / per-package rollup.
    """

    id: int
    execution_id: int
    plan_id_snapshot: int
    execution_state_snapshot: str
    state: str
    refusal_reason: Optional[str]
    refusal_details: Dict[str, Any] = {}
    feasibility_summary: PatchUpdateExecutionRollbackSummary
    evaluated_at: str
    created_at: str
    updated_at: str


class PatchUpdateExecutionRollbackApprovalSummary(BaseModel):
    """PRA-173 slice 2: rollback approval link + status summary.

    Returned alongside the rollback detail when an approval has been
    requested. ``status`` is one of ``pending`` / ``approved`` /
    ``rejected`` / ``expired`` (mirrors :class:`PatchApproval`).
    ``frozen_plan_snapshot`` is the moment-in-time JSONB blob of
    command plans operators are voting on; Slice 3 dispatch reads
    this exact shape rather than the live per-package columns so
    re-evaluate between request and vote cannot rewrite intent.
    """

    rollback_approval_link_id: int
    approval_id: int
    status: Optional[str]
    required_approvals: Optional[int] = None
    expires_at: Optional[str] = None
    decided_by: Optional[int] = None
    decided_at: Optional[str] = None
    requested_by: int
    requested_at: str
    frozen_plan_snapshot: Dict[str, Any] = {}


class PatchUpdateExecutionRollbackRequestApproval(BaseModel):
    """Request body for
    ``POST /patch/update-executions/{id}/rollback/request-approval``."""

    required_approvals: int = 1
    expires_at: Optional[str] = None
    comment: Optional[str] = None


class PatchUpdateExecutionRollbackVote(BaseModel):
    """Request body for
    ``POST /patch/update-executions/{id}/rollback/vote``.

    ``decision`` is one of ``approve`` / ``reject``. Mirrors the
    PRA-164 patch-update-plan vote shape so operator UI can reuse
    its vote helper."""

    decision: str
    comment: Optional[str] = None


class PatchUpdateExecutionRollbackVoteResponse(BaseModel):
    """Response body for the rollback vote endpoint."""

    execution_id: int
    rollback_id: int
    rollback_approval_link_id: int
    approval_id: int
    status: Optional[str]
    approves: Optional[int] = None
    required: Optional[int] = None


class PatchUpdateExecutionRollbackDetail(BaseModel):
    """Full rollback feasibility read envelope for one execution.

    Returned by ``GET /patch/update-executions/{id}/rollback``.

    ``rollback`` is ``None`` when no evaluation has been run yet —
    the read surface stays callable so the operator UI can decide
    whether to surface the "Evaluate rollback feasibility"
    affordance without a separate round-trip. The ``execution_*``
    fields mirror the parent execution so the route doesn't require
    a follow-up call to render the "execution must be terminal"
    message.
    """

    execution_id: int
    execution_state: str
    plan_id: int
    rollback: Optional[PatchUpdateExecutionRollbackRead] = None
    hosts: List[PatchUpdateExecutionRollbackHostRead] = []
    # Package rows are returned flat alongside hosts so a polling
    # client gets the entire feasibility tree in one round-trip.
    # ``rollback_host_id`` on each package row resolves to the parent
    # host without a follow-up query.
    packages: List[PatchUpdateExecutionRollbackPackageRead] = []
    # PRA-173 slice 2: surfaced when an approval has been requested
    # for this rollback. Null when no approval has been requested
    # yet so the operator UI can decide whether to render a
    # "Request approval" affordance.
    approval: Optional[PatchUpdateExecutionRollbackApprovalSummary] = None


class PatchUpdateExecutionRollbackEvaluateResponse(BaseModel):
    """Response body for
    ``POST /patch/update-executions/{id}/rollback/evaluate``.

    Mirrors :class:`PatchUpdateExecutionRollbackDetail` so the
    operator UI can render the refreshed feasibility without a
    follow-up ``GET``.
    """

    execution_id: int
    execution_state: str
    plan_id: int
    rollback: Optional[PatchUpdateExecutionRollbackRead] = None
    hosts: List[PatchUpdateExecutionRollbackHostRead] = []
    packages: List[PatchUpdateExecutionRollbackPackageRead] = []
    approval: Optional[PatchUpdateExecutionRollbackApprovalSummary] = None


class PatchUpdateExecutionRollbackRequestApprovalResponse(BaseModel):
    """Response body for
    ``POST /patch/update-executions/{id}/rollback/request-approval``.

    Mirrors :class:`PatchUpdateExecutionRollbackDetail` so the
    operator UI gets the refreshed feasibility + approval state in
    one round-trip.
    """

    execution_id: int
    execution_state: str
    plan_id: int
    rollback: Optional[PatchUpdateExecutionRollbackRead] = None
    hosts: List[PatchUpdateExecutionRollbackHostRead] = []
    packages: List[PatchUpdateExecutionRollbackPackageRead] = []
    approval: Optional[PatchUpdateExecutionRollbackApprovalSummary] = None


class PatchUpdatePlanRollbackExecutionRef(BaseModel):
    """Per-execution rollup carried inside the plan-scoped read envelope.

    The plan-scoped read endpoint walks every execution started for
    the plan and returns the rollback summary for each one (or
    ``None`` when no evaluation has been run for that execution).
    Execution timestamps are serialized as absolute UTC ISO strings
    via ``patch_rollback_service.utc_iso``.
    """

    execution_id: int
    execution_state: str
    started_at: str
    completed_at: Optional[str] = None
    rollback: Optional[PatchUpdateExecutionRollbackRead] = None


class PatchUpdatePlanRollbackSummary(BaseModel):
    """Plan-level aggregate over every execution's rollback feasibility.

    ``host_counts_by_state`` and ``package_counts_by_state`` include
    every DB-valid state with zero counts when absent. Aggregates
    only consider ``evaluated`` rollback rows; ``refused`` rows
    contribute zero counts.
    """

    execution_count: int = 0
    evaluated_count: int = 0
    host_count: int = 0
    host_counts_by_state: Dict[str, int] = {}
    package_count: int = 0
    package_counts_by_state: Dict[str, int] = {}
    refusal_counts: Dict[str, int] = {}


class PatchRollbackDispatchHostPackageRead(BaseModel):
    """PRA-173 Slice 3: per-package row from a rollback dispatch run.

    Mirrors the PRA-171 host-package read shape but with the rollback
    specifics: ``target_rollback_version_snapshot`` (the version
    the frozen plan said dispatch would target) plus
    ``installed_version_before`` / ``installed_version_after``
    (observed values; ``installed_version_after`` is null in Slice
    3 — Slice 4 re-scan owns that column).
    """

    id: int
    rollback_dispatch_host_id: int
    rollback_package_id: Optional[int]
    package_name: str
    package_manager_family_snapshot: str
    target_rollback_version_snapshot: Optional[str]
    installed_version_before: Optional[str]
    installed_version_after: Optional[str]
    outcome: str
    error_code: Optional[str]
    details: Dict[str, Any] = {}
    created_at: str
    updated_at: str


class PatchRollbackDispatchHostRead(BaseModel):
    """PRA-173 Slice 3: per-host row from a rollback dispatch run.

    State vocabulary: ``pending`` / ``running`` / ``succeeded`` /
    ``failed`` / ``skipped`` / ``canceled``. ``error_details``
    carries the per-host command log (phase, argv,
    command_string, exit_code, transport, duration_ms, error code)
    so the operator UI can render the "what happened" view without
    a follow-up round-trip.
    """

    id: int
    rollback_dispatch_run_id: int
    rollback_host_id: int
    system_id_snapshot: Optional[int]
    system_hostname_snapshot: Optional[str]
    state: str
    error_details: Dict[str, Any] = {}
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str
    updated_at: str


class PatchRollbackDispatchRunRead(BaseModel):
    """PRA-173 Slice 3: dispatch run header.

    ``state`` is one of ``pending`` / ``running`` / ``paused`` /
    ``succeeded`` / ``failed`` / ``canceled``. The dispatch run is
    a separate artifact from the parent rollback feasibility row;
    it has its own lifecycle and audit trail.
    """

    id: int
    rollback_id: int
    rollback_approval_link_id: int
    state: str
    started_by: int
    started_at: str
    completed_at: Optional[str] = None
    paused_at: Optional[str] = None
    canceled_at: Optional[str] = None
    max_parallel: int
    pause_reason: Optional[str] = None
    cancel_reason: Optional[str] = None
    progress_summary: Dict[str, Any] = {}
    created_at: str
    updated_at: str


class PatchRollbackDispatchHostOutcome(BaseModel):
    """One per-host outcome inside a dispatch-next batch response."""

    rollback_dispatch_host_id: int
    rollback_host_id: int
    system_id: Optional[int] = None
    state: str
    succeeded_package_count: int = 0
    failed_package_count: int = 0
    skipped_package_count: int = 0
    error_code: Optional[str] = None


class PatchRollbackDispatchStartRequest(BaseModel):
    """Body for ``POST /patch/update-executions/{id}/rollback/start``."""

    max_parallel: Optional[int] = None


class PatchRollbackDispatchCancelRequest(BaseModel):
    """Body for ``POST /patch/update-executions/{id}/rollback/cancel``."""

    cancel_reason: Optional[str] = None


class PatchRollbackDispatchDetail(BaseModel):
    """Full rollback dispatch read envelope.

    Returned by ``GET /patch/update-executions/{id}/rollback/dispatch``
    and by ``POST .../rollback/start`` / ``.../rollback/cancel``.
    ``run`` is ``None`` when no dispatch has been started for this
    execution's rollback.
    """

    execution_id: int
    execution_state: str
    plan_id: int
    run: Optional[PatchRollbackDispatchRunRead] = None
    hosts: List[PatchRollbackDispatchHostRead] = []
    packages: List[PatchRollbackDispatchHostPackageRead] = []


class PatchRollbackVerifyHostOutcome(BaseModel):
    """PRA-173 Slice 4: per-host verify-due outcome."""

    rollback_dispatch_host_id: int
    system_id: Optional[int] = None
    reachable: bool
    verified_package_count: int = 0
    package_history_written_count: int = 0
    reason: Optional[str] = None


class PatchRollbackVerifyResult(BaseModel):
    """Response body for
    ``POST /patch/update-executions/{id}/rollback/verify-due``.

    Mirrors the PRA-172 ``/reboots/verify-due`` shape. The
    refreshed dispatch detail comes back in ``dispatch`` so polling
    clients see the new ``installed_version_after`` columns +
    ``error_details.verification_refusal`` for unreachable hosts in
    one round-trip."""

    rollback_dispatch_run_id: int
    attempted_host_count: int = 0
    reachable_host_count: int = 0
    unreachable_host_count: int = 0
    no_due: bool = False
    verification_complete: bool = False
    host_outcomes: List[PatchRollbackVerifyHostOutcome] = []
    dispatch: "PatchRollbackDispatchDetail"


class PatchRollbackDispatchBatchResult(BaseModel):
    """Response body for
    ``POST /patch/update-executions/{id}/rollback/dispatch-next``."""

    rollback_dispatch_run_id: int
    dispatched_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    no_pending: bool = False
    finalized_state: Optional[str] = None
    host_outcomes: List[PatchRollbackDispatchHostOutcome] = []
    # The refreshed dispatch detail so polling clients get the full
    # tree in one round-trip.
    dispatch: PatchRollbackDispatchDetail


class PatchUpdatePlanRollbackRead(BaseModel):
    """Plan-scoped rollback feasibility read envelope.

    Returned by ``GET /patch/update-plans/{plan_id}/rollback``. The
    aggregate ``summary`` rolls across every execution row in
    ``executions`` so a plan-detail UI can render one "feasible
    packages across the plan" number; the ``executions`` array
    keeps the per-execution breakdown so the UI can drill into a
    specific run without a follow-up round-trip.
    """

    plan_id: int
    plan_state: str
    summary: PatchUpdatePlanRollbackSummary
    executions: List[PatchUpdatePlanRollbackExecutionRef] = []
