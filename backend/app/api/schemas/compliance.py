"""Pydantic schemas for compliance policies (PRA-165 slice 1).

Pydantic V1 syntax — ``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md`` (the ``@classmethod`` form
silently suppresses validation).

Routes consume these schemas; deep validation of ``definition_json``
is delegated to ``compliance_service.validate_definition`` so the
validator vocabulary stays in one place.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

# Re-export so route imports stay tight.
VALID_SEVERITIES = ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_severity(v: Any) -> str:
    if not isinstance(v, str):
        raise ValueError("severity must be a string")
    if v not in VALID_SEVERITIES:
        raise ValueError(f"severity must be one of: {list(VALID_SEVERITIES)}")
    return v


def _validate_positive_int(v: Any, field: str, max_value: int) -> int:
    # ``bool`` is a subclass of ``int`` — check first so True/False
    # don't silently coerce to 1/0.
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{field} must be an integer")
    if not (1 <= v <= max_value):
        raise ValueError(f"{field} must be in range 1..{max_value}")
    return v


def _validate_display_order(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("display_order must be an integer")
    if not (0 <= v <= 100_000):
        raise ValueError("display_order must be in range 0..100000")
    return v


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class CompliancePolicyCreate(BaseModel):
    slug: str
    name: str
    description: Optional[str] = None
    severity: str = "medium"
    category: str = "custom"
    schedule_interval_hours: int = 24
    evidence_retention_days: int = 90
    remediation_guidance: Optional[str] = None
    enabled: bool = True

    @validator("severity")
    def _severity(cls, v):  # pylint: disable=no-self-argument
        return _validate_severity(v)

    @validator("schedule_interval_hours", pre=True)
    def _schedule(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_int(v, "schedule_interval_hours", 8760)

    @validator("evidence_retention_days", pre=True)
    def _retention(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_int(v, "evidence_retention_days", 3650)


class CompliancePolicyUpdate(BaseModel):
    """Partial update. ``slug`` / ``built_in`` / ``starter_pack_key``
    are intentionally immutable post-create.
    """

    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    schedule_interval_hours: Optional[int] = None
    evidence_retention_days: Optional[int] = None
    remediation_guidance: Optional[str] = None
    enabled: Optional[bool] = None

    @validator("severity")
    def _severity(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_severity(v)

    @validator("schedule_interval_hours", pre=True)
    def _schedule(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_positive_int(v, "schedule_interval_hours", 8760)

    @validator("evidence_retention_days", pre=True)
    def _retention(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_positive_int(v, "evidence_retention_days", 3650)


class CompliancePolicyRead(BaseModel):
    id: int
    slug: str
    name: str
    description: Optional[str] = None
    severity: str
    category: str
    schedule_interval_hours: int
    evidence_retention_days: int
    remediation_guidance: Optional[str] = None
    enabled: bool
    version: int
    built_in: bool
    starter_pack_key: Optional[str] = None
    created_by: int
    # Absolute-UTC ISO 8601 string ending in 'Z' (Slice 1 read lock).
    created_at: str
    updated_at: str
    # PRA-312 run-status surface (all optional / derived, no schema break):
    # last_run_at NULL => never run; next_run_at derived (last_run_at + interval,
    # NULL when never run => due now); last_run_status 'success'|'error'|None.
    last_run_at: Optional[str] = None
    next_run_at: Optional[str] = None
    last_run_status: Optional[str] = None
    never_run: bool = True


class CompliancePolicyEnabledUpdate(BaseModel):
    """Body for the explicit enable/disable convenience endpoint."""

    enabled: bool


class CompliancePolicyRunResult(BaseModel):
    """PRA-312: result of an operator-triggered immediate evaluation."""

    policy_id: int
    policy_slug: str
    run_id: str
    # Absolute-UTC ISO 8601 string ending in 'Z'.
    evaluated_at: str
    counts: Dict[str, int]
    evidence_count: int
    last_run_status: str


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------


class ComplianceCheckCreate(BaseModel):
    slug: str
    title: str
    kind: str
    definition: Dict[str, Any]
    description: Optional[str] = None
    severity_override: Optional[str] = None
    remediation_guidance: Optional[str] = None
    enabled: bool = True
    display_order: int = 0

    @validator("severity_override")
    def _severity_override(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_severity(v)

    @validator("display_order", pre=True)
    def _display_order(cls, v):  # pylint: disable=no-self-argument
        return _validate_display_order(v)


class ComplianceCheckUpdate(BaseModel):
    """Partial update. ``slug`` / ``policy_id`` / ``kind`` are
    intentionally immutable post-create.
    """

    title: Optional[str] = None
    description: Optional[str] = None
    definition: Optional[Dict[str, Any]] = None
    severity_override: Optional[str] = None
    remediation_guidance: Optional[str] = None
    enabled: Optional[bool] = None
    display_order: Optional[int] = None

    @validator("severity_override")
    def _severity_override(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_severity(v)

    @validator("display_order", pre=True)
    def _display_order(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_display_order(v)


class ComplianceCheckRead(BaseModel):
    """Read envelope. ``runner_status`` and ``runner_owner`` are
    derived fields that make Slice 1's no-execution boundary
    explicit on every read.
    """

    id: int
    policy_id: int
    slug: str
    title: str
    description: Optional[str] = None
    kind: str
    definition: Dict[str, Any]
    severity_override: Optional[str] = None
    remediation_guidance: Optional[str] = None
    enabled: bool
    display_order: int
    runner_status: str
    runner_owner: str
    # PRA-346: product-facing labels. UI renders these; the raw enums above stay
    # stable for API/export/test consumers.
    runner_status_label: str = ""
    runner_label: str = ""
    # Absolute-UTC ISO 8601 string ending in 'Z' (Slice 1 read lock).
    created_at: str
    updated_at: str


class CompliancePolicyDetail(CompliancePolicyRead):
    """Policy read envelope with embedded checks for the
    ``GET /compliance/policies/{id}`` detail endpoint.
    """

    checks: List[ComplianceCheckRead]


# ---------------------------------------------------------------------------
# Starter pack
# ---------------------------------------------------------------------------


class StarterPackEntryRead(BaseModel):
    starter_pack_key: str
    slug: str
    name: str
    category: str
    severity: str
    description: Optional[str] = None
    check_count: int
    runner_owners: List[str]
    # PRA-346: product-facing evaluator families + honest coverage signalling.
    # ``has_coverage_pending`` is true when the pack contains fact-shaped checks
    # whose host fact Praxis doesn't collect yet (they can't pass today).
    runner_labels: List[str] = []
    coverage_pending_count: int = 0
    has_coverage_pending: bool = False


class StarterPackSeedResult(BaseModel):
    """Seed result. ``seeded`` lists keys actually inserted by this
    call; ``skipped`` lists keys that were already present (the
    idempotent re-run case).
    """

    seeded: List[str]
    skipped: List[str]


# ---------------------------------------------------------------------------
# Slice 3 read models — evidence rows, per-policy summary, fleet summary,
# and the export-row schema reused by the JSONL/CSV streamers.
# ---------------------------------------------------------------------------


class ComplianceEvidenceRead(BaseModel):
    """One persisted evidence row. ``evaluated_at`` is the
    auditor-facing timestamp (the moment the runner produced the
    verdict); ``created_at`` mirrors the DB insert time and is
    intentionally separate so a future replay/import can distinguish
    them. Both serialize as absolute-UTC ``...Z`` strings.

    ``runner_status`` and ``runner_owner`` are stable per check_kind
    (`runner_not_implemented_in_slice_1` is the only Slice 1 state;
    Slice 2 evaluators store an actual verdict, while file/command
    kinds carry ``deferred_to_pra166``). The export schema relies on
    this triple — ``verdict`` + ``verdict_reason`` + ``runner_owner``
    — so consumers can distinguish "ran and failed" from "deferred
    runner produced no real verdict".
    """

    id: int
    policy_id: int
    check_id: Optional[int] = None
    system_id: int
    policy_slug: str
    policy_version: int
    check_slug: str
    check_kind: str
    verdict: str
    verdict_reason: Optional[str] = None
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None
    severity: str
    runner_owner: str
    runner_status: str
    # PRA-346: product-facing siblings. ``status`` splits the single ``error``
    # verdict into distinguishable, actionable states (error / coverage_pending
    # / awaiting_scan / unsupported); ``status_label`` + ``verdict_reason_label``
    # + ``runner_label`` are what operator UI renders. Raw fields above stay
    # stable for the pinned CSV/JSONL auditor contract.
    status: str = ""
    status_label: str = ""
    verdict_reason_label: Optional[str] = None
    runner_label: str = ""
    evaluation_run_id: str
    evaluated_at: str
    created_at: str
    updated_at: str


class ComplianceEvidencePage(BaseModel):
    """Page envelope for the evidence list endpoints. ``next_offset``
    is null when there are no more rows; ``total`` is the row count
    matching the filter set, NOT the page size."""

    items: List[ComplianceEvidenceRead]
    total: int
    offset: int
    limit: int
    next_offset: Optional[int] = None


class CompliancePerCheckCount(BaseModel):
    """Per-check verdict tally for the policy summary endpoint.
    ``check_id`` is null when the check has been deleted but
    historical evidence remains (Slice 2 keeps `check_id` SET NULL on
    delete so evidence stays auditor-readable)."""

    check_id: Optional[int] = None
    check_slug: str
    check_kind: str
    runner_owner: str
    runner_label: str = ""
    pass_count: int
    fail_count: int
    error_count: int


class CompliancePerHostCount(BaseModel):
    system_id: int
    # PRA-312 follow-up: the host's name for display. Optional/additive — NULL when the
    # System row is gone (evidence outlives a decommissioned host), so the UI falls
    # back to the system id.
    hostname: Optional[str] = None
    pass_count: int
    fail_count: int
    error_count: int


class CompliancePolicySummary(BaseModel):
    """Roll-up for the latest evaluation run of a single policy.

    ``latest_run_id`` is null when the policy has never been
    evaluated; in that case the per-check / per-host lists are
    empty and ``latest_run_at`` is null.
    """

    policy_id: int
    policy_slug: str
    severity: str
    enabled: bool
    schedule_interval_hours: int
    latest_run_id: Optional[str] = None
    latest_run_at: Optional[str] = None
    pass_count: int
    fail_count: int
    error_count: int
    per_check: List[CompliancePerCheckCount]
    per_host: List[CompliancePerHostCount]


class CompliancePerPolicyFleetCount(BaseModel):
    """Per-policy aggregate row inside the fleet summary.

    ``stale`` is true when ``now - last_run_at > 2 *
    schedule_interval_hours`` (or when ``last_run_at`` is null).
    The exact threshold is documented on the fleet summary route so
    operators don't have to read the schema.
    """

    policy_id: int
    policy_slug: str
    severity: str
    enabled: bool
    schedule_interval_hours: int
    last_run_at: Optional[str] = None
    stale: bool
    pass_count: int
    fail_count: int
    error_count: int


class CompliancePerSeverityFleetCount(BaseModel):
    severity: str
    pass_count: int
    fail_count: int
    error_count: int


class ComplianceFleetSummary(BaseModel):
    """Fleet-wide rollup. Counts come from a single bounded GROUP BY
    query per axis (policy / severity / host) — no Python-side scan
    of the full evidence table.
    """

    generated_at: str
    policy_count: int
    enabled_policy_count: int
    host_count: int
    pass_count: int
    fail_count: int
    error_count: int
    per_policy: List[CompliancePerPolicyFleetCount]
    per_severity: List[CompliancePerSeverityFleetCount]
    per_host: List[CompliancePerHostCount]


# ---------------------------------------------------------------------------
# PRA-167 Slice 1 — remediation request substrate.
#
# Non-executing. Approval changes ``state`` only; no host mutation,
# no command execution, no dispatch. The read model snapshots
# policy/check identity + guidance at request time so later execution
# slices have a stable surface to act on.
# ---------------------------------------------------------------------------


VALID_REMEDIATION_STATES = ("requested", "approved", "rejected", "cancelled")


class ComplianceRemediationRequestCreate(BaseModel):
    """Open a remediation request for a failing evidence row.

    ``evidence_id`` is the only required field — the snapshot fields
    (policy/check/system identity, guidance, verdict) are resolved
    server-side from the referenced evidence so the wire stays
    minimal and clients can't fabricate snapshot text.
    """

    evidence_id: int
    justification: Optional[str] = None

    @validator("evidence_id", pre=True)
    def _evidence_id(cls, v):  # pylint: disable=no-self-argument
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("evidence_id must be an integer")
        if v <= 0:
            raise ValueError("evidence_id must be a positive integer")
        return v

    @validator("justification")
    def _justification(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("justification must be a string")
        if len(v) > 4096:
            raise ValueError("justification exceeds 4096 characters")
        return v


class ComplianceRemediationDecisionBody(BaseModel):
    """Optional reason body for approve/reject/cancel. Empty body is
    allowed so a one-click decision still works in the API.
    """

    decided_reason: Optional[str] = None

    @validator("decided_reason")
    def _reason(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("decided_reason must be a string")
        if len(v) > 4096:
            raise ValueError("decided_reason exceeds 4096 characters")
        return v


class ComplianceRemediationRequestRead(BaseModel):
    """Read envelope for a single remediation request.

    ``runner_owner`` is derived from ``check_kind`` so the consumer
    knows whose runner would eventually act on the snapshot; Slice 1
    itself never executes anything. Timestamps are absolute-UTC
    ``...Z`` strings (PRA-165 read-wire lock).
    """

    id: int
    policy_id: int
    check_id: Optional[int] = None
    system_id: int
    evidence_id: Optional[int] = None
    policy_slug: str
    policy_version: int
    check_slug: str
    check_kind: str
    runner_owner: str
    # PRA-346: product-facing siblings for the carried-forward evidence snapshot.
    runner_label: str = ""
    verdict_label: str = ""
    verdict_reason_snapshot_label: Optional[str] = None
    evaluation_run_id: Optional[str] = None
    verdict_snapshot: str
    verdict_reason_snapshot: Optional[str] = None
    severity_snapshot: str
    remediation_guidance_snapshot: Optional[str] = None
    state: str
    justification: Optional[str] = None
    requested_by: int
    decided_by: Optional[int] = None
    decided_at: Optional[str] = None
    decided_reason: Optional[str] = None
    created_at: str
    updated_at: str


class ComplianceRemediationRequestPage(BaseModel):
    """Page envelope mirrors the PRA-165 Slice 3 evidence page shape:
    ``next_offset`` is null when there are no more rows; ``total`` is
    the row count matching the filter set, NOT the page size.
    """

    items: List[ComplianceRemediationRequestRead]
    total: int
    offset: int
    limit: int
    next_offset: Optional[int] = None


# ---------------------------------------------------------------------------
# PRA-167 Slice 2 — remediation execution-plan preview substrate.
#
# Non-executing. Plans describe what a later execution slice *would*
# do for an approved remediation request, in bounded structured form
# (no shell). Building a plan does not mutate the request and does
# not run anything.
# ---------------------------------------------------------------------------


VALID_REMEDIATION_PLAN_STATES = ("planned", "unsupported", "failed")
VALID_REMEDIATION_PLAN_KINDS = (
    "package_install_preview",
    "package_remove_preview",
    "package_upgrade_preview",
    "facts_review_required",
    "file_review_required",
    "command_review_required",
    "unsupported",
)


class ComplianceRemediationPlanRead(BaseModel):
    """Read envelope for a single remediation plan preview.

    ``plan_steps`` is a JSON list of structured intent objects, NOT
    executable shell. Timestamps are absolute-UTC ``...Z`` strings
    (PRA-165 read-wire lock).

    Slice 3 adds lifecycle fields:

    * ``check_definition_fingerprint`` — SHA-256 of the canonical
      check definition at build time (null when the source check
      was already deleted).
    * ``is_current`` — true while the plan has not been superseded.
    * ``superseded_by_plan_id`` — points forward to the new current
      plan once this row is replaced.
    * ``acknowledged_at`` / ``acknowledged_by`` — operator explicit
      "this is the plan I intend to run" signal.
    * ``is_stale`` — derived; true when the live check definition
      no longer matches the fingerprint or the source check is gone.
    * ``ready_for_execution`` — derived readiness gate; true only
      when the source request is approved, the plan is current,
      planned, acknowledged, not stale, and of an executable
      plan_kind (not a ``*_review_required`` / ``unsupported`` kind).
    """

    id: int
    request_id: int
    policy_id: int
    check_id: Optional[int] = None
    system_id: int
    policy_slug: str
    policy_version: int
    check_slug: str
    check_kind: str
    severity_snapshot: str
    state: str
    plan_kind: str
    plan_steps: List[Dict[str, Any]]
    unsupported_reason: Optional[str] = None
    error_message: Optional[str] = None
    check_definition_fingerprint: Optional[str] = None
    is_current: bool
    superseded_by_plan_id: Optional[int] = None
    acknowledged_at: Optional[str] = None
    acknowledged_by: Optional[int] = None
    is_stale: bool
    ready_for_execution: bool
    created_by: int
    created_at: str
    updated_at: str


class ComplianceRemediationPlanPage(BaseModel):
    items: List[ComplianceRemediationPlanRead]
    total: int
    offset: int
    limit: int
    next_offset: Optional[int] = None


# ---------------------------------------------------------------------------
# PRA-167 Slice 4 — fleet remediation summary + per-host inventory.
#
# Read-only rollups. No execution, no probes, no audit events.
# Mirrors the existing ``ComplianceFleetSummary`` shape so consumers
# don't need a new pattern.
# ---------------------------------------------------------------------------


class ComplianceRemediationPerSeverityCount(BaseModel):
    """Per-severity rollup row keyed on the request ``severity_snapshot``.

    Each row carries one count per request state plus a ``total``.
    Severities are sorted ascending so consumers don't need to sort.
    """

    severity: str
    requested: int
    approved: int
    rejected: int
    cancelled: int
    total: int


class ComplianceRemediationFleetSummary(BaseModel):
    """Fleet-wide remediation rollup. ``generated_at`` is absolute UTC.

    ``request_counts_by_state`` and ``current_plan_counts_by_state``
    are dicts keyed on the documented state vocabularies (Slice 1
    request states; Slice 2 plan states). ``current_plan_*`` counts
    are always over the current-plan slice (one row per request)
    so totals are bounded by the request count, not by plan history.
    """

    generated_at: str
    request_total: int
    request_counts_by_state: Dict[str, int]
    current_plan_total: int
    current_plan_counts_by_state: Dict[str, int]
    current_plan_acknowledged_count: int
    current_plan_unacknowledged_count: int
    current_plan_ready_count: int
    current_plan_not_ready_count: int
    current_plan_stale_count: int
    current_plan_not_stale_count: int
    per_severity: List[ComplianceRemediationPerSeverityCount]


# ---------------------------------------------------------------------------
# PRA-176 Slice 1 — non-executing compliance remediation execution-attempt
# substrate.
#
# An attempt is the durable, auditable record of an operator's intent
# to dispatch a current, acknowledged, ready-for-execution package
# remediation plan. Slice 1 is pre-dispatch: creating an attempt
# persists the snapshot + actor + approval lineage and emits one
# audit event, but it does NOT run commands, dispatch jobs, queue
# work, mutate hosts, or change the source request/plan.
# ---------------------------------------------------------------------------


VALID_REMEDIATION_EXECUTION_STATES = (
    "pending",
    "dispatched",
    "succeeded",
    "failed",
    "cancelled",
)


class ComplianceRemediationExecutionAttemptCreate(BaseModel):
    """Create-body for a remediation execution attempt.

    Only ``plan_id`` is required — the service derives the
    request_id, snapshots policy/check/system identity, approval
    lineage, and package identifiers from the referenced current
    acknowledged plan after the fail-closed readiness gate passes.
    """

    plan_id: int

    @validator("plan_id", pre=True)
    def _plan_id(cls, v):  # pylint: disable=no-self-argument
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("plan_id must be an integer")
        if v <= 0:
            raise ValueError("plan_id must be a positive integer")
        return v


class ComplianceRemediationExecutionAttemptRead(BaseModel):
    """Read envelope for a single execution attempt.

    All timestamps are absolute-UTC ``...Z`` strings (PRA-165 read
    lock). ``transport`` / ``failure_reason`` / ``error_message`` /
    ``dispatched_at`` / ``completed_at`` are reserved for future
    PRA-176 dispatch slices and always read ``None`` in Slice 1.
    """

    id: int
    request_id: int
    plan_id: Optional[int] = None
    policy_id: int
    check_id: Optional[int] = None
    system_id: int
    policy_slug: str
    policy_version: int
    check_slug: str
    check_kind: str
    severity_snapshot: str
    plan_kind_snapshot: str
    package_name: Optional[str] = None
    package_version_target: Optional[str] = None
    approval_decided_by: Optional[int] = None
    approval_decided_at: Optional[str] = None
    state: str
    transport: Optional[str] = None
    failure_reason: Optional[str] = None
    error_message: Optional[str] = None
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    stdout_summary: Optional[str] = None
    stderr_summary: Optional[str] = None
    dispatched_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_by: int
    created_at: str
    updated_at: str


class ComplianceRemediationExecutionAttemptPage(BaseModel):
    items: List[ComplianceRemediationExecutionAttemptRead]
    total: int
    offset: int
    limit: int
    next_offset: Optional[int] = None


# ---------------------------------------------------------------------------
# PRA-176 Slice 3 — bounded multi-attempt batch dispatch + per-request
# rollup envelopes.
# ---------------------------------------------------------------------------


VALID_REMEDIATION_BATCH_OUTCOMES = ("succeeded", "failed", "refused")


class ComplianceRemediationExecutionBatchItem(
    ComplianceRemediationExecutionAttemptRead
):
    """One attempt envelope inside a batch result, augmented with the
    per-attempt batch outcome (``succeeded`` / ``failed`` / ``refused``)
    and any refusal reason. ``batch_refusal_reason`` is null for
    ``succeeded`` / ``failed`` outcomes.
    """

    batch_outcome: str
    batch_refusal_reason: Optional[str] = None


class ComplianceRemediationExecutionBatchRefusal(BaseModel):
    attempt_id: int
    outcome: str
    reason: str


class ComplianceRemediationExecutionBatchResult(BaseModel):
    """Bounded request-scoped batch dispatch result envelope.

    ``total_eligible`` is the number of ``pending`` attempts the
    bounded query returned for this request (≤ ``limit``).
    ``dispatched_count`` is the number that actually went through
    ``dispatch_attempt`` and reached a terminal state
    (``succeeded`` + ``failed``). ``refused_count`` counts attempts
    whose dispatch raised a pre-flight ``ComplianceError`` and left
    the attempt row in ``pending``.
    """

    request_id: int
    generated_at: str
    limit: int
    total_eligible: int
    dispatched_count: int
    succeeded_count: int
    failed_count: int
    refused_count: int
    failure_breakdown_by_reason: Dict[str, int]
    refusals: List[ComplianceRemediationExecutionBatchRefusal]
    items: List[ComplianceRemediationExecutionBatchItem]


class ComplianceRemediationExecutionRequestRollup(BaseModel):
    """Read-only paginated aggregate of every execution attempt tied
    to one remediation request.

    Page metadata fields (``offset``, ``limit``, ``returned_count``,
    ``next_offset``, ``has_more``) describe the returned page only.
    Whole-request totals (``total_attempts``, ``counts_by_state``,
    ``counts_by_failure_reason``) reflect the entire request history
    regardless of which page the caller requested — these come from
    bounded SQL aggregates, not from the returned page. Page-local
    aggregates (``page_counts_by_state``,
    ``page_counts_by_failure_reason``) reflect the returned slice
    only, for callers that want "what's on this page" without
    re-running an aggregate.

    ``counts_by_state`` / ``page_counts_by_state`` keys are the
    attempt state vocabulary (``pending`` / ``dispatched`` /
    ``succeeded`` / ``failed`` / ``cancelled``).
    ``counts_by_failure_reason`` / ``page_counts_by_failure_reason``
    are keyed on the structured ``failure_reason`` of attempts in
    ``failed`` state; an empty dict means no failures in the whole
    request (or page).
    """

    request_id: int
    system_id: int
    generated_at: str
    offset: int
    limit: int
    returned_count: int
    total_attempts: int
    next_offset: Optional[int] = None
    has_more: bool
    counts_by_state: Dict[str, int]
    counts_by_failure_reason: Dict[str, int]
    page_counts_by_state: Dict[str, int]
    page_counts_by_failure_reason: Dict[str, int]
    attempts: List[ComplianceRemediationExecutionAttemptRead]


class ComplianceRemediationHostInventory(BaseModel):
    """Per-host remediation inventory. ``generated_at`` is absolute UTC.

    Each section is a bounded paged envelope (``items`` / ``total`` /
    ``offset`` / ``limit`` / ``next_offset``) so a single host with
    many outstanding requests or plans cannot produce an unbounded
    response. ``open_requests`` and ``approved_requests`` reuse the
    Slice 1 request page shape; ``current_plans``, ``ready_plans``,
    and ``superseded_history`` reuse the Slice 2 plan page shape.

    Section semantics:

    * ``open_requests``        — requests in state ``requested``.
    * ``approved_requests``    — decided but may or may not have a
      current plan yet.
    * ``current_plans``        — every non-superseded plan for the host.
    * ``ready_plans``          — the current-plan subset where
      ``ready_for_execution=True``.
    * ``superseded_history``   — superseded plan history, newest-first.
    """

    system_id: int
    generated_at: str
    open_requests: ComplianceRemediationRequestPage
    approved_requests: ComplianceRemediationRequestPage
    current_plans: ComplianceRemediationPlanPage
    ready_plans: ComplianceRemediationPlanPage
    superseded_history: ComplianceRemediationPlanPage
