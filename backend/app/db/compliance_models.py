"""Compliance policy models (PRA-165 slice 1).

Slice 1 is the substrate only: named compliance policies, typed
check definitions, and idempotent starter-pack metadata. No probe
execution, no per-host evidence rows, no scheduler — those land in
later slices.

Tables:

* ``compliance_policies`` — named policy with severity, schedule
  metadata, evidence retention metadata, and starter-pack marker.
* ``compliance_policy_checks`` — typed check definitions belonging
  to a policy. ``definition_json`` is validated by the service
  against ``kind``; execution belongs to Slice 2 (package/fact
  kinds) or PRA-166 (file/command kinds).

Design notes:

* The starter-pack key lives on ``compliance_policies`` so the
  seeder is purely additive — re-running it never duplicates rows
  and never overwrites operator edits to a seeded policy.
* ``built_in=True`` flags starter-pack rows so the delete path can
  refuse to drop locked policies.
* ``version`` bumps on every service-level mutation so future
  evidence rows can reference the policy snapshot they evaluated
  against.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from .base import Base


class CompliancePolicy(Base):  # pylint: disable=too-few-public-methods
    """Named compliance policy (PRA-165 slice 1).

    Slice 1 stores definition + metadata only — no per-host
    evaluation results live here. Severity, schedule, and retention
    fields are persisted so later slices can pick them up without
    another migration.
    """

    __tablename__ = "compliance_policies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    slug = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)

    # 'low' | 'medium' | 'high' | 'critical'
    severity = Column(String(16), nullable=False, server_default="medium")

    # Free-form bucket so the UI / exports can group policies
    # (e.g. 'access-control', 'package-hygiene', 'kernel-baseline').
    category = Column(String(64), nullable=False, server_default="custom")

    # Stored intent for later slices. Slice 1 does not run anything.
    schedule_interval_hours = Column(Integer, nullable=False, server_default="24")
    evidence_retention_days = Column(Integer, nullable=False, server_default="90")

    # Operator-readable remediation guidance. Free-form markdown-ish
    # text — NOT executable. Actual remediation workflows are owned
    # by PRA-167.
    remediation_guidance = Column(Text, nullable=True)

    enabled = Column(Boolean, nullable=False, server_default="true", default=True)

    # Bumped by the service on every CRUD-style mutation. Future
    # evidence rows snapshot this so an auditor can tell which
    # policy version produced a given verdict.
    version = Column(Integer, nullable=False, server_default="1", default=1)

    # ``built_in=True`` marks rows that came from the starter-pack
    # seeder. Delete path refuses to drop these; operators may
    # disable instead.
    built_in = Column(Boolean, nullable=False, server_default="false", default=False)

    # Stable seed identifier. NULL for operator-authored policies.
    # Unique when non-null so seeding is idempotent without
    # re-counting.
    starter_pack_key = Column(String(128), nullable=True, index=True)

    # Last successful evaluation sweep (PRA-165 Slice 2). NULL until the
    # first sweep runs. Drives the due-policy selector keyed off
    # ``schedule_interval_hours``.
    last_run_at = Column(DateTime, nullable=True)

    # PRA-312: outcome of the most recent evaluation attempt — 'success' or
    # 'error'. NULL = never attempted. Distinct from ``last_run_at`` (which only
    # advances on success) so the operator UI can show a failed run without the
    # policy silently looking "never run".
    last_run_status = Column(String(16), nullable=True)

    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    creator = relationship("User")
    checks = relationship(
        "CompliancePolicyCheck",
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="CompliancePolicyCheck.display_order",
    )

    __table_args__ = (
        UniqueConstraint(
            "starter_pack_key",
            name="uq_compliance_policies_starter_pack_key",
        ),
    )


class CompliancePolicyCheck(Base):  # pylint: disable=too-few-public-methods
    """Typed check definition belonging to a compliance policy.

    ``kind`` is validated against ``KNOWN_CHECK_KINDS`` in the
    service layer; ``definition_json`` is validated against the
    per-kind schema. Execution is owned by Slice 2 (package/fact
    kinds) or PRA-166 (file/command kinds) — Slice 1 stores only.
    """

    __tablename__ = "compliance_policy_checks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer,
        ForeignKey("compliance_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    slug = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)

    # One of the strings in ``KNOWN_CHECK_KINDS`` (compliance_service).
    kind = Column(String(64), nullable=False)

    # Per-kind validated payload. JSONB so future read paths can index
    # individual fields without a schema migration.
    definition_json = Column(JSONB, nullable=False)

    # Optional per-check severity override. NULL = inherit from policy.
    severity_override = Column(String(16), nullable=True)

    remediation_guidance = Column(Text, nullable=True)

    enabled = Column(Boolean, nullable=False, server_default="true", default=True)

    # Stable ordering within a policy for UI / exports. Defaults to 0
    # so unspecified checks group by id.
    display_order = Column(Integer, nullable=False, server_default="0", default=0)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    policy = relationship("CompliancePolicy", back_populates="checks")

    __table_args__ = (
        UniqueConstraint(
            "policy_id",
            "slug",
            name="uq_compliance_policy_checks_policy_slug",
        ),
    )


class CompliancePolicyEvidence(Base):  # pylint: disable=too-few-public-methods
    """Append-oriented per-host evidence row (PRA-165 Slice 2).

    Each row records the verdict of evaluating one check against one
    host at a specific point in time. Rows are immutable after insert
    — retention sweeps delete them in bulk; the service never updates.

    Identity fields (``policy_slug`` / ``check_slug`` / ``check_kind``)
    are denormalized so evidence survives downstream policy/check edits
    and so auditors can read the verdict without joining back to a
    mutable row. ``policy_version`` snapshots the policy at evaluation
    time for cross-mutation comparability.

    On policy deletion the cascade drops the evidence rows along with
    the policy. On check deletion the FK is SET NULL — the evidence
    survives because the denormalized identity is enough to read it,
    and dropping rows on every check edit would erode auditor trust.
    """

    __tablename__ = "compliance_policy_evidence"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer,
        ForeignKey("compliance_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    check_id = Column(
        Integer,
        ForeignKey("compliance_policy_checks.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Denormalized identity — survives policy/check edits and aids the
    # retention/read paths.
    policy_slug = Column(String(64), nullable=False)
    policy_version = Column(Integer, nullable=False)
    check_slug = Column(String(64), nullable=False)
    check_kind = Column(String(64), nullable=False)

    # 'pass' | 'fail' | 'error' (verdicts are an enum string for easy
    # JSONL export later). Slice 1 starter content references some
    # fact keys not yet collected by HostFacts — those produce
    # ``error`` with a stable reason code, not a synthetic pass/fail.
    verdict = Column(String(16), nullable=False, index=True)
    verdict_reason = Column(String(512), nullable=True)

    # Operator-facing details captured at evaluation time. NULL when
    # not meaningful for the kind. ``observed_value`` and
    # ``expected_value`` are stored as text so they round-trip through
    # JSONL export without coercion.
    observed_value = Column(Text, nullable=True)
    expected_value = Column(Text, nullable=True)

    # Severity resolved at evaluation time (check_severity_override
    # falls back to policy severity).
    severity = Column(String(16), nullable=False)

    # All evidence rows from a single ``evaluate_*`` invocation share an
    # ``evaluation_run_id`` so a downstream auditor can group "what did
    # this sweep produce". Stable UUID-like string; not an FK.
    evaluation_run_id = Column(String(36), nullable=False, index=True)

    evaluated_at = Column(DateTime, nullable=False, index=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    policy = relationship("CompliancePolicy")
    check = relationship("CompliancePolicyCheck")
    system = relationship("System")


class ComplianceRemediationRequest(Base):  # pylint: disable=too-few-public-methods
    """Non-executing compliance remediation request (PRA-167 Slice 1).

    A request captures operator intent to remediate a failing
    compliance evidence row. Slice 1 stores intent + approval state
    only; nothing here executes, dispatches, mutates a host, installs
    or removes packages, or triggers a reboot. Approval moves the
    request into an ``approved`` state suitable for later execution
    slices but does not run commands.

    Snapshot columns (``policy_slug``, ``policy_version``,
    ``check_slug``, ``check_kind``, ``severity_snapshot``,
    ``verdict_snapshot``, ``verdict_reason_snapshot``,
    ``remediation_guidance_snapshot``) freeze the relevant policy/
    check text at request creation. Later slices can act on the
    snapshot even if the underlying policy/check is edited or the
    check row is deleted; the FK to ``compliance_policy_checks`` is
    ``ON DELETE SET NULL`` so a check delete does not erase history
    while ``ON DELETE CASCADE`` on ``policy_id`` and ``system_id``
    matches the evidence-table semantics.
    """

    __tablename__ = "compliance_remediation_requests"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    policy_id = Column(
        Integer,
        ForeignKey("compliance_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    check_id = Column(
        Integer,
        ForeignKey("compliance_policy_checks.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Evidence row that triggered the request. SET NULL on delete so
    # retention sweeps don't orphan-cascade the remediation history.
    evidence_id = Column(
        Integer,
        ForeignKey("compliance_policy_evidence.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Denormalized snapshot identity — survives policy/check edits.
    policy_slug = Column(String(64), nullable=False)
    policy_version = Column(Integer, nullable=False)
    check_slug = Column(String(64), nullable=False)
    check_kind = Column(String(64), nullable=False)

    # Evaluation context captured at request time so later execution
    # slices can reason about the verdict without re-querying live
    # evidence (which may have been retention-pruned).
    evaluation_run_id = Column(String(36), nullable=True)
    verdict_snapshot = Column(String(16), nullable=False)
    verdict_reason_snapshot = Column(String(512), nullable=True)
    severity_snapshot = Column(String(16), nullable=False)

    # Frozen remediation guidance pulled from the check (or policy
    # fallback) at request creation. Operator-readable text, NOT
    # executable. Bounded at the service layer.
    remediation_guidance_snapshot = Column(Text, nullable=True)

    # State machine. Slice 1 vocabulary:
    #   * ``requested``   — initial state; no decision yet.
    #   * ``approved``    — admin approved; awaits future execution.
    #   * ``rejected``    — admin rejected; terminal.
    #   * ``cancelled``   — requester or admin withdrew; terminal.
    # Approval does NOT trigger execution in this slice.
    state = Column(String(16), nullable=False, server_default="requested")

    # Free-form justification recorded at request time. Bounded by the
    # service layer; intentionally not surfaced to remote execution.
    justification = Column(Text, nullable=True)

    # Approval gate fields. ``decided_by``/``decided_at``/``decided_reason``
    # are NULL until a terminal transition fires.
    requested_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    decided_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    decided_reason = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    policy = relationship("CompliancePolicy")
    check = relationship("CompliancePolicyCheck")
    system = relationship("System")
    evidence = relationship("CompliancePolicyEvidence")
    requester = relationship("User", foreign_keys=[requested_by])
    decider = relationship("User", foreign_keys=[decided_by])


class ComplianceRemediationPlan(Base):  # pylint: disable=too-few-public-methods
    """Non-executing remediation execution-plan preview (PRA-167 Slice 2).

    A plan describes, in bounded structured form, what a later
    execution slice *would* do to satisfy an approved remediation
    request. It is intentionally not a shell script — `plan_steps`
    is a JSONB list of operator-readable intent objects (action,
    target, expected value, safety notes), never executable text.

    Slice 2 is preview-only. Building a plan does NOT mutate the
    referenced remediation request, run a command, dispatch a job,
    refresh facts, or scan packages. The plan rows are deterministic
    re-derivations from the frozen Slice 1 request snapshot plus
    bounded read-only DB context (system hostname, live check
    definition if still present); rebuilding produces equivalent
    content, so there is exactly one row per request.

    State vocabulary:

    * ``planned``     — actionable or review-required preview produced.
    * ``unsupported`` — the check kind has no safe preview shape; the
      stored ``unsupported_reason`` explains why.
    * ``failed``      — the builder errored (e.g. referenced row went
      missing mid-build). ``error_message`` is populated.
    """

    __tablename__ = "compliance_remediation_plans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # Slice 2 created plans with a hard UNIQUE on request_id (one row
    # per request, overwrite-in-place rebuild). Slice 3 relaxes that
    # to "exactly one *current* plan per request" so an acknowledged
    # plan cannot be silently mutated by a rebuild; the constraint
    # moves to a partial unique index in the Slice 3 migration. The
    # column remains non-null + indexed.
    request_id = Column(
        Integer,
        ForeignKey("compliance_remediation_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Snapshot identity carried over from the source request so the
    # plan is auditor-readable even if the request row is later
    # cascaded out (and so a later execution slice can act on the
    # plan without re-fetching the request).
    policy_id = Column(Integer, nullable=False)
    check_id = Column(Integer, nullable=True)
    system_id = Column(Integer, nullable=False)
    policy_slug = Column(String(64), nullable=False)
    policy_version = Column(Integer, nullable=False)
    check_slug = Column(String(64), nullable=False)
    check_kind = Column(String(64), nullable=False)
    severity_snapshot = Column(String(16), nullable=False)

    # Plan vocabulary. State is enforced loud at the service layer;
    # plan_kind is per the Slice 2 taxonomy
    # (`package_install_preview`, `package_remove_preview`,
    # `package_upgrade_preview`, `facts_review_required`,
    # `file_review_required`, `command_review_required`,
    # `unsupported`).
    state = Column(String(16), nullable=False, server_default="planned")
    plan_kind = Column(String(64), nullable=False)

    # Structured, operator-readable plan steps. JSONB so a later
    # read path can index without a schema migration. Service caps
    # the count + serialized length.
    plan_steps = Column(JSONB, nullable=False)

    # Explicit error / unsupported messaging. Bounded at the service
    # layer so a runaway message can't blow up the row.
    unsupported_reason = Column(String(512), nullable=True)
    error_message = Column(String(512), nullable=True)

    # PRA-167 Slice 3 lifecycle fields.
    #
    # ``check_definition_fingerprint`` is the SHA-256 of the
    # canonical-JSON-serialized check ``definition_json`` at build
    # time. NULL when the source check was already gone at build
    # time. The fingerprint lets the read layer compute ``is_stale``
    # by re-fingerprinting the live check without persisting the
    # full definition twice.
    check_definition_fingerprint = Column(String(64), nullable=True)
    #
    # ``acknowledged_at`` / ``acknowledged_by`` record an operator's
    # explicit "this is the plan I intend to run" signal. NULL on
    # plans that are still drafts. Once set they are immutable from
    # the service layer — a fresh build creates a new current plan
    # and marks the old one superseded rather than editing these.
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(Integer, ForeignKey("user.id"), nullable=True)
    #
    # ``superseded_by_plan_id`` points forward to the new current
    # plan when this row has been replaced. NULL means "this row is
    # currently the active plan for its request". A partial unique
    # index in the migration enforces "exactly one current plan per
    # request".
    superseded_by_plan_id = Column(
        Integer,
        ForeignKey("compliance_remediation_plans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    request = relationship("ComplianceRemediationRequest")
    creator = relationship("User", foreign_keys=[created_by])
    acknowledger = relationship("User", foreign_keys=[acknowledged_by])
    superseded_by = relationship(
        "ComplianceRemediationPlan",
        remote_side="ComplianceRemediationPlan.id",
        foreign_keys=[superseded_by_plan_id],
    )


class ComplianceRemediationExecutionAttempt(
    Base
):  # pylint: disable=too-few-public-methods
    """Durable compliance remediation execution-attempt record (PRA-176 Slice 1).

    An attempt is the auditable record of an operator's intent to dispatch
    a current, acknowledged, ready-for-execution package remediation plan.
    Slice 1 is intentionally pre-dispatch: creating an attempt persists
    the snapshot + actor + approval lineage and emits an audit event, but
    it does **not** run commands, dispatch jobs, mutate hosts, refresh
    facts, scan packages, or queue work. Later PRA-176 slices will add
    transport selection, dispatch, and outcome recording.

    Snapshot/denormalization rules mirror the PRA-167 substrate:

    * ``request_id`` is ``ON DELETE CASCADE`` and ``plan_id`` is
      ``ON DELETE SET NULL``. The attempt is the durable audit row;
      losing the source plan (rebuild/supersede or hard delete) does not
      erase the attempt's history of who tried to execute what.
    * ``system_id`` is ``ON DELETE CASCADE`` to mirror evidence/request
      semantics — removing a host drops its remediation attempts too.
    * Identity columns (``policy_slug``, ``policy_version``,
      ``check_slug``, ``check_kind``, ``severity_snapshot``,
      ``plan_kind_snapshot``) and approval lineage
      (``approval_decided_by`` SET NULL, ``approval_decided_at``) are
      copied at attempt creation so the row stays auditor-readable even
      after the underlying request/plan is mutated.
    * ``package_name`` / ``package_version_target`` are extracted from
      the plan_steps at creation time. They are nullable because a plan
      built against a deleted source check carries ``package=None``.
    * ``transport`` is a placeholder for Slice 1 — null means
      "transport not yet selected". Later slices will fill in the
      governed patch transport identifier.
    * ``state`` defaults to ``pending`` at the DB level so a raw-SQL
      insert cannot create a stateless attempt. The vocabulary is
      explicit in the service module; Slice 1 only writes ``pending``.
    * ``failure_reason`` is a short stable code (e.g.
      ``readiness_gate_failed``); ``error_message`` is the bounded
      operator-readable explanation. Slice 1 reserves both columns so
      later slices that record dispatch failures do not need another
      migration.
    """

    __tablename__ = "compliance_remediation_execution_attempts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    request_id = Column(
        Integer,
        ForeignKey("compliance_remediation_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    plan_id = Column(
        Integer,
        ForeignKey("compliance_remediation_plans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Snapshot identity carried from the source request/plan so the
    # attempt is auditor-readable independently of later mutations.
    policy_id = Column(Integer, nullable=False)
    check_id = Column(Integer, nullable=True)
    system_id = Column(
        Integer,
        ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    policy_slug = Column(String(64), nullable=False)
    policy_version = Column(Integer, nullable=False)
    check_slug = Column(String(64), nullable=False)
    check_kind = Column(String(64), nullable=False)
    severity_snapshot = Column(String(16), nullable=False)
    plan_kind_snapshot = Column(String(64), nullable=False)

    # Package identifiers — denormalized from the plan_steps at creation
    # time. ``package_name`` is nullable because a plan built against a
    # deleted source check carries ``package=None``; we still record the
    # attempt so the read surface can explain *why* the operator clicked
    # execute even when the source content vanished.
    package_name = Column(String(256), nullable=True)
    package_version_target = Column(String(128), nullable=True)

    # Approval lineage snapshot at attempt-creation time. Slice 1 of
    # PRA-167 records the deciding admin on the request; we copy those
    # fields here so the attempt's audit context is complete even if the
    # source request is later cascaded out.
    approval_decided_by = Column(
        Integer,
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )
    approval_decided_at = Column(DateTime, nullable=True)

    # State vocabulary (see compliance_remediation_execution_service):
    #   * ``pending`` — created; awaiting future dispatch. Slice 1 only.
    # Later slices will add ``dispatched`` / ``succeeded`` / ``failed`` /
    # ``cancelled`` without a schema migration.
    state = Column(String(16), nullable=False, server_default="pending")

    # Transport placeholder — null until a later slice selects the
    # governed patch transport. The column is bounded so a stray write
    # cannot store an unbounded transport identifier.
    transport = Column(String(32), nullable=True)

    # Failure tracking. Slice 1 leaves these NULL (attempt creation
    # either succeeds or raises before any row is persisted). Slice 2
    # writes ``failure_reason`` (short stable code) and ``error_message``
    # (bounded operator-readable text) when a dispatch terminates in
    # ``failed`` state.
    failure_reason = Column(String(64), nullable=True)
    error_message = Column(String(2048), nullable=True)

    # Dispatch outcome columns (PRA-176 Slice 2). Slice 1 left these
    # null; Slice 2 writes them at the end of a dispatch call. The
    # service layer bounds ``stdout_summary``/``stderr_summary`` to
    # ``MAX_OUTPUT_BYTES = 64 KiB`` per field; ``Text`` rather than
    # bounded varchar lets a future bound grow without another
    # migration.
    exit_code = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    stdout_summary = Column(Text, nullable=True)
    stderr_summary = Column(Text, nullable=True)

    # Lifecycle timestamps. Slice 1 leaves these NULL. Slice 2
    # writes ``dispatched_at`` immediately before invoking the
    # governed patch transport and ``completed_at`` when the attempt
    # reaches a terminal state.
    dispatched_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # PRA-175 Slice 3: JSONB evidence column that records the
    # post-sudo-wrap effective argv alongside the planned/raw argv,
    # matching the JSONB evidence pattern used by
    # ``patch_update_execution_reboots.dispatch_details`` /
    # ``patch_update_execution_hosts.error_details``. Slice 3 writes
    # ``planned_argv``, ``effective_argv``, ``transport``, and
    # ``recorded_at``. The sudo password (password mode) is NEVER
    # persisted here — it flows through stdin only and is dropped on
    # the floor by the orchestrator.
    dispatch_details = Column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )

    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    request = relationship("ComplianceRemediationRequest")
    plan = relationship("ComplianceRemediationPlan")
    system = relationship("System")
    creator = relationship("User", foreign_keys=[created_by])
    approver_snapshot = relationship("User", foreign_keys=[approval_decided_by])
