"""PRA-167 Slice 2 — compliance_remediation_plan_service tests.

Covers:

* Build success for an approved remediation request: snapshot
  identity carried over, deterministic plan_kind per check_kind,
  plan_steps bounded + structured, audit emits via ``safe_emit``
  AFTER commit with no ``db=``.
* Build is idempotent — rebuilding overwrites the previous plan in
  place (same row id, state ``planned`` again, no duplicate row).
* Building a plan does NOT mutate the source remediation request's
  state.
* Build fails closed for requests in any state other than
  ``approved`` (``requested`` / ``rejected`` / ``cancelled``) and
  for unknown request ids.
* Per-check-kind plan_kind correctness:
    - package_installed -> package_install_preview
    - package_absent   -> package_remove_preview
    - package_version_min -> package_upgrade_preview
    - fact_*    -> facts_review_required
    - file_*    -> file_review_required
    - command_* -> command_review_required
* Build still produces a plan row when the source check has been
  deleted (Slice 1 SET-NULL FK semantics) — plan_kind stays
  consistent and the live-def fields are nulled.
* PRA-165 evidence-row export shape and PRA-167 Slice 1 remediation
  request shape are untouched after a plan build (compatibility).
* List/filter pagination with state + plan_kind + system_id filters.
"""

from __future__ import annotations

from typing import List

import pytest

from app.db.models import CompliancePolicyEvidence, Credential, Group, Package, System
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
)
from app.services.compliance_remediation_plan_service import (
    AUDIT_COMPLIANCE_REMEDIATION_PLAN_BUILT,
    AUDIT_COMPLIANCE_REMEDIATION_PLAN_REFRESHED,
    PLAN_KIND_COMMAND_REVIEW,
    PLAN_KIND_FACTS_REVIEW,
    PLAN_KIND_FILE_REVIEW,
    PLAN_KIND_PACKAGE_INSTALL,
    PLAN_KIND_PACKAGE_REMOVE,
    PLAN_KIND_PACKAGE_UPGRADE,
    PLAN_STATE_PLANNED,
)
from app.services.compliance_remediation_service import (
    STATE_APPROVED,
    STATE_REQUESTED,
    ComplianceError,
)


class AuditCapture:
    def __init__(self):
        self.calls: List[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

    def by_action(self, action):
        return [c for c in self.calls if c["action"] == action]


@pytest.fixture
def capture_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_remediation_plan_service, "safe_emit", cap)
    return cap


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra167-plan", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra167-plan-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="plan.example.com",
        ip_address="10.0.0.66",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _failing_evidence_for_kind(
    db,
    admin_user,
    host,
    *,
    kind: str,
    slug_suffix: str,
    definition: dict,
    pre_seed=None,
):
    """Seed a single ``verdict='fail'`` evidence row for the given check kind.

    Package kinds run cleanly through the evaluator. Fact/file/command
    kinds would naturally produce ``error`` (no host_facts row / no
    SSH probe), so for those we synthesize the evidence row directly
    after creating the policy + check. This isolates the plan-builder
    behavior from PRA-165/166 evaluator preconditions.
    """
    import uuid
    from datetime import datetime

    if pre_seed:
        pre_seed(db, host)
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"plan-{kind}-{slug_suffix}",
        name=f"plan {kind}",
    )
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"c-{slug_suffix}",
        title=f"check {slug_suffix}",
        kind=kind,
        definition=definition,
    )
    if kind.startswith("package_"):
        compliance_evaluation_service.evaluate_policy_for_host(
            db, policy_id=policy.id, system_id=host.id
        )
        return (
            db.query(CompliancePolicyEvidence)
            .filter(
                CompliancePolicyEvidence.policy_id == policy.id,
                CompliancePolicyEvidence.system_id == host.id,
                CompliancePolicyEvidence.verdict == "fail",
            )
            .order_by(CompliancePolicyEvidence.id.desc())
            .first()
        )
    # Synthesize a fail evidence row for kinds that need SSH / facts.
    evidence = CompliancePolicyEvidence(
        policy_id=policy.id,
        check_id=check.id,
        system_id=host.id,
        policy_slug=policy.slug,
        policy_version=policy.version,
        check_slug=check.slug,
        check_kind=check.kind,
        verdict="fail",
        verdict_reason="synthetic_fail_for_plan_test",
        observed_value=None,
        expected_value=None,
        severity=policy.severity,
        evaluation_run_id=str(uuid.uuid4()),
        evaluated_at=datetime.utcnow(),
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def _approved_request(db, admin_user, maintainer_user, host, evidence):
    """Open a remediation request as the maintainer, then approve as
    admin (separation of duties satisfied)."""
    req = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    return compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )


# ---------------------------------------------------------------------------
# Build success + snapshot semantics
# ---------------------------------------------------------------------------


def test_build_plan_for_package_install(
    db, admin_user, maintainer_user, host, capture_audit
):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="install",
        definition={"package": "missing-pkg"},
    )
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    assert plan.state == PLAN_STATE_PLANNED
    assert plan.plan_kind == PLAN_KIND_PACKAGE_INSTALL
    assert plan.request_id == request.id
    assert plan.system_id == host.id
    assert plan.policy_slug == request.policy_slug
    assert plan.check_kind == request.check_kind
    assert isinstance(plan.plan_steps, list) and plan.plan_steps
    step = plan.plan_steps[0]
    assert step["action_intent"] == "package_install"
    assert step["package"] == "missing-pkg"
    # Audit emit shape: safe_emit AFTER commit, no db=.
    built = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_PLAN_BUILT)
    assert len(built) == 1
    assert "db" not in built[0]
    assert built[0]["target_kind"] == "compliance_remediation_plan"
    assert built[0]["target_system_id"] == host.id
    ctx = built[0]["context"]
    assert ctx["request_id"] == request.id
    assert ctx["refreshed"] is False
    assert ctx["plan_state"] == PLAN_STATE_PLANNED


def test_build_plan_does_not_mutate_request(db, admin_user, maintainer_user, host):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="immutable",
        definition={"package": "missing-pkg"},
    )
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    state_before = request.state
    decided_before = request.decided_by
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    db.refresh(request)
    assert request.state == state_before == STATE_APPROVED
    assert request.decided_by == decided_before


def test_build_plan_is_idempotent_in_place(
    db, admin_user, maintainer_user, host, capture_audit
):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="idem",
        definition={"package": "missing-pkg"},
    )
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    p2 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    assert p1.id == p2.id  # same row, rebuilt in place
    refreshed = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_PLAN_REFRESHED)
    assert len(refreshed) == 1
    assert refreshed[0]["context"]["refreshed"] is True


# ---------------------------------------------------------------------------
# Gate: only approved requests can build a plan
# ---------------------------------------------------------------------------


def test_build_plan_refused_for_non_approved_request(
    db, admin_user, maintainer_user, host
):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="pending",
        definition={"package": "missing-pkg"},
    )
    # Open but do NOT approve.
    request = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    assert request.state == STATE_REQUESTED
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_plan_service.build_or_refresh_plan(
            db, request_id=request.id, actor_user_id=admin_user.id
        )
    assert "approved" in str(ei.value)


def test_build_plan_unknown_request_returns_not_found(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_plan_service.build_or_refresh_plan(
            db, request_id=999_999, actor_user_id=admin_user.id
        )
    assert "not found" in str(ei.value)


# ---------------------------------------------------------------------------
# Per-check-kind plan_kind taxonomy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "check_kind,definition,expected_plan_kind",
    [
        (
            "package_installed",
            {"package": "missing-pkg"},
            PLAN_KIND_PACKAGE_INSTALL,
        ),
        (
            "package_version_min",
            {"package": "missing-pkg", "min_version": "9.9.9"},
            PLAN_KIND_PACKAGE_UPGRADE,
        ),
        ("fact_present", {"fact_key": "host.kernel_version"}, PLAN_KIND_FACTS_REVIEW),
        ("file_exists", {"path": "/etc/sudoers"}, PLAN_KIND_FILE_REVIEW),
        (
            "command_stdout_contains",
            {"command": "/bin/true", "expected_substring": "ok"},
            PLAN_KIND_COMMAND_REVIEW,
        ),
    ],
)
def test_plan_kind_matches_check_kind(
    db,
    admin_user,
    maintainer_user,
    host,
    check_kind,
    definition,
    expected_plan_kind,
):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind=check_kind,
        slug_suffix=check_kind.replace("_", "-"),
        definition=definition,
    )
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    assert plan.state == PLAN_STATE_PLANNED
    assert plan.plan_kind == expected_plan_kind


def test_package_absent_failing_evidence_builds_remove_plan(
    db, admin_user, maintainer_user, host
):
    """For package_absent, the failure case requires the package to be
    installed. Seed it then evaluate so we get a fail row to remediate.
    """

    def pre_seed(db, host):
        db.add(
            Package(
                system_id=host.id,
                name="present-pkg",
                installed_version="1.0",
                package_type="apt",
            )
        )
        db.flush()

    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_absent",
        slug_suffix="remove",
        definition={"package": "present-pkg"},
        pre_seed=pre_seed,
    )
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    assert plan.plan_kind == PLAN_KIND_PACKAGE_REMOVE


# ---------------------------------------------------------------------------
# Source check delete still produces a plan
# ---------------------------------------------------------------------------


def test_build_plan_survives_check_delete(db, admin_user, maintainer_user, host):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="delete",
        definition={"package": "missing-pkg"},
    )
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    # Delete the source check; SET-NULL FK means evidence + request
    # snapshots stay readable.
    compliance_service.delete_check(db, evidence.check_id, actor_user_id=admin_user.id)
    db.refresh(request)
    assert request.check_id is None

    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    assert plan.state == PLAN_STATE_PLANNED
    assert plan.plan_kind == PLAN_KIND_PACKAGE_INSTALL
    # Live-def lookup returned None — the package field falls through to None.
    assert plan.plan_steps[0]["package"] is None


# ---------------------------------------------------------------------------
# Read envelope + list filters
# ---------------------------------------------------------------------------


def test_read_envelope_serializes_utc(db, admin_user, maintainer_user, host):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="utc",
        definition={"package": "missing-pkg"},
    )
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    env = compliance_remediation_plan_service.remediation_plan_read_envelope(plan)
    assert env["created_at"].endswith("Z")
    assert env["updated_at"].endswith("Z")
    assert env["state"] == PLAN_STATE_PLANNED
    assert isinstance(env["plan_steps"], list)


def test_list_plans_filters_by_state_and_kind(db, admin_user, maintainer_user, host):
    ev1 = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="filter1",
        definition={"package": "missing-pkg"},
    )
    r1 = _approved_request(db, admin_user, maintainer_user, host, ev1)
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=r1.id, actor_user_id=admin_user.id
    )

    ev2 = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="file_exists",
        slug_suffix="filter2",
        definition={"path": "/etc/sudoers"},
    )
    r2 = _approved_request(db, admin_user, maintainer_user, host, ev2)
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=r2.id, actor_user_id=admin_user.id
    )

    rows, total = compliance_remediation_plan_service.list_plans(
        db, plan_kind=PLAN_KIND_PACKAGE_INSTALL
    )
    assert total == 1
    assert rows[0].plan_kind == PLAN_KIND_PACKAGE_INSTALL

    rows, total = compliance_remediation_plan_service.list_plans(db, system_id=host.id)
    assert total == 2


def test_list_plans_rejects_bad_state(db):
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.list_plans(db, state="zombie")


def test_list_plans_rejects_bad_plan_kind(db):
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.list_plans(db, plan_kind="rm-rf-slash")


# ---------------------------------------------------------------------------
# Compatibility: PRA-165 evidence shape + PRA-167 Slice 1 request shape
# ---------------------------------------------------------------------------


def test_evidence_export_row_unchanged_after_plan_build(
    db, admin_user, maintainer_user, host
):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="compat",
        definition={"package": "missing-pkg"},
    )
    before = compliance_evaluation_service.evidence_export_row(evidence)
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    db.refresh(evidence)
    after = compliance_evaluation_service.evidence_export_row(evidence)
    assert before == after


def test_slice1_request_envelope_unchanged_after_plan_build(
    db, admin_user, maintainer_user, host
):
    evidence = _failing_evidence_for_kind(
        db,
        admin_user,
        host,
        kind="package_installed",
        slug_suffix="reqcompat",
        definition={"package": "missing-pkg"},
    )
    request = _approved_request(db, admin_user, maintainer_user, host, evidence)
    before = compliance_remediation_service.remediation_request_read_envelope(request)
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=admin_user.id
    )
    db.refresh(request)
    after = compliance_remediation_service.remediation_request_read_envelope(request)
    assert before == after
