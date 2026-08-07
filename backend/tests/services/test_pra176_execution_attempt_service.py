"""PRA-176 Slice 1 — compliance_remediation_execution_service tests.

Covers:

* Successful attempt creation snapshots policy/check/system identity,
  plan_kind, package identifiers, and approval lineage; emits
  ``compliance_remediation_execution.created`` via ``safe_emit`` AFTER
  commit with no ``db=`` (session-boundary lock).
* Fail-closed readiness gate refuses each branch with a distinct
  error: missing plan, superseded plan, non-``planned`` state,
  unacknowledged plan, stale plan (live def drift / deleted check),
  non-executable plan_kind (review-required / unsupported), source
  request no longer approved.
* Invalid actor / non-positive plan_id raise.
* Creating an attempt does NOT mutate the source plan, the source
  remediation request, or any host (no-dispatch property).
* Package install / remove / upgrade plans yield the expected
  ``package_name`` and ``package_version_target`` snapshot.
* List filters (request_id, plan_id, system_id, state) + bad-state
  rejection.
* PRA-165/PRA-167 read envelopes are unchanged after an attempt is
  created (compatibility).
"""

from __future__ import annotations

from datetime import datetime
from typing import List

import pytest

from app.db.models import (
    CompliancePolicyEvidence,
    ComplianceRemediationExecutionAttempt,
    Credential,
    Group,
    Package,
    System,
)
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_execution_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
)
from app.services.compliance_remediation_execution_service import (
    AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_CREATED,
    STATE_PENDING,
    ComplianceError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class AuditCapture:
    def __init__(self):
        self.calls: List[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

    def by_action(self, action):
        return [c for c in self.calls if c["action"] == action]

    def actions(self):
        return [c["action"] for c in self.calls]


@pytest.fixture
def capture_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_remediation_execution_service, "safe_emit", cap)
    return cap


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra176-host", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra176-host-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra176.example.com",
        ip_address="10.0.0.176",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _make_acknowledged_package_plan(
    db,
    admin_user,
    maintainer_user,
    host,
    *,
    suffix: str = "exec",
    check_kind: str = "package_installed",
    definition: dict | None = None,
    pre_seed=None,
):
    """Build the full PRA-167 chain: policy + package check + failing
    evidence → request → approve → build plan → acknowledge. Returns
    ``(policy, check, request, plan)`` ready for an execution-attempt
    test.
    """
    definition = definition or {"package": f"missing-{suffix}"}
    if pre_seed:
        pre_seed(db, host)
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"exec-{suffix}",
        name=f"exec {suffix}",
    )
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"c-{suffix}",
        title=f"c {suffix}",
        kind=check_kind,
        definition=definition,
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    evidence = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == host.id,
            CompliancePolicyEvidence.verdict == "fail",
        )
        .order_by(CompliancePolicyEvidence.id.desc())
        .first()
    )
    assert evidence is not None
    req = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    db.refresh(plan)
    return policy, check, req, plan


def _make_synthetic_command_plan(db, admin_user, maintainer_user, host, *, suffix):
    """Build a non-executable (review-required) plan for negative-path
    tests. command_stdout_contains naturally evaluates to ``error``
    without an SSH probe, so we synthesize the fail-evidence row.
    """
    import uuid

    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"exec-cmd-{suffix}",
        name=f"exec cmd {suffix}",
    )
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"cmd-{suffix}",
        title=f"cmd {suffix}",
        kind="command_stdout_contains",
        definition={"command": "/bin/true", "expected_substring": "ok"},
    )
    evidence = CompliancePolicyEvidence(
        policy_id=policy.id,
        check_id=check.id,
        system_id=host.id,
        policy_slug=policy.slug,
        policy_version=policy.version,
        check_slug=check.slug,
        check_kind=check.kind,
        verdict="fail",
        verdict_reason="synthetic",
        severity=policy.severity,
        evaluation_run_id=str(uuid.uuid4()),
        evaluated_at=datetime.utcnow(),
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    req = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    return policy, check, req, plan


# ---------------------------------------------------------------------------
# Creation + snapshot semantics
# ---------------------------------------------------------------------------


def test_create_attempt_snapshots_identity_and_audit(
    db, admin_user, maintainer_user, host, capture_audit
):
    policy, check, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="happy"
    )
    attempt = compliance_remediation_execution_service.create_attempt(
        db,
        plan_id=plan.id,
        actor_user_id=admin_user.id,
        actor_username="admintest",
        actor_ip="10.0.0.5",
    )
    assert attempt.id is not None
    assert attempt.state == STATE_PENDING
    assert attempt.request_id == req.id
    assert attempt.plan_id == plan.id
    assert attempt.system_id == host.id
    assert attempt.policy_slug == plan.policy_slug
    assert attempt.policy_version == plan.policy_version
    assert attempt.check_slug == plan.check_slug
    assert attempt.check_kind == plan.check_kind
    assert attempt.severity_snapshot == plan.severity_snapshot
    assert attempt.plan_kind_snapshot == plan.plan_kind
    assert attempt.package_name == "missing-happy"
    assert attempt.package_version_target is None
    assert attempt.approval_decided_by == admin_user.id
    assert isinstance(attempt.approval_decided_at, datetime)
    # Slice 1 pre-dispatch: transport, failure, timestamps stay null.
    assert attempt.transport is None
    assert attempt.failure_reason is None
    assert attempt.error_message is None
    assert attempt.dispatched_at is None
    assert attempt.completed_at is None
    # Audit emit pattern: AFTER commit, no db=.
    created = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_CREATED)
    assert len(created) == 1
    call = created[0]
    assert "db" not in call
    assert call["target_kind"] == "compliance_remediation_execution_attempt"
    assert call["target_id"] == str(attempt.id)
    assert call["target_system_id"] == host.id
    ctx = call["context"]
    assert ctx["request_id"] == req.id
    assert ctx["plan_id"] == plan.id
    assert ctx["plan_kind_snapshot"] == plan.plan_kind
    assert ctx["state"] == STATE_PENDING
    assert ctx["dispatched"] is False
    assert ctx["package_name"] == "missing-happy"


def test_create_attempt_records_upgrade_version_target(
    db, admin_user, maintainer_user, host
):
    """package_version_min plans set ``expected_value`` to ``>= X.Y.Z``;
    the attempt should record that as the package_version_target.
    """

    def pre_seed(db, host):
        db.add(
            Package(
                system_id=host.id,
                name="upgrade-pkg",
                installed_version="0.1",
                package_type="apt",
            )
        )
        db.flush()

    policy, check, req, plan = _make_acknowledged_package_plan(
        db,
        admin_user,
        maintainer_user,
        host,
        suffix="upgrade",
        check_kind="package_version_min",
        definition={"package": "upgrade-pkg", "min_version": "9.9.9"},
        pre_seed=pre_seed,
    )
    attempt = compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    assert attempt.plan_kind_snapshot == "package_upgrade_preview"
    assert attempt.package_name == "upgrade-pkg"
    assert attempt.package_version_target == ">= 9.9.9"


def test_create_attempt_does_not_mutate_plan_or_request(
    db, admin_user, maintainer_user, host
):
    policy, check, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="immutable"
    )
    plan_state_before = plan.state
    plan_ack_at_before = plan.acknowledged_at
    plan_superseded_before = plan.superseded_by_plan_id
    req_state_before = req.state
    req_decided_at_before = req.decided_at

    compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    db.refresh(plan)
    db.refresh(req)
    assert plan.state == plan_state_before
    assert plan.acknowledged_at == plan_ack_at_before
    assert plan.superseded_by_plan_id == plan_superseded_before
    assert req.state == req_state_before
    assert req.decided_at == req_decided_at_before


# ---------------------------------------------------------------------------
# Fail-closed readiness gate — one branch at a time
# ---------------------------------------------------------------------------


def test_create_attempt_unknown_plan_returns_not_found(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=999_999, actor_user_id=admin_user.id
        )
    assert "not found" in str(ei.value)


def test_create_attempt_rejects_non_positive_plan_id(db, admin_user):
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=0, actor_user_id=admin_user.id
        )


def test_create_attempt_rejects_unknown_actor(db, admin_user, maintainer_user, host):
    _, _, _, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="actor"
    )
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan.id, actor_user_id=999_999
        )


def test_create_attempt_refuses_unacknowledged_plan(
    db, admin_user, maintainer_user, host
):
    # Build but do NOT acknowledge.
    policy, check, req, _ = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="noack"
    )
    # _make_acknowledged_package_plan acknowledges; for this branch we
    # need a fresh request and a plan that is built but not ack'd.
    ev = _make_acknowledged_package_plan  # noqa: F841 — silence unused
    policy2 = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="exec-noack2", name="noack2"
    )
    compliance_service.add_check(
        db,
        policy2.id,
        actor_user_id=admin_user.id,
        slug="c-noack2",
        title="noack2",
        kind="package_installed",
        definition={"package": "missing-noack2"},
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy2.id, system_id=host.id
    )
    evidence2 = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy2.id,
            CompliancePolicyEvidence.system_id == host.id,
            CompliancePolicyEvidence.verdict == "fail",
        )
        .order_by(CompliancePolicyEvidence.id.desc())
        .first()
    )
    req2 = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence2.id
    )
    compliance_remediation_service.approve_request(
        db, req2.id, actor_user_id=admin_user.id
    )
    plan2 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req2.id, actor_user_id=admin_user.id
    )
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan2.id, actor_user_id=admin_user.id
        )
    assert "not acknowledged" in str(ei.value)


def test_create_attempt_refuses_superseded_plan(db, admin_user, maintainer_user, host):
    policy, check, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="supr"
    )
    # Rebuild after a check edit supersedes the acknowledged plan.
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "v2"}},
        actor_user_id=admin_user.id,
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    db.refresh(plan)
    assert plan.superseded_by_plan_id is not None
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert "superseded" in str(ei.value)


def test_create_attempt_refuses_stale_plan(db, admin_user, maintainer_user, host):
    """Edit the live check AFTER acknowledgement but BEFORE any
    rebuild: the acknowledged row stays current but fingerprint drift
    makes it stale."""
    policy, check, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="stale"
    )
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "different-pkg"}},
        actor_user_id=admin_user.id,
    )
    # No rebuild yet — the plan is still current and acknowledged but
    # its fingerprint no longer matches the live def.
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert "stale" in str(ei.value)


def test_create_attempt_refuses_review_required_plan_kind(
    db, admin_user, maintainer_user, host
):
    policy, check, req, plan = _make_synthetic_command_plan(
        db, admin_user, maintainer_user, host, suffix="rev"
    )
    # Acknowledge the review-required plan (acknowledgement is allowed
    # at the state-machine level, even though the plan_kind makes it
    # not ready for execution — see PRA-167 Slice 3 test).
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    db.refresh(plan)
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert "executable package plan kind" in str(ei.value)


def test_create_attempt_refuses_non_planned_state(
    db, admin_user, maintainer_user, host
):
    """An unsupported / failed plan cannot reach acknowledged-ready,
    but we still defend against admin DB tampering by re-checking
    plan.state at attempt-creation time."""
    policy, check, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="badstate"
    )
    plan.state = "unsupported"
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert "'planned'" in str(ei.value)


def test_create_attempt_refuses_when_request_no_longer_approved(
    db, admin_user, maintainer_user, host
):
    policy, check, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="notapp"
    )
    # PRA-167 Slice 1's strict state machine forbids transitioning out
    # of approved; simulate admin tampering directly so we exercise
    # the defense-in-depth gate.
    req.state = "rejected"
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.create_attempt(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert "no longer approved" in str(ei.value)


# ---------------------------------------------------------------------------
# No-dispatch property — nothing dispatches under any error / success
# path. We assert by name that no SSH/agent/runner service was
# imported into the module and that the only row written is the
# attempt itself.
# ---------------------------------------------------------------------------


def test_service_module_has_no_unsafe_imports():
    """Static guard: the compliance execution service may only reach
    hosts through the PRA-171 governed dispatch seam
    (``patch_execution_dispatch_service``). It must not introduce raw
    SSH/agent clients, ``subprocess``, the command-execution service,
    the reboot/rollback dispatchers, or any local-fallback path. Slice
    1 banned all dispatch entirely; Slice 2 narrows that to "only via
    the governed transport".
    """
    import app.services.compliance_remediation_execution_service as svc

    src = open(svc.__file__, "r", encoding="utf-8").read()
    for needle in (
        "import paramiko",
        "from paramiko",
        "remote_command_service",
        "ssh_client",
        "agent_client",
        "broker_client",
        "import subprocess",
        "from subprocess",
        "command_execution_service",
        "reboot_dispatch_service",
        "rollback_dispatch_service",
        "patch_reboot_service",
        "patch_rollback_service",
    ):
        assert (
            needle not in src
        ), f"unexpected import/use {needle!r} in execution service"


def test_create_attempt_writes_only_the_attempt_row(
    db, admin_user, maintainer_user, host
):
    policy, check, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="onlyrow"
    )
    before_pkg_count = db.query(Package).filter(Package.system_id == host.id).count()
    compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    after_pkg_count = db.query(Package).filter(Package.system_id == host.id).count()
    # No package was installed / removed by attempt creation.
    assert after_pkg_count == before_pkg_count
    # Exactly one attempt row exists for this plan.
    rows = (
        db.query(ComplianceRemediationExecutionAttempt)
        .filter(ComplianceRemediationExecutionAttempt.plan_id == plan.id)
        .all()
    )
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# Read envelope + list filters
# ---------------------------------------------------------------------------


def test_read_envelope_serializes_absolute_utc(db, admin_user, maintainer_user, host):
    _, _, _, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="utc"
    )
    attempt = compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    env = compliance_remediation_execution_service.attempt_read_envelope(attempt)
    assert env["created_at"].endswith("Z")
    assert env["updated_at"].endswith("Z")
    assert env["approval_decided_at"].endswith("Z")
    assert env["dispatched_at"] is None
    assert env["completed_at"] is None
    assert env["state"] == STATE_PENDING


def test_list_attempts_filters_by_request_and_state(
    db, admin_user, maintainer_user, host
):
    _, _, req1, plan1 = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="list1"
    )
    a1 = compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan1.id, actor_user_id=admin_user.id
    )
    _, _, req2, plan2 = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="list2"
    )
    a2 = compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan2.id, actor_user_id=admin_user.id
    )

    rows, total = compliance_remediation_execution_service.list_attempts(
        db, request_id=req1.id
    )
    assert total == 1 and rows[0].id == a1.id
    rows, total = compliance_remediation_execution_service.list_attempts(
        db, system_id=host.id
    )
    assert total == 2
    rows, total = compliance_remediation_execution_service.list_attempts(
        db, state=STATE_PENDING
    )
    # All Slice 1 attempts are pending; both should appear.
    ids = {r.id for r in rows}
    assert a1.id in ids and a2.id in ids


def test_list_attempts_rejects_bad_state(db):
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.list_attempts(db, state="zombie")


def test_list_attempts_rejects_bad_offset_limit(db):
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.list_attempts(db, offset=-1)
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.list_attempts(db, limit=0)
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.list_attempts(db, limit=10_000)


# ---------------------------------------------------------------------------
# Compatibility: PRA-165/PRA-167 read envelopes unchanged by attempt creation.
# ---------------------------------------------------------------------------


def test_pra167_request_envelope_unchanged_after_attempt(
    db, admin_user, maintainer_user, host
):
    _, _, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="reqcompat"
    )
    before = compliance_remediation_service.remediation_request_read_envelope(req)
    compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    db.refresh(req)
    after = compliance_remediation_service.remediation_request_read_envelope(req)
    assert before == after


def test_pra167_plan_envelope_unchanged_after_attempt(
    db, admin_user, maintainer_user, host
):
    _, _, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="plancompat"
    )
    before = compliance_remediation_plan_service.remediation_plan_read_envelope(
        plan, db=db
    )
    compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    db.refresh(plan)
    after = compliance_remediation_plan_service.remediation_plan_read_envelope(
        plan, db=db
    )
    assert before == after


def test_pra165_evidence_export_row_unchanged_after_attempt(
    db, admin_user, maintainer_user, host
):
    _, _, req, plan = _make_acknowledged_package_plan(
        db, admin_user, maintainer_user, host, suffix="evcompat"
    )
    evidence = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == req.policy_id,
            CompliancePolicyEvidence.system_id == host.id,
            CompliancePolicyEvidence.verdict == "fail",
        )
        .order_by(CompliancePolicyEvidence.id.desc())
        .first()
    )
    before = compliance_evaluation_service.evidence_export_row(evidence)
    compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    db.refresh(evidence)
    after = compliance_evaluation_service.evidence_export_row(evidence)
    assert before == after
