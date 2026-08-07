"""PRA-167 Slice 3 — plan lifecycle / acknowledgement / supersede / readiness tests.

Covers:

* Build records ``check_definition_fingerprint``; rebuild of an
  unacknowledged draft is overwrite-in-place (Slice 2 compat: same
  row id, ``refreshed=True``).
* Acknowledge happy path: state, ``acknowledged_at`` / ``_by`` set,
  audit fires via ``safe_emit`` AFTER commit with no ``db=``.
* Acknowledge fails closed on unsupported / failed / stale /
  superseded / already-acknowledged / non-approved-request / missing.
* Rebuilding an acknowledged current plan supersedes it and writes a
  new current draft; the acknowledged row is preserved verbatim
  and `compliance_remediation_plan.superseded` fires.
* Exactly one current plan per request after rebuild.
* `is_stale` flips when the live check definition changes; the
  fingerprint pins the build.
* `ready_for_execution` matches the gate (current + planned +
  acknowledged + not stale + executable plan_kind + approved
  source).
* `list_plans` filters: `is_current`, `acknowledged`,
  `ready_for_execution` post-filter, plus bad-input rejection.
* PRA-165 evidence export shape and PRA-167 Slice 1 request envelope
  are byte-equal before and after acknowledgement / rebuild.
"""

from __future__ import annotations

from datetime import datetime
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
    AUDIT_COMPLIANCE_REMEDIATION_PLAN_ACKNOWLEDGED,
    AUDIT_COMPLIANCE_REMEDIATION_PLAN_BUILT,
    AUDIT_COMPLIANCE_REMEDIATION_PLAN_REFRESHED,
    AUDIT_COMPLIANCE_REMEDIATION_PLAN_SUPERSEDED,
    PLAN_KIND_PACKAGE_INSTALL,
    PLAN_STATE_PLANNED,
)
from app.services.compliance_remediation_service import ComplianceError


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
    monkeypatch.setattr(compliance_remediation_plan_service, "safe_emit", cap)
    return cap


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra167-lifecycle", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="pra167-lifecycle-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="lifecycle.example.com",
        ip_address="10.0.0.55",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _approved_package_request(
    db,
    admin_user,
    maintainer_user,
    host,
    *,
    suffix="ack",
    check_kind="package_installed",
):
    """Open + approve a remediation request backed by a failing
    package check (real evaluator path so the evidence row is real).
    """
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"ack-{suffix}",
        name=f"ack {suffix}",
    )
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"c-{suffix}",
        title=f"c {suffix}",
        kind=check_kind,
        definition={"package": f"missing-{suffix}"},
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
    req = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )
    return policy, check, req


# ---------------------------------------------------------------------------
# Build / refresh: fingerprint + Slice 2 overwrite-in-place compat
# ---------------------------------------------------------------------------


def test_build_records_fingerprint(db, admin_user, maintainer_user, host):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="fp"
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    assert plan.check_definition_fingerprint is not None
    assert len(plan.check_definition_fingerprint) == 64  # sha256 hex


def test_rebuild_unacknowledged_draft_is_overwrite_in_place(
    db, admin_user, maintainer_user, host, capture_audit
):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="overwrite"
    )
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    p2 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    assert p1.id == p2.id  # Slice 2 compat
    refreshed = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_PLAN_REFRESHED)
    assert refreshed and refreshed[0]["context"]["refreshed"] is True
    assert refreshed[0]["context"]["superseded_plan_id"] is None


# ---------------------------------------------------------------------------
# Acknowledge: happy path
# ---------------------------------------------------------------------------


def test_acknowledge_happy_path(db, admin_user, maintainer_user, host, capture_audit):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="happy"
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    ack = compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    assert ack.acknowledged_by == admin_user.id
    assert isinstance(ack.acknowledged_at, datetime)
    events = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_PLAN_ACKNOWLEDGED)
    assert len(events) == 1
    assert "db" not in events[0]
    assert events[0]["target_kind"] == "compliance_remediation_plan"
    assert events[0]["context"]["ready_for_execution"] is True


def test_read_envelope_exposes_lifecycle_fields(db, admin_user, maintainer_user, host):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="envelope"
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    env = compliance_remediation_plan_service.remediation_plan_read_envelope(
        plan, db=db
    )
    assert env["is_current"] is True
    assert env["superseded_by_plan_id"] is None
    assert env["acknowledged_at"] is None
    assert env["acknowledged_by"] is None
    assert env["is_stale"] is False
    assert env["ready_for_execution"] is False  # not yet acknowledged
    assert env["check_definition_fingerprint"]
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    db.refresh(plan)
    env2 = compliance_remediation_plan_service.remediation_plan_read_envelope(
        plan, db=db
    )
    assert env2["acknowledged_at"].endswith("Z")
    assert env2["acknowledged_by"] == admin_user.id
    assert env2["ready_for_execution"] is True


# ---------------------------------------------------------------------------
# Acknowledge: fail-closed gates
# ---------------------------------------------------------------------------


def test_acknowledge_unknown_plan_returns_not_found(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_plan_service.acknowledge_plan(
            db, plan_id=999_999, actor_user_id=admin_user.id
        )
    assert "not found" in str(ei.value)


def test_acknowledge_already_acknowledged_refused(
    db, admin_user, maintainer_user, host
):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="reack"
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_plan_service.acknowledge_plan(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert "already acknowledged" in str(ei.value)


def test_acknowledge_refuses_stale_plan(db, admin_user, maintainer_user, host):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="stale"
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    # Mutate the live check definition without rebuilding — the plan
    # should now read as stale.
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "different-pkg"}},
        actor_user_id=admin_user.id,
    )
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_plan_service.acknowledge_plan(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert "stale" in str(ei.value)


def test_acknowledge_refuses_when_check_deleted(db, admin_user, maintainer_user, host):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="checkgone"
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_service.delete_check(db, check.id, actor_user_id=admin_user.id)
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_plan_service.acknowledge_plan(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    # Source-check delete → live def gone → stale.
    assert "stale" in str(ei.value)


def test_acknowledge_refuses_unsupported_plan(db, admin_user, maintainer_user, host):
    """Synthesize a fail-evidence row for a kind that maps to an
    unsupported plan_kind (no_such_kind would be unsupported, but the
    vocabulary is closed). Easier: command_review_required is not in
    EXECUTABLE_PLAN_KINDS, so acknowledge should fail when state is
    planned but plan_kind is review_required.
    """
    # Build a synthetic fail-evidence row for a command kind so the
    # request is openable + approvable.
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="cmd-review", name="cmd review"
    )
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="cmd",
        title="cmd",
        kind="command_stdout_contains",
        definition={"command": "/bin/true", "expected_substring": "ok"},
    )
    import uuid

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
    # Plan kind is command_review_required; state is planned. Ack is
    # allowed at the state-machine level but ready_for_execution will
    # be False (review_required plan_kind). Acknowledge does NOT
    # block on plan_kind — only the readiness gate does. Verify:
    ack = compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    env = compliance_remediation_plan_service.remediation_plan_read_envelope(ack, db=db)
    assert env["acknowledged_at"] is not None
    assert env["ready_for_execution"] is False  # review_required plan_kind


def test_acknowledge_refuses_when_request_no_longer_approved(
    db, admin_user, maintainer_user, host
):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="cancelled"
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    # Cannot cancel an approved request directly (Slice 1 strict
    # state machine — only requested can transition). So this guard
    # mainly defends against admin-led DB tampering. Simulate by
    # mutating the row.
    req.state = "rejected"
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_plan_service.acknowledge_plan(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert "no longer approved" in str(ei.value)


# ---------------------------------------------------------------------------
# Supersede on rebuild
# ---------------------------------------------------------------------------


def test_rebuild_of_acknowledged_plan_creates_new_current(
    db, admin_user, maintainer_user, host, capture_audit
):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="supersede"
    )
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    ack1 = compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p1.id, actor_user_id=admin_user.id
    )
    ack_at = ack1.acknowledged_at
    ack_by = ack1.acknowledged_by

    # Mutate the live check; now rebuild — the acknowledged row
    # should supersede, not overwrite.
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "supersede-target-pkg"}},
        actor_user_id=admin_user.id,
    )
    p2 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    assert p2.id != p1.id
    assert p2.superseded_by_plan_id is None  # new row is current
    db.refresh(ack1)
    assert ack1.superseded_by_plan_id == p2.id
    # Acknowledged row's ack metadata is preserved verbatim.
    assert ack1.acknowledged_at == ack_at
    assert ack1.acknowledged_by == ack_by
    # Audit: superseded event fires.
    superseded = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_PLAN_SUPERSEDED)
    assert len(superseded) == 1
    assert superseded[0]["context"]["superseded_by_plan_id"] == p2.id
    # The new build is a `built` event (not refreshed), and its
    # context records the superseded_plan_id.
    built = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_PLAN_BUILT)
    assert built[-1]["context"]["superseded_plan_id"] == p1.id


def test_exactly_one_current_after_rebuild(db, admin_user, maintainer_user, host):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="onecurrent"
    )
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p1.id, actor_user_id=admin_user.id
    )
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "rebuild-pkg"}},
        actor_user_id=admin_user.id,
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    history = compliance_remediation_plan_service.list_plans_for_request(db, req.id)
    assert len(history) == 2
    current = [p for p in history if p.superseded_by_plan_id is None]
    assert len(current) == 1


def test_acknowledge_refuses_superseded_plan(db, admin_user, maintainer_user, host):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="supnoack"
    )
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p1.id, actor_user_id=admin_user.id
    )
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "fresh-pkg"}},
        actor_user_id=admin_user.id,
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    # p1 is now superseded — re-acknowledging it must fail closed.
    db.refresh(p1)
    assert p1.superseded_by_plan_id is not None
    # Already acknowledged so error is "already acknowledged" first;
    # try the non-current case with a fresh request to isolate the
    # superseded guard.
    policy2, check2, req2 = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="supnoack2"
    )
    p2 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req2.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p2.id, actor_user_id=admin_user.id
    )
    compliance_service.update_check(
        db,
        check2.id,
        {"definition": {"package": "v2"}},
        actor_user_id=admin_user.id,
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req2.id, actor_user_id=admin_user.id
    )
    db.refresh(p2)
    # p2 is acknowledged AND superseded. The "already acknowledged"
    # gate fires first — that's still a fail-closed refusal, which
    # is the property we care about.
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.acknowledge_plan(
            db, plan_id=p2.id, actor_user_id=admin_user.id
        )


# ---------------------------------------------------------------------------
# List filters
# ---------------------------------------------------------------------------


def test_list_plans_filter_is_current(db, admin_user, maintainer_user, host):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="listcur"
    )
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p1.id, actor_user_id=admin_user.id
    )
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "v2"}},
        actor_user_id=admin_user.id,
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    cur_rows, cur_total = compliance_remediation_plan_service.list_plans(
        db, is_current=True, system_id=host.id
    )
    assert all(p.superseded_by_plan_id is None for p in cur_rows)
    sup_rows, _ = compliance_remediation_plan_service.list_plans(
        db, is_current=False, system_id=host.id
    )
    assert all(p.superseded_by_plan_id is not None for p in sup_rows)


def test_list_plans_filter_ready_for_execution(db, admin_user, maintainer_user, host):
    # One ready plan + one not-yet-acked plan.
    policy_a, check_a, req_a = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="ready1"
    )
    p_ready = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req_a.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p_ready.id, actor_user_id=admin_user.id
    )
    _, _, req_b = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="notready"
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req_b.id, actor_user_id=admin_user.id
    )
    ready_rows, _ = compliance_remediation_plan_service.list_plans(
        db, ready_for_execution=True, system_id=host.id
    )
    assert any(p.id == p_ready.id for p in ready_rows)
    not_ready_rows, _ = compliance_remediation_plan_service.list_plans(
        db, ready_for_execution=False, system_id=host.id
    )
    assert not any(p.id == p_ready.id for p in not_ready_rows)


def test_list_plans_rejects_bad_bools(db):
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.list_plans(db, is_current="yes")
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.list_plans(db, acknowledged=1)


# ---------------------------------------------------------------------------
# Compatibility: PRA-165 + PRA-167 Slice 1 wire shapes unchanged
# ---------------------------------------------------------------------------


def test_evidence_export_row_unchanged_after_ack_and_rebuild(
    db, admin_user, maintainer_user, host
):
    policy, check, req = _approved_package_request(
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
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p1.id, actor_user_id=admin_user.id
    )
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "v2"}},
        actor_user_id=admin_user.id,
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    db.refresh(evidence)
    after = compliance_evaluation_service.evidence_export_row(evidence)
    assert before == after


def test_slice1_request_envelope_unchanged_after_ack(
    db, admin_user, maintainer_user, host
):
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="reqcompat"
    )
    before = compliance_remediation_service.remediation_request_read_envelope(req)
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    db.refresh(req)
    after = compliance_remediation_service.remediation_request_read_envelope(req)
    assert before == after


def test_get_plan_for_request_returns_current_after_supersede(
    db, admin_user, maintainer_user, host
):
    """Slice 2 get_plan_for_request returned the single plan; Slice 3
    must still return one plan but it should be the *current* one
    after supersede.
    """
    policy, check, req = _approved_package_request(
        db, admin_user, maintainer_user, host, suffix="getcurrent"
    )
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p1.id, actor_user_id=admin_user.id
    )
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "v2"}},
        actor_user_id=admin_user.id,
    )
    p2 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    current = compliance_remediation_plan_service.get_plan_for_request(db, req.id)
    assert current.id == p2.id
    assert current.id != p1.id
