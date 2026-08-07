"""PRA-167 Slice 1 — compliance_remediation_service tests.

Covers:

* Creating a request from a failing evidence row snapshots
  policy/check/system/evidence identifiers and remediation guidance,
  records the requester, and emits ``compliance_remediation.requested``
  via ``safe_emit`` AFTER its own commit (no ``db=``).
* Invalid references (unknown evidence/policy/system) raise
  :class:`ComplianceError` with a "not found" message that maps to 404.
* Requesting against passing / error verdict evidence fails closed.
* State transitions are strict: only ``requested`` can move to
  ``approved`` / ``rejected`` / ``cancelled``; terminal states refuse
  further transitions.
* Approval and reject paths enforce approver != requester
  (separation-of-duties).
* Cancel allows self-withdraw by the requester.
* Audit events fire on every transition with the correct action
  vocabulary and never carry ``db=``.
* The PRA-165 evidence-row export/read shape is untouched by adding
  this substrate (compatibility check).
"""

from __future__ import annotations

from datetime import datetime
from typing import List

import pytest

from app.db.models import CompliancePolicyEvidence, Credential, Group, Package, System
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_service,
    compliance_service,
)
from app.services.compliance_remediation_service import (
    AUDIT_COMPLIANCE_REMEDIATION_APPROVED,
    AUDIT_COMPLIANCE_REMEDIATION_CANCELLED,
    AUDIT_COMPLIANCE_REMEDIATION_REJECTED,
    AUDIT_COMPLIANCE_REMEDIATION_REQUESTED,
    STATE_APPROVED,
    STATE_CANCELLED,
    STATE_REJECTED,
    STATE_REQUESTED,
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

    def actions(self):
        return [c["action"] for c in self.calls]

    def by_action(self, action):
        return [c for c in self.calls if c["action"] == action]


@pytest.fixture
def capture_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_remediation_service, "safe_emit", cap)
    return cap


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra167-host", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra167-host-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra167.example.com",
        ip_address="10.0.0.99",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _failing_evidence(
    db,
    admin_user,
    host,
    *,
    policy_slug="pra167-policy",
    check_slug="missing-pkg",
    guidance_on_check="apt-get install -y missing-pkg",
    guidance_on_policy=None,
) -> CompliancePolicyEvidence:
    """Seed a single failing evidence row by evaluating a policy whose
    check targets a package that is intentionally not installed.

    The check carries an operator-readable guidance string so the
    snapshot resolution can be asserted; the policy-level guidance is
    only set when ``guidance_on_policy`` is provided so we can also
    exercise the "policy fallback" path.
    """
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=policy_slug,
        name=policy_slug.upper(),
        remediation_guidance=guidance_on_policy,
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=check_slug,
        title=check_slug,
        kind="package_installed",
        definition={"package": "definitely-not-installed-pkg"},
        remediation_guidance=guidance_on_check,
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
        .one()
    )
    return evidence


def _passing_evidence(db, admin_user, host) -> CompliancePolicyEvidence:
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="pra167-pass",
        name="PRA167 PASS",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="pkg-present",
        title="present",
        kind="package_installed",
        definition={"package": "is-installed-pkg"},
    )
    pkg = Package(
        system_id=host.id,
        name="is-installed-pkg",
        installed_version="1.0",
        package_type="apt",
    )
    db.add(pkg)
    db.flush()
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    return (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == host.id,
            CompliancePolicyEvidence.verdict == "pass",
        )
        .one()
    )


# ---------------------------------------------------------------------------
# Creation + snapshot semantics
# ---------------------------------------------------------------------------


def test_create_request_from_failing_evidence_snapshots_context(
    db, admin_user, host, capture_audit
):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db,
        actor_user_id=admin_user.id,
        actor_username="admintest",
        actor_ip="10.0.0.5",
        evidence_id=evidence.id,
        justification="open per audit finding 2026-Q2-007",
    )
    assert row.id is not None
    assert row.state == STATE_REQUESTED
    assert row.requested_by == admin_user.id
    assert row.policy_id == evidence.policy_id
    assert row.check_id == evidence.check_id
    assert row.system_id == evidence.system_id
    assert row.evidence_id == evidence.id
    # Snapshot identity comes from the evidence row, not the live policy.
    assert row.policy_slug == evidence.policy_slug
    assert row.policy_version == evidence.policy_version
    assert row.check_slug == evidence.check_slug
    assert row.check_kind == evidence.check_kind
    assert row.evaluation_run_id == evidence.evaluation_run_id
    assert row.verdict_snapshot == "fail"
    assert row.severity_snapshot == evidence.severity
    # Check-level guidance wins over policy fallback.
    assert row.remediation_guidance_snapshot == "apt-get install -y missing-pkg"
    assert row.justification == "open per audit finding 2026-Q2-007"
    # Audit event fires AFTER commit, with no ``db=`` arg (session-boundary lock).
    created = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_REQUESTED)
    assert len(created) == 1
    call = created[0]
    assert "db" not in call
    assert call["target_kind"] == "compliance_remediation_request"
    assert call["target_id"] == str(row.id)
    assert call["target_system_id"] == host.id
    ctx = call["context"]
    assert ctx["state"] == STATE_REQUESTED
    assert ctx["policy_slug"] == evidence.policy_slug
    assert ctx["has_guidance_snapshot"] is True


def test_create_request_uses_policy_guidance_when_check_has_none(db, admin_user, host):
    evidence = _failing_evidence(
        db,
        admin_user,
        host,
        policy_slug="policy-fallback",
        check_slug="no-check-guidance",
        guidance_on_check=None,
        guidance_on_policy="see runbook/runbook.md",
    )
    row = compliance_remediation_service.create_request(
        db, actor_user_id=admin_user.id, evidence_id=evidence.id
    )
    assert row.remediation_guidance_snapshot == "see runbook/runbook.md"


def test_create_request_snapshot_survives_check_delete(db, admin_user, host):
    """Editing/deleting the source check after the snapshot is taken
    must not corrupt the request's snapshot identity. ``check_id``
    SET NULLs but ``check_slug``/``check_kind`` remain readable.
    """
    evidence = _failing_evidence(db, admin_user, host)
    check_id = evidence.check_id
    row = compliance_remediation_service.create_request(
        db, actor_user_id=admin_user.id, evidence_id=evidence.id
    )
    compliance_service.delete_check(db, check_id, actor_user_id=admin_user.id)
    db.refresh(row)
    assert row.check_id is None
    assert row.check_slug  # snapshot identity still present
    assert row.check_kind == "package_installed"
    assert row.policy_slug == evidence.policy_slug


# ---------------------------------------------------------------------------
# Invalid reference handling
# ---------------------------------------------------------------------------


def test_create_request_unknown_evidence_raises_not_found(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_service.create_request(
            db, actor_user_id=admin_user.id, evidence_id=999_999
        )
    assert "not found" in str(ei.value)


def test_create_request_rejects_non_failing_verdict(db, admin_user, host):
    evidence = _passing_evidence(db, admin_user, host)
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_service.create_request(
            db, actor_user_id=admin_user.id, evidence_id=evidence.id
        )
    assert "verdict='fail'" in str(ei.value) or "fail" in str(ei.value)


def test_create_request_rejects_unknown_actor(db, admin_user, host):
    evidence = _failing_evidence(db, admin_user, host)
    with pytest.raises(ComplianceError):
        compliance_remediation_service.create_request(
            db, actor_user_id=999_999, evidence_id=evidence.id
        )


def test_create_request_rejects_overlong_justification(db, admin_user, host):
    evidence = _failing_evidence(db, admin_user, host)
    with pytest.raises(ComplianceError):
        compliance_remediation_service.create_request(
            db,
            actor_user_id=admin_user.id,
            evidence_id=evidence.id,
            justification="x" * 5000,
        )


def test_create_request_rejects_non_positive_evidence_id(db, admin_user):
    with pytest.raises(ComplianceError):
        compliance_remediation_service.create_request(
            db, actor_user_id=admin_user.id, evidence_id=0
        )


# ---------------------------------------------------------------------------
# Read / list
# ---------------------------------------------------------------------------


def test_list_requests_filters_by_state(db, admin_user, maintainer_user, host):
    evidence = _failing_evidence(db, admin_user, host, policy_slug="list-p1")
    r1 = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, r1.id, actor_user_id=admin_user.id
    )

    ev2 = _failing_evidence(db, admin_user, host, policy_slug="list-p2")
    compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=ev2.id
    )

    pending_rows, total = compliance_remediation_service.list_requests(
        db, state="requested"
    )
    assert total == 1
    assert all(r.state == "requested" for r in pending_rows)

    approved_rows, _ = compliance_remediation_service.list_requests(
        db, state="approved"
    )
    assert any(r.id == r1.id for r in approved_rows)


def test_list_requests_filters_by_policy_and_system(
    db, admin_user, maintainer_user, host
):
    evidence = _failing_evidence(db, admin_user, host, policy_slug="list-pol-sys")
    compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    rows, total = compliance_remediation_service.list_requests(
        db, policy_id=evidence.policy_id, system_id=host.id
    )
    assert total == 1
    assert rows[0].system_id == host.id


def test_list_requests_rejects_bad_state_filter(db):
    with pytest.raises(ComplianceError):
        compliance_remediation_service.list_requests(db, state="zombie")


# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------


def test_approve_request_flips_state_and_emits_audit(
    db, admin_user, maintainer_user, host, capture_audit
):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    approved = compliance_remediation_service.approve_request(
        db,
        row.id,
        actor_user_id=admin_user.id,
        actor_username="admintest",
        decided_reason="approved per CC6.2 change record 2026-05-16",
    )
    assert approved.state == STATE_APPROVED
    assert approved.decided_by == admin_user.id
    assert isinstance(approved.decided_at, datetime)
    assert approved.decided_reason.startswith("approved")
    events = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_APPROVED)
    assert len(events) == 1
    assert events[0]["context"]["separation_of_duties_enforced"] is True
    assert "db" not in events[0]


def test_approve_rejects_when_actor_is_requester(db, admin_user, maintainer_user, host):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_service.approve_request(
            db, row.id, actor_user_id=maintainer_user.id
        )
    assert "separation of duties" in str(ei.value)


def test_reject_request_flips_state_and_emits_audit(
    db, admin_user, maintainer_user, host, capture_audit
):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    rejected = compliance_remediation_service.reject_request(
        db, row.id, actor_user_id=admin_user.id, decided_reason="duplicate"
    )
    assert rejected.state == STATE_REJECTED
    assert rejected.decided_by == admin_user.id
    events = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_REJECTED)
    assert len(events) == 1


def test_reject_refuses_self_reject(db, admin_user, maintainer_user, host):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    with pytest.raises(ComplianceError):
        compliance_remediation_service.reject_request(
            db, row.id, actor_user_id=maintainer_user.id
        )


def test_cancel_request_allows_requester_self_withdraw(
    db, admin_user, maintainer_user, host, capture_audit
):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    cancelled = compliance_remediation_service.cancel_request(
        db, row.id, actor_user_id=maintainer_user.id, decided_reason="withdrew"
    )
    assert cancelled.state == STATE_CANCELLED
    assert cancelled.decided_by == maintainer_user.id
    events = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_CANCELLED)
    assert events and events[0]["context"]["self_cancel"] is True


def test_cancel_request_allows_third_party_admin(
    db, admin_user, maintainer_user, host, capture_audit
):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    cancelled = compliance_remediation_service.cancel_request(
        db, row.id, actor_user_id=admin_user.id
    )
    assert cancelled.state == STATE_CANCELLED
    events = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_CANCELLED)
    assert events and events[0]["context"]["self_cancel"] is False


def test_terminal_state_refuses_further_transition(
    db, admin_user, maintainer_user, host
):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, row.id, actor_user_id=admin_user.id
    )
    for fn in (
        compliance_remediation_service.approve_request,
        compliance_remediation_service.reject_request,
        compliance_remediation_service.cancel_request,
    ):
        with pytest.raises(ComplianceError) as ei:
            fn(db, row.id, actor_user_id=admin_user.id)
        assert "state" in str(ei.value)


def test_state_transition_unknown_request_returns_not_found(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_service.approve_request(
            db, 999_999, actor_user_id=admin_user.id
        )
    assert "not found" in str(ei.value)


# ---------------------------------------------------------------------------
# Read envelope timestamps
# ---------------------------------------------------------------------------


def test_read_envelope_serializes_absolute_utc(db, admin_user, host):
    evidence = _failing_evidence(db, admin_user, host)
    row = compliance_remediation_service.create_request(
        db, actor_user_id=admin_user.id, evidence_id=evidence.id
    )
    env = compliance_remediation_service.remediation_request_read_envelope(row)
    assert env["created_at"].endswith("Z")
    assert env["updated_at"].endswith("Z")
    assert env["decided_at"] is None
    assert env["state"] == STATE_REQUESTED
    assert env["runner_owner"]  # always present


# ---------------------------------------------------------------------------
# Compatibility — PRA-165/PRA-166 evidence-row export must be untouched
# ---------------------------------------------------------------------------


def test_evidence_export_row_unaffected_by_remediation_request(
    db, admin_user, maintainer_user, host
):
    """Opening a remediation request must not mutate any evidence row
    or its export-shape: the PRA-165 Slice 3 wire contract is frozen.
    """
    evidence = _failing_evidence(db, admin_user, host)
    before = compliance_evaluation_service.evidence_export_row(evidence)
    compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    db.refresh(evidence)
    after = compliance_evaluation_service.evidence_export_row(evidence)
    assert before == after
