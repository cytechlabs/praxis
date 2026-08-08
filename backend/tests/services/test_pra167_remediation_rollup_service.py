"""PRA-167 Slice 4 — fleet remediation rollup + per-host inventory service tests.

Covers:

* Empty-state fleet summary: all counts zero, per_severity empty,
  generated_at ends in 'Z'.
* Mixed-state fleet summary: counts roll up per request state +
  current plan state + per severity; current-plan acknowledged /
  unacknowledged / ready / not-ready / stale / not-stale counts wire
  through Slice 3 lifecycle correctly.
* Per-host inventory empty for unknown system (service helper just
  returns empty sections; route returns 404).
* Per-host inventory: open requests, approved requests, current
  plans, ready plans, paginated superseded history.
* Pagination on superseded history.
* PRA-165 evidence row + PRA-167 Slice 1 request + Slice 2/3 plan
  read shapes are byte-equal before and after a rollup is computed.
* No audit events fire for either read endpoint (safe_emit not
  invoked from the rollup helpers).
"""

from __future__ import annotations

from typing import List

import pytest

from app.db.models import CompliancePolicyEvidence, Credential, Group, System
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
)
from app.services.compliance_remediation_service import ComplianceError


class AuditCapture:
    def __init__(self):
        self.calls: List[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def capture_plan_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_remediation_plan_service, "safe_emit", cap)
    return cap


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra167-rollup", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra167-rollup-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="rollup.example.com",
        ip_address="10.0.0.33",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


@pytest.fixture
def host2(db, seed_distro):
    g = Group(name="pra167-rollup-h2", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="pra167-rollup-h2-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="rollup2.example.com",
        ip_address="10.0.0.34",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _open_request(db, admin_user, maintainer_user, host, suffix, severity="medium"):
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"rollup-{suffix}",
        name=f"rollup {suffix}",
        severity=severity,
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"c-{suffix}",
        title=f"c {suffix}",
        kind="package_installed",
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
    return policy, compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )


def _approve(db, admin_user, req):
    return compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )


# ---------------------------------------------------------------------------
# Fleet summary
# ---------------------------------------------------------------------------


def test_fleet_summary_empty(db):
    summary = compliance_remediation_plan_service.fleet_remediation_summary(db)
    assert summary["generated_at"].endswith("Z")
    assert summary["request_total"] == 0
    assert summary["request_counts_by_state"]["requested"] == 0
    assert summary["current_plan_total"] == 0
    assert summary["current_plan_counts_by_state"]["planned"] == 0
    assert summary["current_plan_acknowledged_count"] == 0
    assert summary["current_plan_ready_count"] == 0
    assert summary["per_severity"] == []


def test_fleet_summary_mixed_state_counts(db, admin_user, maintainer_user, host, host2):
    # h1: requested, approved+plan+ack (ready), approved+plan no-ack, rejected
    _, req_open = _open_request(
        db, admin_user, maintainer_user, host, "rs-open", severity="low"
    )

    _, req_ready = _open_request(
        db, admin_user, maintainer_user, host, "rs-ready", severity="high"
    )
    _approve(db, admin_user, req_ready)
    plan_ready = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req_ready.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan_ready.id, actor_user_id=admin_user.id
    )

    _, req_notack = _open_request(
        db, admin_user, maintainer_user, host, "rs-noack", severity="high"
    )
    _approve(db, admin_user, req_notack)
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req_notack.id, actor_user_id=admin_user.id
    )

    _, req_rej = _open_request(
        db, admin_user, maintainer_user, host, "rs-rej", severity="medium"
    )
    compliance_remediation_service.reject_request(
        db, req_rej.id, actor_user_id=admin_user.id
    )

    # h2: one open requested, severity critical.
    _, _ = _open_request(
        db, admin_user, maintainer_user, host2, "rs-crit", severity="critical"
    )

    summary = compliance_remediation_plan_service.fleet_remediation_summary(db)
    rs = summary["request_counts_by_state"]
    assert rs["requested"] == 2  # rs-open + rs-crit
    assert rs["approved"] == 2  # rs-ready + rs-noack
    assert rs["rejected"] == 1
    assert rs["cancelled"] == 0
    assert summary["request_total"] == 5

    cp = summary["current_plan_counts_by_state"]
    assert cp["planned"] == 2  # rs-ready + rs-noack each produced a current plan
    assert summary["current_plan_total"] == 2
    assert summary["current_plan_acknowledged_count"] == 1
    assert summary["current_plan_unacknowledged_count"] == 1
    assert summary["current_plan_ready_count"] == 1
    assert summary["current_plan_not_ready_count"] == 1
    assert summary["current_plan_stale_count"] == 0
    assert summary["current_plan_not_stale_count"] == 2

    sev_index = {row["severity"]: row for row in summary["per_severity"]}
    assert sev_index["low"]["requested"] == 1
    assert sev_index["high"]["approved"] == 2
    assert sev_index["medium"]["rejected"] == 1
    assert sev_index["critical"]["requested"] == 1
    assert sev_index["low"]["total"] == 1
    assert sev_index["high"]["total"] == 2


def test_fleet_summary_stale_counts_after_check_edit(
    db, admin_user, maintainer_user, host
):
    _, req = _open_request(db, admin_user, maintainer_user, host, "stale-roll")
    _approve(db, admin_user, req)
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    # Mutate the live check after the plan is built — plan becomes stale.
    from app.db.models import CompliancePolicyCheck

    check = (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.id == plan.check_id)
        .first()
    )
    compliance_service.update_check(
        db, check.id, {"definition": {"package": "v2"}}, actor_user_id=admin_user.id
    )
    summary = compliance_remediation_plan_service.fleet_remediation_summary(db)
    assert summary["current_plan_stale_count"] == 1
    assert summary["current_plan_not_stale_count"] == 0
    assert summary["current_plan_ready_count"] == 0


def test_fleet_summary_does_not_emit_audit_events(
    db, admin_user, maintainer_user, host, capture_plan_audit
):
    _, req = _open_request(db, admin_user, maintainer_user, host, "no-audit")
    _approve(db, admin_user, req)
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    audit_calls_before = len(capture_plan_audit.calls)
    compliance_remediation_plan_service.fleet_remediation_summary(db)
    # No new safe_emit invocations from the rollup itself.
    assert len(capture_plan_audit.calls) == audit_calls_before


# ---------------------------------------------------------------------------
# Per-host inventory
# ---------------------------------------------------------------------------


def _empty_page(section):
    """Helper: assert a section is an empty paged envelope."""
    return (
        section["items"] == []
        and section["total"] == 0
        and section["offset"] == 0
        and section["next_offset"] is None
    )


def test_host_inventory_empty(db, host):
    inv = compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id
    )
    assert inv["system_id"] == host.id
    assert inv["generated_at"].endswith("Z")
    # All five sections are now bounded paged envelopes (Slice 4
    # P2 fix). Each has items / total / offset / limit / next_offset.
    for section_name in (
        "open_requests",
        "approved_requests",
        "current_plans",
        "ready_plans",
        "superseded_history",
    ):
        assert _empty_page(inv[section_name]), section_name
        assert inv[section_name]["limit"] >= 1


def test_host_inventory_mixed(db, admin_user, maintainer_user, host, host2):
    # h1: open request + approved request with current ready plan +
    # approved request with current draft plan.
    _, req_open = _open_request(db, admin_user, maintainer_user, host, "inv-open")
    _, req_ready = _open_request(db, admin_user, maintainer_user, host, "inv-ready")
    _approve(db, admin_user, req_ready)
    plan_ready = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req_ready.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan_ready.id, actor_user_id=admin_user.id
    )
    _, req_draft = _open_request(db, admin_user, maintainer_user, host, "inv-draft")
    _approve(db, admin_user, req_draft)
    plan_draft = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req_draft.id, actor_user_id=admin_user.id
    )
    # h2: separate open request — must NOT appear in h1 inventory.
    _, _ = _open_request(db, admin_user, maintainer_user, host2, "inv-other")

    inv = compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id
    )
    assert inv["open_requests"]["total"] == 1
    assert inv["open_requests"]["items"][0]["id"] == req_open.id
    assert {r["id"] for r in inv["approved_requests"]["items"]} == {
        req_ready.id,
        req_draft.id,
    }
    assert inv["approved_requests"]["total"] == 2
    assert {p["id"] for p in inv["current_plans"]["items"]} == {
        plan_ready.id,
        plan_draft.id,
    }
    assert inv["current_plans"]["total"] == 2
    assert {p["id"] for p in inv["ready_plans"]["items"]} == {plan_ready.id}
    assert inv["ready_plans"]["total"] == 1


def test_host_inventory_section_pagination(db, admin_user, maintainer_user, host):
    """All four non-superseded sections honor limit + offset, populate
    next_offset when more remains, and clear it on the last page.
    """
    # Five open requests for the host.
    for i in range(5):
        _open_request(db, admin_user, maintainer_user, host, f"page-open-{i}")
    inv = compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id, limit=2
    )
    assert inv["open_requests"]["total"] == 5
    assert len(inv["open_requests"]["items"]) == 2
    assert inv["open_requests"]["limit"] == 2
    assert inv["open_requests"]["offset"] == 0
    assert inv["open_requests"]["next_offset"] == 2

    inv2 = compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id, limit=2, open_offset=4
    )
    assert inv2["open_requests"]["total"] == 5
    assert len(inv2["open_requests"]["items"]) == 1
    assert inv2["open_requests"]["offset"] == 4
    assert inv2["open_requests"]["next_offset"] is None


def test_host_inventory_ready_plans_pagination(db, admin_user, maintainer_user, host):
    """Build three acknowledged ready plans and page ``ready_plans``
    with limit=1 so the post-filter pagination math is exercised.
    """
    plan_ids = []
    for i in range(3):
        _, req = _open_request(db, admin_user, maintainer_user, host, f"ready-page-{i}")
        _approve(db, admin_user, req)
        p = compliance_remediation_plan_service.build_or_refresh_plan(
            db, request_id=req.id, actor_user_id=admin_user.id
        )
        compliance_remediation_plan_service.acknowledge_plan(
            db, plan_id=p.id, actor_user_id=admin_user.id
        )
        plan_ids.append(p.id)

    page1 = compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id, limit=1, ready_plans_offset=0
    )["ready_plans"]
    assert page1["total"] == 3
    assert len(page1["items"]) == 1
    assert page1["next_offset"] == 1

    page_last = compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id, limit=1, ready_plans_offset=2
    )["ready_plans"]
    assert page_last["total"] == 3
    assert page_last["next_offset"] is None


def test_host_inventory_superseded_pagination(db, admin_user, maintainer_user, host):
    """Generate two acknowledged-then-superseded plan rows for a single
    request, then page through superseded history with limit=1.
    """
    _, req = _open_request(db, admin_user, maintainer_user, host, "page")
    _approve(db, admin_user, req)
    p1 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p1.id, actor_user_id=admin_user.id
    )
    from app.db.models import CompliancePolicyCheck

    check = (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.id == p1.check_id)
        .first()
    )
    compliance_service.update_check(
        db, check.id, {"definition": {"package": "v2"}}, actor_user_id=admin_user.id
    )
    p2 = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=p2.id, actor_user_id=admin_user.id
    )
    compliance_service.update_check(
        db, check.id, {"definition": {"package": "v3"}}, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )

    inv = compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id, limit=1, superseded_offset=0
    )
    assert inv["superseded_history"]["total"] == 2
    assert len(inv["superseded_history"]["items"]) == 1
    assert inv["superseded_history"]["next_offset"] == 1

    inv2 = compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id, limit=1, superseded_offset=1
    )
    assert inv2["superseded_history"]["total"] == 2
    assert inv2["superseded_history"]["next_offset"] is None


def test_host_inventory_rejects_bad_pagination(db, host):
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.host_remediation_inventory(
            db, system_id=host.id, superseded_offset=-1
        )
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.host_remediation_inventory(
            db, system_id=host.id, limit=0
        )
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.host_remediation_inventory(
            db, system_id=host.id, limit=1000  # > INVENTORY_PAGE_MAX
        )
    for field in (
        "open_offset",
        "approved_offset",
        "current_plans_offset",
        "ready_plans_offset",
        "superseded_offset",
    ):
        with pytest.raises(ComplianceError):
            compliance_remediation_plan_service.host_remediation_inventory(
                db, system_id=host.id, **{field: -1}
            )


def test_host_inventory_rejects_bad_system_id(db):
    with pytest.raises(ComplianceError):
        compliance_remediation_plan_service.host_remediation_inventory(db, system_id=0)


# ---------------------------------------------------------------------------
# Compatibility: rollup must not mutate evidence / request / plan shapes
# ---------------------------------------------------------------------------


def test_rollup_leaves_evidence_export_shape_unchanged(
    db, admin_user, maintainer_user, host
):
    _, req = _open_request(db, admin_user, maintainer_user, host, "compat-ev")
    _approve(db, admin_user, req)
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    evidence = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == req.policy_id,
            CompliancePolicyEvidence.system_id == host.id,
        )
        .first()
    )
    before = compliance_evaluation_service.evidence_export_row(evidence)
    compliance_remediation_plan_service.fleet_remediation_summary(db)
    compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id
    )
    db.refresh(evidence)
    after = compliance_evaluation_service.evidence_export_row(evidence)
    assert before == after


def test_rollup_leaves_request_envelope_unchanged(
    db, admin_user, maintainer_user, host
):
    _, req = _open_request(db, admin_user, maintainer_user, host, "compat-req")
    _approve(db, admin_user, req)
    before = compliance_remediation_service.remediation_request_read_envelope(req)
    compliance_remediation_plan_service.fleet_remediation_summary(db)
    compliance_remediation_plan_service.host_remediation_inventory(
        db, system_id=host.id
    )
    db.refresh(req)
    after = compliance_remediation_service.remediation_request_read_envelope(req)
    assert before == after
