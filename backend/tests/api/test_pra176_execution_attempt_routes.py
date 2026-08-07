"""PRA-176 Slice 1 — execution-attempt route tests.

Covers:

* POST /compliance/remediation-executions
  - admin happy path returns 201 + attempt envelope with UTC stamps.
  - maintainer is blocked (admin-only — matches plan acknowledge RBAC).
  - auditor is blocked.
  - unknown plan returns 404.
  - readiness-gate failure returns 422 with the service error message.
* GET /compliance/remediation-executions
  - admin / auditor can read; filters work; bad state filter is 422.
* GET /compliance/remediation-executions/{id}
  - 200 for any authed user; 404 on miss.
* PRA-165 + PRA-167 routes still work after the executions router is
  mounted (compatibility).
"""

from __future__ import annotations

import pytest

from app.db.models import CompliancePolicyEvidence
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
)


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _pra281_grant_scope(db, host, maintainer_user, auditor_user):
    """PRA-281: compliance routes are now fleet-scoped. These pre-scope tests
    drive the compliance flow as a maintainer/auditor, so grant those non-admin
    actors access to this file's single host (admin stays tenant-wide)."""
    from app.db.access_models import AccessGrant, FleetRole

    role = FleetRole(
        name=f"pra281-legacy-scope-{host.id}",
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    for u in (maintainer_user, auditor_user):
        db.add(
            AccessGrant(
                user_id=u.id,
                system_id=host.id,
                fleet_role_id=role.id,
                login=u.username,
            )
        )
    db.flush()


@pytest.fixture
def host(db, seed_distro):
    from app.db.models import Credential, Group, System

    g = Group(name="pra176-routes", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra176-routes-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra176-routes.example.com",
        ip_address="10.0.0.177",
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
def acknowledged_plan_id(db, admin_user, maintainer_user, host):
    """Build the full PRA-167 chain end-to-end (policy → check →
    evidence → request → approve → plan → acknowledge) and return the
    acknowledged plan id ready for an execution-attempt route test.
    """
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="exec-routes",
        name="Exec Routes",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="missing-pkg",
        title="missing pkg",
        kind="package_installed",
        definition={"package": "missing-route-pkg"},
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
    return plan.id


# ---------------------------------------------------------------------------
# POST /compliance/remediation-executions
# ---------------------------------------------------------------------------


def test_create_attempt_201(client, admin_user, acknowledged_plan_id):
    token = _login(client, admin_user)
    res = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(token),
        json={"plan_id": acknowledged_plan_id},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["plan_id"] == acknowledged_plan_id
    assert body["state"] == "pending"
    assert body["plan_kind_snapshot"] == "package_install_preview"
    assert body["package_name"] == "missing-route-pkg"
    assert body["transport"] is None
    assert body["failure_reason"] is None
    assert body["error_message"] is None
    assert body["dispatched_at"] is None
    assert body["completed_at"] is None
    assert body["created_at"].endswith("Z")
    assert body["approval_decided_at"].endswith("Z")
    assert body["created_by"] == admin_user.id


def test_create_attempt_blocks_maintainer(
    client, maintainer_user, acknowledged_plan_id
):
    """Admin-only — matches plan acknowledge RBAC."""
    token = _login(client, maintainer_user)
    res = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(token),
        json={"plan_id": acknowledged_plan_id},
    )
    assert res.status_code in (401, 403), res.text


def test_create_attempt_blocks_auditor(client, auditor_user, acknowledged_plan_id):
    token = _login(client, auditor_user)
    res = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(token),
        json={"plan_id": acknowledged_plan_id},
    )
    assert res.status_code in (401, 403), res.text


def test_create_attempt_unknown_plan_404(client, admin_user):
    token = _login(client, admin_user)
    res = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(token),
        json={"plan_id": 999_999},
    )
    assert res.status_code == 404, res.text


def test_create_attempt_unacknowledged_plan_422(
    client, db, admin_user, maintainer_user, host
):
    """Build but do NOT acknowledge — POST should fail closed with 422."""
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="exec-noack-route",
        name="noack",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="np",
        title="np",
        kind="package_installed",
        definition={"package": "missing-noack-route"},
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
    req = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    token = _login(client, admin_user)
    res = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(token),
        json={"plan_id": plan.id},
    )
    assert res.status_code == 422, res.text
    assert "not acknowledged" in res.json()["detail"]


def test_create_attempt_rejects_bad_plan_id_body(client, admin_user):
    token = _login(client, admin_user)
    res = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(token),
        json={"plan_id": 0},
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# GET list + filters
# ---------------------------------------------------------------------------


def test_list_attempts_admin_and_auditor(
    client, admin_user, auditor_user, acknowledged_plan_id
):
    a_token = _login(client, admin_user)
    aid = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(a_token),
        json={"plan_id": acknowledged_plan_id},
    ).json()["id"]
    # Admin lists.
    res = client.get("/compliance/remediation-executions", headers=_bearer(a_token))
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    assert any(item["id"] == aid for item in body["items"])
    # Auditor can also list.
    aud_token = _login(client, auditor_user)
    res = client.get("/compliance/remediation-executions", headers=_bearer(aud_token))
    assert res.status_code == 200


def test_list_attempts_filter_by_plan(client, admin_user, acknowledged_plan_id):
    token = _login(client, admin_user)
    aid = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(token),
        json={"plan_id": acknowledged_plan_id},
    ).json()["id"]
    res = client.get(
        f"/compliance/remediation-executions?plan_id={acknowledged_plan_id}",
        headers=_bearer(token),
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == aid


def test_list_attempts_rejects_bad_state(client, admin_user):
    token = _login(client, admin_user)
    res = client.get(
        "/compliance/remediation-executions?state=zombie",
        headers=_bearer(token),
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# GET /{id}
# ---------------------------------------------------------------------------


def test_get_attempt_404(client, admin_user):
    token = _login(client, admin_user)
    res = client.get(
        "/compliance/remediation-executions/999999", headers=_bearer(token)
    )
    assert res.status_code == 404


def test_get_attempt_200_for_auditor(
    client, admin_user, auditor_user, acknowledged_plan_id
):
    a_token = _login(client, admin_user)
    aid = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(a_token),
        json={"plan_id": acknowledged_plan_id},
    ).json()["id"]
    aud_token = _login(client, auditor_user)
    res = client.get(
        f"/compliance/remediation-executions/{aid}", headers=_bearer(aud_token)
    )
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == aid
    assert body["state"] == "pending"


# ---------------------------------------------------------------------------
# Compatibility — PRA-165 / PRA-167 routes unaffected
# ---------------------------------------------------------------------------


def test_pra165_policies_route_still_works(authed_client):
    res = authed_client.post(
        "/compliance/policies",
        json={"slug": "pra176-compat", "name": "PRA176 Compat"},
    )
    assert res.status_code == 201


def test_pra167_request_and_plan_routes_still_work(
    client, admin_user, maintainer_user, acknowledged_plan_id
):
    """Reading the request + plan after an attempt is created must
    return the same wire shape as before."""
    a_token = _login(client, admin_user)
    plan_res = client.get(
        f"/compliance/remediation-plans/{acknowledged_plan_id}",
        headers=_bearer(a_token),
    )
    assert plan_res.status_code == 200
    plan_before = plan_res.json()
    rid = plan_before["request_id"]
    req_res = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(a_token)
    )
    assert req_res.status_code == 200
    req_before = req_res.json()
    # Create the attempt.
    res = client.post(
        "/compliance/remediation-executions",
        headers=_bearer(a_token),
        json={"plan_id": acknowledged_plan_id},
    )
    assert res.status_code == 201
    # Re-read; should be byte-equal.
    plan_after = client.get(
        f"/compliance/remediation-plans/{acknowledged_plan_id}",
        headers=_bearer(a_token),
    ).json()
    req_after = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(a_token)
    ).json()
    assert plan_after == plan_before
    assert req_after == req_before
