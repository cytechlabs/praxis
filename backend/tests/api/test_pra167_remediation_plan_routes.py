"""PRA-167 Slice 2 — remediation plan preview route tests.

Covers:

* POST /compliance/remediation-requests/{id}/plan — admin/maintainer
  may build; auditor blocked; non-approved request returns 422;
  unknown request returns 404; rebuild returns the same row id.
* GET /compliance/remediation-requests/{id}/plan — any authed reads;
  404 for unknown request or no-plan-yet.
* GET /compliance/remediation-plans (list + filter) — any authed.
* GET /compliance/remediation-plans/{id} — any authed; 404 on miss.
* Existing PRA-165 + PRA-167 Slice 1 routes still work alongside
  the new plan router (compatibility).
"""

from __future__ import annotations

import pytest

from app.db.models import CompliancePolicyEvidence
from app.services import compliance_evaluation_service, compliance_service


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

    g = Group(name="pra167-plan-routes", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="pra167-plan-routes-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="plan-routes.example.com",
        ip_address="10.0.0.44",
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
def failing_evidence(db, admin_user, host) -> CompliancePolicyEvidence:
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="plan-routes-policy",
        name="Plan Routes",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="missing-pkg",
        title="missing pkg",
        kind="package_installed",
        definition={"package": "missing-pkg"},
    )
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
        .one()
    )


def _approved_request_id(client, maintainer_user, admin_user, failing_evidence):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    a_token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-requests/{rid}/approve",
        headers=_bearer(a_token),
        json={},
    )
    assert res.status_code == 200, res.text
    return rid


# ---------------------------------------------------------------------------
# Build / get on the request sub-resource
# ---------------------------------------------------------------------------


def test_build_plan_201(client, admin_user, maintainer_user, failing_evidence):
    rid = _approved_request_id(client, maintainer_user, admin_user, failing_evidence)
    a_token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-requests/{rid}/plan",
        headers=_bearer(a_token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["request_id"] == rid
    assert body["state"] == "planned"
    assert body["plan_kind"] == "package_install_preview"
    assert isinstance(body["plan_steps"], list) and body["plan_steps"]
    assert body["plan_steps"][0]["action_intent"] == "package_install"
    assert body["created_at"].endswith("Z")
    assert body["updated_at"].endswith("Z")


def test_build_plan_is_idempotent(
    client, admin_user, maintainer_user, failing_evidence
):
    rid = _approved_request_id(client, maintainer_user, admin_user, failing_evidence)
    a_token = _login(client, admin_user)
    r1 = client.post(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    ).json()
    r2 = client.post(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    ).json()
    assert r1["id"] == r2["id"]


def test_build_plan_unapproved_request_returns_422(
    client, maintainer_user, failing_evidence
):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    # No approve.
    res = client.post(
        f"/compliance/remediation-requests/{rid}/plan",
        headers=_bearer(m_token),
    )
    assert res.status_code == 422
    assert "approved" in res.json()["detail"]


def test_build_plan_unknown_request_returns_404(client, admin_user):
    a_token = _login(client, admin_user)
    res = client.post(
        "/compliance/remediation-requests/999999/plan",
        headers=_bearer(a_token),
    )
    assert res.status_code == 404


def test_build_plan_requires_write_role(
    client, auditor_user, admin_user, maintainer_user, failing_evidence
):
    rid = _approved_request_id(client, maintainer_user, admin_user, failing_evidence)
    token = _login(client, auditor_user)
    res = client.post(
        f"/compliance/remediation-requests/{rid}/plan",
        headers=_bearer(token),
    )
    assert res.status_code in (401, 403)


def test_get_plan_404_when_no_plan_yet(client, maintainer_user, failing_evidence):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    res = client.get(
        f"/compliance/remediation-requests/{rid}/plan",
        headers=_bearer(m_token),
    )
    assert res.status_code == 404


def test_get_plan_after_build_returns_200(
    client, admin_user, maintainer_user, failing_evidence
):
    rid = _approved_request_id(client, maintainer_user, admin_user, failing_evidence)
    a_token = _login(client, admin_user)
    client.post(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    )
    res = client.get(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    )
    assert res.status_code == 200
    assert res.json()["request_id"] == rid


# ---------------------------------------------------------------------------
# Flat plan resource
# ---------------------------------------------------------------------------


def test_list_plans_endpoint(client, admin_user, maintainer_user, failing_evidence):
    rid = _approved_request_id(client, maintainer_user, admin_user, failing_evidence)
    a_token = _login(client, admin_user)
    client.post(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    )
    res = client.get("/compliance/remediation-plans", headers=_bearer(a_token))
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    assert any(item["request_id"] == rid for item in body["items"])


def test_list_plans_filters_bad_state_422(client, admin_user):
    a_token = _login(client, admin_user)
    res = client.get(
        "/compliance/remediation-plans?state=zombie", headers=_bearer(a_token)
    )
    assert res.status_code == 422


def test_get_plan_by_id_404(client, admin_user):
    a_token = _login(client, admin_user)
    res = client.get("/compliance/remediation-plans/999999", headers=_bearer(a_token))
    assert res.status_code == 404


def test_auditor_can_read_plan_list_and_detail(
    client, auditor_user, admin_user, maintainer_user, failing_evidence
):
    rid = _approved_request_id(client, maintainer_user, admin_user, failing_evidence)
    a_token = _login(client, admin_user)
    pid = client.post(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    ).json()["id"]
    aud_token = _login(client, auditor_user)
    page = client.get("/compliance/remediation-plans", headers=_bearer(aud_token))
    assert page.status_code == 200
    detail = client.get(
        f"/compliance/remediation-plans/{pid}", headers=_bearer(aud_token)
    )
    assert detail.status_code == 200


# ---------------------------------------------------------------------------
# Compatibility: PRA-165 + PRA-167 Slice 1 wire shapes unchanged
# ---------------------------------------------------------------------------


def test_pra165_policy_route_unaffected(authed_client):
    res = authed_client.post(
        "/compliance/policies",
        json={"slug": "plan-compat", "name": "Plan Compat"},
    )
    assert res.status_code == 201


def test_slice1_request_envelope_unchanged_after_plan_build(
    client, admin_user, maintainer_user, failing_evidence
):
    rid = _approved_request_id(client, maintainer_user, admin_user, failing_evidence)
    a_token = _login(client, admin_user)
    before = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(a_token)
    ).json()
    client.post(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    )
    after = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(a_token)
    ).json()
    # Only updated_at could legitimately change if the row was
    # touched — but Slice 2 must NOT touch the request row.
    assert before == after
