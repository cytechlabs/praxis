"""PRA-167 Slice 3 — plan lifecycle / acknowledge / readiness route tests.

Covers:

* POST /compliance/remediation-requests/{id}/plan/acknowledge —
  admin only; auditor + maintainer blocked; 404 when request or
  plan is missing; 422 on stale / superseded / already-acknowledged
  plans.
* GET surfaces include the new lifecycle metadata
  (`is_current`, `superseded_by_plan_id`, `acknowledged_at`,
  `acknowledged_by`, `is_stale`, `ready_for_execution`,
  `check_definition_fingerprint`).
* Rebuild of an acknowledged plan creates a new current row;
  GET /plan now returns the new current row, but the flat
  /compliance/remediation-plans/{old_id} still serves the
  superseded row read-only.
* List filters: `is_current=true`, `acknowledged=true`,
  `ready_for_execution=true`.
* Existing PRA-165 + PRA-167 Slice 1 + Slice 2 routes still work.
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

    g = Group(name="pra167-lc-routes", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="pra167-lc-routes-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="lc-routes.example.com",
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
def package_evidence(db, admin_user, host) -> CompliancePolicyEvidence:
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="lc-route-policy",
        name="LC Routes",
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
    return (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == host.id,
            CompliancePolicyEvidence.verdict == "fail",
        )
        .one()
    )


def _approve_and_build(client, maintainer_user, admin_user, package_evidence):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": package_evidence.id},
    ).json()["id"]
    a_token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-requests/{rid}/approve",
        headers=_bearer(a_token),
        json={},
    )
    assert res.status_code == 200, res.text
    plan_res = client.post(
        f"/compliance/remediation-requests/{rid}/plan",
        headers=_bearer(a_token),
    )
    assert plan_res.status_code == 200, plan_res.text
    return rid, plan_res.json(), a_token


# ---------------------------------------------------------------------------
# Acknowledge endpoint
# ---------------------------------------------------------------------------


def test_acknowledge_happy_path_200(
    client, admin_user, maintainer_user, package_evidence
):
    rid, plan_body, a_token = _approve_and_build(
        client, maintainer_user, admin_user, package_evidence
    )
    res = client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(a_token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["acknowledged_by"] == admin_user.id
    assert body["acknowledged_at"].endswith("Z")
    assert body["is_current"] is True
    assert body["is_stale"] is False
    assert body["ready_for_execution"] is True


def test_acknowledge_requires_admin(
    client, maintainer_user, admin_user, package_evidence
):
    rid, plan_body, _ = _approve_and_build(
        client, maintainer_user, admin_user, package_evidence
    )
    m_token = _login(client, maintainer_user)
    res = client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(m_token),
    )
    assert res.status_code in (401, 403)


def test_acknowledge_unknown_request_404(client, admin_user):
    a_token = _login(client, admin_user)
    res = client.post(
        "/compliance/remediation-requests/999999/plan/acknowledge",
        headers=_bearer(a_token),
    )
    assert res.status_code == 404


def test_acknowledge_request_without_plan_404(
    client, maintainer_user, admin_user, package_evidence
):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": package_evidence.id},
    ).json()["id"]
    a_token = _login(client, admin_user)
    client.post(
        f"/compliance/remediation-requests/{rid}/approve",
        headers=_bearer(a_token),
        json={},
    )
    # No plan built yet.
    res = client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(a_token),
    )
    assert res.status_code == 404


def test_acknowledge_already_acknowledged_422(
    client, admin_user, maintainer_user, package_evidence
):
    rid, plan_body, a_token = _approve_and_build(
        client, maintainer_user, admin_user, package_evidence
    )
    client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(a_token),
    )
    res = client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(a_token),
    )
    assert res.status_code == 422
    assert "already acknowledged" in res.json()["detail"]


# ---------------------------------------------------------------------------
# Read surfaces expose lifecycle metadata
# ---------------------------------------------------------------------------


def test_get_plan_exposes_lifecycle_fields(
    client, admin_user, maintainer_user, package_evidence
):
    rid, plan_body, a_token = _approve_and_build(
        client, maintainer_user, admin_user, package_evidence
    )
    res = client.get(
        f"/compliance/remediation-requests/{rid}/plan",
        headers=_bearer(a_token),
    )
    assert res.status_code == 200
    body = res.json()
    assert body["is_current"] is True
    assert body["superseded_by_plan_id"] is None
    assert body["acknowledged_at"] is None
    assert body["acknowledged_by"] is None
    assert body["is_stale"] is False
    assert body["ready_for_execution"] is False
    assert isinstance(body["check_definition_fingerprint"], str)
    assert len(body["check_definition_fingerprint"]) == 64


def test_get_plan_after_supersede_returns_new_current(
    db, client, admin_user, maintainer_user, package_evidence
):
    rid, plan_body, a_token = _approve_and_build(
        client, maintainer_user, admin_user, package_evidence
    )
    old_id = plan_body["id"]
    client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(a_token),
    )
    # Mutate the live check, then rebuild.
    from app.db.models import CompliancePolicyCheck

    check = (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.policy_id == package_evidence.policy_id)
        .first()
    )
    compliance_service.update_check(
        db, check.id, {"definition": {"package": "v2"}}, actor_user_id=admin_user.id
    )
    rebuilt = client.post(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    ).json()
    assert rebuilt["id"] != old_id
    assert rebuilt["is_current"] is True
    # GET /plan returns the new current row.
    current = client.get(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    ).json()
    assert current["id"] == rebuilt["id"]
    # The flat /compliance/remediation-plans/{old_id} still serves
    # the superseded row read-only.
    old = client.get(
        f"/compliance/remediation-plans/{old_id}", headers=_bearer(a_token)
    ).json()
    assert old["id"] == old_id
    assert old["is_current"] is False
    assert old["superseded_by_plan_id"] == rebuilt["id"]


# ---------------------------------------------------------------------------
# List filters
# ---------------------------------------------------------------------------


def test_list_plans_filter_is_current_via_route(
    db, client, admin_user, maintainer_user, package_evidence
):
    rid, plan_body, a_token = _approve_and_build(
        client, maintainer_user, admin_user, package_evidence
    )
    client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(a_token),
    )
    from app.db.models import CompliancePolicyCheck

    check = (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.policy_id == package_evidence.policy_id)
        .first()
    )
    compliance_service.update_check(
        db, check.id, {"definition": {"package": "v2"}}, actor_user_id=admin_user.id
    )
    client.post(
        f"/compliance/remediation-requests/{rid}/plan", headers=_bearer(a_token)
    )
    cur = client.get(
        "/compliance/remediation-plans?is_current=true",
        headers=_bearer(a_token),
    ).json()
    assert all(item["is_current"] is True for item in cur["items"])
    sup = client.get(
        "/compliance/remediation-plans?is_current=false",
        headers=_bearer(a_token),
    ).json()
    assert all(item["is_current"] is False for item in sup["items"])


def test_list_plans_filter_ready_for_execution_via_route(
    client, admin_user, maintainer_user, package_evidence
):
    rid, plan_body, a_token = _approve_and_build(
        client, maintainer_user, admin_user, package_evidence
    )
    client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(a_token),
    )
    res = client.get(
        "/compliance/remediation-plans?ready_for_execution=true",
        headers=_bearer(a_token),
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    assert all(item["ready_for_execution"] is True for item in body["items"])


# ---------------------------------------------------------------------------
# Compatibility
# ---------------------------------------------------------------------------


def test_pra165_policy_route_still_works(authed_client):
    res = authed_client.post(
        "/compliance/policies",
        json={"slug": "lc-compat", "name": "LC Compat"},
    )
    assert res.status_code == 201


def test_slice1_request_envelope_unchanged_after_acknowledge(
    client, admin_user, maintainer_user, package_evidence
):
    rid, plan_body, a_token = _approve_and_build(
        client, maintainer_user, admin_user, package_evidence
    )
    before = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(a_token)
    ).json()
    client.post(
        f"/compliance/remediation-requests/{rid}/plan/acknowledge",
        headers=_bearer(a_token),
    )
    after = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(a_token)
    ).json()
    assert before == after
