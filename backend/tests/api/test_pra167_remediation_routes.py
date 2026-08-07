"""PRA-167 Slice 1 — compliance remediation request route tests.

Covers:

* POST /compliance/remediation-requests — admin/maintainer create
  succeeds; auditor blocked; unknown evidence returns 404; passing
  evidence is rejected as 422.
* GET / and GET /{id} — read-only access for auditor.
* POST /{id}/approve — admin only; separation-of-duties (requester
  cannot self-approve) returns 422.
* POST /{id}/reject — admin only; requester self-reject blocked.
* POST /{id}/cancel — admin or requester (maintainer self-withdraw)
  succeed; non-requester maintainer blocked.
* Read envelopes serialize timestamps as absolute UTC ``...Z`` and
  carry derived ``runner_owner``.
* Existing PRA-165 compliance routes still work alongside the new
  remediation router (compatibility).
"""

from __future__ import annotations

import pytest

from app.db.models import CompliancePolicyEvidence, Credential, Group, Package, System
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


# ---------------------------------------------------------------------------
# Fixtures: a host with a failing compliance evidence row.
# ---------------------------------------------------------------------------


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
    g = Group(name="pra167-routes", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra167-routes-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra167-routes.example.com",
        ip_address="10.0.0.77",
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
        slug="route-fail-policy",
        name="Route Fail",
        remediation_guidance="run the playbook",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="missing-pkg",
        title="missing pkg",
        kind="package_installed",
        definition={"package": "definitely-not-installed-pkg"},
        remediation_guidance="apt-get install -y missing-pkg",
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


@pytest.fixture
def passing_evidence(db, admin_user, host) -> CompliancePolicyEvidence:
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="route-pass-policy",
        name="Route Pass",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="pkg-installed",
        title="installed",
        kind="package_installed",
        definition={"package": "ok-pkg"},
    )
    db.add(
        Package(
            system_id=host.id,
            name="ok-pkg",
            installed_version="1.0",
            package_type="apt",
        )
    )
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
# Create
# ---------------------------------------------------------------------------


def test_create_remediation_request_201(authed_client, failing_evidence):
    res = authed_client.post(
        "/compliance/remediation-requests",
        json={
            "evidence_id": failing_evidence.id,
            "justification": "open per finding",
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["state"] == "requested"
    assert body["evidence_id"] == failing_evidence.id
    assert body["policy_slug"] == failing_evidence.policy_slug
    assert body["check_kind"] == failing_evidence.check_kind
    assert body["verdict_snapshot"] == "fail"
    assert body["remediation_guidance_snapshot"] == "apt-get install -y missing-pkg"
    assert body["created_at"].endswith("Z")
    assert body["updated_at"].endswith("Z")
    assert body["decided_at"] is None
    assert body["runner_owner"]  # always present on the read envelope


def test_create_unknown_evidence_returns_404(authed_client):
    res = authed_client.post(
        "/compliance/remediation-requests",
        json={"evidence_id": 999_999},
    )
    assert res.status_code == 404


def test_create_passing_evidence_returns_422(authed_client, passing_evidence):
    res = authed_client.post(
        "/compliance/remediation-requests",
        json={"evidence_id": passing_evidence.id},
    )
    assert res.status_code == 422


def test_create_requires_write_role(client, auditor_user, failing_evidence):
    token = _login(client, auditor_user)
    res = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(token),
        json={"evidence_id": failing_evidence.id},
    )
    assert res.status_code in (401, 403)


def test_maintainer_can_create(client, maintainer_user, failing_evidence):
    token = _login(client, maintainer_user)
    res = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(token),
        json={"evidence_id": failing_evidence.id},
    )
    assert res.status_code == 201, res.text


def test_create_rejects_overlong_justification(authed_client, failing_evidence):
    res = authed_client.post(
        "/compliance/remediation-requests",
        json={
            "evidence_id": failing_evidence.id,
            "justification": "x" * 5000,
        },
    )
    assert res.status_code == 422


def test_create_rejects_negative_evidence_id(authed_client):
    res = authed_client.post(
        "/compliance/remediation-requests",
        json={"evidence_id": -1},
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# List / get
# ---------------------------------------------------------------------------


def test_list_and_get(authed_client, failing_evidence):
    rid = authed_client.post(
        "/compliance/remediation-requests",
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    page = authed_client.get("/compliance/remediation-requests").json()
    assert page["total"] >= 1
    ids = {item["id"] for item in page["items"]}
    assert rid in ids
    detail = authed_client.get(f"/compliance/remediation-requests/{rid}")
    assert detail.status_code == 200
    assert detail.json()["id"] == rid


def test_list_filters_by_state(authed_client, failing_evidence):
    authed_client.post(
        "/compliance/remediation-requests",
        json={"evidence_id": failing_evidence.id},
    )
    res = authed_client.get("/compliance/remediation-requests?state=requested")
    assert res.status_code == 200
    body = res.json()
    assert all(item["state"] == "requested" for item in body["items"])


def test_list_rejects_bad_state(authed_client):
    res = authed_client.get("/compliance/remediation-requests?state=zombie")
    assert res.status_code == 422


def test_auditor_can_read_list_and_detail(
    client, auditor_user, authed_client, failing_evidence
):
    rid = authed_client.post(
        "/compliance/remediation-requests",
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    token = _login(client, auditor_user)
    page = client.get("/compliance/remediation-requests", headers=_bearer(token))
    assert page.status_code == 200
    detail = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(token)
    )
    assert detail.status_code == 200


def test_get_missing_returns_404(authed_client):
    res = authed_client.get("/compliance/remediation-requests/999999")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Approve / reject — separation of duties
# ---------------------------------------------------------------------------


def test_approve_by_third_party_admin_succeeds(
    client, maintainer_user, admin_user, failing_evidence
):
    # Maintainer creates; admin approves.
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
        json={"decided_reason": "approved per change record"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["state"] == "approved"
    assert body["decided_by"] == admin_user.id
    assert body["decided_at"].endswith("Z")


def test_approve_by_requester_rejected(authed_client, failing_evidence):
    # authed_client is admin; admin requests AND tries to approve → 422.
    rid = authed_client.post(
        "/compliance/remediation-requests",
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    res = authed_client.post(f"/compliance/remediation-requests/{rid}/approve", json={})
    assert res.status_code == 422
    assert "separation of duties" in res.json()["detail"]


def test_approve_requires_admin(client, maintainer_user, failing_evidence):
    # Maintainer creates AND tries to approve.
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    res = client.post(
        f"/compliance/remediation-requests/{rid}/approve",
        headers=_bearer(m_token),
        json={},
    )
    assert res.status_code in (401, 403)


def test_reject_flow(client, maintainer_user, admin_user, failing_evidence):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    a_token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-requests/{rid}/reject",
        headers=_bearer(a_token),
        json={"decided_reason": "duplicate"},
    )
    assert res.status_code == 200
    assert res.json()["state"] == "rejected"


def test_terminal_state_blocks_further_transition(
    client, maintainer_user, admin_user, failing_evidence
):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    a_token = _login(client, admin_user)
    client.post(
        f"/compliance/remediation-requests/{rid}/approve",
        headers=_bearer(a_token),
        json={},
    )
    res = client.post(
        f"/compliance/remediation-requests/{rid}/reject",
        headers=_bearer(a_token),
        json={},
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Cancel — requester self-withdraw + admin third-party cancel
# ---------------------------------------------------------------------------


def test_cancel_by_requester_succeeds(client, maintainer_user, failing_evidence):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    res = client.post(
        f"/compliance/remediation-requests/{rid}/cancel",
        headers=_bearer(m_token),
        json={"decided_reason": "withdrew"},
    )
    assert res.status_code == 200
    assert res.json()["state"] == "cancelled"


def test_cancel_by_non_requester_maintainer_forbidden(
    db,
    client,
    maintainer_user,
    seed_roles,
    failing_evidence,
    host,
):
    """A maintainer who did NOT open the request cannot cancel it."""
    from app.core.auth import get_password_hash
    from app.db.models import User

    # Seed a second maintainer.
    other = User(
        username="othermaint",
        email="other@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    other.roles.append(seed_roles["maintainer"])
    db.add(other)
    db.flush()
    # PRA-281: the fleet-scope gate (404) precedes the ownership gate (403), so
    # to exercise the OWNERSHIP forbidden path the second maintainer must hold a
    # grant on the request's host. Without it they get a non-disclosing 404
    # (covered by the PRA-281 suite).
    from app.db.access_models import AccessGrant, FleetRole

    other_role = FleetRole(
        name=f"pra281-othermaint-{host.id}",
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(other_role)
    db.flush()
    db.add(
        AccessGrant(
            user_id=other.id,
            system_id=host.id,
            fleet_role_id=other_role.id,
            login=other.username,
        )
    )
    db.flush()

    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]

    other_token = _login(client, other)
    res = client.post(
        f"/compliance/remediation-requests/{rid}/cancel",
        headers=_bearer(other_token),
        json={},
    )
    assert res.status_code == 403


def test_cancel_by_third_party_admin_succeeds(
    client, maintainer_user, admin_user, failing_evidence
):
    m_token = _login(client, maintainer_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": failing_evidence.id},
    ).json()["id"]
    a_token = _login(client, admin_user)
    res = client.post(
        f"/compliance/remediation-requests/{rid}/cancel",
        headers=_bearer(a_token),
        json={},
    )
    assert res.status_code == 200
    assert res.json()["state"] == "cancelled"


# ---------------------------------------------------------------------------
# Compatibility: PRA-165 endpoints still work next to the new router.
# ---------------------------------------------------------------------------


def test_pra165_policies_route_still_works(authed_client):
    res = authed_client.post(
        "/compliance/policies",
        json={"slug": "compat-check", "name": "Compat"},
    )
    assert res.status_code == 201
    listing = authed_client.get("/compliance/policies")
    assert listing.status_code == 200
    slugs = {p["slug"] for p in listing.json()}
    assert "compat-check" in slugs


def test_evidence_export_row_unchanged_after_request(authed_client, failing_evidence):
    before = authed_client.get(
        f"/compliance/policies/{failing_evidence.policy_id}/evidence"
    ).json()
    authed_client.post(
        "/compliance/remediation-requests",
        json={"evidence_id": failing_evidence.id},
    )
    after = authed_client.get(
        f"/compliance/policies/{failing_evidence.policy_id}/evidence"
    ).json()
    assert before == after
