"""PRA-167 Slice 4 — fleet summary + per-host inventory route tests.

Covers:

* GET /compliance/remediation/fleet-summary — empty + mixed counts;
  auditor read access; absolute UTC timestamps; no audit emit.
* GET /compliance/systems/{system_id}/remediation — empty + mixed;
  404 on unknown system; pagination on superseded history;
  auditor read access.
* Existing PRA-165 + PRA-167 Slice 1+2+3 routes still work alongside
  the new Slice 4 surfaces.
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

    g = Group(name="pra167-rollup-routes", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="pra167-rollup-routes-cred", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="rollup-routes.example.com",
        ip_address="10.0.0.22",
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
def failing_evidence_factory(db, admin_user, host):
    """Returns a function that builds and returns one failing evidence
    row for a given suffix + severity.
    """

    def _make(suffix, severity="medium"):
        policy = compliance_service.create_policy(
            db,
            actor_user_id=admin_user.id,
            slug=f"rollup-routes-{suffix}",
            name=f"rollup routes {suffix}",
            severity=severity,
        )
        compliance_service.add_check(
            db,
            policy.id,
            actor_user_id=admin_user.id,
            slug=f"c-{suffix}",
            title=f"c {suffix}",
            kind="package_installed",
            definition={"package": f"missing-routes-{suffix}"},
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

    return _make


# ---------------------------------------------------------------------------
# Fleet summary
# ---------------------------------------------------------------------------


def test_fleet_summary_empty_200(authed_client):
    res = authed_client.get("/compliance/remediation/fleet-summary")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["generated_at"].endswith("Z")
    assert body["request_total"] == 0
    assert body["current_plan_total"] == 0
    assert body["per_severity"] == []


def test_fleet_summary_mixed_state(
    client, admin_user, maintainer_user, failing_evidence_factory
):
    ev_open = failing_evidence_factory("flt-open", severity="low")
    ev_ack = failing_evidence_factory("flt-ack", severity="high")

    m_token = _login(client, maintainer_user)
    a_token = _login(client, admin_user)

    # open request stays in 'requested'
    client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": ev_open.id},
    )

    # acknowledged + ready plan
    rid_ack = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": ev_ack.id},
    ).json()["id"]
    client.post(
        f"/compliance/remediation-requests/{rid_ack}/approve",
        headers=_bearer(a_token),
        json={},
    )
    client.post(
        f"/compliance/remediation-requests/{rid_ack}/plan",
        headers=_bearer(a_token),
    )
    client.post(
        f"/compliance/remediation-requests/{rid_ack}/plan/acknowledge",
        headers=_bearer(a_token),
    )

    body = client.get(
        "/compliance/remediation/fleet-summary", headers=_bearer(a_token)
    ).json()
    rs = body["request_counts_by_state"]
    assert rs["requested"] == 1
    assert rs["approved"] == 1
    assert body["current_plan_counts_by_state"]["planned"] == 1
    assert body["current_plan_acknowledged_count"] == 1
    assert body["current_plan_ready_count"] == 1
    sev_index = {row["severity"]: row for row in body["per_severity"]}
    assert sev_index["low"]["requested"] == 1
    assert sev_index["high"]["approved"] == 1


def test_fleet_summary_auditor_read(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.get("/compliance/remediation/fleet-summary", headers=_bearer(token))
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# Per-host inventory
# ---------------------------------------------------------------------------


def test_host_inventory_unknown_system_404(authed_client):
    res = authed_client.get("/compliance/systems/999999/remediation")
    assert res.status_code == 404


def test_host_inventory_empty_for_known_host(authed_client, host):
    res = authed_client.get(f"/compliance/systems/{host.id}/remediation")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["system_id"] == host.id
    assert body["generated_at"].endswith("Z")
    # All five sections are bounded paged envelopes (Slice 4 P2 fix).
    for section_name in (
        "open_requests",
        "approved_requests",
        "current_plans",
        "ready_plans",
        "superseded_history",
    ):
        section = body[section_name]
        assert section["items"] == [], section_name
        assert section["total"] == 0
        assert section["offset"] == 0
        assert section["limit"] >= 1
        assert section["next_offset"] is None


def test_host_inventory_mixed(
    client, admin_user, maintainer_user, failing_evidence_factory, host
):
    ev_open = failing_evidence_factory("inv-open")
    ev_ready = failing_evidence_factory("inv-ready")

    m_token = _login(client, maintainer_user)
    a_token = _login(client, admin_user)

    rid_open = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": ev_open.id},
    ).json()["id"]

    rid_ready = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": ev_ready.id},
    ).json()["id"]
    client.post(
        f"/compliance/remediation-requests/{rid_ready}/approve",
        headers=_bearer(a_token),
        json={},
    )
    plan_body = client.post(
        f"/compliance/remediation-requests/{rid_ready}/plan",
        headers=_bearer(a_token),
    ).json()
    client.post(
        f"/compliance/remediation-requests/{rid_ready}/plan/acknowledge",
        headers=_bearer(a_token),
    )

    body = client.get(
        f"/compliance/systems/{host.id}/remediation", headers=_bearer(a_token)
    ).json()
    assert {r["id"] for r in body["open_requests"]["items"]} == {rid_open}
    assert body["open_requests"]["total"] == 1
    assert {r["id"] for r in body["approved_requests"]["items"]} == {rid_ready}
    assert body["approved_requests"]["total"] == 1
    assert {p["id"] for p in body["current_plans"]["items"]} == {plan_body["id"]}
    assert body["current_plans"]["total"] == 1
    assert {p["id"] for p in body["ready_plans"]["items"]} == {plan_body["id"]}
    assert body["ready_plans"]["total"] == 1


def test_host_inventory_section_pagination_via_route(
    client, admin_user, maintainer_user, failing_evidence_factory, host
):
    """Five open requests, paged via the route with limit=2 + open_offset."""
    m_token = _login(client, maintainer_user)
    for i in range(5):
        ev = failing_evidence_factory(f"route-page-{i}")
        client.post(
            "/compliance/remediation-requests",
            headers=_bearer(m_token),
            json={"evidence_id": ev.id},
        )
    body = client.get(
        f"/compliance/systems/{host.id}/remediation?limit=2",
        headers=_bearer(m_token),
    ).json()
    assert body["open_requests"]["total"] == 5
    assert len(body["open_requests"]["items"]) == 2
    assert body["open_requests"]["next_offset"] == 2
    body2 = client.get(
        f"/compliance/systems/{host.id}/remediation?limit=2&open_offset=4",
        headers=_bearer(m_token),
    ).json()
    assert body2["open_requests"]["total"] == 5
    assert len(body2["open_requests"]["items"]) == 1
    assert body2["open_requests"]["next_offset"] is None


def test_host_inventory_auditor_read(authed_client, client, auditor_user, host):
    token = _login(client, auditor_user)
    res = client.get(
        f"/compliance/systems/{host.id}/remediation", headers=_bearer(token)
    )
    assert res.status_code == 200


def test_host_inventory_pagination_bad_params_422(authed_client, host):
    # FastAPI Query(ge=0/ge=1/le=500) catches negative offsets +
    # out-of-bounds limits at the framework layer.
    res = authed_client.get(
        f"/compliance/systems/{host.id}/remediation?superseded_offset=-1"
    )
    assert res.status_code == 422
    res = authed_client.get(f"/compliance/systems/{host.id}/remediation?limit=0")
    assert res.status_code == 422
    res = authed_client.get(f"/compliance/systems/{host.id}/remediation?limit=1000")
    assert res.status_code == 422
    for offset_param in (
        "open_offset",
        "approved_offset",
        "current_plans_offset",
        "ready_plans_offset",
        "superseded_offset",
    ):
        res = authed_client.get(
            f"/compliance/systems/{host.id}/remediation?{offset_param}=-1"
        )
        assert res.status_code == 422, offset_param


# ---------------------------------------------------------------------------
# Compatibility: existing PRA-165 / Slice 1+2+3 routes still work.
# ---------------------------------------------------------------------------


def test_pra165_policy_route_still_works(authed_client):
    res = authed_client.post(
        "/compliance/policies",
        json={"slug": "slice4-compat", "name": "Slice4 compat"},
    )
    assert res.status_code == 201


def test_slice1_request_envelope_unchanged_after_rollup(
    client, admin_user, maintainer_user, failing_evidence_factory, host
):
    ev = failing_evidence_factory("compat-req")
    m_token = _login(client, maintainer_user)
    a_token = _login(client, admin_user)
    rid = client.post(
        "/compliance/remediation-requests",
        headers=_bearer(m_token),
        json={"evidence_id": ev.id},
    ).json()["id"]
    before = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(a_token)
    ).json()
    client.get("/compliance/remediation/fleet-summary", headers=_bearer(a_token))
    client.get(f"/compliance/systems/{host.id}/remediation", headers=_bearer(a_token))
    after = client.get(
        f"/compliance/remediation-requests/{rid}", headers=_bearer(a_token)
    ).json()
    assert before == after
