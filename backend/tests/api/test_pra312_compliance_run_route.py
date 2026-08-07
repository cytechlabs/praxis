"""PRA-312 Slice 1 — POST /compliance/policies/{id}/run operator route."""

from __future__ import annotations

import pytest

from app.db.models import Credential, Group, Package, System
from app.services import compliance_service


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


@pytest.fixture
def policy_with_host(db, admin_user, seed_distro):
    g = Group(name="pra312-route", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra312-route-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra312-route-host.example.com",
        ip_address="10.0.0.71",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    db.add(Package(system_id=sys_row.id, name="openssl", installed_version="3.0.2"))
    db.flush()
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="route-run", name="ROUTE", enabled=True
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug="route-chk",
        title="openssl",
        kind="package_installed",
        definition={"package": "openssl"},
    )
    return policy


def test_admin_can_run_policy_now(db, client, admin_user, policy_with_host):
    _login(client, admin_user)
    res = client.post(f"/compliance/policies/{policy_with_host.id}/run")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["policy_id"] == policy_with_host.id
    assert body["last_run_status"] == "success"
    assert body["evidence_count"] >= 1
    assert body["run_id"]


def test_run_now_reflected_in_policy_read(db, client, admin_user, policy_with_host):
    _login(client, admin_user)
    # Before: never run.
    before = client.get(f"/compliance/policies/{policy_with_host.id}").json()
    assert before["never_run"] is True and before["last_run_status"] is None

    client.post(f"/compliance/policies/{policy_with_host.id}/run")

    after = client.get(f"/compliance/policies/{policy_with_host.id}").json()
    assert after["never_run"] is False
    assert after["last_run_status"] == "success"
    assert after["last_run_at"] and after["next_run_at"]


def test_run_now_refuses_disabled(db, client, admin_user, policy_with_host):
    compliance_service.set_policy_enabled(
        db, policy_with_host.id, False, actor_user_id=admin_user.id
    )
    _login(client, admin_user)
    res = client.post(f"/compliance/policies/{policy_with_host.id}/run")
    assert res.status_code == 422
    assert "disabled" in res.json()["detail"]


def test_run_now_missing_policy_404(db, client, admin_user):
    _login(client, admin_user)
    assert client.post("/compliance/policies/999999/run").status_code == 404


def test_run_now_requires_admin_or_maintainer(
    db, client, auditor_user, policy_with_host
):
    _login(client, auditor_user)
    assert (
        client.post(f"/compliance/policies/{policy_with_host.id}/run").status_code
        == 403
    )
