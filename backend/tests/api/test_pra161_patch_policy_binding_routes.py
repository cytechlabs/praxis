"""PRA-161 slice 1c — patch policy binding route tests.

Covers POST/DELETE for the three binding kinds plus the GET list.
"""

from __future__ import annotations

import pytest

from app.db.models import Credential, Group, SmartGroup, System


@pytest.fixture
def policy_id(authed_client) -> int:
    res = authed_client.post(
        "/patch/policies",
        json={
            "slug": "binding-routes-policy",
            "name": "Binding Routes Policy",
            "scope_kind": "security_only",
        },
    )
    assert res.status_code == 201
    return res.json()["id"]


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="route-bind-group", description="t")
    db.add(g)
    db.commit()
    db.refresh(g)
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="route-bind-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@pytest.fixture
def host(db, seed_distro, static_group, credentials) -> System:
    s = System(
        hostname="route-bind-host.example.com",
        ip_address="10.0.0.20",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@pytest.fixture
def smart_group(db) -> SmartGroup:
    sg = SmartGroup(
        name="route-bind-smart",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.commit()
    db.refresh(sg)
    return sg


# -- list -------------------------------------------------------------------


def test_get_bindings_empty(authed_client, policy_id):
    res = authed_client.get(f"/patch/policies/{policy_id}/bindings")
    assert res.status_code == 200
    body = res.json()
    assert body["policy_id"] == policy_id
    assert body["hosts"] == []
    assert body["groups"] == []
    assert body["smart_groups"] == []


def test_get_bindings_unknown_policy_404(authed_client):
    res = authed_client.get("/patch/policies/999999/bindings")
    assert res.status_code == 404


# -- host bindings ----------------------------------------------------------


def test_post_host_binding_201(authed_client, policy_id, host):
    res = authed_client.post(
        f"/patch/policies/{policy_id}/bindings/hosts",
        json={"host_id": host.id},
    )
    assert res.status_code == 201
    body = res.json()
    assert body["policy_id"] == policy_id
    assert body["system_id"] == host.id


def test_post_host_binding_duplicate_422(authed_client, policy_id, host):
    authed_client.post(
        f"/patch/policies/{policy_id}/bindings/hosts",
        json={"host_id": host.id},
    )
    res = authed_client.post(
        f"/patch/policies/{policy_id}/bindings/hosts",
        json={"host_id": host.id},
    )
    assert res.status_code == 422
    assert "already bound" in res.json()["detail"]


def test_post_host_binding_unknown_policy_404(authed_client, host):
    res = authed_client.post(
        f"/patch/policies/999999/bindings/hosts",
        json={"host_id": host.id},
    )
    assert res.status_code == 404


def test_post_host_binding_unknown_target_422(authed_client, policy_id):
    res = authed_client.post(
        f"/patch/policies/{policy_id}/bindings/hosts",
        json={"host_id": 999_999},
    )
    assert res.status_code == 422


@pytest.mark.parametrize("bad", [0, -1, True, False])
def test_post_host_binding_rejects_bad_id(authed_client, policy_id, bad):
    res = authed_client.post(
        f"/patch/policies/{policy_id}/bindings/hosts",
        json={"host_id": bad},
    )
    assert res.status_code == 422


def test_delete_host_binding_204(authed_client, policy_id, host):
    authed_client.post(
        f"/patch/policies/{policy_id}/bindings/hosts",
        json={"host_id": host.id},
    )
    res = authed_client.delete(f"/patch/policies/{policy_id}/bindings/hosts/{host.id}")
    assert res.status_code == 204


def test_delete_host_binding_when_absent_422(authed_client, policy_id, host):
    res = authed_client.delete(f"/patch/policies/{policy_id}/bindings/hosts/{host.id}")
    assert res.status_code == 422


# -- group bindings ---------------------------------------------------------


def test_post_group_binding_201(authed_client, policy_id, static_group):
    res = authed_client.post(
        f"/patch/policies/{policy_id}/bindings/groups",
        json={"group_id": static_group.id},
    )
    assert res.status_code == 201
    assert res.json()["group_id"] == static_group.id


def test_delete_group_binding_204(authed_client, policy_id, static_group):
    authed_client.post(
        f"/patch/policies/{policy_id}/bindings/groups",
        json={"group_id": static_group.id},
    )
    res = authed_client.delete(
        f"/patch/policies/{policy_id}/bindings/groups/{static_group.id}"
    )
    assert res.status_code == 204


def test_post_group_binding_unknown_target_422(authed_client, policy_id):
    res = authed_client.post(
        f"/patch/policies/{policy_id}/bindings/groups",
        json={"group_id": 999_999},
    )
    assert res.status_code == 422


# -- smart-group bindings ---------------------------------------------------


def test_post_smart_group_binding_201(authed_client, policy_id, smart_group):
    res = authed_client.post(
        f"/patch/policies/{policy_id}/bindings/smart-groups",
        json={"smart_group_id": smart_group.id},
    )
    assert res.status_code == 201
    assert res.json()["smart_group_id"] == smart_group.id


def test_delete_smart_group_binding_204(authed_client, policy_id, smart_group):
    authed_client.post(
        f"/patch/policies/{policy_id}/bindings/smart-groups",
        json={"smart_group_id": smart_group.id},
    )
    res = authed_client.delete(
        f"/patch/policies/{policy_id}/bindings/smart-groups/{smart_group.id}"
    )
    assert res.status_code == 204


def test_post_smart_group_binding_unknown_target_422(authed_client, policy_id):
    res = authed_client.post(
        f"/patch/policies/{policy_id}/bindings/smart-groups",
        json={"smart_group_id": 999_999},
    )
    assert res.status_code == 422


# -- list returns all three kinds -------------------------------------------


def test_get_bindings_returns_all_three_kinds(
    authed_client, policy_id, host, static_group, smart_group
):
    authed_client.post(
        f"/patch/policies/{policy_id}/bindings/hosts",
        json={"host_id": host.id},
    )
    authed_client.post(
        f"/patch/policies/{policy_id}/bindings/groups",
        json={"group_id": static_group.id},
    )
    authed_client.post(
        f"/patch/policies/{policy_id}/bindings/smart-groups",
        json={"smart_group_id": smart_group.id},
    )
    res = authed_client.get(f"/patch/policies/{policy_id}/bindings")
    assert res.status_code == 200
    body = res.json()
    assert len(body["hosts"]) == 1
    assert len(body["groups"]) == 1
    assert len(body["smart_groups"]) == 1


# -- auth gates -------------------------------------------------------------


def test_post_host_binding_requires_admin_or_maintainer(
    client, auditor_user, policy_id, host
):
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.post(
        f"/patch/policies/{policy_id}/bindings/hosts",
        headers={"Authorization": f"Bearer {token}"},
        json={"host_id": host.id},
    )
    assert res.status_code in (401, 403)
