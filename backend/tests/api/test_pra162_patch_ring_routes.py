"""PRA-162 slice 1 — patch ring CRUD + binding + seed-defaults route tests."""

from __future__ import annotations

import pytest

from app.db.models import Credential, Group, SmartGroup, System


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="ring-route-group", description="t")
    db.add(g)
    db.commit()
    db.refresh(g)
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="ring-route-cred",
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
        hostname="ring-route-host.example.com",
        ip_address="10.0.0.70",
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
        name="ring-route-smart",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.commit()
    db.refresh(sg)
    return sg


# -- POST -------------------------------------------------------------------


def test_post_creates_ring(authed_client):
    res = authed_client.post(
        "/patch/rings",
        json={"slug": "canary", "name": "Canary", "sort_order": 1},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["slug"] == "canary"
    assert body["sort_order"] == 1
    assert body["enabled"] is True


def test_post_duplicate_slug_returns_422(authed_client):
    authed_client.post(
        "/patch/rings",
        json={"slug": "dup", "name": "A", "sort_order": 1},
    )
    res = authed_client.post(
        "/patch/rings",
        json={"slug": "dup", "name": "B", "sort_order": 2},
    )
    assert res.status_code == 422
    assert "already exists" in res.json()["detail"]


def test_post_duplicate_sort_order_returns_422(authed_client):
    authed_client.post(
        "/patch/rings",
        json={"slug": "first", "name": "A", "sort_order": 1},
    )
    res = authed_client.post(
        "/patch/rings",
        json={"slug": "second", "name": "B", "sort_order": 1},
    )
    assert res.status_code == 422


@pytest.mark.parametrize("bad", [0, -1, True, False])
def test_post_rejects_bad_sort_order(authed_client, bad):
    res = authed_client.post(
        "/patch/rings",
        json={"slug": f"so-{bad}", "name": "X", "sort_order": bad},
    )
    assert res.status_code == 422


@pytest.mark.parametrize("bad_slug", ["", "UPPER", "has space", "x" * 65])
def test_post_bad_slug_returns_422(authed_client, bad_slug):
    res = authed_client.post(
        "/patch/rings",
        json={"slug": bad_slug, "name": "X", "sort_order": 1},
    )
    assert res.status_code == 422


def test_post_requires_admin_or_maintainer(client, auditor_user):
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.post(
        "/patch/rings",
        headers={"Authorization": f"Bearer {token}"},
        json={"slug": "blocked", "name": "X", "sort_order": 1},
    )
    assert res.status_code in (401, 403)


# -- GET --------------------------------------------------------------------


def test_get_list_orders_by_sort_order(authed_client):
    authed_client.post(
        "/patch/rings",
        json={"slug": "c", "name": "C", "sort_order": 3},
    )
    authed_client.post(
        "/patch/rings",
        json={"slug": "a", "name": "A", "sort_order": 1},
    )
    authed_client.post(
        "/patch/rings",
        json={"slug": "b", "name": "B", "sort_order": 2},
    )
    res = authed_client.get("/patch/rings")
    assert res.status_code == 200
    rows = res.json()
    assert [r["slug"] for r in rows] == ["a", "b", "c"]


def test_get_by_id_404(authed_client):
    res = authed_client.get("/patch/rings/999999")
    assert res.status_code == 404


def test_get_by_slug_routes_correctly(authed_client):
    authed_client.post(
        "/patch/rings",
        json={"slug": "by-slug-test", "name": "X", "sort_order": 1},
    )
    res = authed_client.get("/patch/rings/by-slug/by-slug-test")
    assert res.status_code == 200
    assert res.json()["slug"] == "by-slug-test"

    assert authed_client.get("/patch/rings/by-slug/nope").status_code == 404


# -- seed-defaults ----------------------------------------------------------


def test_post_seed_defaults_creates_canary_pilot_prod(authed_client):
    res = authed_client.post("/patch/rings/seed-defaults")
    assert res.status_code == 200, res.text
    body = res.json()
    assert sorted(body["created"]) == ["canary", "pilot", "prod"]
    assert body["existing"] == []
    assert sorted(r["slug"] for r in body["rings"]) == ["canary", "pilot", "prod"]


def test_post_seed_defaults_idempotent(authed_client):
    authed_client.post("/patch/rings/seed-defaults")
    res = authed_client.post("/patch/rings/seed-defaults")
    assert res.status_code == 200
    body = res.json()
    assert body["created"] == []
    assert sorted(body["existing"]) == ["canary", "pilot", "prod"]


def test_post_seed_defaults_requires_admin_or_maintainer(client, auditor_user):
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.post(
        "/patch/rings/seed-defaults",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code in (401, 403)


# -- PATCH ------------------------------------------------------------------


def test_patch_partial(authed_client):
    create = authed_client.post(
        "/patch/rings",
        json={"slug": "p", "name": "Original", "sort_order": 1},
    )
    rid = create.json()["id"]
    res = authed_client.patch(
        f"/patch/rings/{rid}",
        json={"name": "Renamed", "enabled": False},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["name"] == "Renamed"
    assert body["enabled"] is False


def test_patch_sort_order_collision_returns_422(authed_client):
    a = authed_client.post(
        "/patch/rings",
        json={"slug": "a", "name": "A", "sort_order": 1},
    )
    authed_client.post(
        "/patch/rings",
        json={"slug": "b", "name": "B", "sort_order": 2},
    )
    res = authed_client.patch(
        f"/patch/rings/{a.json()['id']}",
        json={"sort_order": 2},
    )
    assert res.status_code == 422


def test_patch_unknown_id_returns_404(authed_client):
    res = authed_client.patch("/patch/rings/999999", json={"name": "x"})
    assert res.status_code == 404


def test_patch_empty_body_returns_422(authed_client):
    create = authed_client.post(
        "/patch/rings",
        json={"slug": "e", "name": "E", "sort_order": 1},
    )
    res = authed_client.patch(f"/patch/rings/{create.json()['id']}", json={})
    assert res.status_code == 422


# -- DELETE -----------------------------------------------------------------


def test_delete_ring_204(authed_client):
    create = authed_client.post(
        "/patch/rings",
        json={"slug": "d", "name": "D", "sort_order": 1},
    )
    rid = create.json()["id"]
    res = authed_client.delete(f"/patch/rings/{rid}")
    assert res.status_code == 204
    assert authed_client.get(f"/patch/rings/{rid}").status_code == 404


def test_delete_unknown_id_returns_404(authed_client):
    res = authed_client.delete("/patch/rings/999999")
    assert res.status_code == 404


def test_delete_requires_admin(client, maintainer_user):
    res = client.post(
        "/auth/login",
        data={
            "username": maintainer_user.username,
            "password": "testpass123",
        },
    )
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    create = client.post(
        "/patch/rings",
        headers=headers,
        json={"slug": "no-del", "name": "X", "sort_order": 1},
    )
    assert create.status_code == 201
    rid = create.json()["id"]
    res = client.delete(f"/patch/rings/{rid}", headers=headers)
    assert res.status_code in (401, 403)


# -- Bindings ---------------------------------------------------------------


@pytest.fixture
def ring_id(authed_client) -> int:
    res = authed_client.post(
        "/patch/rings",
        json={"slug": "bind-target", "name": "Bind Target", "sort_order": 1},
    )
    return res.json()["id"]


def test_get_bindings_empty(authed_client, ring_id):
    res = authed_client.get(f"/patch/rings/{ring_id}/bindings")
    assert res.status_code == 200
    body = res.json()
    assert body["ring_id"] == ring_id
    assert body["hosts"] == []
    assert body["groups"] == []
    assert body["smart_groups"] == []


def test_get_bindings_unknown_ring_404(authed_client):
    res = authed_client.get("/patch/rings/999999/bindings")
    assert res.status_code == 404


def test_post_host_binding_201(authed_client, ring_id, host):
    res = authed_client.post(
        f"/patch/rings/{ring_id}/bindings/hosts",
        json={"host_id": host.id},
    )
    assert res.status_code == 201
    assert res.json()["system_id"] == host.id


def test_post_host_binding_unknown_target_422(authed_client, ring_id):
    res = authed_client.post(
        f"/patch/rings/{ring_id}/bindings/hosts",
        json={"host_id": 999_999},
    )
    assert res.status_code == 422


def test_post_host_binding_unknown_ring_404(authed_client, host):
    res = authed_client.post(
        f"/patch/rings/999999/bindings/hosts",
        json={"host_id": host.id},
    )
    assert res.status_code == 404


def test_delete_host_binding_204(authed_client, ring_id, host):
    authed_client.post(
        f"/patch/rings/{ring_id}/bindings/hosts",
        json={"host_id": host.id},
    )
    res = authed_client.delete(f"/patch/rings/{ring_id}/bindings/hosts/{host.id}")
    assert res.status_code == 204


def test_delete_host_binding_when_absent_422(authed_client, ring_id, host):
    res = authed_client.delete(f"/patch/rings/{ring_id}/bindings/hosts/{host.id}")
    assert res.status_code == 422


def test_post_group_binding_201(authed_client, ring_id, static_group):
    res = authed_client.post(
        f"/patch/rings/{ring_id}/bindings/groups",
        json={"group_id": static_group.id},
    )
    assert res.status_code == 201


def test_post_smart_group_binding_201(authed_client, ring_id, smart_group):
    res = authed_client.post(
        f"/patch/rings/{ring_id}/bindings/smart-groups",
        json={"smart_group_id": smart_group.id},
    )
    assert res.status_code == 201


def test_get_bindings_returns_all_three_kinds(
    authed_client, ring_id, host, static_group, smart_group
):
    authed_client.post(
        f"/patch/rings/{ring_id}/bindings/hosts", json={"host_id": host.id}
    )
    authed_client.post(
        f"/patch/rings/{ring_id}/bindings/groups",
        json={"group_id": static_group.id},
    )
    authed_client.post(
        f"/patch/rings/{ring_id}/bindings/smart-groups",
        json={"smart_group_id": smart_group.id},
    )
    res = authed_client.get(f"/patch/rings/{ring_id}/bindings")
    assert res.status_code == 200
    body = res.json()
    assert len(body["hosts"]) == 1
    assert len(body["groups"]) == 1
    assert len(body["smart_groups"]) == 1


def test_post_binding_requires_admin_or_maintainer(client, auditor_user, ring_id, host):
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.post(
        f"/patch/rings/{ring_id}/bindings/hosts",
        headers={"Authorization": f"Bearer {token}"},
        json={"host_id": host.id},
    )
    assert res.status_code in (401, 403)
