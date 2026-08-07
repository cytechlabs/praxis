"""PRA-161 slice 1d — effective-policy + fleet-default route tests."""

from __future__ import annotations

import pytest

from app.db.models import Credential, Group, SmartGroup, SmartGroupMembership, System

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="effective-route-group", description="t")
    db.add(g)
    db.commit()
    db.refresh(g)
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="effective-route-cred",
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
        hostname="effective-route-host.example.com",
        ip_address="10.0.0.40",
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


def _create_policy(authed_client, slug, **kwargs):
    payload = {
        "slug": slug,
        "name": slug,
        "scope_kind": "security_only",
        **kwargs,
    }
    res = authed_client.post("/patch/policies", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


# -- Effective endpoint -----------------------------------------------------


def test_effective_no_policy_returns_200_with_null(authed_client, host):
    res = authed_client.get(f"/systems/{host.id}/patch-policy/effective")
    assert res.status_code == 200
    body = res.json()
    assert body["system_id"] == host.id
    assert body["resolution_kind"] == "no_policy"
    assert body["policy"] is None


def test_effective_direct_host_binding(authed_client, host):
    p = _create_policy(authed_client, "direct-route")
    res = authed_client.post(
        f"/patch/policies/{p['id']}/bindings/hosts",
        json={"host_id": host.id},
    )
    assert res.status_code == 201

    res = authed_client.get(f"/systems/{host.id}/patch-policy/effective")
    assert res.status_code == 200
    body = res.json()
    assert body["resolution_kind"] == "direct_host"
    assert body["policy"]["slug"] == "direct-route"


def test_effective_static_group_binding(authed_client, host, static_group):
    p = _create_policy(authed_client, "group-route")
    authed_client.post(
        f"/patch/policies/{p['id']}/bindings/groups",
        json={"group_id": static_group.id},
    )
    res = authed_client.get(f"/systems/{host.id}/patch-policy/effective")
    assert res.status_code == 200
    body = res.json()
    assert body["resolution_kind"] == "static_group"


def test_effective_smart_group_binding(authed_client, db, host):
    sg = SmartGroup(
        name="effective-sg-route",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.commit()
    db.refresh(sg)
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host.id))
    db.commit()

    p = _create_policy(authed_client, "smart-route")
    authed_client.post(
        f"/patch/policies/{p['id']}/bindings/smart-groups",
        json={"smart_group_id": sg.id},
    )
    res = authed_client.get(f"/systems/{host.id}/patch-policy/effective")
    assert res.status_code == 200
    body = res.json()
    assert body["resolution_kind"] == "smart_group"


def test_effective_fleet_default_fallback(authed_client, host):
    p = _create_policy(authed_client, "fleet-route")
    authed_client.post(f"/patch/policies/{p['id']}/fleet-default")

    res = authed_client.get(f"/systems/{host.id}/patch-policy/effective")
    assert res.status_code == 200
    body = res.json()
    assert body["resolution_kind"] == "fleet_default"
    assert body["policy"]["slug"] == "fleet-route"


def test_effective_unknown_host_returns_404(authed_client):
    res = authed_client.get("/systems/999999/patch-policy/effective")
    assert res.status_code == 404


def test_effective_conflict_returns_409_with_detail(authed_client, host):
    """Two distinct policies bound at the same tier produce 409 with
    structured detail naming the tier and the conflicting policies."""
    p1 = _create_policy(authed_client, "conf-1")
    p2 = _create_policy(authed_client, "conf-2")
    authed_client.post(
        f"/patch/policies/{p1['id']}/bindings/hosts",
        json={"host_id": host.id},
    )
    authed_client.post(
        f"/patch/policies/{p2['id']}/bindings/hosts",
        json={"host_id": host.id},
    )

    res = authed_client.get(f"/systems/{host.id}/patch-policy/effective")
    assert res.status_code == 409
    detail = res.json()["detail"]
    assert detail["error"] == "effective_policy_conflict"
    assert detail["tier"] == "direct_host"
    slugs = {entry["slug"] for entry in detail["policies"]}
    assert slugs == {"conf-1", "conf-2"}


# -- Fleet-default set/clear ----------------------------------------------


def test_post_fleet_default_marks_policy(authed_client):
    p = _create_policy(authed_client, "fd-set")
    res = authed_client.post(f"/patch/policies/{p['id']}/fleet-default")
    assert res.status_code == 200
    assert res.json()["is_fleet_default"] is True


def test_post_fleet_default_replaces_prior(authed_client):
    p1 = _create_policy(authed_client, "fd-prior")
    p2 = _create_policy(authed_client, "fd-new")
    authed_client.post(f"/patch/policies/{p1['id']}/fleet-default")
    authed_client.post(f"/patch/policies/{p2['id']}/fleet-default")

    res1 = authed_client.get(f"/patch/policies/{p1['id']}")
    res2 = authed_client.get(f"/patch/policies/{p2['id']}")
    assert res1.json()["is_fleet_default"] is False
    assert res2.json()["is_fleet_default"] is True


def test_delete_fleet_default_clears_flag(authed_client):
    p = _create_policy(authed_client, "fd-clear")
    authed_client.post(f"/patch/policies/{p['id']}/fleet-default")
    res = authed_client.delete(f"/patch/policies/{p['id']}/fleet-default")
    assert res.status_code == 200
    assert res.json()["is_fleet_default"] is False


def test_post_fleet_default_unknown_policy_404(authed_client):
    res = authed_client.post("/patch/policies/999999/fleet-default")
    assert res.status_code == 404


def test_delete_fleet_default_unknown_policy_404(authed_client):
    res = authed_client.delete("/patch/policies/999999/fleet-default")
    assert res.status_code == 404


def test_fleet_default_requires_admin_or_maintainer(client, auditor_user):
    """Auditor (read-only) cannot toggle fleet default."""
    p_admin = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    assert p_admin.status_code == 200
    token = p_admin.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    res = client.post("/patch/policies/1/fleet-default", headers=headers)
    assert res.status_code in (401, 403, 404)
