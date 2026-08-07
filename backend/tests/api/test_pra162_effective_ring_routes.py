"""PRA-162 slice 2 — effective-ring route tests for
``GET /systems/{id}/patch-ring``."""

from __future__ import annotations

import pytest

from app.db.access_models import AccessGrant, FleetRole
from app.db.models import Credential, Group, SmartGroup, SmartGroupMembership, System

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="effective-ring-route-group", description="t")
    db.add(g)
    db.commit()
    db.refresh(g)
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="effective-ring-route-cred",
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
        hostname="effective-ring-route-host.example.com",
        ip_address="10.0.0.90",
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
def smart_group_with_host(db, host) -> SmartGroup:
    sg = SmartGroup(
        name="effective-ring-route-smart",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg)
    db.commit()
    db.refresh(sg)
    db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=host.id))
    db.commit()
    return sg


def _create_ring(authed_client, slug, *, sort_order, enabled=True):
    res = authed_client.post(
        "/patch/rings",
        json={
            "slug": slug,
            "name": slug,
            "sort_order": sort_order,
            "enabled": enabled,
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


# -- 200 / status payload ---------------------------------------------------


def test_no_ring_returns_200_with_null_ring(authed_client, host):
    res = authed_client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code == 200
    body = res.json()
    assert body["system_id"] == host.id
    assert body["status"] == "no_ring"
    assert body["source_tier"] is None
    assert body["ring"] is None
    assert body["candidates"] == []
    assert body["message"]


def test_resolved_direct_host(authed_client, host):
    ring = _create_ring(authed_client, "host-route", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/bindings/hosts",
        json={"host_id": host.id},
    )
    assert res.status_code == 201, res.text

    res = authed_client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "resolved"
    assert body["source_tier"] == "host"
    assert body["ring"]["id"] == ring["id"]
    assert body["ring"]["slug"] == "host-route"
    assert body["candidates"] == []


def test_resolved_static_group(authed_client, host, static_group):
    ring = _create_ring(authed_client, "group-route", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/bindings/groups",
        json={"group_id": static_group.id},
    )
    assert res.status_code == 201

    res = authed_client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "resolved"
    assert body["source_tier"] == "group"
    assert body["ring"]["id"] == ring["id"]


def test_resolved_smart_group(authed_client, host, smart_group_with_host):
    ring = _create_ring(authed_client, "smart-route", sort_order=1)
    res = authed_client.post(
        f"/patch/rings/{ring['id']}/bindings/smart-groups",
        json={"smart_group_id": smart_group_with_host.id},
    )
    assert res.status_code == 201

    res = authed_client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "resolved"
    assert body["source_tier"] == "smart_group"
    assert body["ring"]["id"] == ring["id"]


# -- Conflict-as-state ------------------------------------------------------


def test_conflict_at_host_tier_returns_200_with_candidates(authed_client, host):
    a = _create_ring(authed_client, "ring-a", sort_order=1)
    b = _create_ring(authed_client, "ring-b", sort_order=2)
    authed_client.post(
        f"/patch/rings/{a['id']}/bindings/hosts", json={"host_id": host.id}
    )
    authed_client.post(
        f"/patch/rings/{b['id']}/bindings/hosts", json={"host_id": host.id}
    )

    res = authed_client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "conflict"
    assert body["source_tier"] == "host"
    assert body["ring"] is None
    slugs = sorted(r["slug"] for r in body["candidates"])
    assert slugs == ["ring-a", "ring-b"]
    assert body["message"]


def test_conflict_higher_tier_short_circuits(authed_client, host, static_group):
    a = _create_ring(authed_client, "h-a", sort_order=1)
    b = _create_ring(authed_client, "h-b", sort_order=2)
    group_pick = _create_ring(authed_client, "g-pick", sort_order=3)

    authed_client.post(
        f"/patch/rings/{a['id']}/bindings/hosts", json={"host_id": host.id}
    )
    authed_client.post(
        f"/patch/rings/{b['id']}/bindings/hosts", json={"host_id": host.id}
    )
    authed_client.post(
        f"/patch/rings/{group_pick['id']}/bindings/groups",
        json={"group_id": static_group.id},
    )

    res = authed_client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "conflict"
    assert body["source_tier"] == "host"


# -- Disabled-ring filtering ------------------------------------------------


def test_disabled_ring_skipped(authed_client, host, static_group):
    disabled = _create_ring(authed_client, "off", sort_order=1, enabled=False)
    fallback = _create_ring(authed_client, "fallback", sort_order=2)
    authed_client.post(
        f"/patch/rings/{disabled['id']}/bindings/hosts",
        json={"host_id": host.id},
    )
    authed_client.post(
        f"/patch/rings/{fallback['id']}/bindings/groups",
        json={"group_id": static_group.id},
    )

    res = authed_client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "resolved"
    assert body["source_tier"] == "group"
    assert body["ring"]["id"] == fallback["id"]


# -- 404 / auth -------------------------------------------------------------


def test_unknown_host_returns_404(authed_client):
    res = authed_client.get("/systems/999999/patch-ring")
    assert res.status_code == 404


def test_requires_auth(client, host):
    res = client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code in (401, 403)


def test_auditor_can_read(client, db, auditor_user, host):
    """Read endpoints don't gate on admin/maintainer — any authenticated
    user can read effective state, mirroring the patch-policy resolver.

    PRA-281: reads are now additionally fleet-scoped, so the auditor needs a
    grant on the host. Role visibility (any authenticated user may read) is
    what this test exercises."""
    role = FleetRole(
        name="pra162-ring-read",
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    db.add(
        AccessGrant(
            user_id=auditor_user.id,
            system_id=host.id,
            fleet_role_id=role.id,
            login=auditor_user.username,
        )
    )
    db.commit()
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.get(
        f"/systems/{host.id}/patch-ring",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "no_ring"


# -- Same-ring dedupe ------------------------------------------------------


def test_same_ring_via_two_smart_groups_resolves(
    authed_client, db, host, smart_group_with_host
):
    sg2 = SmartGroup(
        name="effective-ring-route-smart-2",
        description="t",
        rule_json="[]",
        enabled=True,
    )
    db.add(sg2)
    db.commit()
    db.refresh(sg2)
    db.add(SmartGroupMembership(smart_group_id=sg2.id, system_id=host.id))
    db.commit()

    ring = _create_ring(authed_client, "shared-route", sort_order=1)
    authed_client.post(
        f"/patch/rings/{ring['id']}/bindings/smart-groups",
        json={"smart_group_id": smart_group_with_host.id},
    )
    authed_client.post(
        f"/patch/rings/{ring['id']}/bindings/smart-groups",
        json={"smart_group_id": sg2.id},
    )

    res = authed_client.get(f"/systems/{host.id}/patch-ring")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "resolved"
    assert body["source_tier"] == "smart_group"
    assert body["ring"]["id"] == ring["id"]
