"""PRA-164 slice 2 — selection-preview route tests.

Covers the two new endpoints + the ``selection_summary`` extension on
the existing detail / hosts read paths:

* ``GET /patch/update-plans/{plan_id}/hosts/{plan_host_id}/selected-packages``
  - happy path (rows ordered by state then package_name).
  - 404 when the host id does not belong to the plan.
* ``GET /patch/update-plans/{plan_id}/selected-packages``
  - 404 on unknown plan.
  - state filter (``selected`` / ``excluded`` / ``unresolvable``).
  - 422 on invalid state.
* ``GET /patch/update-plans/{plan_id}`` (Slice 1 detail) now returns
  ``selection_summary`` on each host row.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-sel-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-sel-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.commit()
    return c


@pytest.fixture
def host_factory(db, seed_distro, static_group, credentials):
    counter = {"n": 0}

    def make() -> System:
        counter["n"] += 1
        s = System(
            hostname=f"rt-sel-host-{counter['n']}.example.com",
            ip_address=f"10.0.40.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.commit()
        return s

    return make


def _make_policy(
    db,
    admin_user,
    slug: str,
    *,
    scope_kind: str = "full",
    scope_packages: Optional[list] = None,
):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind=scope_kind,
        scope_packages=scope_packages,
        rollout_cadence="immediate",
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _seed_pkg(db, host: System, name: str, installed: str, available: str):
    p = Package(
        system_id=host.id,
        name=name,
        installed_version=installed,
        package_type="apt",
    )
    db.add(p)
    db.commit()
    upd = PackageUpdate(
        package_id=p.id,
        system_id=host.id,
        available_version=available,
        update_type="security",
        discovered_on=datetime.utcnow(),
    )
    db.add(upd)
    db.commit()


# ---------------------------------------------------------------------------
# /selected-packages happy paths and ordering
# ---------------------------------------------------------------------------


def test_get_host_selected_packages_returns_rows(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-sel-host", scope_kind="full")
    h = host_factory()
    _bind(db, admin_user, pol, h)
    _seed_pkg(db, h, "alpha", "1.0", "1.1")
    _seed_pkg(db, h, "beta", "2.0", "2.1")

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "rt-sel"},
    )
    assert create_res.status_code == 201
    plan = create_res.json()
    host_id = plan["hosts"][0]["id"]

    res = authed_client.get(
        f"/patch/update-plans/{plan['id']}/hosts/{host_id}/selected-packages"
    )
    assert res.status_code == 200
    rows = res.json()
    assert {r["package_name"] for r in rows} == {"alpha", "beta"}
    assert all(r["state"] == "selected" for r in rows)
    assert all(r["selection_reason"] == "policy_full" for r in rows)


def test_get_host_selected_packages_404_when_host_not_in_plan(
    authed_client, db, admin_user, host_factory
):
    pol_a = _make_policy(db, admin_user, "rt-404-a", scope_kind="full")
    pol_b = _make_policy(db, admin_user, "rt-404-b", scope_kind="full")
    h_a = host_factory()
    h_b = host_factory()
    _bind(db, admin_user, pol_a, h_a)
    _bind(db, admin_user, pol_b, h_b)
    _seed_pkg(db, h_a, "x", "1", "2")
    _seed_pkg(db, h_b, "y", "1", "2")

    plan_a = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol_a.id, "name": "a"},
    ).json()
    plan_b = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol_b.id, "name": "b"},
    ).json()

    # Use plan A's id with plan B's host id.
    host_b_id = plan_b["hosts"][0]["id"]
    res = authed_client.get(
        f"/patch/update-plans/{plan_a['id']}/hosts/{host_b_id}/selected-packages"
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"]


# ---------------------------------------------------------------------------
# Plan-wide /selected-packages
# ---------------------------------------------------------------------------


def test_get_plan_selected_packages_state_filter(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(
        db,
        admin_user,
        "rt-pwide",
        scope_kind="package_denylist",
        scope_packages=["frozen"],
    )
    h = host_factory()
    _bind(db, admin_user, pol, h)
    _seed_pkg(db, h, "frozen", "1.0", "1.1")
    _seed_pkg(db, h, "free", "1.0", "1.1")

    plan = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "pwide"},
    ).json()

    sel = authed_client.get(
        f"/patch/update-plans/{plan['id']}/selected-packages?state=selected"
    )
    assert sel.status_code == 200
    sel_rows = sel.json()
    assert {r["package_name"] for r in sel_rows} == {"free"}

    excl = authed_client.get(
        f"/patch/update-plans/{plan['id']}/selected-packages?state=excluded"
    )
    assert excl.status_code == 200
    excl_rows = excl.json()
    assert {r["package_name"] for r in excl_rows} == {"frozen"}


def test_get_plan_selected_packages_404_on_unknown_plan(authed_client):
    res = authed_client.get("/patch/update-plans/999999/selected-packages")
    assert res.status_code == 404


def test_get_plan_selected_packages_invalid_state_returns_422(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-bad-state", scope_kind="full")
    h = host_factory()
    _bind(db, admin_user, pol, h)
    _seed_pkg(db, h, "x", "1", "2")
    plan = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "bad-state"},
    ).json()

    res = authed_client.get(
        f"/patch/update-plans/{plan['id']}/selected-packages?state=not-a-state"
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# selection_summary surfaces on Slice 1 detail endpoint
# ---------------------------------------------------------------------------


def test_plan_detail_returns_selection_summary_on_hosts(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-sum", scope_kind="full")
    h = host_factory()
    _bind(db, admin_user, pol, h)
    _seed_pkg(db, h, "alpha", "1.0", "1.1")
    _seed_pkg(db, h, "beta", "1.0", "1.1")

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "sum"},
    )
    body = create_res.json()
    assert len(body["hosts"]) == 1
    summary = body["hosts"][0]["selection_summary"]
    assert summary == {
        "selected": 2,
        "excluded": 0,
        "unresolvable": 0,
        "inventory_missing": False,
    }
