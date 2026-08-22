"""PRA-398 - ``POST /patch/update-executions/start`` route contract for
plans with no selected package work.

Asserts the HTTP surface of the zero-work start gate:

* a plan with nothing to dispatch is refused 422 with the stable
  ``no_selected_packages`` code in the error detail;
* the refusal leaves no execution behind, so ``GET /by-plan/{plan_id}``
  still reports that none was ever started and a retry refuses again;
* a mixed plan still starts 201 with the empty host skipped per host.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-zw-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-zw-cred",
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
            hostname=f"rt-zw-host-{counter['n']}.example.com",
            ip_address=f"10.0.97.{counter['n']}",
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


def _make_policy(db, admin_user, slug: str):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
        requires_approval=False,
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _empty_host(db, host_factory, suffix: str) -> System:
    """Installed package, no available update, so selection picks
    nothing for this host."""
    h = host_factory()
    db.add(
        Package(
            system_id=h.id,
            name=f"pkg-{suffix}",
            installed_version="1.0",
            package_type="apt",
        )
    )
    db.commit()
    return h


def _host_with_update(db, host_factory, suffix: str) -> System:
    h = host_factory()
    p = Package(
        system_id=h.id,
        name=f"pkg-{suffix}",
        installed_version="1.0",
        package_type="apt",
    )
    db.add(p)
    db.commit()
    db.add(
        PackageUpdate(
            package_id=p.id,
            system_id=h.id,
            available_version="1.1",
            update_type="security",
            discovered_on=datetime.utcnow(),
        )
    )
    db.commit()
    return h


def _approved_plan(authed_client, policy) -> dict:
    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": policy.id, "name": f"p-{policy.slug}"},
    )
    assert res.status_code == 201, res.text
    plan = res.json()
    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/approval/approve", json={}
    )
    assert res.status_code == 200, res.text
    return plan


def test_start_route_422_with_no_selected_packages_code(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-zw-refuse")
    h = _empty_host(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(authed_client, pol)

    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"]},
    )

    assert res.status_code == 422, res.text
    assert "no_selected_packages" in res.json()["detail"]


def test_refused_start_leaves_no_execution_and_retry_refuses(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-zw-retry")
    h = _empty_host(db, host_factory, "b")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(authed_client, pol)

    first = authed_client.post(
        "/patch/update-executions/start", json={"plan_id": plan["id"]}
    )
    assert first.status_code == 422, first.text

    # No run was recorded, so the plan still reports "never started".
    lookup = authed_client.get(f"/patch/update-executions/by-plan/{plan['id']}")
    assert lookup.status_code == 404

    second = authed_client.post(
        "/patch/update-executions/start", json={"plan_id": plan["id"]}
    )
    assert second.status_code == 422, second.text
    assert "no_selected_packages" in second.json()["detail"]


def test_start_route_201_for_mixed_plan(authed_client, db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rt-zw-mixed")
    h_work = _host_with_update(db, host_factory, "c")
    _bind(db, admin_user, pol, h_work)
    h_empty = _empty_host(db, host_factory, "d")
    _bind(db, admin_user, pol, h_empty)
    plan = _approved_plan(authed_client, pol)

    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"], "max_parallel_per_wave": 2},
    )

    assert res.status_code == 201, res.text
    body = res.json()
    assert body["state"] == "running"
    states = {h["system_id_snapshot"]: h["state"] for h in body["hosts"]}
    assert states[h_work.id] == "pending"
    assert states[h_empty.id] == "skipped"
    assert body["progress"]["selected_package_count"] == 1
