"""PRA-173 slice 4 — rollback verify-due route tests.

Covers the one new endpoint:

* ``POST /patch/update-executions/{id}/rollback/verify-due``

The fixtures only exercise the route + serialization + HTTP status
mapping; the service-side tests cover the full verification
semantics with a fake probe. The cancel-only fixture path produces
an evaluated rollback with zero feasible packages, so the route
tests rely on the 404 / 422 refusal paths plus the envelope shape.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-rb-s4-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-rb-s4-cred",
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
            hostname=f"rt-rb-s4-host-{counter['n']}.example.com",
            ip_address=f"10.0.102.{counter['n']}",
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
        reboot_policy="if_required",
        requires_approval=False,
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _seed_host_with_package(db, host_factory, suffix: str) -> System:
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


def _create_approved_plan(authed_client, db, admin_user, host, policy):
    _bind(db, admin_user, policy, host)
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
    return res.json()


def _start_and_terminate_execution(authed_client, plan_id: int) -> dict:
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan_id},
    )
    assert res.status_code == 201, res.text
    execution = res.json()
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/cancel",
        json={"cancel_reason": "rb-s4-route-fixture"},
    )
    assert res.status_code == 200
    return res.json()


def _setup_evaluated_rollback(
    authed_client, db, admin_user, host_factory, *, suffix: str
):
    pol = _make_policy(db, admin_user, f"rt-rb-s4-{suffix}")
    h = _seed_host_with_package(db, host_factory, suffix)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_terminate_execution(authed_client, plan["id"])
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate"
    )
    assert res.status_code == 200
    return execution


def test_verify_due_route_404_on_unknown_execution(authed_client):
    res = authed_client.post("/patch/update-executions/987654/rollback/verify-due")
    assert res.status_code == 404


def test_verify_due_route_404_when_no_dispatch_run(
    authed_client, db, admin_user, host_factory
):
    """Without a prior /rollback/start call there is no dispatch
    run; verify-due must 404 cleanly with a hint."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="verify-no-run"
    )
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/verify-due"
    )
    assert res.status_code == 404
    assert "/rollback/start" in res.json()["detail"]
