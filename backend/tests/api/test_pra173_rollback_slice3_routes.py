"""PRA-173 slice 3 — rollback dispatch route tests.

Covers the four new endpoints:

* ``GET  /patch/update-executions/{id}/rollback/dispatch`` — read
  the latest dispatch run + per-host/per-package rows
* ``POST /patch/update-executions/{id}/rollback/start``
* ``POST /patch/update-executions/{id}/rollback/dispatch-next``
* ``POST /patch/update-executions/{id}/rollback/cancel``

The fixtures here only exercise the route + serialization + HTTP
status mapping; the service-side tests cover the full dispatch
semantics with a fake DispatchCallable. Because the cancel-only
plan path produces zero feasible packages, the route tests rely
on the 422 refusal paths plus the empty-detail shape rather than
running the dispatcher itself.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-rb-s3-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-rb-s3-cred",
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
            hostname=f"rt-rb-s3-host-{counter['n']}.example.com",
            ip_address=f"10.0.100.{counter['n']}",
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
        json={"cancel_reason": "rb-s3-route-fixture"},
    )
    assert res.status_code == 200
    return res.json()


def _setup_evaluated_rollback(
    authed_client, db, admin_user, host_factory, *, suffix: str
):
    pol = _make_policy(db, admin_user, f"rt-rb-s3-{suffix}")
    h = _seed_host_with_package(db, host_factory, suffix)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_terminate_execution(authed_client, plan["id"])
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate"
    )
    assert res.status_code == 200
    return execution


# ---------------------------------------------------------------------------
# GET /rollback/dispatch
# ---------------------------------------------------------------------------


def test_get_rollback_dispatch_returns_none_before_start(
    authed_client, db, admin_user, host_factory
):
    """Before any start_rollback_execution, the read endpoint returns
    the execution envelope with ``run=None``."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="get-none"
    )
    res = authed_client.get(
        f"/patch/update-executions/{execution['id']}/rollback/dispatch"
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_id"] == execution["id"]
    assert body["run"] is None
    assert body["hosts"] == []
    assert body["packages"] == []


def test_get_rollback_dispatch_404_on_unknown_execution(authed_client):
    res = authed_client.get("/patch/update-executions/987654/rollback/dispatch")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# POST /rollback/start
# ---------------------------------------------------------------------------


def test_start_route_404_on_unknown_execution(authed_client):
    res = authed_client.post(
        "/patch/update-executions/987654/rollback/start",
        json={},
    )
    assert res.status_code == 404


def test_start_route_422_when_zero_feasible_packages(
    authed_client, db, admin_user, host_factory
):
    """Cancel-only fixture produces an evaluated rollback with zero
    feasible packages (host_not_succeeded). Start must 422 with
    ``rollback_not_evaluated``-class refusal or ``approval_not_approved``
    (no approval has been requested either)."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="start-zero"
    )
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/start",
        json={},
    )
    assert res.status_code == 422
    msg = res.json()["detail"].lower()
    assert "approval" in msg or "feasible" in msg


# ---------------------------------------------------------------------------
# POST /rollback/dispatch-next
# ---------------------------------------------------------------------------


def test_dispatch_next_404_when_no_run_yet(authed_client, db, admin_user, host_factory):
    """dispatch-next must 404 cleanly when there is no run to
    advance — that's the operator hint to call /start first."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="disp-no-run"
    )
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/dispatch-next"
    )
    assert res.status_code == 404
    assert "/rollback/start" in res.json()["detail"]


def test_dispatch_next_404_on_unknown_execution(authed_client):
    res = authed_client.post("/patch/update-executions/987654/rollback/dispatch-next")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# POST /rollback/cancel
# ---------------------------------------------------------------------------


def test_cancel_route_404_when_no_run_yet(authed_client, db, admin_user, host_factory):
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="cancel-no-run"
    )
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/cancel",
        json={"cancel_reason": "route-test"},
    )
    assert res.status_code == 404


def test_cancel_route_404_on_unknown_execution(authed_client):
    res = authed_client.post(
        "/patch/update-executions/987654/rollback/cancel",
        json={},
    )
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Envelope shape sanity (UTC + run/hosts/packages fields all present)
# ---------------------------------------------------------------------------


def test_dispatch_envelope_carries_expected_fields(
    authed_client, db, admin_user, host_factory
):
    """The GET dispatch endpoint envelope must always expose the
    Slice 3 fields (run / hosts / packages) even when the run is
    None, so polling clients can render conditionally without
    defensive defaults."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="envelope"
    )
    res = authed_client.get(
        f"/patch/update-executions/{execution['id']}/rollback/dispatch"
    )
    assert res.status_code == 200
    body = res.json()
    for key in (
        "execution_id",
        "execution_state",
        "plan_id",
        "run",
        "hosts",
        "packages",
    ):
        assert key in body
