"""PRA-171 slice 1 — execution-run substrate route tests.

Covers the six endpoints under ``/patch/update-executions``:

* ``POST /start`` — materializes one execution row + per-host rows
  from an approved/scheduled plan; refuses unapproved/blocked/etc.
* ``GET /by-plan/{plan_id}`` — returns latest execution for a plan
  or 404 when none exists.
* ``POST /{execution_id}/pause`` / ``/resume`` / ``/cancel`` —
  metadata-only transitions.
* ``GET /{execution_id}`` — execution detail.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-exec-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-exec-cred",
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
            hostname=f"rt-exec-host-{counter['n']}.example.com",
            ip_address=f"10.0.90.{counter['n']}",
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


def _seed_host_with_update(db, host_factory, suffix: str = "h") -> System:
    h = host_factory()
    p = Package(
        system_id=h.id,
        name=f"pkg-{suffix}",
        installed_version="1.0",
        package_type="apt",
    )
    db.add(p)
    db.commit()
    upd = PackageUpdate(
        package_id=p.id,
        system_id=h.id,
        available_version="1.1",
        update_type="security",
        discovered_on=datetime.utcnow(),
    )
    db.add(upd)
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


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------


def test_start_route_creates_execution(authed_client, db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rt-exec-start")
    h = _seed_host_with_update(db, host_factory, "a")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)

    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"]},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["state"] == "running"
    assert body["plan_id"] == plan["id"]
    assert body["plan_state_snapshot"] == "approved"
    assert body["progress"]["host_count"] == 1
    assert len(body["hosts"]) == 1
    assert body["hosts"][0]["state"] == "pending"


def test_start_route_422_on_draft_plan(authed_client, db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rt-exec-draft")
    h = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h)
    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "draft"},
    )
    assert res.status_code == 201, res.text
    plan = res.json()
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"]},
    )
    assert res.status_code == 422


def test_start_route_404_on_unknown_plan(authed_client):
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": 999_999},
    )
    assert res.status_code == 404


def test_start_route_422_on_active_execution_exists(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-exec-dup")
    h = _seed_host_with_update(db, host_factory, "c")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"]},
    )
    assert res.status_code == 201
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"]},
    )
    assert res.status_code == 422


def test_start_route_validation_rejects_negative_concurrency(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-exec-bad-conc")
    h = _seed_host_with_update(db, host_factory, "d")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"], "max_parallel_per_wave": 0},
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Pause / resume / cancel
# ---------------------------------------------------------------------------


def _start_and_get(authed_client, plan_id: int) -> dict:
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan_id},
    )
    assert res.status_code == 201, res.text
    return res.json()


def test_pause_resume_cancel_route_lifecycle(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-exec-life")
    h = _seed_host_with_update(db, host_factory, "e")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_get(authed_client, plan["id"])

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/pause",
        json={"pause_reason": "operator request"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["state"] == "paused"

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/resume",
    )
    assert res.status_code == 200
    assert res.json()["state"] == "running"

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/cancel",
        json={"cancel_reason": "rollback"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["state"] == "canceled"
    assert body["cancel_reason"] == "rollback"
    # Pending host got flipped to canceled.
    states = {h["state"] for h in body["hosts"]}
    assert "canceled" in states


def test_pause_route_422_when_not_running(authed_client, db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rt-exec-pause-bad")
    h = _seed_host_with_update(db, host_factory, "f")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_get(authed_client, plan["id"])
    authed_client.post(f"/patch/update-executions/{execution['id']}/cancel", json={})
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/pause", json={}
    )
    assert res.status_code == 422


def test_resume_route_422_when_not_paused(authed_client, db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rt-exec-resume-bad")
    h = _seed_host_with_update(db, host_factory, "g")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_get(authed_client, plan["id"])
    res = authed_client.post(f"/patch/update-executions/{execution['id']}/resume")
    assert res.status_code == 422


def test_cancel_route_404_on_unknown_execution(authed_client):
    res = authed_client.post("/patch/update-executions/999999/cancel", json={})
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Get / by-plan
# ---------------------------------------------------------------------------


def test_get_route_returns_detail_with_progress(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-exec-get")
    h = _seed_host_with_update(db, host_factory, "h")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_get(authed_client, plan["id"])

    res = authed_client.get(f"/patch/update-executions/{execution['id']}")
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == execution["id"]
    assert body["progress"]["host_count"] == 1
    assert "host_counts_by_state" in body["progress"]
    assert "waves" in body["progress"]


def test_get_route_404_on_unknown_execution(authed_client):
    res = authed_client.get("/patch/update-executions/999999")
    assert res.status_code == 404


def test_by_plan_route_returns_latest_execution(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-exec-bp")
    h = _seed_host_with_update(db, host_factory, "i")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_get(authed_client, plan["id"])
    res = authed_client.get(f"/patch/update-executions/by-plan/{plan['id']}")
    assert res.status_code == 200
    assert res.json()["id"] == execution["id"]


def test_by_plan_route_404_when_no_execution_started(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-exec-bp-empty")
    h = _seed_host_with_update(db, host_factory, "j")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    res = authed_client.get(f"/patch/update-executions/by-plan/{plan['id']}")
    assert res.status_code == 404


def test_by_plan_route_404_on_unknown_plan(authed_client):
    res = authed_client.get("/patch/update-executions/by-plan/999999")
    assert res.status_code == 404
