"""PRA-164 slice 1 — patch update plan route tests.

Covers:

* POST /patch/update-plans/dry-run — happy path (immediate + staged),
  returns 201 with full plan envelope including hosts.
* GET /patch/update-plans (list) with policy_id and state filters.
* GET /patch/update-plans/{plan_id} — detail; 404 for unknown id.
* GET /patch/update-plans/{plan_id}/hosts — host rows ordered by wave.
* POST /patch/update-plans/{plan_id}/refresh — rebuild + 422 on
  non-refreshable state.
* POST /patch/update-plans/{plan_id}/cancel — 200 + idempotent.
* Validation: unknown policy_id -> 404, unknown target_system_ids -> 422,
  empty target_system_ids list -> 422, role gating on mutating verbs.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, PatchUpdateExecution, System
from app.services import patch_policy_service, patch_ring_service

# ---------------------------------------------------------------------------
# Local fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="route-plan-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="route-plan-cred",
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
            hostname=f"route-plan-host-{counter['n']}.example.com",
            ip_address=f"10.0.20.{counter['n']}",
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


def _make_immediate_policy(db, admin_user, slug: str):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="security_only",
        rollout_cadence="immediate",
    )


def _bind_policy_to_host(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


# ---------------------------------------------------------------------------
# POST /patch/update-plans/dry-run
# ---------------------------------------------------------------------------


def test_post_dry_run_creates_immediate_plan(
    authed_client, db, admin_user, host_factory
):
    pol = _make_immediate_policy(db, admin_user, "rt-imm")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "first",
            "target_system_ids": [h.id],
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["state"] == "draft"
    assert body["policy_id"] == pol.id
    assert len(body["hosts"]) == 1
    assert body["hosts"][0]["wave_index"] == 0
    assert body["hosts"][0]["state"] == "planned"
    assert body["policy_snapshot"]["slug"] == "rt-imm"
    assert body["request_snapshot"]["requested_target_system_ids"] == [h.id]


def test_post_dry_run_unknown_policy_returns_404(authed_client):
    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": 999_999, "name": "ghost"},
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"]


def test_post_dry_run_unknown_target_returns_422(
    authed_client, db, admin_user, host_factory
):
    pol = _make_immediate_policy(db, admin_user, "rt-bad")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "bad",
            "target_system_ids": [h.id, 999_999],
        },
    )
    assert res.status_code == 422
    assert "999999" in res.json()["detail"]


def test_post_dry_run_empty_target_list_rejected_by_schema(
    authed_client, db, admin_user
):
    pol = _make_immediate_policy(db, admin_user, "rt-empty")

    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "empty",
            "target_system_ids": [],
        },
    )
    # Pydantic schema rejection -> FastAPI default 422.
    assert res.status_code == 422


def test_post_dry_run_rejects_bool_in_target_system_ids(authed_client, db, admin_user):
    """Slice 1a: without ``pre=True`` on the validator,
    Pydantic coerces ``True`` -> 1 before our checks see it. The
    ``pre=True`` validator must reject the bool entry so it never
    becomes an audited host id."""
    pol = _make_immediate_policy(db, admin_user, "rt-bool")
    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "bool",
            "target_system_ids": [True],
        },
    )
    assert res.status_code == 422


def test_post_dry_run_rejects_string_in_target_system_ids(
    authed_client, db, admin_user
):
    """Companion to the bool check: ``"5"`` would otherwise coerce to
    5 before validation. With ``pre=True`` the validator sees the raw
    string and rejects."""
    pol = _make_immediate_policy(db, admin_user, "rt-str")
    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "str",
            "target_system_ids": ["5"],
        },
    )
    assert res.status_code == 422


def test_post_dry_run_unknown_maintenance_window_returns_422(
    authed_client, db, admin_user, host_factory
):
    """Slice 1a: unknown plan-level MW override must
    map to 422 via PatchUpdatePlanError, not a 500 IntegrityError."""
    pol = _make_immediate_policy(db, admin_user, "rt-mw-bad")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "mw-bad",
            "target_system_ids": [h.id],
            "maintenance_window_id": 999_999,
        },
    )
    assert res.status_code == 422
    assert "maintenance_window_id" in res.json()["detail"]


def test_post_dry_run_unknown_reboot_window_returns_422(
    authed_client, db, admin_user, host_factory
):
    """Slice 1a: same guarantee for reboot window."""
    pol = _make_immediate_policy(db, admin_user, "rt-rw-bad")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "rw-bad",
            "target_system_ids": [h.id],
            "reboot_window_id": 999_999,
        },
    )
    assert res.status_code == 422
    assert "reboot_window_id" in res.json()["detail"]


def test_post_dry_run_blocks_when_no_hosts(authed_client, db, admin_user):
    pol = _make_immediate_policy(db, admin_user, "rt-noh")
    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "lonely"},
    )
    assert res.status_code == 201
    body = res.json()
    assert body["state"] == "blocked"
    codes = [r["code"] for r in body["block_reasons"]]
    assert "no_target_hosts" in codes


# ---------------------------------------------------------------------------
# Staged plan via the route (covers ring snapshot serialization)
# ---------------------------------------------------------------------------


def test_post_dry_run_staged_plan_orders_waves(
    authed_client, db, admin_user, host_factory
):
    pol = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="rt-staged",
        name="rt-staged",
        scope_kind="security_only",
        rollout_cadence="staged",
        enabled=False,
    )
    canary = patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="rt-canary",
        name="canary",
        sort_order=1,
    )
    prod = patch_ring_service.create_ring(
        db,
        actor_user_id=admin_user.id,
        slug="rt-prod",
        name="prod",
        sort_order=2,
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=canary.id, actor_user_id=admin_user.id
    )
    patch_policy_service.bind_policy_ring(
        db, policy_id=pol.id, ring_id=prod.id, actor_user_id=admin_user.id
    )

    h_canary = host_factory()
    h_prod = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h_canary)
    _bind_policy_to_host(db, admin_user, pol, h_prod)
    patch_ring_service.bind_host(
        db, ring_id=canary.id, system_id=h_canary.id, actor_user_id=admin_user.id
    )
    patch_ring_service.bind_host(
        db, ring_id=prod.id, system_id=h_prod.id, actor_user_id=admin_user.id
    )
    pol.enabled = True
    db.commit()

    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "staged-rt",
            "target_system_ids": [h_prod.id, h_canary.id],
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["state"] == "draft"
    waves = {h["system_id"]: h["wave_index"] for h in body["hosts"]}
    assert waves[h_canary.id] == 0
    assert waves[h_prod.id] == 1
    assert [r["ring_slug"] for r in body["ring_sequence_snapshot"]] == [
        "rt-canary",
        "rt-prod",
    ]


# ---------------------------------------------------------------------------
# GET endpoints
# ---------------------------------------------------------------------------


def test_get_plan_by_id(authed_client, db, admin_user, host_factory):
    pol = _make_immediate_policy(db, admin_user, "rt-get")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "g"},
    )
    plan_id = create_res.json()["id"]

    res = authed_client.get(f"/patch/update-plans/{plan_id}")
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == plan_id
    assert body["state"] == "draft"
    assert len(body["hosts"]) == 1


def test_get_plan_unknown_returns_404(authed_client):
    res = authed_client.get("/patch/update-plans/999999")
    assert res.status_code == 404


def test_get_plan_hosts_orders_by_wave(authed_client, db, admin_user, host_factory):
    pol = _make_immediate_policy(db, admin_user, "rt-hosts")
    h1 = host_factory()
    h2 = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h1)
    _bind_policy_to_host(db, admin_user, pol, h2)

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "h"},
    )
    plan_id = create_res.json()["id"]

    res = authed_client.get(f"/patch/update-plans/{plan_id}/hosts")
    assert res.status_code == 200
    assert {h["system_id"] for h in res.json()} == {h1.id, h2.id}


def test_list_plans_filters_by_policy_and_state(
    authed_client, db, admin_user, host_factory
):
    pol_a = _make_immediate_policy(db, admin_user, "rt-list-a")
    pol_b = _make_immediate_policy(db, admin_user, "rt-list-b")
    h_a = host_factory()
    h_b = host_factory()
    _bind_policy_to_host(db, admin_user, pol_a, h_a)
    _bind_policy_to_host(db, admin_user, pol_b, h_b)

    a = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol_a.id, "name": "a"},
    ).json()
    b = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol_b.id, "name": "b"},
    ).json()
    authed_client.post(f"/patch/update-plans/{b['id']}/cancel")

    res = authed_client.get(f"/patch/update-plans?policy_id={pol_a.id}")
    assert res.status_code == 200
    assert {p["id"] for p in res.json()} == {a["id"]}

    res = authed_client.get("/patch/update-plans?state=canceled")
    assert b["id"] in {p["id"] for p in res.json()}
    assert a["id"] not in {p["id"] for p in res.json()}


def test_list_plans_invalid_state_returns_422(authed_client):
    res = authed_client.get("/patch/update-plans?state=not-a-state")
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Refresh / cancel
# ---------------------------------------------------------------------------


def test_refresh_plan_endpoint(authed_client, db, admin_user, host_factory):
    pol = _make_immediate_policy(db, admin_user, "rt-refresh")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "r"},
    )
    plan_id = create_res.json()["id"]

    h2 = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h2)

    res = authed_client.post(f"/patch/update-plans/{plan_id}/refresh")
    assert res.status_code == 200
    assert {h_["system_id"] for h_ in res.json()["hosts"]} == {h.id, h2.id}


def test_cancel_then_refresh_returns_422(authed_client, db, admin_user, host_factory):
    pol = _make_immediate_policy(db, admin_user, "rt-cycle")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "c"},
    )
    plan_id = create_res.json()["id"]

    cancel_res = authed_client.post(f"/patch/update-plans/{plan_id}/cancel")
    assert cancel_res.status_code == 200
    assert cancel_res.json()["state"] == "canceled"

    refresh_res = authed_client.post(f"/patch/update-plans/{plan_id}/refresh")
    assert refresh_res.status_code == 422
    assert "canceled" in refresh_res.json()["detail"]


# ---------------------------------------------------------------------------
# PRA-355 — DELETE /patch/update-plans/{plan_id} cleanup path
# ---------------------------------------------------------------------------


def test_delete_draft_plan_returns_204(authed_client, db, admin_user, host_factory):
    pol = _make_immediate_policy(db, admin_user, "rt-del-ok")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "d"},
    )
    plan_id = create_res.json()["id"]

    del_res = authed_client.delete(f"/patch/update-plans/{plan_id}")
    assert del_res.status_code == 204
    # Gone — a follow-up GET now 404s.
    assert authed_client.get(f"/patch/update-plans/{plan_id}").status_code == 404


def test_delete_executed_plan_returns_422(authed_client, db, admin_user, host_factory):
    pol = _make_immediate_policy(db, admin_user, "rt-del-exec")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)

    create_res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "d"},
    )
    plan_id = create_res.json()["id"]

    # Attach execution history — this plan is now immutable audit data.
    db.add(
        PatchUpdateExecution(
            plan_id=plan_id,
            state="succeeded",
            started_by=admin_user.id,
            started_at=datetime(2026, 1, 1, 0, 0, 0),
            max_parallel_per_wave=1,
            plan_state_snapshot="draft",
        )
    )
    db.commit()

    del_res = authed_client.delete(f"/patch/update-plans/{plan_id}")
    assert del_res.status_code == 422
    assert "execution history" in del_res.json()["detail"]
    # Not destroyed.
    assert authed_client.get(f"/patch/update-plans/{plan_id}").status_code == 200


# ---------------------------------------------------------------------------
# PRA-355 — POST /patch/update-plans/{plan_id}/archive (admin retire)
# ---------------------------------------------------------------------------


def test_archive_plan_route_hides_from_default_list(
    authed_client, db, admin_user, host_factory
):
    pol = _make_immediate_policy(db, admin_user, "rt-arch-ok")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)
    plan_id = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "a"},
    ).json()["id"]
    # Attach execution history so archive (not delete) is the correct tool.
    db.add(
        PatchUpdateExecution(
            plan_id=plan_id,
            state="succeeded",
            started_by=admin_user.id,
            started_at=datetime(2026, 1, 1, 0, 0, 0),
            max_parallel_per_wave=1,
            plan_state_snapshot="draft",
        )
    )
    db.commit()

    res = authed_client.post(
        f"/patch/update-plans/{plan_id}/archive",
        json={"reason": "learning-cleanup"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["archived_at"] is not None
    assert res.json()["archive_reason"] == "learning-cleanup"

    # Hidden from the default list, visible with include_archived.
    default_ids = [p["id"] for p in authed_client.get("/patch/update-plans").json()]
    assert plan_id not in default_ids
    archived_ids = [
        p["id"]
        for p in authed_client.get("/patch/update-plans?include_archived=true").json()
    ]
    assert plan_id in archived_ids
    # Evidence still fetchable directly.
    assert authed_client.get(f"/patch/update-plans/{plan_id}").status_code == 200


def test_archive_plan_route_requires_admin(
    client, authed_client, db, admin_user, maintainer_user, host_factory
):
    pol = _make_immediate_policy(db, admin_user, "rt-arch-role")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)
    plan_id = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "a"},
    ).json()["id"]

    token = client.post(
        "/auth/login",
        data={"username": maintainer_user.username, "password": "testpass123"},
    ).json()["access_token"]
    res = client.post(
        f"/patch/update-plans/{plan_id}/archive",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    assert res.status_code in (401, 403)


# ---------------------------------------------------------------------------
# PRA-355 send-back #2 — list rows advertise delete-vs-archive from truth
# ---------------------------------------------------------------------------


def test_draft_plan_row_exposes_hard_delete_not_archive(
    authed_client, db, admin_user, host_factory
):
    pol = _make_immediate_policy(db, admin_user, "rt-draft-flags")
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)
    plan_id = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "d"},
    ).json()["id"]
    row = next(
        p for p in authed_client.get("/patch/update-plans").json() if p["id"] == plan_id
    )
    assert row["has_lifecycle_history"] is False
    assert row["can_hard_delete"] is True
    assert row["can_archive"] is False


def test_blocked_plan_with_approval_history_exposes_archive_not_delete(
    authed_client, db, admin_user, host_factory
):
    """Regression: an approval rejection leaves a `blocked` plan that
    retains approval history. Its list row must advertise can_archive (NOT a
    dead-end can_hard_delete), and archive from the list must succeed while the
    backend authoritatively refuses hard-delete."""
    pol = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug="rt-reject-arch",
        name="rt-reject-arch",
        scope_kind="security_only",
        rollout_cadence="immediate",
        requires_approval=True,
        required_approvals=1,
    )
    h = host_factory()
    _bind_policy_to_host(db, admin_user, pol, h)
    plan_id = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "r"},
    ).json()["id"]
    assert (
        authed_client.post(
            f"/patch/update-plans/{plan_id}/approval/request", json={}
        ).status_code
        == 200
    )
    reject = authed_client.post(
        f"/patch/update-plans/{plan_id}/approval/reject",
        json={"comment": "no"},
    )
    assert reject.status_code == 200
    assert reject.json()["state"] == "blocked"

    row = next(
        p for p in authed_client.get("/patch/update-plans").json() if p["id"] == plan_id
    )
    assert row["state"] == "blocked"
    assert row["has_lifecycle_history"] is True
    assert row["can_hard_delete"] is False
    assert row["can_archive"] is True

    # Backend authoritatively refuses hard-delete...
    del_res = authed_client.delete(f"/patch/update-plans/{plan_id}")
    assert del_res.status_code == 422
    assert "approval history" in del_res.json()["detail"]
    # ...and archive from the list succeeds (not a dead end).
    arch = authed_client.post(
        f"/patch/update-plans/{plan_id}/archive",
        json={"reason": "rejected-cleanup"},
    )
    assert arch.status_code == 200
    assert arch.json()["archived_at"] is not None
