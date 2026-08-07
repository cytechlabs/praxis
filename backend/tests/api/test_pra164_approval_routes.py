"""PRA-164 slice 4 — approval / schedule / supersede / export route tests.

Covers the six new endpoints declared before ``/{plan_id}``:

* ``POST /patch/update-plans/{plan_id}/approval/request`` — flips
  ``draft`` → ``awaiting_approval`` for approval-required policies;
  422 otherwise.
* ``POST /patch/update-plans/{plan_id}/approval/approve`` —
  disambiguates by plan state: direct-approve for ``draft``
  (non-approval-required), record-vote for ``awaiting_approval``.
* ``POST /patch/update-plans/{plan_id}/approval/reject`` — vote
  reject; flips to ``blocked`` with ``approval_rejected`` block
  reason.
* ``POST /patch/update-plans/{plan_id}/schedule`` — flips
  ``approved`` → ``scheduled``; validates plan-level MW overrides.
* ``POST /patch/update-plans/{plan_id}/supersede`` — explicit-only
  supersede.
* ``GET /patch/update-plans/{plan_id}/export`` — JSON download with
  Content-Disposition attachment.
"""

from __future__ import annotations

import json

import pytest

from app.db.models import Credential, Group, System
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-aprv-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-aprv-cred",
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
            hostname=f"rt-aprv-host-{counter['n']}.example.com",
            ip_address=f"10.0.80.{counter['n']}",
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
    requires_approval: bool = False,
    required_approvals: int = 1,
):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="security_only",
        rollout_cadence="immediate",
        requires_approval=requires_approval,
        required_approvals=required_approvals,
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _create_draft(authed_client, db, admin_user, host, policy, name="rt"):
    _bind(db, admin_user, policy, host)
    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": policy.id, "name": name},
    )
    assert res.status_code == 201, res.text
    return res.json()


# ---------------------------------------------------------------------------
# Approval request
# ---------------------------------------------------------------------------


def test_request_approval_route_happy_path(authed_client, db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rt-req-ok", requires_approval=True)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)

    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/approval/request",
        json={"comment": "please review"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["state"] == "awaiting_approval"
    assert body["approval"] is not None
    assert body["approval"]["status"] == "pending"


def test_request_approval_route_422_when_policy_does_not_require_approval(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-req-no", requires_approval=False)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)

    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/approval/request",
        json={},
    )
    assert res.status_code == 422
    assert "does not require approval" in res.json()["detail"]


# ---------------------------------------------------------------------------
# Direct approve / vote approve
# ---------------------------------------------------------------------------


def test_approve_route_direct_path_for_non_approval_policy(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-dir-ok", requires_approval=False)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)

    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/approval/approve",
        json={"comment": "good to go"},
    )
    assert res.status_code == 200
    assert res.json()["state"] == "approved"


def test_approve_route_vote_path_for_approval_policy(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-vote-ok", requires_approval=True)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    authed_client.post(f"/patch/update-plans/{plan['id']}/approval/request", json={})
    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/approval/approve",
        json={},
    )
    assert res.status_code == 200
    assert res.json()["state"] == "approved"


def test_approve_route_404_on_unknown_plan(authed_client):
    res = authed_client.post("/patch/update-plans/999999/approval/approve", json={})
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Reject
# ---------------------------------------------------------------------------


def test_reject_route_blocks_plan(authed_client, db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rt-rej-ok", requires_approval=True)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    authed_client.post(f"/patch/update-plans/{plan['id']}/approval/request", json={})

    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/approval/reject",
        json={"comment": "regression risk"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["state"] == "blocked"
    codes = [r["code"] for r in body["block_reasons"]]
    assert "approval_rejected" in codes


def test_reject_route_422_on_non_awaiting_state(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-rej-bad", requires_approval=True)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    # Draft, no approval row yet -> reject must 422.
    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/approval/reject", json={}
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Schedule
# ---------------------------------------------------------------------------


def test_schedule_route_flips_approved_to_scheduled(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-sched-ok", requires_approval=False)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    authed_client.post(f"/patch/update-plans/{plan['id']}/approval/approve", json={})

    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/schedule",
        json={"scheduled_start_at": "2030-01-01T02:00:00"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["state"] == "scheduled"


def test_schedule_route_422_on_non_approved_plan(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-sched-bad", requires_approval=False)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/schedule",
        json={"scheduled_start_at": "2030-01-01T02:00:00"},
    )
    assert res.status_code == 422


def test_schedule_route_unknown_window_returns_422(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-sched-mw-bad", requires_approval=False)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    authed_client.post(f"/patch/update-plans/{plan['id']}/approval/approve", json={})
    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/schedule",
        json={
            "scheduled_start_at": "2030-01-01T02:00:00",
            "maintenance_window_id": 999_999,
        },
    )
    assert res.status_code == 422
    assert "maintenance_window_id" in res.json()["detail"]


# ---------------------------------------------------------------------------
# Supersede
# ---------------------------------------------------------------------------


def test_supersede_route_flips_to_superseded(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-sup-ok", requires_approval=False)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)

    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/supersede",
        json={"comment": "newer plan landed"},
    )
    assert res.status_code == 200
    assert res.json()["state"] == "superseded"


def test_supersede_route_422_on_canceled_plan(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-sup-bad", requires_approval=False)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    authed_client.post(f"/patch/update-plans/{plan['id']}/cancel")
    res = authed_client.post(f"/patch/update-plans/{plan['id']}/supersede", json={})
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def test_export_route_returns_json_attachment(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-exp-ok", requires_approval=False)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    authed_client.post(f"/patch/update-plans/{plan['id']}/approval/approve", json={})

    res = authed_client.get(f"/patch/update-plans/{plan['id']}/export")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/json")
    cd = res.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert f"patch-update-plan-{plan['id']}.json" in cd
    bundle = json.loads(res.content)
    assert bundle["plan"]["id"] == plan["id"]
    assert bundle["plan"]["state"] == "approved"
    assert bundle["praxis_patch_update_plan_export_version"] == 1


def test_export_route_404_on_unknown_plan(authed_client):
    res = authed_client.get("/patch/update-plans/999999/export")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Detail endpoint surfaces approval
# ---------------------------------------------------------------------------


def test_plan_detail_returns_approval_after_request(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-det-aprv", requires_approval=True)
    h = host_factory()
    plan = _create_draft(authed_client, db, admin_user, h, pol)
    authed_client.post(f"/patch/update-plans/{plan['id']}/approval/request", json={})

    res = authed_client.get(f"/patch/update-plans/{plan['id']}")
    body = res.json()
    assert body["approval"] is not None
    assert body["approval"]["status"] == "pending"
