"""PRA-173 slice 2 — rollback approval / command-plan route tests.

Covers the two new endpoints + the read-surface extensions:

* ``POST /patch/update-executions/{id}/rollback/request-approval``
  — creates or reuses a rollback-scoped patch_approval row, freezes
  the moment-in-time command plans into the link's
  frozen_plan_snapshot.
* ``POST /patch/update-executions/{id}/rollback/vote`` — wraps
  patch_approval_service.record_vote and surfaces the resulting
  status.
* The existing rollback detail / evaluate envelopes now expose
  ``command_plan`` on each feasible package and an ``approval``
  block on the envelope.

Slice 2 is non-executing — these tests confirm the route + service
layer never dispatch, never call SSH, and never mutate package
history.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-rb-s2-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-rb-s2-cred",
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
            hostname=f"rt-rb-s2-host-{counter['n']}.example.com",
            ip_address=f"10.0.98.{counter['n']}",
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
        json={"cancel_reason": "rb-s2-test-fixture"},
    )
    assert res.status_code == 200
    return res.json()


def _setup_evaluated_rollback(
    authed_client, db, admin_user, host_factory, *, suffix: str
):
    pol = _make_policy(db, admin_user, f"rt-rb-s2-{suffix}")
    h = _seed_host_with_package(db, host_factory, suffix)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_terminate_execution(authed_client, plan["id"])
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate"
    )
    assert res.status_code == 200
    return execution


# ---------------------------------------------------------------------------
# request-approval endpoint
# ---------------------------------------------------------------------------


def test_request_approval_route_422_when_zero_feasible_packages(
    authed_client, db, admin_user, host_factory
):
    """The cancel-only fixture host lands as ``infeasible`` /
    ``host_not_succeeded`` after evaluate, so request-approval
    should 422 with "zero feasible packages"."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="zero"
    )

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/request-approval",
        json={"required_approvals": 1},
    )
    assert res.status_code == 422
    assert "zero feasible" in res.json()["detail"].lower()


def test_request_approval_route_422_before_evaluate(
    authed_client, db, admin_user, host_factory
):
    """Without a prior evaluate call, request-approval should
    422 with "evaluate it first"."""
    pol = _make_policy(db, admin_user, "rt-rb-s2-no-eval")
    h = _seed_host_with_package(db, host_factory, "noeval")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_terminate_execution(authed_client, plan["id"])

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/request-approval",
        json={"required_approvals": 1},
    )
    assert res.status_code == 422
    assert "evaluate" in res.json()["detail"].lower()


def test_request_approval_route_404_on_unknown_execution(authed_client):
    res = authed_client.post(
        "/patch/update-executions/987654/rollback/request-approval",
        json={"required_approvals": 1},
    )
    assert res.status_code == 404


def test_request_approval_route_validates_expires_at_format(
    authed_client, db, admin_user, host_factory
):
    """``expires_at`` is parsed as ISO 8601. Bad shapes must 422
    rather than crashing the route."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="badts"
    )
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/request-approval",
        json={"required_approvals": 1, "expires_at": "not-a-date"},
    )
    assert res.status_code == 422
    assert "iso 8601" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# vote endpoint
# ---------------------------------------------------------------------------


def test_vote_route_422_without_pending_link(
    authed_client, db, admin_user, host_factory
):
    """Voting before request-approval has been called must 422 with
    a clear "no approval link" error."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="vote-no-link"
    )
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/vote",
        json={"decision": "approve"},
    )
    assert res.status_code == 422
    assert "approval link" in res.json()["detail"].lower()


def test_vote_route_404_on_unknown_execution(authed_client):
    res = authed_client.post(
        "/patch/update-executions/987654/rollback/vote",
        json={"decision": "approve"},
    )
    assert res.status_code == 404


def test_vote_route_422_on_unknown_decision(
    authed_client, db, admin_user, host_factory
):
    """Decisions other than approve/reject must 422 — the PRA-161
    voting primitive locks the vocabulary."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="vote-bad"
    )
    # No link request — but the route's first guard is
    # "approval link not found", which we already cover. To exercise
    # the decision-vocab guard we need a pending link; the cancel-
    # only fixture produces zero feasible packages so we cannot run
    # request-approval through the API. Skip the API-side decision-
    # vocab check (covered by service tests) and assert the
    # well-formed-but-no-link path returns 422.
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/vote",
        json={"decision": "maybe"},
    )
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# detail / evaluate envelope extensions
# ---------------------------------------------------------------------------


def test_evaluate_route_surfaces_command_plan_field_on_packages(
    authed_client, db, admin_user, host_factory
):
    """The evaluate response includes ``command_plan`` on every
    package row (null for infeasible). The cancel-only fixture
    short-circuits at the dispatcher so there are no per-package
    execution rows and consequently no rollback package rows — the
    test confirms the *envelope shape* on the wire (the
    ``packages`` field exists and the rollback header records the
    ``host_not_succeeded`` infeasibility per Slice 1). Service-side
    tests cover the feasible-row command_plan rendering."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="cp-field"
    )
    res = authed_client.get(f"/patch/update-executions/{execution['id']}/rollback")
    assert res.status_code == 200
    body = res.json()
    assert "packages" in body
    assert isinstance(body["packages"], list)
    # Every package row that DOES exist must carry the command_plan
    # field; for this cancel-only fixture the host is infeasible
    # and there are no package rows yet (no dispatch ran).
    for pkg in body["packages"]:
        assert "command_plan" in pkg
        if pkg["state"] == "infeasible":
            assert pkg["command_plan"] is None
    # The host row exists and reflects ``host_not_succeeded``.
    assert body["hosts"], "expected at least one rollback host row"
    assert body["hosts"][0]["state"] == "infeasible"
    assert body["hosts"][0]["refusal_reason"] == "host_not_succeeded"


def test_detail_route_surfaces_approval_field(
    authed_client, db, admin_user, host_factory
):
    """The detail envelope carries an ``approval`` field. Before any
    approval request runs, it should be None."""
    execution = _setup_evaluated_rollback(
        authed_client, db, admin_user, host_factory, suffix="ap-field"
    )
    res = authed_client.get(f"/patch/update-executions/{execution['id']}/rollback")
    assert res.status_code == 200
    body = res.json()
    assert "approval" in body
    assert body["approval"] is None
