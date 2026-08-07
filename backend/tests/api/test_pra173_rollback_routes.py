"""PRA-173 slice 1 — rollback feasibility route tests.

Covers the three endpoints exposed by Slice 1:

* ``GET /patch/update-executions/{execution_id}/rollback`` —
  per-execution read (``rollback=None`` when no evaluation has been
  run yet).
* ``POST /patch/update-executions/{execution_id}/rollback/evaluate``
  — explicit, idempotent evaluation that produces the artifact (or
  a ``refused`` header row for non-terminal executions).
* ``GET /patch/update-plans/{plan_id}/rollback`` — plan-scoped
  read that aggregates per-execution rollback summaries.

Slice 1 deliberately stops before any real rollback work — these
tests assert the route serialization, HTTP status mapping, and the
plan-level + per-execution read contract, not the (non-existent)
rollback command planning, approval, or dispatch.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    Credential,
    Group,
    HostContentProfileSubscription,
    MirrorRepo,
    MirrorSyncRun,
    MirrorSyncRunPackage,
    Package,
    PackageUpdate,
    System,
)
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-rollback-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-rollback-cred",
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
            hostname=f"rt-rollback-host-{counter['n']}.example.com",
            ip_address=f"10.0.96.{counter['n']}",
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


def _seed_host_for_plan(db, host_factory, suffix: str) -> System:
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


def _bind_profile_with_evidence(db, host: System, *, slug: str):
    """Build a content profile + mirror + ok sync run that publishes
    ``pkg-{suffix}`` at version 1.0 (the rollback target), and bind
    it to ``host`` so the plan resolver picks it up.
    """
    mirror = MirrorRepo(
        slug=f"{slug}-mirror",
        display_name=f"{slug}-mirror",
        package_family="deb",
        upstream_url=f"https://example.com/{slug}",
        distribution="jammy",
        components="[]",
        architectures="[]",
        sync_schedule_cron="0 4 * * *",
    )
    db.add(mirror)
    db.commit()
    profile = ContentProfile(
        slug=slug,
        display_name=slug,
        package_family="deb",
    )
    db.add(profile)
    db.commit()
    channel = ContentChannel(
        slug=f"{slug}-ch",
        display_name=f"{slug}-ch",
        package_family="deb",
    )
    db.add(channel)
    db.commit()
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(
        ContentChannelRepo(
            channel_id=channel.id,
            mirror_id=mirror.id,
            suite_override=None,
        )
    )
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        run_kind="sync",
        package_count=1,
        manifest_sha256="0" * 64,
        manifest_path=None,
    )
    db.add(run)
    db.commit()
    # Publish the OLD version we want to roll back to.
    # Match Package.name from _seed_host_for_plan: pkg-{suffix}.
    suffix = slug.split("-")[-1] if "-" in slug else slug
    db.add(
        MirrorSyncRunPackage(
            mirror_sync_run_id=run.id,
            mirror_repo_id=mirror.id,
            package_name=f"pkg-{suffix}",
            version="1.0",
            arch="amd64",
            filename=f"pkg-{suffix}_1.0_amd64.deb",
            sha256="a" * 64,
            size=1,
        )
    )
    db.commit()
    return profile


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


def _start_and_cancel(authed_client, plan_id: int) -> dict:
    """Start an execution then cancel it — produces a terminal
    execution without needing the dispatcher. Hosts will be in
    ``canceled`` state, so the rollback rows will be ``infeasible``
    with ``host_not_succeeded`` — fine for proving the route
    shape."""
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan_id},
    )
    assert res.status_code == 201, res.text
    execution = res.json()
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/cancel",
        json={"cancel_reason": "test-fixture"},
    )
    assert res.status_code == 200
    return res.json()


# ---------------------------------------------------------------------------
# GET /{execution_id}/rollback
# ---------------------------------------------------------------------------


def test_get_rollback_returns_none_before_evaluation(
    authed_client, db, admin_user, host_factory
):
    """Before any evaluation, the read endpoint returns the
    execution envelope with ``rollback=None`` — the UI uses that to
    decide whether to surface the evaluate affordance."""
    pol = _make_policy(db, admin_user, "rt-rb-no-eval")
    h = _seed_host_for_plan(db, host_factory, "a")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    res = authed_client.get(
        f"/patch/update-executions/{execution['id']}/rollback",
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_id"] == execution["id"]
    assert body["plan_id"] == plan["id"]
    assert body["execution_state"] == "canceled"
    assert body["rollback"] is None
    assert body["hosts"] == []
    assert body["packages"] == []


def test_get_rollback_route_404_on_unknown_execution(authed_client):
    res = authed_client.get("/patch/update-executions/987654/rollback")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# POST /{execution_id}/rollback/evaluate
# ---------------------------------------------------------------------------


def test_evaluate_route_initializes_artifact_for_terminal_execution(
    authed_client, db, admin_user, host_factory
):
    """A terminal execution produces an ``evaluated`` rollback header
    row plus per-host rows. Cancel-only fixture means hosts are
    skipped/canceled, so they land as ``infeasible`` with
    ``host_not_succeeded``."""
    pol = _make_policy(db, admin_user, "rt-rb-init")
    h = _seed_host_for_plan(db, host_factory, "b")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate",
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_id"] == execution["id"]
    assert body["execution_state"] == "canceled"
    assert body["rollback"] is not None
    assert body["rollback"]["state"] == "evaluated"
    assert body["rollback"]["refusal_reason"] is None
    # The single host is infeasible (state='skipped' so
    # host_not_succeeded).
    hosts = body["hosts"]
    assert len(hosts) == 1
    assert hosts[0]["state"] == "infeasible"
    assert hosts[0]["refusal_reason"] == "host_not_succeeded"


def test_evaluate_route_refused_for_non_terminal_execution(
    authed_client, db, admin_user, host_factory
):
    """Non-terminal executions produce a ``refused`` header row with
    ``execution_not_terminal`` rather than 422-ing. The read API
    must always have an artifact."""
    pol = _make_policy(db, admin_user, "rt-rb-running")
    h = _seed_host_for_plan(db, host_factory, "c")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"]},
    )
    assert res.status_code == 201
    execution = res.json()

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate",
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["rollback"] is not None
    assert body["rollback"]["state"] == "refused"
    assert body["rollback"]["refusal_reason"] == "execution_not_terminal"
    # No per-host / per-package rows for refused executions.
    assert body["hosts"] == []
    assert body["packages"] == []


def test_evaluate_route_404_on_unknown_execution(authed_client):
    res = authed_client.post(
        "/patch/update-executions/987654/rollback/evaluate",
    )
    assert res.status_code == 404


def test_evaluate_then_get_returns_same_artifact(
    authed_client, db, admin_user, host_factory
):
    """Once evaluate has run, the GET endpoint returns the same
    payload shape. Re-running evaluate is idempotent: no duplicate
    rows."""
    pol = _make_policy(db, admin_user, "rt-rb-idem")
    h = _seed_host_for_plan(db, host_factory, "d")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    res1 = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate",
    )
    assert res1.status_code == 200
    res2 = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate",
    )
    assert res2.status_code == 200
    # Same rollback row id (no duplicate).
    assert res1.json()["rollback"]["id"] == res2.json()["rollback"]["id"]
    assert len(res1.json()["hosts"]) == len(res2.json()["hosts"])

    res3 = authed_client.get(
        f"/patch/update-executions/{execution['id']}/rollback",
    )
    assert res3.status_code == 200
    assert res3.json()["rollback"]["id"] == res1.json()["rollback"]["id"]


def test_evaluate_response_timestamps_are_absolute_utc(
    authed_client, db, admin_user, host_factory
):
    """PRA-173 review lock #2 (carry-forward from PRA-172): read
    payload timestamps are absolute UTC (``...Z``) so API consumers
    cannot mistake them for local time."""
    pol = _make_policy(db, admin_user, "rt-rb-utc")
    h = _seed_host_for_plan(db, host_factory, "e")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate",
    )
    assert res.status_code == 200
    body = res.json()
    rollback = body["rollback"]
    assert rollback["evaluated_at"].endswith("Z")
    assert rollback["created_at"].endswith("Z")
    assert rollback["updated_at"].endswith("Z")
    assert body["hosts"][0]["evaluated_at"].endswith("Z")
    assert body["hosts"][0]["created_at"].endswith("Z")


# ---------------------------------------------------------------------------
# Plan-scoped read: GET /patch/update-plans/{plan_id}/rollback
# ---------------------------------------------------------------------------


def test_plan_rollback_route_404_on_unknown_plan(authed_client):
    res = authed_client.get("/patch/update-plans/987654/rollback")
    assert res.status_code == 404


def test_plan_rollback_route_empty_envelope_when_no_executions(
    authed_client, db, admin_user, host_factory
):
    """A plan with no executions yet returns a zero-count aggregate
    summary plus an empty executions list. The plan surface must be
    readable without requiring a prior evaluate."""
    pol = _make_policy(db, admin_user, "rt-plan-empty")
    h = _seed_host_for_plan(db, host_factory, "f")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)

    res = authed_client.get(f"/patch/update-plans/{plan['id']}/rollback")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["plan_id"] == plan["id"]
    assert body["plan_state"] == "approved"
    assert body["executions"] == []
    assert body["summary"]["execution_count"] == 0
    assert body["summary"]["evaluated_count"] == 0
    assert body["summary"]["package_count"] == 0


def test_plan_rollback_route_aggregates_after_evaluate(
    authed_client, db, admin_user, host_factory
):
    """Once an execution has been evaluated, the plan-scoped read
    returns the aggregate summary plus the per-execution breakdown
    in ``executions``. Wire-shape timestamps are absolute UTC."""
    pol = _make_policy(db, admin_user, "rt-plan-aggr")
    h = _seed_host_for_plan(db, host_factory, "g")
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    rec = authed_client.post(
        f"/patch/update-executions/{execution['id']}/rollback/evaluate",
    )
    assert rec.status_code == 200

    res = authed_client.get(f"/patch/update-plans/{plan['id']}/rollback")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["plan_id"] == plan["id"]
    assert body["summary"]["execution_count"] == 1
    assert body["summary"]["evaluated_count"] == 1
    assert len(body["executions"]) == 1
    exec_ref = body["executions"][0]
    assert exec_ref["execution_id"] == execution["id"]
    assert exec_ref["execution_state"] == "canceled"
    assert exec_ref["rollback"] is not None
    assert exec_ref["rollback"]["state"] == "evaluated"
    # Wire-shape timestamps are absolute UTC.
    assert exec_ref["started_at"].endswith("Z")
    assert exec_ref["completed_at"].endswith("Z")
    assert exec_ref["rollback"]["evaluated_at"].endswith("Z")
