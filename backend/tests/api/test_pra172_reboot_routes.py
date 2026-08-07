"""PRA-172 slice 1 — reboot queue route tests.

Covers the two endpoints under ``/patch/update-executions``:

* ``GET /{execution_id}/reboots`` — read the queue (empty when
  reconcile hasn't run yet).
* ``POST /{execution_id}/reboots/reconcile`` — explicit, idempotent
  init/refresh.

Slice 1 deliberately stops before any real reboot execution — these
tests assert the route serialization and HTTP status mapping, not
the (non-existent) reboot transport.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, HostFacts, Package, PackageUpdate, System
from app.services import patch_policy_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-rb-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-rb-cred",
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

    def make(*, reboot_required=None) -> System:
        counter["n"] += 1
        s = System(
            hostname=f"rt-rb-host-{counter['n']}.example.com",
            ip_address=f"10.0.95.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.commit()
        if reboot_required is not None:
            db.add(
                HostFacts(
                    system_id=s.id,
                    schema_version=1,
                    collected_at=datetime.utcnow(),
                    source_transport="ssh",
                    reboot_required=reboot_required,
                )
            )
            db.commit()
        return s

    return make


def _make_policy(db, admin_user, slug: str, *, reboot_policy: str = "if_required"):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
        reboot_policy=reboot_policy,
        requires_approval=False,
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _seed_host_for_plan(
    db, host_factory, suffix: str, *, reboot_required=None
) -> System:
    h = host_factory(reboot_required=reboot_required)
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


def _start_and_cancel(authed_client, plan_id: int) -> dict:
    """Start an execution then cancel it — produces a terminal
    execution without needing the dispatcher (which Slice 1 of
    PRA-172 must not depend on). Hosts will be in ``canceled``
    state, so the queue rows will be ``skipped`` with
    ``host_did_not_succeed`` — fine for proving the route shape."""
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
# GET /{execution_id}/reboots
# ---------------------------------------------------------------------------


def test_get_reboots_route_returns_queue_after_auto_reconcile_on_cancel(
    authed_client, db, admin_user, host_factory
):
    """PRA-172 Slice 2 wires auto-reconcile into the cancel path, so
    a canceled execution's reboot queue is populated without an
    explicit ``POST /reboots/reconcile`` call. Hosts that didn't
    succeed land as ``skipped`` (``host_did_not_succeed``)."""
    pol = _make_policy(db, admin_user, "rt-rb-auto-cancel")
    h = _seed_host_for_plan(db, host_factory, "a", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    res = authed_client.get(
        f"/patch/update-executions/{execution['id']}/reboots",
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_id"] == execution["id"]
    assert body["plan_id"] == plan["id"]
    assert body["execution_state"] == "canceled"
    assert body["summary"]["row_count"] == 1
    assert body["summary"]["state_counts"]["skipped"] == 1
    # The other DB-valid states are present in the rollup with zero
    # counts for the ones absent from this queue.
    for s in (
        "not_required",
        "pending",
        "scheduled",
        "rebooting",
        "verifying",
        "healthy",
        "failed",
    ):
        assert s in body["summary"]["state_counts"]
        assert body["summary"]["state_counts"][s] == 0


def test_get_reboots_route_404_on_unknown_execution(authed_client):
    res = authed_client.get("/patch/update-executions/987654/reboots")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# POST /{execution_id}/reboots/reconcile
# ---------------------------------------------------------------------------


def test_reconcile_route_initializes_queue_for_terminal_execution(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-rb-init")
    h = _seed_host_for_plan(db, host_factory, "b", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/reboots/reconcile",
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_id"] == execution["id"]
    assert body["plan_id"] == plan["id"]
    assert body["summary"]["row_count"] == 1
    # The host was canceled (not succeeded), so the queue row is
    # ``skipped`` with the ``host_did_not_succeed`` decision.
    rows = body["rows"]
    assert len(rows) == 1
    assert rows[0]["state"] == "skipped"
    assert rows[0]["decision_code"] == "host_did_not_succeed"


def test_reconcile_route_422_on_running_execution(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-rb-running")
    h = _seed_host_for_plan(db, host_factory, "c", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"]},
    )
    assert res.status_code == 201
    execution = res.json()

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/reboots/reconcile",
    )
    assert res.status_code == 422


def test_reconcile_route_404_on_unknown_execution(authed_client):
    res = authed_client.post(
        "/patch/update-executions/987654/reboots/reconcile",
    )
    assert res.status_code == 404


def test_reconcile_then_get_returns_same_queue(
    authed_client, db, admin_user, host_factory
):
    """Once reconcile has run, the GET endpoint returns the same
    summary/rows. Re-running reconcile is idempotent: no duplicate
    rows."""
    pol = _make_policy(db, admin_user, "rt-rb-idem")
    h = _seed_host_for_plan(db, host_factory, "d", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    res1 = authed_client.post(
        f"/patch/update-executions/{execution['id']}/reboots/reconcile",
    )
    assert res1.status_code == 200
    res2 = authed_client.post(
        f"/patch/update-executions/{execution['id']}/reboots/reconcile",
    )
    assert res2.status_code == 200
    assert res1.json()["summary"]["row_count"] == res2.json()["summary"]["row_count"]

    res3 = authed_client.get(
        f"/patch/update-executions/{execution['id']}/reboots",
    )
    assert res3.status_code == 200
    assert res3.json()["summary"]["row_count"] == 1


def test_reconcile_response_timestamps_are_absolute_utc(
    authed_client, db, admin_user, host_factory
):
    """PRA-172 review lock #2: read payload timestamps are absolute
    UTC (``...Z``) so API consumers cannot mistake them for local
    time. Decision-detail ``evaluated_at`` is also Z-suffixed."""
    pol = _make_policy(db, admin_user, "rt-rb-utc")
    h = _seed_host_for_plan(db, host_factory, "e", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/reboots/reconcile",
    )
    assert res.status_code == 200
    body = res.json()
    assert body["rows"], "expected at least one reconciled queue row"
    row = body["rows"][0]
    assert row["created_at"].endswith("Z")
    assert row["updated_at"].endswith("Z")
    assert row["scheduled_for_at"] is None  # Slice 1 never writes this
    assert row["started_at"] is None
    assert row["completed_at"] is None
    evaluated_at = row["decision_details"].get("evaluated_at")
    assert isinstance(evaluated_at, str)
    assert evaluated_at.endswith("Z")


# ---------------------------------------------------------------------------
# Plan-scoped read: GET /patch/update-plans/{plan_id}/reboots
# ---------------------------------------------------------------------------


def test_plan_reboots_route_404_on_unknown_plan(authed_client):
    res = authed_client.get("/patch/update-plans/987654/reboots")
    assert res.status_code == 404


def test_plan_reboots_route_empty_envelope_when_no_executions(
    authed_client, db, admin_user, host_factory
):
    """A plan with no executions yet returns a zero-count aggregate
    summary plus empty executions/rows lists. The plan surface
    must be readable without requiring a prior reconcile."""
    pol = _make_policy(db, admin_user, "rt-plan-empty")
    h = _seed_host_for_plan(db, host_factory, "f", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)

    res = authed_client.get(f"/patch/update-plans/{plan['id']}/reboots")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["plan_id"] == plan["id"]
    assert body["plan_state"] == "approved"
    assert body["executions"] == []
    assert body["rows"] == []
    assert body["summary"]["row_count"] == 0


def test_plan_reboots_route_aggregates_after_reconcile(
    authed_client, db, admin_user, host_factory
):
    """Once an execution has been reconciled, the plan-scoped read
    returns the aggregate summary plus the per-execution breakdown
    in ``executions``. All timestamp payloads are absolute UTC."""
    pol = _make_policy(db, admin_user, "rt-plan-aggr")
    h = _seed_host_for_plan(db, host_factory, "g", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    rec = authed_client.post(
        f"/patch/update-executions/{execution['id']}/reboots/reconcile",
    )
    assert rec.status_code == 200

    res = authed_client.get(f"/patch/update-plans/{plan['id']}/reboots")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["plan_id"] == plan["id"]
    assert body["summary"]["row_count"] == 1
    assert len(body["executions"]) == 1
    exec_ref = body["executions"][0]
    assert exec_ref["execution_id"] == execution["id"]
    assert exec_ref["execution_state"] == "canceled"
    assert exec_ref["summary"]["row_count"] == 1
    # Wire-shape timestamps are absolute UTC.
    assert exec_ref["started_at"].endswith("Z")
    assert exec_ref["completed_at"].endswith("Z")
    assert body["rows"][0]["created_at"].endswith("Z")


def test_scheduled_row_scheduled_for_at_serializes_with_utc_z(
    authed_client, db, admin_user, host_factory
):
    """PRA-172 review lock #2 + Slice 2 scheduling: when a row is
    in ``scheduled`` state, the wire payload's ``scheduled_for_at``
    is serialized as an absolute-UTC ISO string (``...Z``). The
    test sets up a canceled execution (which auto-reconciles), then
    directly mutates the queue row into ``scheduled`` with a
    naive-UTC ``scheduled_for_at`` so the route helper's
    ``utc_iso`` conversion can be asserted on both the
    execution-scoped and plan-scoped read endpoints."""
    from datetime import datetime as _dt

    from app.db.models import PatchUpdateExecutionReboot

    pol = _make_policy(db, admin_user, "rt-rb-utc-z")
    h = _seed_host_for_plan(db, host_factory, "z", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    # Promote the auto-reconciled row into a scheduled state via
    # direct DB mutation — exercising the wire-shape contract is
    # the focus here, not the dispatcher integration (the dispatcher
    # path is covered end-to-end in the service-level tests).
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution["id"])
        .one()
    )
    row.state = "scheduled"
    row.scheduled_for_at = _dt(2026, 5, 12, 4, 30, 0)
    db.commit()

    res = authed_client.get(f"/patch/update-executions/{execution['id']}/reboots")
    assert res.status_code == 200, res.text
    body = res.json()
    scheduled_rows = [r for r in body["rows"] if r["state"] == "scheduled"]
    assert len(scheduled_rows) == 1
    wire = scheduled_rows[0]
    assert isinstance(wire["scheduled_for_at"], str)
    assert wire["scheduled_for_at"].endswith("Z")
    # Round-trip parse confirms a real ISO 8601 datetime, not just
    # a literal "Z" suffix on garbage.
    _dt.fromisoformat(wire["scheduled_for_at"].rstrip("Z"))

    # Plan-scoped read surface uses the same UTC convention.
    res = authed_client.get(f"/patch/update-plans/{plan['id']}/reboots")
    assert res.status_code == 200, res.text
    body = res.json()
    scheduled_rows = [r for r in body["rows"] if r["state"] == "scheduled"]
    assert len(scheduled_rows) == 1
    assert scheduled_rows[0]["scheduled_for_at"].endswith("Z")


# ---------------------------------------------------------------------------
# Slice 3: POST /{execution_id}/reboots/dispatch-due
# ---------------------------------------------------------------------------


def test_dispatch_due_route_serializes_rebooting_row_with_utc_z(
    authed_client, db, admin_user, host_factory
):
    """End-to-end route test for the Slice 3 dispatch-due endpoint.

    Stages a single ``scheduled`` row whose ``scheduled_for_at`` is
    already past, monkey-patches the reboot transport to return an
    ``exit_zero`` success signal, hits the route, and asserts the
    response shape: row state ``rebooting``, ``started_at``
    serialized as absolute UTC ``...Z``, structured dispatch
    outcome on the response, audit-grade columns persisted."""
    from datetime import datetime as _dt
    from datetime import timedelta as _td

    from app.db.models import PatchUpdateExecutionReboot
    from app.services import patch_reboot_dispatch_service
    from app.services.patch_reboot_dispatch_service import (
        EXIT_SIGNAL_EXIT_ZERO,
        RebootDispatchResult,
    )

    pol = _make_policy(db, admin_user, "rt-rb-dispatch-due")
    h = _seed_host_for_plan(db, host_factory, "rd", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    # Stage a ``scheduled`` row whose ``scheduled_for_at`` is past.
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution["id"])
        .one()
    )
    row.state = "scheduled"
    row.scheduled_for_at = _dt.utcnow() - _td(seconds=60)
    db.commit()

    # Mock the transport so no real reboot is issued. The route
    # invokes the default reboot dispatcher; patch
    # ``default_reboot_dispatch`` so the test stays transport-free.
    def _fake_default(db_arg, system, cmd):
        return RebootDispatchResult(
            exit_signal_kind=EXIT_SIGNAL_EXIT_ZERO,
            exit_code=0,
            transport_name="fake-route-ssh",
        )

    import app.services.patch_reboot_dispatch_service as _mod

    orig = _mod.default_reboot_dispatch
    _mod.default_reboot_dispatch = _fake_default
    try:
        res = authed_client.post(
            f"/patch/update-executions/{execution['id']}/reboots/dispatch-due",
        )
    finally:
        _mod.default_reboot_dispatch = orig

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_id"] == execution["id"]
    assert body["dispatched_count"] == 1
    assert body["succeeded_count"] == 1
    assert body["failed_count"] == 0
    assert body["no_due"] is False
    assert body["pause_reason"] is None

    outcomes = body["host_outcomes"]
    assert len(outcomes) == 1
    assert outcomes[0]["state"] == "rebooting"
    assert outcomes[0]["exit_signal_kind"] == EXIT_SIGNAL_EXIT_ZERO
    assert outcomes[0]["transport_kind"] == "ssh"
    assert outcomes[0]["exit_code"] == 0

    # The embedded queue payload is the same shape as
    # GET /reboots — assert UTC wire shape on the rebooting row.
    rebooting = [r for r in body["queue"]["rows"] if r["state"] == "rebooting"]
    assert len(rebooting) == 1
    rb = rebooting[0]
    assert rb["transport_kind"] == "ssh"
    assert rb["exit_signal_kind"] == EXIT_SIGNAL_EXIT_ZERO
    # PRA-175: DEFAULT_REBOOT_COMMAND is now the planned argv without
    # ``sudo``; the dispatcher applies privilege escalation per
    # credential.sudo_method (this route fixture uses the default
    # ``sudo_method=none``).
    assert rb["command_snapshot"] == "systemctl reboot"
    assert rb["started_at"].endswith("Z")
    assert rb["completed_at"] is None  # rebooting is not terminal
    # dispatch_details is JSON; its dispatched_at must be Z-suffixed.
    dispatched_at = rb["dispatch_details"].get("dispatched_at")
    assert isinstance(dispatched_at, str)
    assert dispatched_at.endswith("Z")


def test_dispatch_due_route_422_on_running_execution(
    authed_client, db, admin_user, host_factory
):
    """Running executions cannot dispatch reboots; the gate must
    return 422 (not 500)."""
    pol = _make_policy(db, admin_user, "rt-rb-dd-running")
    h = _seed_host_for_plan(db, host_factory, "rr", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    res = authed_client.post(
        "/patch/update-executions/start", json={"plan_id": plan["id"]}
    )
    assert res.status_code == 201
    execution = res.json()

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/reboots/dispatch-due",
    )
    assert res.status_code == 422


def test_dispatch_due_route_404_on_unknown_execution(authed_client):
    res = authed_client.post(
        "/patch/update-executions/987654/reboots/dispatch-due",
    )
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Slice 4: POST /{execution_id}/reboots/verify-due
# ---------------------------------------------------------------------------


def test_verify_due_route_serializes_healthy_row_with_utc_z(
    authed_client, db, admin_user, host_factory
):
    """End-to-end route test for Slice 4 verify-due. Stages a
    ``rebooting`` row past the grace window, monkeypatches the
    default health probe to return uptime-reset evidence, hits the
    route, and asserts the response shape: row state ``healthy``,
    ``verified_at`` serialized as absolute UTC ``...Z``, structured
    verification result on the response."""
    from datetime import datetime as _dt
    from datetime import timedelta as _td

    from app.db.models import PatchUpdateExecutionReboot
    from app.services import patch_reboot_verify_service
    from app.services.patch_reboot_verify_service import RebootHealthProbeResult

    pol = _make_policy(db, admin_user, "rt-rb-verify")
    h = _seed_host_for_plan(db, host_factory, "v", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    execution = _start_and_cancel(authed_client, plan["id"])

    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution["id"])
        .one()
    )
    row.state = "rebooting"
    row.started_at = _dt.utcnow() - _td(seconds=120)
    row.dispatch_details = {
        "pre_reboot_facts": {
            "system_id": h.id,
            "uptime_seconds": 100_000,
            "kernel_version": "5.15.0-1.azure",
        }
    }
    db.commit()

    def _fake_default(db_arg, system, pre_facts):
        return RebootHealthProbeResult(
            reachable=True,
            post_reboot_facts={
                "system_id": system.id,
                "uptime_seconds": 42,
                "kernel_version": "5.15.0-1.azure",
            },
        )

    orig = patch_reboot_verify_service.default_reboot_health_probe
    patch_reboot_verify_service.default_reboot_health_probe = _fake_default
    try:
        res = authed_client.post(
            f"/patch/update-executions/{execution['id']}/reboots/verify-due",
        )
    finally:
        patch_reboot_verify_service.default_reboot_health_probe = orig

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_id"] == execution["id"]
    assert body["verified_count"] == 1
    assert body["succeeded_count"] == 1
    assert body["failed_count"] == 0
    assert body["no_due"] is False
    assert body["pause_reason"] is None

    outcomes = body["host_outcomes"]
    assert len(outcomes) == 1
    assert outcomes[0]["state"] == "healthy"
    assert outcomes[0]["reason"] == "uptime_reset"

    healthy = [r for r in body["queue"]["rows"] if r["state"] == "healthy"]
    assert len(healthy) == 1
    healthy_row = healthy[0]
    assert healthy_row["verified_at"].endswith("Z")
    assert isinstance(healthy_row["verification_details"], dict)
    assert healthy_row["verification_details"]["reason"] == "uptime_reset"
    assert healthy_row["verification_details"]["verified_at"].endswith("Z")


def test_verify_due_route_422_on_running_execution(
    authed_client, db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "rt-rb-verify-running")
    h = _seed_host_for_plan(db, host_factory, "vr", reboot_required=True)
    plan = _create_approved_plan(authed_client, db, admin_user, h, pol)
    res = authed_client.post(
        "/patch/update-executions/start", json={"plan_id": plan["id"]}
    )
    assert res.status_code == 201
    execution = res.json()
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/reboots/verify-due",
    )
    assert res.status_code == 422


def test_verify_due_route_404_on_unknown_execution(authed_client):
    res = authed_client.post(
        "/patch/update-executions/987654/reboots/verify-due",
    )
    assert res.status_code == 404
