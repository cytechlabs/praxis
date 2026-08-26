"""PRA-405: reboot-queue read surface reports reconciliation health.

The reboot queue is the operator's answer to "what still has to
reboot". These tests assert the API cannot present that answer as
complete when the pass that built it failed or left hosts uncovered,
including on a final wave where no dependent wave exists to block.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import (
    Credential,
    Group,
    Package,
    PackageUpdate,
    PatchUpdateExecutionReboot,
    System,
)
from app.services import patch_policy_service, patch_reboot_service


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="pra405-api-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra405-api-cred",
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
            hostname=f"pra405-api-host-{counter['n']}.example.com",
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


def _approved_plan(authed_client, db, admin_user, host, slug):
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
        reboot_policy="if_required",
        requires_approval=False,
    )
    patch_policy_service.bind_host(
        db, policy_id=policy.id, system_id=host.id, actor_user_id=admin_user.id
    )
    res = authed_client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": policy.id, "name": f"p-{slug}"},
    )
    assert res.status_code == 201, res.text
    plan = res.json()
    res = authed_client.post(
        f"/patch/update-plans/{plan['id']}/approval/approve", json={}
    )
    assert res.status_code == 200, res.text
    return res.json()


def _start_and_cancel(authed_client, plan_id: int) -> dict:
    res = authed_client.post(
        "/patch/update-executions/start", json={"plan_id": plan_id}
    )
    assert res.status_code == 201, res.text
    execution = res.json()
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/cancel",
        json={"cancel_reason": "test-fixture"},
    )
    assert res.status_code == 200, res.text
    return res.json()


def test_queue_read_reports_reconciliation_health(
    authed_client, db, admin_user, host_factory
):
    host = _seed_host_for_plan(db, host_factory, "ok")
    plan = _approved_plan(authed_client, db, admin_user, host, "pra405-api-ok")
    execution = _start_and_cancel(authed_client, plan["id"])

    res = authed_client.get(f"/patch/update-executions/{execution['id']}/reboots")

    assert res.status_code == 200, res.text
    block = res.json()["summary"]["reconciliation"]
    assert block["status"] == "ok"
    assert block["action_required"] is False
    assert block["missing_row_count"] == 0
    assert block["last_failure"] is None


def test_queue_read_reports_a_recorded_reconcile_failure(
    authed_client, db, admin_user, host_factory
):
    """A failed pass leaves the operator without a reboot workflow. The
    read surface has to say so rather than returning counts that look
    settled."""
    host = _seed_host_for_plan(db, host_factory, "fail")
    plan = _approved_plan(authed_client, db, admin_user, host, "pra405-api-fail")
    execution = _start_and_cancel(authed_client, plan["id"])

    patch_reboot_service.record_reconciliation_failure(
        db,
        execution["id"],
        reason="connection pool exhausted",
        phase="auto_reconcile",
    )

    res = authed_client.get(f"/patch/update-executions/{execution['id']}/reboots")

    assert res.status_code == 200, res.text
    block = res.json()["summary"]["reconciliation"]
    assert block["status"] == "failed"
    assert block["action_required"] is True
    assert block["last_failure"]["reason"] == "connection pool exhausted"
    assert block["last_failure"]["failed_at"].endswith("Z")


def test_plan_scoped_read_aggregates_reconciliation_health(
    authed_client, db, admin_user, host_factory
):
    host = _seed_host_for_plan(db, host_factory, "plan")
    plan = _approved_plan(authed_client, db, admin_user, host, "pra405-api-plan")
    execution = _start_and_cancel(authed_client, plan["id"])

    patch_reboot_service.record_reconciliation_failure(
        db, execution["id"], reason="boom", phase="auto_reconcile"
    )

    res = authed_client.get(f"/patch/update-plans/{plan['id']}/reboots")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["summary"]["reconciliation"]["status"] == "failed"
    assert body["summary"]["reconciliation"]["action_required"] is True
    assert body["summary"]["reconciliation"]["execution_ids_action_required"] == [
        execution["id"]
    ]
    assert body["executions"][0]["summary"]["reconciliation"]["status"] == "failed"


def test_queue_read_reports_missing_rows_as_incomplete(
    authed_client, db, admin_user, host_factory
):
    host = _seed_host_for_plan(db, host_factory, "gap")
    plan = _approved_plan(authed_client, db, admin_user, host, "pra405-api-gap")
    execution = _start_and_cancel(authed_client, plan["id"])

    # A canceled host produces a ``skipped`` row and no coverage
    # requirement, so drive the host to succeeded before removing its
    # row to model a reconcile pass that rolled back.
    from app.db.models import PatchUpdateExecutionHost

    exec_host = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution["id"])
        .one()
    )
    exec_host.state = "succeeded"
    db.query(PatchUpdateExecutionReboot).filter(
        PatchUpdateExecutionReboot.execution_id == execution["id"]
    ).delete()
    db.commit()

    res = authed_client.get(f"/patch/update-executions/{execution['id']}/reboots")

    assert res.status_code == 200, res.text
    block = res.json()["summary"]["reconciliation"]
    assert block["status"] == "incomplete"
    assert block["action_required"] is True
    assert block["missing_row_count"] == 1
