"""PRA-171 slice 2 — dispatch route tests.

Covers ``POST /patch/update-executions/{id}/dispatch-next`` and
``GET /patch/update-executions/{id}/hosts/{host_id}/packages``.
Patches the dispatch service's ``default_dispatch`` so no real
package manager / SSH / agent is invoked in CI.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, HostFacts, Package, PackageUpdate, System
from app.services import patch_execution_dispatch_service, patch_policy_service
from app.services.patch_execution_dispatch_service import DispatchResult


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rt-disp-group", description="t")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rt-disp-cred",
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
            hostname=f"rt-disp-host-{counter['n']}.example.com",
            ip_address=f"10.0.92.{counter['n']}",
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


def _seed_host_with_update(db, host_factory, suffix: str) -> System:
    """Seed a host with one Package + one PackageUpdate plus the
    HostFacts row the PRA-164 preflight resolver needs so the
    dispatcher derives an apt family (not 'unknown')."""
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
    db.add(
        HostFacts(
            system_id=h.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="ssh",
            package_manager="apt",
            distro_id_facts="ubuntu",
        )
    )
    db.commit()
    return h


def _create_running_execution(authed_client, db, admin_user, host, policy):
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
    res = authed_client.post(
        "/patch/update-executions/start",
        json={"plan_id": plan["id"]},
    )
    assert res.status_code == 201, res.text
    return res.json()


@pytest.fixture
def patch_default_dispatch(monkeypatch):
    """Monkey-patch the dispatch service's default adapter so route
    tests never reach real SSH/agent transport. Returns a recorder
    list of the package commands the test can inspect.

    Reboot-required probes ride the same adapter after a host's package
    work succeeds. They answer "no reboot needed" here and are kept out
    of the recorder so it stays a record of package dispatches.
    """
    calls = []

    def fake(db, system, cmd):  # pylint: disable=unused-argument
        if "PRAXIS_REBOOT_PROBE" in " ".join(cmd):
            return DispatchResult(
                exit_code=0,
                stdout="PRAXIS_REBOOT_PROBE=false",
                stderr="",
                duration_ms=5,
                transport_name="fake",
            )
        calls.append({"system_id": system.id, "cmd": cmd})
        return DispatchResult(
            exit_code=0,
            stdout="ok",
            stderr="",
            duration_ms=5,
            transport_name="fake",
        )

    monkeypatch.setattr(patch_execution_dispatch_service, "default_dispatch", fake)
    return calls


def test_dispatch_next_route_runs_one_batch(
    authed_client, db, admin_user, host_factory, patch_default_dispatch
):
    pol = _make_policy(db, admin_user, "rt-disp-ok")
    h = _seed_host_with_update(db, host_factory, "a")
    execution = _create_running_execution(authed_client, db, admin_user, h, pol)

    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/dispatch-next"
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_id"] == execution["id"]
    assert body["dispatched_count"] == 1
    assert body["succeeded_count"] == 1
    assert body["failed_count"] == 0
    assert body["wave_index"] == 0
    assert body["execution"]["progress"]["host_counts_by_state"]["succeeded"] == 1
    assert body["execution"]["progress"]["package_outcome_counts"]["succeeded"] == 1
    assert len(patch_default_dispatch) == 1


def test_dispatch_next_route_404_on_unknown_execution(authed_client):
    res = authed_client.post("/patch/update-executions/999999/dispatch-next")
    assert res.status_code == 404


def test_dispatch_next_route_422_when_paused(
    authed_client, db, admin_user, host_factory, patch_default_dispatch
):
    pol = _make_policy(db, admin_user, "rt-disp-paused")
    h = _seed_host_with_update(db, host_factory, "b")
    execution = _create_running_execution(authed_client, db, admin_user, h, pol)
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/pause", json={}
    )
    assert res.status_code == 200
    res = authed_client.post(
        f"/patch/update-executions/{execution['id']}/dispatch-next"
    )
    assert res.status_code == 422


def test_dispatch_next_route_finalizes_when_drained(
    authed_client, db, admin_user, host_factory, patch_default_dispatch
):
    """Slice 3: a single-host happy-path call drains the wave, finalizes
    the execution to ``succeeded``, and a follow-up dispatch call must
    refuse with the standard non-running 422."""
    pol = _make_policy(db, admin_user, "rt-disp-drain")
    h = _seed_host_with_update(db, host_factory, "c")
    execution = _create_running_execution(authed_client, db, admin_user, h, pol)
    # First call drains the only host and finalizes the execution.
    res1 = authed_client.post(
        f"/patch/update-executions/{execution['id']}/dispatch-next"
    )
    assert res1.status_code == 200, res1.text
    body1 = res1.json()
    assert body1["finalized_state"] == "succeeded"
    assert body1["execution"]["state"] == "succeeded"
    # Follow-up call: terminal execution refuses further dispatch.
    res2 = authed_client.post(
        f"/patch/update-executions/{execution['id']}/dispatch-next"
    )
    assert res2.status_code == 422


def test_host_packages_route_returns_per_package_rows(
    authed_client, db, admin_user, host_factory, patch_default_dispatch
):
    pol = _make_policy(db, admin_user, "rt-disp-pkgs")
    h = _seed_host_with_update(db, host_factory, "d")
    execution = _create_running_execution(authed_client, db, admin_user, h, pol)
    authed_client.post(f"/patch/update-executions/{execution['id']}/dispatch-next")
    detail = authed_client.get(f"/patch/update-executions/{execution['id']}").json()
    host_id = detail["hosts"][0]["id"]

    res = authed_client.get(
        f"/patch/update-executions/{execution['id']}/hosts/{host_id}/packages"
    )
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["package_name"] == "pkg-d"
    assert rows[0]["outcome"] == "succeeded"


def test_host_packages_route_404_when_host_not_on_execution(
    authed_client, db, admin_user, host_factory, patch_default_dispatch
):
    pol = _make_policy(db, admin_user, "rt-disp-bad-host")
    h = _seed_host_with_update(db, host_factory, "e")
    execution = _create_running_execution(authed_client, db, admin_user, h, pol)
    res = authed_client.get(
        f"/patch/update-executions/{execution['id']}/hosts/999999/packages"
    )
    assert res.status_code == 404
