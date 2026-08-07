"""PRA-180 P2 Remediation (PRA-223): patch dispatch idempotency.

PATCH-01: ``patch_execution_dispatch_service`` flipped a host ``pending ->
running`` with a plain ORM write before dispatching, so two concurrent
``dispatch_next_batch`` calls (operator double-click, or a scheduler tick
overlapping an operator action across the prod uvicorn workers) could both
observe the same pending row and dispatch the package command twice. The fix is
an atomic conditional UPDATE (``WHERE state == pending``) claim, mirroring the
reboot dispatcher.

This module proves a host is claimed/dispatched at most once even when a
concurrent dispatcher claims a host mid-batch, and that normal sequential
dispatch is unaffected. The symmetric ROLLBACK-01 fix is covered in
``test_pra173_rollback_slice3.py`` where the rollback fixtures live.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    Package,
    PackageUpdate,
    PatchPolicy,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    System,
)
from app.services import (
    patch_execution_service,
    patch_policy_service,
    patch_update_plan_service,
)
from app.services.patch_execution_dispatch_service import (
    OUTCOME_SKIPPED_CLAIM,
    DispatchResult,
    dispatch_next_batch,
)
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_PENDING,
    EXECUTION_HOST_STATE_RUNNING,
    EXECUTION_HOST_STATE_SUCCEEDED,
)

# ── fixtures / helpers (self-contained; mirror test_pra171) ────────────────


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="pra223-grp", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra223-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def host_factory(db, seed_distro, static_group, credentials):
    counter = {"n": 0}

    def make() -> System:
        counter["n"] += 1
        s = System(
            hostname=f"pra223-host-{counter['n']}.example.com",
            ip_address=f"10.0.93.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        return s

    return make


def _make_policy(db, admin_user, slug: str) -> PatchPolicy:
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
        requires_approval=False,
    )


def _seed_host_with_update(db, host_factory, suffix: str) -> System:
    h = host_factory()
    p = Package(
        system_id=h.id,
        name=f"pkg-{suffix}",
        installed_version="1.0",
        package_type="apt",
    )
    db.add(p)
    db.flush()
    db.add(
        PackageUpdate(
            package_id=p.id,
            system_id=h.id,
            available_version="1.1",
            update_type="security",
            discovered_on=datetime.utcnow(),
        )
    )
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
    db.flush()
    return h


def _bind(db, admin_user, policy, host) -> None:
    patch_policy_service.bind_host(
        db, policy_id=policy.id, system_id=host.id, actor_user_id=admin_user.id
    )


def _start(db, admin_user, hosts: List[System], policy: PatchPolicy, max_parallel: int):
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=policy.id,
        name=f"plan-{policy.slug}",
        target_system_ids=[h.id for h in hosts],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    return patch_execution_service.start_execution(
        db,
        plan_id=plan.id,
        actor_user_id=admin_user.id,
        max_parallel_per_wave=max_parallel,
    )


def _ok(system, cmd):
    return DispatchResult(exit_code=0, stdout="ok", stderr="", transport_name="fake")


# ── tests ──────────────────────────────────────────────────────────────────


def test_concurrent_claim_dispatches_each_host_once(db, admin_user, host_factory):
    """Two hosts are taken into one batch. While host A is dispatching, a
    concurrent worker claims host B (flips it to ``running``). The atomic
    claim must then skip B: the dispatcher is invoked only for A, and B is
    neither dispatched nor double-counted."""
    pol = _make_policy(db, admin_user, "pra223-claim")
    h1 = _seed_host_with_update(db, host_factory, "a")
    h2 = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h1)
    _bind(db, admin_user, pol, h2)
    execution = _start(db, admin_user, [h1, h2], pol, max_parallel=2)

    rows = patch_execution_service.list_execution_hosts(db, execution.id)
    pending = sorted(
        [r for r in rows if r.state == EXECUTION_HOST_STATE_PENDING],
        key=lambda r: r.id,
    )
    assert len(pending) == 2, "both hosts should be pending in the batch"
    assert pending[0].wave_index == pending[1].wave_index, "same wave for one batch"
    host_a_id, host_b_id = pending[0].id, pending[1].id

    calls: List[int] = []

    def racing_dispatch(system, cmd):
        calls.append(system.id)
        if len(calls) == 1:
            # Simulate a concurrent dispatcher claiming host B between the
            # batch SELECT and our per-host claim.
            db.query(PatchUpdateExecutionHost).filter(
                PatchUpdateExecutionHost.id == host_b_id
            ).update(
                {PatchUpdateExecutionHost.state: EXECUTION_HOST_STATE_RUNNING},
                synchronize_session=False,
            )
            db.flush()
        return DispatchResult(exit_code=0, transport_name="fake")

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=racing_dispatch,
    )

    # Dispatcher ran for host A only; B was skipped at claim time.
    assert len(calls) == 1
    assert summary.dispatched_count == 1
    assert summary.succeeded_count == 1
    assert summary.failed_count == 0
    assert all(o["outcome"] != OUTCOME_SKIPPED_CLAIM for o in summary.host_outcomes)

    host_a = db.get(PatchUpdateExecutionHost, host_a_id)
    host_b = db.get(PatchUpdateExecutionHost, host_b_id)
    assert host_a.state == EXECUTION_HOST_STATE_SUCCEEDED
    # B stays running (claimed by the "other worker"); we did not process it,
    # so it has no completion and no per-package rows from this call.
    assert host_b.state == EXECUTION_HOST_STATE_RUNNING
    assert host_b.completed_at is None
    b_pkgs = (
        db.query(PatchUpdateExecutionHostPackage)
        .filter(PatchUpdateExecutionHostPackage.execution_host_id == host_b_id)
        .all()
    )
    assert b_pkgs == []


def test_sequential_dispatch_claims_and_dispatches_normally(
    db, admin_user, host_factory
):
    """No concurrency: the atomic claim is transparent — the single pending
    host is claimed and dispatched exactly once."""
    pol = _make_policy(db, admin_user, "pra223-seq")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol, max_parallel=1)

    calls: List[int] = []

    def counting_dispatch(system, cmd):
        calls.append(system.id)
        return _ok(system, cmd)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=counting_dispatch,
    )
    assert len(calls) == 1
    assert summary.dispatched_count == 1
    assert summary.succeeded_count == 1
    host_row = patch_execution_service.list_execution_hosts(db, execution.id)[0]
    assert host_row.state == EXECUTION_HOST_STATE_SUCCEEDED
    assert host_row.started_at is not None
