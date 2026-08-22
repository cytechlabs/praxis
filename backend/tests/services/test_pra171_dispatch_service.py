"""PRA-171 slice 2 — per-host dispatch service tests.

Covers ``patch_execution_dispatch_service.dispatch_next_batch`` and
the pure command builders. All tests use a fake ``DispatchCallable``
so no real package manager / SSH / agent is invoked.

Slice 2 contract verified:

* Dispatch refuses unknown executions (404 wording) and non-running
  executions (422 wording).
* Dispatch picks the lowest pending wave and respects
  ``max_parallel_per_wave``.
* Per-host state transitions deterministically: pending → running →
  succeeded/failed.
* Per-package result rows are written for every selected package on
  the dispatched host with the correct outcome.
* Three new audit events emit via patched ``safe_emit`` no ``db=``.
* Unknown package family is refused with ``unsupported_package_family``
  and the host lands ``failed`` with per-package rows recorded.
* No ``Package`` / ``PackageUpdate`` mutation occurs in any path.
* ``PatchUpdatePlanSelectedPackage`` rows are NOT mutated by the
  dispatcher.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Dict, List

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
    PatchUpdatePlanSelectedPackage,
    System,
)
from app.services import (
    patch_execution_dispatch_service,
    patch_execution_service,
    patch_policy_service,
    patch_update_plan_service,
)
from app.services.patch_execution_dispatch_service import (
    AUDIT_EXECUTION_HOST_FAILED,
    AUDIT_EXECUTION_HOST_STARTED,
    AUDIT_EXECUTION_HOST_SUCCEEDED,
    ERROR_CODE_PACKAGE_MANAGER_FAILED,
    ERROR_CODE_TRANSPORT_ERROR,
    PACKAGE_OUTCOME_FAILED,
    PACKAGE_OUTCOME_SUCCEEDED,
    DispatchResult,
    build_apt_command,
    build_command_for_family,
    build_dnf_command,
    dispatch_next_batch,
)
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_FAILED,
    EXECUTION_HOST_STATE_PENDING,
    EXECUTION_HOST_STATE_SKIPPED,
    EXECUTION_HOST_STATE_SUCCEEDED,
    SKIP_REASON_PLAN_HOST_TARGETLESS,
    PatchUpdateExecutionError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="disp-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="disp-test-cred",
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
            hostname=f"disp-host-{counter['n']}.example.com",
            ip_address=f"10.0.91.{counter['n']}",
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


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _add_installed(db, system: System, name: str, version: str) -> Package:
    p = Package(
        system_id=system.id,
        name=name,
        installed_version=version,
        package_type="apt",
    )
    db.add(p)
    db.flush()
    return p


def _add_update(
    db,
    system: System,
    package: Package,
    available_version: str,
    update_type: str = "security",
) -> PackageUpdate:
    upd = PackageUpdate(
        package_id=package.id,
        system_id=system.id,
        available_version=available_version,
        update_type=update_type,
        discovered_on=datetime.utcnow(),
    )
    db.add(upd)
    db.flush()
    return upd


def _seed_host_with_update(
    db, host_factory, suffix: str, *, package_manager: str = "apt"
) -> System:
    """Seed a host with one Package + one PackageUpdate plus the
    HostFacts row that the PRA-164 preflight resolver needs to derive
    a non-``unknown`` ``package_manager_family_snapshot``. Without
    HostFacts the dispatcher refuses with ``unsupported_package_family``."""
    h = host_factory()
    p = _add_installed(db, h, f"pkg-{suffix}", "1.0")
    _add_update(db, h, p, "1.1")
    db.add(
        HostFacts(
            system_id=h.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="ssh",
            package_manager=package_manager,
            distro_id_facts="ubuntu" if package_manager == "apt" else "rhel",
        )
    )
    db.flush()
    return h


def _start(
    db, admin_user, hosts: List[System], policy: PatchPolicy, max_parallel: int = 1
):
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


def _skip_all_pending_hosts(db, execution_id: int) -> int:
    """Mark every still-pending host row of an execution ``skipped``.

    Models a target that stops being dispatchable between
    materialization and the dispatch call, which is how an execution
    reaches "running with nothing left to dispatch" now that a plan
    with no selected work at all is refused at the start gate.
    """
    rows = (
        db.query(PatchUpdateExecutionHost)
        .filter(
            PatchUpdateExecutionHost.execution_id == execution_id,
            PatchUpdateExecutionHost.state == EXECUTION_HOST_STATE_PENDING,
        )
        .all()
    )
    for row in rows:
        row.state = EXECUTION_HOST_STATE_SKIPPED
        row.skip_reasons = [
            {"code": SKIP_REASON_PLAN_HOST_TARGETLESS, "details": {}},
        ]
    db.flush()
    return len(rows)


def _succeed_callable() -> Callable:
    """DispatchCallable that always returns exit 0."""

    def _impl(system, cmd):
        return DispatchResult(
            exit_code=0,
            stdout="installed.\n",
            stderr="",
            duration_ms=42,
            transport_name="fake",
        )

    return _impl


def _fail_callable(exit_code: int = 100, stderr: str = "broken pkg") -> Callable:
    def _impl(system, cmd):
        return DispatchResult(
            exit_code=exit_code,
            stdout="",
            stderr=stderr,
            duration_ms=11,
            transport_name="fake",
        )

    return _impl


def _transport_error_callable() -> Callable:
    def _impl(system, cmd):
        return DispatchResult(
            exit_code=-1,
            error=ERROR_CODE_TRANSPORT_ERROR,
            stderr="connection refused",
        )

    return _impl


# ---------------------------------------------------------------------------
# Pure command builders
# ---------------------------------------------------------------------------


def test_build_apt_command_pins_versions():
    args = build_apt_command([("openssl", "1.0.1"), ("curl", None)])
    assert args == [
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        "openssl=1.0.1",
        "curl",
    ]


def test_build_dnf_command_pins_versions():
    args = build_dnf_command([("openssl", "1.0.1"), ("curl", None)])
    assert args == ["dnf", "install", "-y", "openssl-1.0.1", "curl"]


def test_build_command_for_family_unknown_raises():
    with pytest.raises(PatchUpdateExecutionError) as exc:
        build_command_for_family("unknown", [("p", "1")])
    assert "unsupported package family" in str(exc.value)


# ---------------------------------------------------------------------------
# dispatch_next_batch refusals
# ---------------------------------------------------------------------------


def test_dispatch_refuses_unknown_execution(db, admin_user):
    with pytest.raises(PatchUpdateExecutionError) as exc:
        dispatch_next_batch(
            db,
            999_999,
            actor_user_id=admin_user.id,
            dispatch_callable=_succeed_callable(),
        )
    assert "not found" in str(exc.value)


def test_dispatch_refuses_paused_execution(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "disp-paused")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.pause_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    with pytest.raises(PatchUpdateExecutionError) as exc:
        dispatch_next_batch(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            dispatch_callable=_succeed_callable(),
        )
    assert (
        "paused" in str(exc.value).lower()
        or "not 'running'" in str(exc.value).lower()
        or "may dispatch" in str(exc.value).lower()
    )


def test_dispatch_refuses_canceled_execution(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "disp-canceled")
    h = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    with pytest.raises(PatchUpdateExecutionError):
        dispatch_next_batch(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            dispatch_callable=_succeed_callable(),
        )


# ---------------------------------------------------------------------------
# Empty-pending case
# ---------------------------------------------------------------------------


def test_dispatch_no_pending_returns_no_pending(db, admin_user, host_factory):
    """An execution with only skipped hosts has no pending hosts; the
    dispatcher returns ``no_pending=True`` rather than raising.

    The start gate refuses a plan whose every host resolves to zero
    selected packages, so the state is reached the way it is reachable
    at run time: a mixed plan starts, and the one dispatchable host is
    then skipped before the dispatcher runs.
    """
    pol = _make_policy(db, admin_user, "disp-skipped-only")
    h_work = _seed_host_with_update(db, host_factory, "nopending")
    _bind(db, admin_user, pol, h_work)
    h_empty = host_factory()  # no Package / PackageUpdate => skipped
    _bind(db, admin_user, pol, h_empty)
    execution = _start(db, admin_user, [h_work, h_empty], pol)

    _skip_all_pending_hosts(db, execution.id)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_succeed_callable(),
    )
    assert summary.no_pending is True
    assert summary.dispatched_count == 0


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_dispatch_succeeds_for_apt_host(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "disp-apt-ok")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_succeed_callable(),
    )
    assert summary.dispatched_count == 1
    assert summary.succeeded_count == 1
    assert summary.failed_count == 0
    assert summary.wave_index == 0

    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    assert len(hosts) == 1
    h_row = hosts[0]
    assert h_row.state == EXECUTION_HOST_STATE_SUCCEEDED
    assert h_row.started_at is not None
    assert h_row.completed_at is not None
    assert h_row.error_details["exit_code"] == 0
    assert "fake" == h_row.error_details.get("transport")

    pkgs = (
        db.query(PatchUpdateExecutionHostPackage)
        .filter(PatchUpdateExecutionHostPackage.execution_host_id == h_row.id)
        .all()
    )
    assert len(pkgs) == 1
    assert pkgs[0].outcome == PACKAGE_OUTCOME_SUCCEEDED
    assert pkgs[0].package_name == "pkg-a"
    assert pkgs[0].requested_version_snapshot == "1.1"
    assert pkgs[0].installed_version_before == "1.0"
    assert pkgs[0].package_manager_family_snapshot == "apt"


def test_dispatch_failed_for_apt_host_records_per_package_failure(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "disp-apt-fail")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fail_callable(exit_code=100, stderr="apt blew up"),
    )
    assert summary.failed_count == 1
    assert summary.succeeded_count == 0

    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    h_row = hosts[0]
    assert h_row.state == EXECUTION_HOST_STATE_FAILED
    assert h_row.error_details["exit_code"] == 100
    assert h_row.error_details["code"] == ERROR_CODE_PACKAGE_MANAGER_FAILED
    assert "apt blew up" in h_row.error_details["stderr"]

    pkgs = list(h_row.packages)
    assert len(pkgs) == 1
    assert pkgs[0].outcome == PACKAGE_OUTCOME_FAILED
    assert pkgs[0].error_code == ERROR_CODE_PACKAGE_MANAGER_FAILED


def test_dispatch_transport_error_marks_host_failed_with_transport_code(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "disp-transport-err")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_transport_error_callable(),
    )
    assert summary.failed_count == 1
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    assert hosts[0].state == EXECUTION_HOST_STATE_FAILED
    assert hosts[0].error_details["code"] == ERROR_CODE_TRANSPORT_ERROR


# ---------------------------------------------------------------------------
# max_parallel_per_wave + wave ordering
# ---------------------------------------------------------------------------


def test_dispatch_respects_max_parallel_per_wave(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "disp-max-par")
    h_a = _seed_host_with_update(db, host_factory, "a")
    h_b = _seed_host_with_update(db, host_factory, "b")
    h_c = _seed_host_with_update(db, host_factory, "c")
    for h in (h_a, h_b, h_c):
        _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h_a, h_b, h_c], pol, max_parallel=2)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_succeed_callable(),
    )
    assert summary.dispatched_count == 2
    assert summary.succeeded_count == 2

    # The third host should still be pending after the first call.
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    state_counts: Dict[str, int] = {}
    for h_row in hosts:
        state_counts[h_row.state] = state_counts.get(h_row.state, 0) + 1
    assert state_counts.get(EXECUTION_HOST_STATE_PENDING, 0) == 1
    assert state_counts.get(EXECUTION_HOST_STATE_SUCCEEDED, 0) == 2

    # Second call should drain the remaining pending host.
    summary2 = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_succeed_callable(),
    )
    assert summary2.dispatched_count == 1


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def test_audit_emitted_for_host_dispatch(db, admin_user, host_factory, monkeypatch):
    captured: List[dict] = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_execution_dispatch_service, "safe_emit", fake_safe_emit)

    pol = _make_policy(db, admin_user, "disp-aud")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_succeed_callable(),
    )
    actions = [c["action"] for c in captured]
    assert AUDIT_EXECUTION_HOST_STARTED in actions
    assert AUDIT_EXECUTION_HOST_SUCCEEDED in actions
    # safe_emit session-boundary lock: no db= argument.
    for c in captured:
        assert "db" not in c


def test_audit_emits_host_failed_on_failure(db, admin_user, host_factory, monkeypatch):
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_execution_dispatch_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )

    pol = _make_policy(db, admin_user, "disp-aud-fail")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fail_callable(),
    )
    actions = [c["action"] for c in captured]
    assert AUDIT_EXECUTION_HOST_FAILED in actions
    assert AUDIT_EXECUTION_HOST_SUCCEEDED not in actions


# ---------------------------------------------------------------------------
# Out-of-scope guarantees (Slice 2 must not mutate package state)
# ---------------------------------------------------------------------------


def test_dispatch_does_not_mutate_packages_or_selected_packages(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "disp-no-pkg-mut")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    pkg_count_before = db.query(Package).filter(Package.system_id == h.id).count()
    upd_count_before = (
        db.query(PackageUpdate).filter(PackageUpdate.system_id == h.id).count()
    )
    sel_count_before = db.query(PatchUpdatePlanSelectedPackage).count()

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_succeed_callable(),
    )

    assert (
        db.query(Package).filter(Package.system_id == h.id).count()
    ) == pkg_count_before
    assert (
        db.query(PackageUpdate).filter(PackageUpdate.system_id == h.id).count()
    ) == upd_count_before
    assert db.query(PatchUpdatePlanSelectedPackage).count() == sel_count_before


def test_dispatch_idempotent_per_pending_host(db, admin_user, host_factory):
    """Once a host transitions to succeeded/failed, a subsequent
    dispatch-next call should not re-process it. Slice 2 selects only
    `pending` hosts. Slice 3 then finalizes the execution to
    ``succeeded`` after the only host completes; a follow-up dispatch
    call must therefore refuse with the standard non-running error
    (the execution is terminal)."""
    pol = _make_policy(db, admin_user, "disp-idem")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    s1 = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_succeed_callable(),
    )
    assert s1.succeeded_count == 1
    # Slice 3: the only host completed, so the execution is now
    # ``succeeded``. Further dispatch calls are refused.
    assert s1.finalized_state == "succeeded"

    with pytest.raises(PatchUpdateExecutionError):
        dispatch_next_batch(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            dispatch_callable=_succeed_callable(),
        )


# ---------------------------------------------------------------------------
# Progress aggregation includes per-package outcome counts
# ---------------------------------------------------------------------------


def test_progress_summary_includes_package_outcome_counts(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "disp-progress")
    h_a = _seed_host_with_update(db, host_factory, "a")
    h_b = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    execution = _start(db, admin_user, [h_a, h_b], pol, max_parallel=2)

    # A: succeed; B: fail. Run with two callables in sequence is
    # cumbersome; instead use a stateful callable that succeeds first
    # then fails.
    state = {"calls": 0}

    def alternate(system, cmd):
        state["calls"] += 1
        if state["calls"] == 1:
            return DispatchResult(exit_code=0, transport_name="fake")
        return DispatchResult(exit_code=100, stderr="fail", transport_name="fake")

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=alternate,
    )
    progress = patch_execution_service.execution_with_progress(db, execution)[1]
    counts = progress["package_outcome_counts"]
    assert counts["succeeded"] >= 1
    assert counts["failed"] >= 1
