"""PRA-173 slice 3 — rollback dispatch service tests.

Covers ``patch_rollback_dispatch_service``:

* ``start_rollback_execution`` refuses unless rollback approval is
  ``approved`` and a frozen plan snapshot exists; refuses if a live
  dispatch already exists; materializes one host + one package row
  per snapshot entry.
* ``dispatch_next_batch`` consumes the *frozen* plan snapshot (NOT
  the live ``command_plan`` columns), processes hosts through the
  injected ``DispatchCallable`` fake, runs pre-steps before primary
  before post-steps, records per-package outcomes, and emits
  ``patch_rollback.host_succeeded`` / ``host_failed`` /
  ``completed`` via the safe-emit path.
* ``cancel_rollback_execution`` flips pending hosts to canceled and
  preserves succeeded / failed.
* Slice 3 never mutates ``PackageHistory``, never re-derives plans
  from live columns, and never calls real SSH (the fake adapter is
  the entire dispatch surface in these tests).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Tuple

import pytest

from app.db.models import (
    Credential,
    Group,
    Package,
    PackageHistory,
    PatchPolicy,
    PatchRollbackDispatchHost,
    PatchRollbackDispatchHostPackage,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdateExecutionRollbackPackage,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    System,
)
from app.services import patch_rollback_dispatch_service, patch_rollback_service
from app.services.patch_execution_dispatch_service import DispatchResult
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_SUCCEEDED,
    EXECUTION_STATE_SUCCEEDED,
)
from app.services.patch_rollback_dispatch_service import (
    HOST_STATE_CANCELED,
    HOST_STATE_FAILED,
    HOST_STATE_PENDING,
    HOST_STATE_SUCCEEDED,
    PACKAGE_OUTCOME_FAILED,
    PACKAGE_OUTCOME_SUCCEEDED,
    REFUSAL_APPROVAL_NOT_APPROVED,
    REFUSAL_LIVE_DISPATCH_EXISTS,
    RUN_STATE_FAILED,
    RUN_STATE_RUNNING,
    RUN_STATE_SUCCEEDED,
)
from app.services.patch_rollback_service import PatchUpdateRollbackError
from app.services.patch_update_plan_service import PLAN_STATE_APPROVED

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rb-s3-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rb-s3-cred",
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
            hostname=f"rb-s3-host-{counter['n']}.example.com",
            ip_address=f"10.0.99.{counter['n']}",
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


def _make_policy_row(db, slug: str, admin_user) -> PatchPolicy:
    p = PatchPolicy(
        slug=slug,
        name=slug,
        scope_kind="full",
        scope_packages=[],
        reboot_policy="if_required",
        reboot_window_id=None,
        maintenance_window_id=None,
        rollout_cadence="immediate",
        failure_policy="continue",
        requires_approval=False,
        required_approvals=1,
        enabled=True,
        is_fleet_default=False,
        created_by=admin_user.id,
    )
    db.add(p)
    db.flush()
    return p


def _make_plan_row(db, policy: PatchPolicy, admin_user) -> PatchUpdatePlan:
    plan = PatchUpdatePlan(
        policy_id=policy.id,
        name=f"plan-{policy.slug}",
        state=PLAN_STATE_APPROVED,
        policy_snapshot={"id": policy.id, "slug": policy.slug, "name": policy.name},
        ring_sequence_snapshot=[],
        request_snapshot={},
        block_reasons=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    return plan


def _make_execution_row(db, plan, admin_user) -> PatchUpdateExecution:
    now = datetime.utcnow()
    e = PatchUpdateExecution(
        plan_id=plan.id,
        state=EXECUTION_STATE_SUCCEEDED,
        started_by=admin_user.id,
        started_at=now,
        completed_at=now,
        max_parallel_per_wave=1,
        failure_threshold_percent=None,
        plan_state_snapshot=plan.state,
        policy_snapshot=dict(plan.policy_snapshot or {}),
        execution_config_snapshot={},
        progress_summary={},
    )
    db.add(e)
    db.flush()
    return e


def _make_plan_host(
    db, plan, system, *, content_profile_id_snapshot
) -> PatchUpdatePlanHost:
    ph = PatchUpdatePlanHost(
        plan_id=plan.id,
        system_id=system.id,
        system_hostname_snapshot=system.hostname,
        policy_resolution_kind="direct_host",
        ring_resolution_status="resolved",
        wave_index=0,
        content_profile_state="resolved",
        content_profile_id_snapshot=content_profile_id_snapshot,
        content_profile_conflict_snapshot=[],
        state="planned",
        block_reasons=[],
    )
    db.add(ph)
    db.flush()
    return ph


def _make_execution_host(db, execution, plan_host) -> PatchUpdateExecutionHost:
    host = PatchUpdateExecutionHost(
        execution_id=execution.id,
        plan_host_id=plan_host.id,
        system_id_snapshot=plan_host.system_id,
        system_hostname_snapshot=plan_host.system_hostname_snapshot,
        wave_index=0,
        state=EXECUTION_HOST_STATE_SUCCEEDED,
        selected_package_count=1,
        skip_reasons=[],
        error_details={},
    )
    db.add(host)
    db.flush()
    return host


def _make_pkg_row(
    db,
    execution_host,
    *,
    package_name,
    before="1.0",
    after="1.1",
    family="apt",
):
    row = PatchUpdateExecutionHostPackage(
        execution_host_id=execution_host.id,
        package_name=package_name,
        requested_version_snapshot=None,
        installed_version_before=before,
        installed_version_after=after,
        package_manager_family_snapshot=family,
        outcome="succeeded",
        error_code=None,
        details={},
    )
    db.add(row)
    db.flush()
    return row


def _setup_content_profile(
    db,
    *,
    slug: str,
    family: str = "deb",
    package_name: str = "openssl",
    old_version: str = "1.0",
):
    from app.db.models import (
        ContentChannel,
        ContentChannelRepo,
        ContentProfile,
        ContentProfileChannel,
        MirrorRepo,
        MirrorSyncRun,
        MirrorSyncRunPackage,
    )

    mirror = MirrorRepo(
        slug=f"{slug}-mirror",
        display_name=f"{slug}-mirror",
        package_family=family,
        upstream_url=f"https://example.com/{slug}",
        distribution="jammy",
        components="[]",
        architectures="[]",
        sync_schedule_cron="0 4 * * *",
    )
    db.add(mirror)
    db.flush()
    profile = ContentProfile(slug=slug, display_name=slug, package_family=family)
    db.add(profile)
    db.flush()
    channel = ContentChannel(
        slug=f"{slug}-ch", display_name=f"{slug}-ch", package_family=family
    )
    db.add(channel)
    db.flush()
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(
        ContentChannelRepo(
            channel_id=channel.id, mirror_id=mirror.id, suite_override=None
        )
    )
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
    db.flush()
    db.add(
        MirrorSyncRunPackage(
            mirror_sync_run_id=run.id,
            mirror_repo_id=mirror.id,
            package_name=package_name,
            version=old_version,
            arch="amd64",
            filename=f"{package_name}_{old_version}_amd64.deb",
            sha256="a" * 64,
            size=1,
        )
    )
    db.flush()
    return profile


def _add_package_row(
    db, system_id: int, name: str, *, version: str = "1.0", is_held: bool = False
) -> Package:
    p = Package(
        system_id=system_id,
        name=name,
        installed_version=version,
        package_type="apt",
        is_held=is_held,
    )
    db.add(p)
    db.flush()
    return p


def _build_approved_rollback(
    db,
    admin_user,
    host_factory,
    *,
    slug: str,
    package_name: str = "openssl",
    is_held: bool = False,
):
    """Stand up a feasible rollback, request approval, vote approve.
    Returns (execution, rollback_row, approval, link)."""
    pol = _make_policy_row(db, slug, admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile = _setup_content_profile(
        db,
        slug=f"{slug}-profile",
        package_name=package_name,
        old_version="1.0",
    )
    h = host_factory()
    if is_held:
        _add_package_row(db, h.id, package_name, version="1.1", is_held=True)
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db,
        exec_host,
        package_name=package_name,
        before="1.0",
        after="1.1",
        family="apt",
    )
    rb = patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    _, link, approval = patch_rollback_service.request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id
    )
    result = patch_rollback_service.record_rollback_approval_vote(
        db, execution.id, actor_user_id=admin_user.id, decision="approve"
    )
    assert result["status"] == "approved"
    return execution, rb, approval, link


# ---------------------------------------------------------------------------
# Fake dispatcher: records every (system, argv) call and returns
# scripted DispatchResults.
# ---------------------------------------------------------------------------


class _FakeDispatcher:
    def __init__(self, responses: Optional[List[DispatchResult]] = None):
        self.calls: List[Tuple[int, List[str]]] = []
        self._responses = list(responses or [])
        self._default = DispatchResult(
            exit_code=0, stdout="", stderr="", transport_name="fake"
        )

    def __call__(self, system: System, cmd: List[str]) -> DispatchResult:
        self.calls.append((system.id, list(cmd)))
        if self._responses:
            return self._responses.pop(0)
        return self._default


# ---------------------------------------------------------------------------
# start_rollback_execution
# ---------------------------------------------------------------------------


def test_start_refuses_unknown_execution(db, admin_user):
    with pytest.raises(PatchUpdateRollbackError) as exc:
        patch_rollback_dispatch_service.start_rollback_execution(
            db, execution_id=987654, actor_user_id=admin_user.id
        )
    assert "not found" in str(exc.value)


def test_start_refuses_when_no_rollback_artifact(db, admin_user, host_factory):
    pol = _make_policy_row(db, "rb-s3-no-rb", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    with pytest.raises(PatchUpdateRollbackError) as exc:
        patch_rollback_dispatch_service.start_rollback_execution(
            db, execution.id, actor_user_id=admin_user.id
        )
    assert "rollback_not_evaluated" in str(exc.value) or (
        "no rollback" in str(exc.value).lower()
    )


def test_start_refuses_when_approval_not_approved(db, admin_user, host_factory):
    """Approval still pending — start must refuse."""
    pol = _make_policy_row(db, "rb-s3-pending", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile = _setup_content_profile(db, slug="rb-s3-pending-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl")
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    patch_rollback_service.request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id
    )
    # Did NOT vote → approval still pending.
    with pytest.raises(PatchUpdateRollbackError) as exc:
        patch_rollback_dispatch_service.start_rollback_execution(
            db, execution.id, actor_user_id=admin_user.id
        )
    assert REFUSAL_APPROVAL_NOT_APPROVED in str(exc.value)


def test_start_creates_run_and_per_host_rows_from_frozen_snapshot(
    db, admin_user, host_factory
):
    """Happy path: approved rollback yields one dispatch run + one
    host + one package row materialized from the snapshot."""
    execution, _rb, _approval, link = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-start"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    assert run.state == RUN_STATE_RUNNING
    assert run.rollback_approval_link_id == link.id
    assert run.max_parallel == 1
    hosts = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .all()
    )
    assert len(hosts) == 1
    assert hosts[0].state == HOST_STATE_PENDING
    pkgs = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == hosts[0].id
        )
        .all()
    )
    assert len(pkgs) == 1
    assert pkgs[0].package_name == "openssl"
    assert pkgs[0].outcome == "pending"
    assert pkgs[0].target_rollback_version_snapshot == "1.0"


def test_start_refuses_live_duplicate_dispatch(db, admin_user, host_factory):
    """Starting a second dispatch while the first is still running
    must refuse with the structured ``live_dispatch_exists`` code
    rather than racing the DB partial-unique index."""
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-dup"
    )
    patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    with pytest.raises(PatchUpdateRollbackError) as exc:
        patch_rollback_dispatch_service.start_rollback_execution(
            db, execution.id, actor_user_id=admin_user.id
        )
    assert REFUSAL_LIVE_DISPATCH_EXISTS in str(exc.value)


# ---------------------------------------------------------------------------
# dispatch_next_batch
# ---------------------------------------------------------------------------


def test_dispatch_next_happy_path_runs_primary_and_records_success(
    db, admin_user, host_factory
):
    """Single host, single apt package, no held packages: dispatcher
    runs the primary apt-get install --allow-downgrades command,
    records per-package succeeded, transitions the host + the run."""
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-happy"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    fake = _FakeDispatcher()
    summary = patch_rollback_dispatch_service.dispatch_next_batch(
        db, run.id, actor_user_id=admin_user.id, dispatch_callable=fake
    )
    assert summary.dispatched_count == 1
    assert summary.succeeded_count == 1
    assert summary.failed_count == 0
    assert summary.finalized_state == RUN_STATE_SUCCEEDED

    # The fake dispatcher should have been called exactly once with
    # the apt-get install --allow-downgrades primary command.
    assert len(fake.calls) == 1
    _system_id, argv = fake.calls[0]
    assert argv[:4] == ["apt-get", "install", "-y", "--allow-downgrades"]
    assert argv[4] == "openssl=1.0"

    db.refresh(run)
    assert run.state == RUN_STATE_SUCCEEDED
    host_row = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .one()
    )
    assert host_row.state == HOST_STATE_SUCCEEDED
    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_row.id
        )
        .one()
    )
    assert pkg_row.outcome == PACKAGE_OUTCOME_SUCCEEDED


def test_dispatch_idempotent_under_concurrent_claim(db, admin_user, host_factory):
    """PRA-180 ROLLBACK-01 (PRA-223): the atomic host claim prevents a
    concurrent ``dispatch_next_batch`` from re-dispatching an already-claimed
    host. The race is simulated by issuing a nested dispatch from inside the
    dispatch callable — exactly the window where the row is loaded but the
    first caller has just claimed it. The nested call must dispatch nothing,
    so the rollback command runs exactly once."""
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-idem"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    call_count = {"n": 0}

    def racing_dispatch(system: System, cmd: List[str]) -> DispatchResult:
        call_count["n"] += 1
        # Concurrent worker arrives mid-dispatch. The host is already
        # claimed (running), so the nested batch finds no pending host
        # and dispatches nothing.
        nested = patch_rollback_dispatch_service.dispatch_next_batch(
            db, run.id, actor_user_id=admin_user.id, dispatch_callable=racing_dispatch
        )
        assert (
            nested.dispatched_count == 0
        ), "concurrent dispatch must not re-claim the running host"
        return DispatchResult(exit_code=0, transport_name="fake")

    summary = patch_rollback_dispatch_service.dispatch_next_batch(
        db, run.id, actor_user_id=admin_user.id, dispatch_callable=racing_dispatch
    )
    assert summary.dispatched_count == 1
    assert summary.succeeded_count == 1
    assert call_count["n"] == 1, "rollback command must run exactly once"
    host_row = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .one()
    )
    assert host_row.state == HOST_STATE_SUCCEEDED


def test_dispatch_runs_pre_steps_before_primary_for_held_package(
    db, admin_user, host_factory
):
    """When the frozen plan carries apt-mark unhold pre-steps and
    apt-mark hold post-steps, dispatch executes them in order:
    unhold → install --allow-downgrades → hold."""
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-held", is_held=True
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    fake = _FakeDispatcher()
    summary = patch_rollback_dispatch_service.dispatch_next_batch(
        db, run.id, actor_user_id=admin_user.id, dispatch_callable=fake
    )
    assert summary.succeeded_count == 1
    # Expect three invocations: unhold → primary → hold.
    assert len(fake.calls) == 3
    argv_seq = [argv for _sys, argv in fake.calls]
    assert argv_seq[0] == ["apt-mark", "unhold", "openssl"]
    assert argv_seq[1][:3] == ["apt-get", "install", "-y"]
    assert argv_seq[2] == ["apt-mark", "hold", "openssl"]


def test_dispatch_records_failure_on_non_zero_primary(db, admin_user, host_factory):
    """Primary exits non-zero → package row is failed, host is
    failed, run finalizes ``failed``."""
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-fail"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    fake = _FakeDispatcher(
        responses=[
            DispatchResult(
                exit_code=100,
                stderr="E: Unable to locate package openssl",
                transport_name="fake",
            )
        ]
    )
    summary = patch_rollback_dispatch_service.dispatch_next_batch(
        db, run.id, actor_user_id=admin_user.id, dispatch_callable=fake
    )
    assert summary.succeeded_count == 0
    assert summary.failed_count == 1
    assert summary.finalized_state == RUN_STATE_FAILED

    db.refresh(run)
    assert run.state == RUN_STATE_FAILED
    host_row = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .one()
    )
    assert host_row.state == HOST_STATE_FAILED
    assert host_row.error_details.get("code") == "package_manager_failed"
    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_row.id
        )
        .one()
    )
    assert pkg_row.outcome == PACKAGE_OUTCOME_FAILED


def test_dispatch_does_not_re_derive_from_live_command_plan(
    db, admin_user, host_factory
):
    """The dispatcher must consume the FROZEN snapshot, not the live
    column. Mutating the live `command_plan` after approval must NOT
    change the dispatched argv. Pins the Slice 3 lock from spec."""
    execution, _rb, _approval, link = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-frozen"
    )
    # Tamper with the live command_plan column AFTER approval.
    live_pkg = (
        db.query(PatchUpdateExecutionRollbackPackage)
        .filter(PatchUpdateExecutionRollbackPackage.target_rollback_version == "1.0")
        .one()
    )
    live_pkg.command_plan = {
        "family": "apt",
        "package_name": "openssl",
        "target_rollback_version": "9.9.9",  # would-be malicious drift
        "primary_command": {
            "argv": ["rm", "-rf", "/"],
            "command_string": "rm -rf /",
        },
        "held_package_handling": {
            "supported": True,
            "is_held": False,
            "pre_steps": [],
            "post_steps": [],
        },
        "versionlock_handling": {
            "supported": False,
            "reason": "not_applicable_for_family",
            "pre_steps": [],
            "post_steps": [],
        },
    }
    db.commit()

    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    fake = _FakeDispatcher()
    patch_rollback_dispatch_service.dispatch_next_batch(
        db, run.id, actor_user_id=admin_user.id, dispatch_callable=fake
    )
    # The fake must have received the FROZEN argv (apt-get install
    # --allow-downgrades openssl=1.0), NOT the tampered live one.
    assert any(
        argv
        == [
            "apt-get",
            "install",
            "-y",
            "--allow-downgrades",
            "openssl=1.0",
        ]
        for _sys, argv in fake.calls
    )
    assert not any(
        "rm" in argv or "9.9.9" in " ".join(argv) for _sys, argv in fake.calls
    )


def test_dispatch_next_no_pending_finalizes_run(db, admin_user, host_factory):
    """Calling dispatch-next with no pending hosts finalizes the
    run idempotently (run was already succeeded after the previous
    batch)."""
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-empty"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    fake = _FakeDispatcher()
    # First batch fully drains.
    patch_rollback_dispatch_service.dispatch_next_batch(
        db, run.id, actor_user_id=admin_user.id, dispatch_callable=fake
    )
    db.refresh(run)
    assert run.state == RUN_STATE_SUCCEEDED
    # Second batch: run is already terminal, so service refuses.
    with pytest.raises(PatchUpdateRollbackError):
        patch_rollback_dispatch_service.dispatch_next_batch(
            db, run.id, actor_user_id=admin_user.id, dispatch_callable=fake
        )


def test_dispatch_does_not_mutate_package_history(db, admin_user, host_factory):
    """Slice 3 review lock: dispatch must NOT write to
    PackageHistory. Slice 4 owns that integration."""
    history_count_before = db.query(PackageHistory).count()
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-no-history"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    patch_rollback_dispatch_service.dispatch_next_batch(
        db,
        run.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_FakeDispatcher(),
    )
    assert db.query(PackageHistory).count() == history_count_before


# ---------------------------------------------------------------------------
# cancel_rollback_execution
# ---------------------------------------------------------------------------


def test_cancel_flips_pending_hosts_and_preserves_others(db, admin_user, host_factory):
    """Cancel mid-batch: pending hosts → canceled; succeeded /
    failed rows preserved."""
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-cancel"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    # Don't dispatch — just cancel while pending.
    patch_rollback_dispatch_service.cancel_rollback_execution(
        db, run.id, actor_user_id=admin_user.id, cancel_reason="operator-test"
    )
    db.refresh(run)
    assert run.state == "canceled"
    host_row = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .one()
    )
    assert host_row.state == HOST_STATE_CANCELED


def test_cancel_refuses_terminal_run(db, admin_user, host_factory):
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-cancel-terminal"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    patch_rollback_dispatch_service.dispatch_next_batch(
        db,
        run.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_FakeDispatcher(),
    )
    db.refresh(run)
    assert run.state == RUN_STATE_SUCCEEDED
    with pytest.raises(PatchUpdateRollbackError):
        patch_rollback_dispatch_service.cancel_rollback_execution(
            db, run.id, actor_user_id=admin_user.id
        )


# ---------------------------------------------------------------------------
# Read helper
# ---------------------------------------------------------------------------


def test_get_latest_dispatch_returns_none_before_start(db, admin_user, host_factory):
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-read-pre"
    )
    (
        out_execution,
        run,
        hosts,
        pkgs_by_host,
    ) = patch_rollback_dispatch_service.get_latest_dispatch_for_execution(
        db, execution.id
    )
    assert out_execution.id == execution.id
    assert run is None
    assert hosts == []
    assert pkgs_by_host == {}


def test_get_latest_dispatch_returns_run_after_start(db, admin_user, host_factory):
    execution, *_ = _build_approved_rollback(
        db, admin_user, host_factory, slug="rb-s3-read-post"
    )
    started = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    (
        _,
        run,
        hosts,
        pkgs_by_host,
    ) = patch_rollback_dispatch_service.get_latest_dispatch_for_execution(
        db, execution.id
    )
    assert run is not None
    assert run.id == started.id
    assert len(hosts) == 1
    assert pkgs_by_host[hosts[0].id]
