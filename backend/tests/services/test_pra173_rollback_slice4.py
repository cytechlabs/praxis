"""PRA-173 slice 4 — rollback verification + PackageHistory tests.

Covers ``patch_rollback_verify_service``:

* ``verify_due_rollbacks`` reads each succeeded/failed dispatch
  host's current package versions through the injected probe seam,
  writes the observation to
  ``PatchRollbackDispatchHostPackage.installed_version_after``,
  and emits one ``PackageHistory`` row per package whose
  ``Package`` row exists on the host.
* Failed-dispatch hosts get ``operation='rollback_attempted_failed'``;
  succeeded hosts get ``operation='rollback'``.
* Transport-unavailable / system-deleted hosts record a structured
  ``verification_refusal`` in ``error_details`` and do NOT write
  PackageHistory.
* Re-running on a fully-verified run is a no-op + emits the
  ``patch_rollback.verification_complete`` event exactly once.
* Slice 4 never re-derives commands, never dispatches, never mutates
  the parent rollback feasibility rows.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    Package,
    PackageHistory,
    PatchPolicy,
    PatchRollbackDispatchHost,
    PatchRollbackDispatchHostPackage,
    PatchRollbackDispatchRun,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdateExecutionRollback,
    PatchUpdateExecutionRollbackPackage,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    System,
)
from app.services import (
    patch_rollback_dispatch_service,
    patch_rollback_service,
    patch_rollback_verify_service,
)
from app.services.patch_execution_dispatch_service import DispatchResult
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_SUCCEEDED,
    EXECUTION_STATE_SUCCEEDED,
)
from app.services.patch_rollback_dispatch_service import (
    HOST_STATE_FAILED,
    HOST_STATE_SUCCEEDED,
)
from app.services.patch_rollback_service import PatchUpdateRollbackError
from app.services.patch_rollback_verify_service import (
    PACKAGE_HISTORY_OPERATION_ROLLBACK,
    PACKAGE_HISTORY_OPERATION_ROLLBACK_FAILED,
    VERIFY_REASON_SYSTEM_DELETED,
    VERIFY_REASON_TRANSPORT_UNAVAILABLE,
    RollbackPackageProbeResult,
    verify_due_rollbacks,
)
from app.services.patch_update_plan_service import PLAN_STATE_APPROVED

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rb-s4-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rb-s4-cred",
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
            hostname=f"rb-s4-host-{counter['n']}.example.com",
            ip_address=f"10.0.101.{counter['n']}",
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


def _make_plan_row(db, policy, admin_user) -> PatchUpdatePlan:
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
    db, execution_host, *, package_name, before="1.0", after="1.1", family="apt"
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


def _add_package_row(db, system_id: int, name: str, *, version: str) -> Package:
    p = Package(
        system_id=system_id,
        name=name,
        installed_version=version,
        package_type="apt",
    )
    db.add(p)
    db.flush()
    return p


def _build_dispatched_run(
    db,
    admin_user,
    host_factory,
    *,
    slug: str,
    dispatch_result: Optional[DispatchResult] = None,
):
    """Stand up an approved rollback, dispatch it (with optional
    DispatchResult override), and return the dispatch run + the
    host row."""
    pol = _make_policy_row(db, slug, admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile = _setup_content_profile(
        db, slug=f"{slug}-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    # Seed a Package row so PackageHistory has an FK target. Reflects
    # the post-update state (Package.installed_version=1.1 before
    # rollback runs).
    _add_package_row(db, h.id, "openssl", version="1.1")
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db, exec_host, package_name="openssl", before="1.0", after="1.1", family="apt"
    )
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    patch_rollback_service.request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id
    )
    patch_rollback_service.record_rollback_approval_vote(
        db, execution.id, actor_user_id=admin_user.id, decision="approve"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    class _FakeDispatcher:
        def __init__(self, result):
            self._result = result or DispatchResult(
                exit_code=0, stdout="", stderr="", transport_name="fake"
            )

        def __call__(self, system, cmd):
            return self._result

    patch_rollback_dispatch_service.dispatch_next_batch(
        db,
        run.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_FakeDispatcher(dispatch_result),
    )
    db.refresh(run)
    host_row = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .one()
    )
    return run, host_row, h


class _FakeProbe:
    """Records every call and returns scripted results."""

    def __init__(self, results: List[RollbackPackageProbeResult]):
        self.calls: List[List[str]] = []
        self._results = list(results)

    def __call__(self, system, package_names):
        self.calls.append(list(package_names))
        if self._results:
            return self._results.pop(0)
        return RollbackPackageProbeResult(reachable=True, observed_versions={})


# ---------------------------------------------------------------------------
# verify_due_rollbacks: happy path + PackageHistory writes
# ---------------------------------------------------------------------------


def test_verify_due_records_observed_version_and_writes_package_history(
    db, admin_user, host_factory
):
    """Succeeded host + reachable probe + observed rollback-to-1.0
    version → package row's installed_version_after = '1.0',
    PackageHistory row inserted with operation='rollback',
    old=1.1, new=1.0."""
    run, host_row, system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-happy"
    )
    assert host_row.state == HOST_STATE_SUCCEEDED

    probe = _FakeProbe(
        [
            RollbackPackageProbeResult(
                reachable=True, observed_versions={"openssl": "1.0"}
            )
        ]
    )
    history_before = db.query(PackageHistory).count()

    summary = verify_due_rollbacks(
        db, run.id, actor_user_id=admin_user.id, probe_callable=probe
    )
    assert summary.attempted_host_count == 1
    assert summary.reachable_host_count == 1
    assert summary.host_outcomes[0]["verified_package_count"] == 1
    assert summary.host_outcomes[0]["package_history_written_count"] == 1
    assert summary.verification_complete is True

    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_row.id
        )
        .one()
    )
    assert pkg_row.installed_version_after == "1.0"

    history_rows = (
        db.query(PackageHistory)
        .order_by(PackageHistory.id.desc())
        .limit(db.query(PackageHistory).count() - history_before)
        .all()
    )
    assert len(history_rows) == 1
    hist = history_rows[0]
    assert hist.operation == PACKAGE_HISTORY_OPERATION_ROLLBACK
    assert hist.old_version == "1.1"
    assert hist.new_version == "1.0"
    assert hist.status == "completed"
    assert hist.performed_by == admin_user.id


def test_verify_due_records_observation_for_failed_dispatch_host(
    db, admin_user, host_factory
):
    """A failed dispatch host still gets verified: observation
    recorded, PackageHistory written with
    operation='rollback_attempted_failed'."""
    run, host_row, _system = _build_dispatched_run(
        db,
        admin_user,
        host_factory,
        slug="rb-s4-failed",
        dispatch_result=DispatchResult(
            exit_code=100, stderr="oops", transport_name="fake"
        ),
    )
    assert host_row.state == HOST_STATE_FAILED

    # The host failed → the package never actually rolled back, so
    # the observed version is still 1.1 (the post-update value).
    probe = _FakeProbe(
        [
            RollbackPackageProbeResult(
                reachable=True, observed_versions={"openssl": "1.1"}
            )
        ]
    )
    summary = verify_due_rollbacks(
        db, run.id, actor_user_id=admin_user.id, probe_callable=probe
    )
    assert summary.reachable_host_count == 1

    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_row.id
        )
        .one()
    )
    assert pkg_row.installed_version_after == "1.1"

    hist = db.query(PackageHistory).order_by(PackageHistory.id.desc()).first()
    assert hist.operation == PACKAGE_HISTORY_OPERATION_ROLLBACK_FAILED
    assert hist.old_version == "1.1"
    assert hist.new_version == "1.1"
    assert hist.status == "failed"


# ---------------------------------------------------------------------------
# Refusal paths
# ---------------------------------------------------------------------------


def test_verify_due_records_refusal_when_transport_unavailable(
    db, admin_user, host_factory
):
    """Probe returns reachable=False → host's error_details records
    a verification_refusal; no PackageHistory written; package row
    keeps installed_version_after = None."""
    run, host_row, _system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-unreach"
    )
    history_before = db.query(PackageHistory).count()
    probe = _FakeProbe(
        [
            RollbackPackageProbeResult(
                reachable=False,
                reason=VERIFY_REASON_TRANSPORT_UNAVAILABLE,
                error="SSH closed",
            )
        ]
    )

    summary = verify_due_rollbacks(
        db, run.id, actor_user_id=admin_user.id, probe_callable=probe
    )
    assert summary.unreachable_host_count == 1
    assert summary.reachable_host_count == 0
    assert summary.host_outcomes[0]["reason"] == VERIFY_REASON_TRANSPORT_UNAVAILABLE

    db.refresh(host_row)
    refusal = host_row.error_details.get("verification_refusal")
    assert refusal is not None
    assert refusal["reason"] == VERIFY_REASON_TRANSPORT_UNAVAILABLE
    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_row.id
        )
        .one()
    )
    assert pkg_row.installed_version_after is None
    assert db.query(PackageHistory).count() == history_before


def test_verify_due_records_refusal_when_system_deleted(db, admin_user, host_factory):
    """When the dispatch host's system_id_snapshot no longer
    resolves to a System row, verifier records
    system_deleted refusal."""
    run, host_row, system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-sys-deleted"
    )
    # Detach the host from its system after dispatch (simulating
    # operator-side delete between dispatch and verify).
    host_row.system_id_snapshot = 987654
    db.commit()

    summary = verify_due_rollbacks(
        db, run.id, actor_user_id=admin_user.id, probe_callable=_FakeProbe([])
    )
    assert summary.unreachable_host_count == 1
    assert summary.host_outcomes[0]["reason"] == VERIFY_REASON_SYSTEM_DELETED
    db.refresh(host_row)
    refusal = host_row.error_details.get("verification_refusal")
    assert refusal is not None
    assert refusal["reason"] == VERIFY_REASON_SYSTEM_DELETED


# ---------------------------------------------------------------------------
# Idempotency + completion
# ---------------------------------------------------------------------------


def test_verify_due_is_idempotent_on_fully_verified_run(db, admin_user, host_factory):
    """Re-running verify-due after a successful verification is a
    no-op: ``no_due=True``, no new PackageHistory rows."""
    run, _host_row, _system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-idem"
    )
    probe = _FakeProbe(
        [
            RollbackPackageProbeResult(
                reachable=True, observed_versions={"openssl": "1.0"}
            )
        ]
    )
    verify_due_rollbacks(db, run.id, actor_user_id=admin_user.id, probe_callable=probe)
    history_after_first = db.query(PackageHistory).count()

    summary = verify_due_rollbacks(
        db,
        run.id,
        actor_user_id=admin_user.id,
        probe_callable=_FakeProbe([]),
    )
    assert summary.no_due is True
    assert summary.attempted_host_count == 0
    assert db.query(PackageHistory).count() == history_after_first


def test_verify_due_re_probes_after_transient_refusal(db, admin_user, host_factory):
    """A host that refused on one batch (transport_unavailable) is
    re-probed on the next batch; a successful observation clears
    the refusal and writes the observation."""
    run, host_row, _system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-retry"
    )
    # First batch: unreachable.
    verify_due_rollbacks(
        db,
        run.id,
        actor_user_id=admin_user.id,
        probe_callable=_FakeProbe(
            [
                RollbackPackageProbeResult(
                    reachable=False,
                    reason=VERIFY_REASON_TRANSPORT_UNAVAILABLE,
                    error="SSH closed",
                )
            ]
        ),
    )
    db.refresh(host_row)
    assert (
        host_row.error_details.get("verification_refusal", {}).get("reason")
        == VERIFY_REASON_TRANSPORT_UNAVAILABLE
    )

    # Second batch: probe succeeds.
    verify_due_rollbacks(
        db,
        run.id,
        actor_user_id=admin_user.id,
        probe_callable=_FakeProbe(
            [
                RollbackPackageProbeResult(
                    reachable=True, observed_versions={"openssl": "1.0"}
                )
            ]
        ),
    )
    db.refresh(host_row)
    assert "verification_refusal" not in (host_row.error_details or {})
    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_row.id
        )
        .one()
    )
    assert pkg_row.installed_version_after == "1.0"


# ---------------------------------------------------------------------------
# PackageHistory + scope locks
# ---------------------------------------------------------------------------


def test_verify_due_skips_package_history_when_no_package_row(
    db, admin_user, host_factory
):
    """When the host has no ``Package`` row matching the dispatch
    package name (e.g. facts pipeline never recorded it), the
    dispatch row's ``installed_version_after`` is still set, but
    PackageHistory is skipped (the FK has no target)."""
    run, host_row, system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-no-pkg"
    )
    # Delete the Package row we seeded so PackageHistory has no FK
    # target.
    db.query(Package).filter(
        Package.system_id == system.id, Package.name == "openssl"
    ).delete(synchronize_session=False)
    db.commit()

    history_before = db.query(PackageHistory).count()
    probe = _FakeProbe(
        [
            RollbackPackageProbeResult(
                reachable=True, observed_versions={"openssl": "1.0"}
            )
        ]
    )
    summary = verify_due_rollbacks(
        db, run.id, actor_user_id=admin_user.id, probe_callable=probe
    )
    assert summary.host_outcomes[0]["verified_package_count"] == 1
    assert summary.host_outcomes[0]["package_history_written_count"] == 0
    assert db.query(PackageHistory).count() == history_before
    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_row.id
        )
        .one()
    )
    assert pkg_row.installed_version_after == "1.0"


def test_verify_due_does_not_re_dispatch_or_mutate_feasibility_rows(
    db, admin_user, host_factory
):
    """Slice 4 review lock: verifier must not re-derive commands,
    must not start a new dispatch, and must not mutate the parent
    rollback feasibility rows. We snapshot the feasibility rows
    before/after and confirm equality."""
    run, _host_row, _system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-no-mutate"
    )
    rb_row = db.query(PatchUpdateExecutionRollback).one()
    feas_pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    before_command_plan = dict(feas_pkg.command_plan or {})
    before_state = feas_pkg.state
    dispatch_runs_before = db.query(PatchRollbackDispatchRun).count()

    probe = _FakeProbe(
        [
            RollbackPackageProbeResult(
                reachable=True, observed_versions={"openssl": "1.0"}
            )
        ]
    )
    verify_due_rollbacks(db, run.id, actor_user_id=admin_user.id, probe_callable=probe)

    db.refresh(feas_pkg)
    assert dict(feas_pkg.command_plan or {}) == before_command_plan
    assert feas_pkg.state == before_state
    assert db.query(PatchRollbackDispatchRun).count() == dispatch_runs_before


def test_verify_due_refuses_unknown_run(db, admin_user):
    with pytest.raises(PatchUpdateRollbackError) as exc:
        verify_due_rollbacks(db, run_id=987654, actor_user_id=admin_user.id)
    assert "not found" in str(exc.value)


def test_verify_due_default_probe_triggers_package_inventory_scan(
    db, admin_user, host_factory, monkeypatch
):
    """Slice 4b: the default probe must trigger
    a fresh ``PackageService.scan_packages`` call *before* reading
    the ``Package`` table. Slice 4a's first attempt called
    ``ssh_facts_collector_service.collect_and_ingest``, but that
    path only refreshes ``HostFacts`` and leaves
    ``Package.installed_version`` stale. The correct primitive is
    the package inventory scanner."""
    from app.services import package_service

    run, _host_row, system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-default-probe"
    )
    call_log: list = []

    def _fake_scan_packages(self, system_id):
        call_log.append(system_id)
        pkg = (
            self.db.query(Package)
            .filter(Package.system_id == system_id, Package.name == "openssl")
            .one()
        )
        pkg.installed_version = "1.0"
        self.db.commit()
        return {
            "system_id": system_id,
            "hostname": "fake",
            "status": "success",
            "packages_found": 1,
        }

    monkeypatch.setattr(
        package_service.PackageService, "scan_packages", _fake_scan_packages
    )

    summary = verify_due_rollbacks(db, run.id, actor_user_id=admin_user.id)
    assert call_log == [system.id], (
        "default probe must invoke PackageService.scan_packages for the host "
        "before reading Package rows"
    )
    assert summary.reachable_host_count == 1
    pkg_row = db.query(PatchRollbackDispatchHostPackage).one()
    assert pkg_row.installed_version_after == "1.0"
    assert pkg_row.verified_at is not None


def test_verify_due_default_probe_records_refusal_when_scan_raises(
    db, admin_user, host_factory, monkeypatch
):
    """Slice 4b: when ``PackageService.scan_packages`` raises, the
    default probe surfaces it as ``transport_unavailable`` — host
    gets a refusal block, no ``installed_version_after`` written, no
    PackageHistory."""
    from app.services import package_service

    run, host_row, _system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-default-probe-fail"
    )

    def _raise(self, system_id):
        raise ValueError("ssh down")

    monkeypatch.setattr(package_service.PackageService, "scan_packages", _raise)

    history_before = db.query(PackageHistory).count()
    summary = verify_due_rollbacks(db, run.id, actor_user_id=admin_user.id)
    assert summary.unreachable_host_count == 1
    assert summary.host_outcomes[0]["reason"] == VERIFY_REASON_TRANSPORT_UNAVAILABLE
    db.refresh(host_row)
    refusal = host_row.error_details.get("verification_refusal")
    assert refusal is not None
    assert refusal["reason"] == VERIFY_REASON_TRANSPORT_UNAVAILABLE
    pkg_row = db.query(PatchRollbackDispatchHostPackage).one()
    assert pkg_row.installed_version_after is None
    assert pkg_row.verified_at is None
    assert db.query(PackageHistory).count() == history_before


def test_verify_due_default_probe_records_refusal_on_scan_status_error(
    db, admin_user, host_factory, monkeypatch
):
    """Slice 4b: ``PackageService.scan_packages`` returning
    ``status='error'`` (SSH connected but remote list_installed
    produced no usable output) is also surfaced as
    ``transport_unavailable``. The scanner's structured message
    flows into the refusal so operators see what went wrong."""
    from app.services import package_service

    run, host_row, _system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-default-probe-status-err"
    )

    def _error(self, system_id):
        return {
            "system_id": system_id,
            "hostname": "fake",
            "status": "error",
            "message": "no output from remote host",
            "packages_found": 0,
        }

    monkeypatch.setattr(package_service.PackageService, "scan_packages", _error)

    summary = verify_due_rollbacks(db, run.id, actor_user_id=admin_user.id)
    assert summary.unreachable_host_count == 1
    db.refresh(host_row)
    refusal = host_row.error_details.get("verification_refusal")
    assert refusal["reason"] == VERIFY_REASON_TRANSPORT_UNAVAILABLE
    assert "no output" in (refusal.get("error") or "")


def test_verify_due_handles_observed_package_not_installed(
    db, admin_user, host_factory
):
    """Slice 4a: a successful observation of "host
    reports package not installed" stores
    ``installed_version_after = NULL`` and a non-null
    ``verified_at``. The presence of ``verified_at`` is the
    unambiguous "verified" sentinel — subsequent verify-due batches
    must NOT re-probe this row, and the completion event must fire
    exactly once."""
    run, host_row, _system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-not-installed"
    )
    # Probe reports the package as not installed (e.g. an apt purge
    # rollback ended with the package absent).
    probe = _FakeProbe(
        [
            RollbackPackageProbeResult(
                reachable=True, observed_versions={"openssl": None}
            )
        ]
    )
    summary = verify_due_rollbacks(
        db, run.id, actor_user_id=admin_user.id, probe_callable=probe
    )
    assert summary.reachable_host_count == 1
    assert summary.verification_complete is True

    pkg_row = db.query(PatchRollbackDispatchHostPackage).one()
    assert pkg_row.installed_version_after is None
    assert pkg_row.verified_at is not None

    # Second verify-due: package row is already verified, so the
    # service must NOT probe it again. Inject a probe that would
    # raise if called.
    class _PoisonProbe:
        def __call__(self, system, package_names):
            raise AssertionError("should not be probed again")

    summary_b = verify_due_rollbacks(
        db, run.id, actor_user_id=admin_user.id, probe_callable=_PoisonProbe()
    )
    assert summary_b.no_due is True
    assert summary_b.attempted_host_count == 0


def test_verify_due_distinguishes_verified_not_installed_from_pending(
    db, admin_user, host_factory
):
    """Slice 4a regression: the OLD logic used
    ``installed_version_after IS NULL`` as the "still pending"
    filter, which collided with a legitimate "verified, not
    installed" observation. The NEW logic uses
    ``verified_at IS NULL`` — this test pins the distinction."""
    run, _host_row, _system = _build_dispatched_run(
        db, admin_user, host_factory, slug="rb-s4-pending-vs-null"
    )

    # Run #1: observe "not installed" → installed_version_after=None,
    # verified_at set.
    verify_due_rollbacks(
        db,
        run.id,
        actor_user_id=admin_user.id,
        probe_callable=_FakeProbe(
            [
                RollbackPackageProbeResult(
                    reachable=True, observed_versions={"openssl": None}
                )
            ]
        ),
    )
    pkg_row = db.query(PatchRollbackDispatchHostPackage).one()
    first_verified_at = pkg_row.verified_at
    assert first_verified_at is not None
    assert pkg_row.installed_version_after is None

    # Run #2: idempotency check. verify_due_rollbacks should NOT
    # re-write verified_at (the row is no longer pending).
    verify_due_rollbacks(
        db,
        run.id,
        actor_user_id=admin_user.id,
        probe_callable=_FakeProbe([]),
    )
    db.refresh(pkg_row)
    assert pkg_row.verified_at == first_verified_at
