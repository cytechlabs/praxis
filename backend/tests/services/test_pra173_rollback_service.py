"""PRA-173 slice 1 — rollback feasibility service tests.

Covers the Slice 1 contract:

* ``evaluate_rollback_feasibility`` initializes one rollback
  header row per ``PatchUpdateExecution`` plus per-host /
  per-package rows from the existing PRA-164 plan-host /
  preflight evidence and the PRA-171 ``patch_update_execution_
  host_packages`` outcomes.
* Re-running ``evaluate_rollback_feasibility`` upserts the three
  layers in place (idempotent, no duplicates).
* Non-terminal executions produce a ``refused`` header row with
  ``execution_not_terminal`` and zero per-host / per-package rows.
* Per-host state is derived from the per-package rollup, with
  ``host_not_succeeded`` explicit when ``execution_host.state`` is
  not ``succeeded``.
* Every documented refusal code is reachable: package_not_
  succeeded, missing_before_version, missing_after_version,
  version_unchanged, unsupported_package_family,
  content_profile_missing, content_evidence_missing,
  old_version_unavailable.
* The feasibility check verifies old-version availability through
  the host's effective content profile / mirror index — never
  fetches upstream, never reads on-disk manifests outside the
  PRA-164 helper.
* The summary rollup includes every DB-valid host/package state
  with zero counts when absent.
* Persisted timestamps follow the patch-lifecycle naive-UTC DB
  convention; the ``evaluated_at`` ISO string emitted to audit is
  absolute UTC (``...Z``).

Slice 1 deliberately stops before any real rollback work — these
tests assert the feasibility substrate, not the (non-existent)
rollback command planning, approval, dispatch, or verification.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import pytest

from app.db.models import (
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    Credential,
    Group,
    MirrorRepo,
    MirrorSyncRun,
    MirrorSyncRunPackage,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdateExecutionRollback,
    PatchUpdateExecutionRollbackHost,
    PatchUpdateExecutionRollbackPackage,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    System,
)
from app.services import patch_rollback_service
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_FAILED,
    EXECUTION_HOST_STATE_SKIPPED,
    EXECUTION_HOST_STATE_SUCCEEDED,
    EXECUTION_STATE_FAILED,
    EXECUTION_STATE_RUNNING,
    EXECUTION_STATE_SUCCEEDED,
)
from app.services.patch_rollback_service import (
    REFUSAL_CONTENT_EVIDENCE_MISSING,
    REFUSAL_CONTENT_PROFILE_MISSING,
    REFUSAL_EXECUTION_NOT_TERMINAL,
    REFUSAL_HOST_NOT_SUCCEEDED,
    REFUSAL_MISSING_AFTER_VERSION,
    REFUSAL_MISSING_BEFORE_VERSION,
    REFUSAL_OLD_VERSION_UNAVAILABLE,
    REFUSAL_PACKAGE_NOT_SUCCEEDED,
    REFUSAL_UNSUPPORTED_PACKAGE_FAMILY,
    REFUSAL_VERSION_UNCHANGED,
    ROLLBACK_HOST_STATE_FEASIBLE,
    ROLLBACK_HOST_STATE_INFEASIBLE,
    ROLLBACK_HOST_STATE_PARTIAL_FEASIBLE,
    ROLLBACK_PACKAGE_STATE_FEASIBLE,
    ROLLBACK_PACKAGE_STATE_INFEASIBLE,
    ROLLBACK_PLAN_STATE_EVALUATED,
    ROLLBACK_PLAN_STATE_REFUSED,
    PatchUpdateRollbackError,
)
from app.services.patch_update_plan_service import PLAN_STATE_APPROVED

# ---------------------------------------------------------------------------
# Fixtures + minimal-substrate helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rollback-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rollback-test-cred",
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
            hostname=f"rollback-host-{counter['n']}.example.com",
            ip_address=f"10.0.95.{counter['n']}",
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
        policy_snapshot={
            "id": policy.id,
            "slug": policy.slug,
            "name": policy.name,
        },
        ring_sequence_snapshot=[],
        request_snapshot={},
        block_reasons=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    return plan


def _make_execution_row(
    db,
    plan,
    admin_user,
    *,
    state: str = EXECUTION_STATE_SUCCEEDED,
) -> PatchUpdateExecution:
    now = datetime.utcnow()
    e = PatchUpdateExecution(
        plan_id=plan.id,
        state=state,
        started_by=admin_user.id,
        started_at=now,
        completed_at=now if state != EXECUTION_STATE_RUNNING else None,
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
    db,
    plan: PatchUpdatePlan,
    system: System,
    *,
    content_profile_state: str = "resolved",
    content_profile_id_snapshot: Optional[int] = None,
    content_profile_slug_snapshot: Optional[str] = None,
    content_profile_display_name_snapshot: Optional[str] = None,
    content_profile_package_family_snapshot: Optional[str] = None,
    content_profile_conflict_snapshot=None,
    wave_index: int = 0,
) -> PatchUpdatePlanHost:
    plan_host = PatchUpdatePlanHost(
        plan_id=plan.id,
        system_id=system.id,
        system_hostname_snapshot=system.hostname,
        policy_resolution_kind="direct_host",
        ring_resolution_status="resolved",
        wave_index=wave_index,
        content_profile_state=content_profile_state,
        content_profile_id_snapshot=content_profile_id_snapshot,
        content_profile_slug_snapshot=content_profile_slug_snapshot,
        content_profile_display_name_snapshot=content_profile_display_name_snapshot,
        content_profile_package_family_snapshot=(
            content_profile_package_family_snapshot
        ),
        content_profile_conflict_snapshot=content_profile_conflict_snapshot or [],
        state="planned",
        block_reasons=[],
    )
    db.add(plan_host)
    db.flush()
    return plan_host


def _make_execution_host(
    db,
    execution: PatchUpdateExecution,
    plan_host: PatchUpdatePlanHost,
    *,
    state: str = EXECUTION_HOST_STATE_SUCCEEDED,
) -> PatchUpdateExecutionHost:
    host = PatchUpdateExecutionHost(
        execution_id=execution.id,
        plan_host_id=plan_host.id,
        system_id_snapshot=plan_host.system_id,
        system_hostname_snapshot=plan_host.system_hostname_snapshot,
        wave_index=plan_host.wave_index,
        state=state,
        selected_package_count=1,
        skip_reasons=[],
        error_details={},
    )
    db.add(host)
    db.flush()
    return host


def _make_pkg_row(
    db,
    execution_host: PatchUpdateExecutionHost,
    *,
    package_name: str,
    family: str = "apt",
    before: Optional[str] = "1.0",
    after: Optional[str] = "1.1",
    requested: Optional[str] = None,
    outcome: str = "succeeded",
    error_code: Optional[str] = None,
) -> PatchUpdateExecutionHostPackage:
    row = PatchUpdateExecutionHostPackage(
        execution_host_id=execution_host.id,
        package_name=package_name,
        requested_version_snapshot=requested,
        installed_version_before=before,
        installed_version_after=after,
        package_manager_family_snapshot=family,
        outcome=outcome,
        error_code=error_code,
        details={},
    )
    db.add(row)
    db.flush()
    return row


def _setup_content_profile(
    db,
    *,
    slug: str = "rb-profile",
    family: str = "deb",
    package_name: str = "openssl",
    old_version: str = "1.0",
    publish_old: bool = True,
):
    """Set up a content profile with one channel + one mirror + one
    ok sync run that optionally publishes the requested
    ``package_name`` at the ``old_version`` value.

    Returns ``(profile, mirror, run)`` so callers can attach the
    profile to a plan host and decide what evidence to publish (or
    not publish, for the ``old_version_unavailable`` path).
    """
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
    profile = ContentProfile(
        slug=slug,
        display_name=slug,
        package_family=family,
    )
    db.add(profile)
    db.flush()
    channel = ContentChannel(
        slug=f"{slug}-ch",
        display_name=f"{slug}-ch",
        package_family=family,
    )
    db.add(channel)
    db.flush()
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(
        ContentChannelRepo(
            channel_id=channel.id,
            mirror_id=mirror.id,
            suite_override=None,
        )
    )
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="ok",
        run_kind="sync",
        package_count=1 if publish_old else 0,
        manifest_sha256="0" * 64,
        manifest_path=None,
    )
    db.add(run)
    db.flush()
    if publish_old:
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
    else:
        # Mark the run as ok with NO package rows so the lookup goes
        # through the backfill path (returns 0 rows) and we hit
        # ``old_version_unavailable``.
        pass
    db.flush()
    return profile, mirror, run


# ---------------------------------------------------------------------------
# Plan-level gate: non-terminal execution → refused
# ---------------------------------------------------------------------------


def test_evaluate_refuses_non_terminal_execution(db, admin_user, host_factory):
    """Non-terminal executions produce a ``refused`` header row with
    ``execution_not_terminal`` and zero per-host / per-package
    rows. The read API must always have an artifact to render."""
    pol = _make_policy_row(db, "rb-non-terminal", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user, state=EXECUTION_STATE_RUNNING)

    rollback_row = patch_rollback_service.evaluate_rollback_feasibility(
        db, execution.id
    )

    assert rollback_row.state == ROLLBACK_PLAN_STATE_REFUSED
    assert rollback_row.refusal_reason == REFUSAL_EXECUTION_NOT_TERMINAL
    assert rollback_row.execution_state_snapshot == EXECUTION_STATE_RUNNING
    host_count = (
        db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.rollback_id == rollback_row.id)
        .count()
    )
    assert host_count == 0


def test_evaluate_refuses_unknown_execution(db):
    with pytest.raises(PatchUpdateRollbackError) as exc_info:
        patch_rollback_service.evaluate_rollback_feasibility(db, execution_id=999_999)
    assert "not found" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Happy path: terminal execution with a feasible package
# ---------------------------------------------------------------------------


def test_evaluate_feasible_package_records_evidence(db, admin_user, host_factory):
    """A succeeded package whose ``installed_version_before`` is
    published by a mirror in the host's effective content profile is
    ``feasible`` and the row records the matching channel/mirror/run
    in ``content_evidence``."""
    pol = _make_policy_row(db, "rb-feasible", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, mirror, run = _setup_content_profile(
        db, slug="rb-feasible-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    plan_host = _make_plan_host(
        db,
        plan,
        h,
        content_profile_state="resolved",
        content_profile_id_snapshot=profile.id,
        content_profile_slug_snapshot=profile.slug,
    )
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db, exec_host, package_name="openssl", before="1.0", after="1.1", family="apt"
    )

    rollback_row = patch_rollback_service.evaluate_rollback_feasibility(
        db, execution.id
    )

    assert rollback_row.state == ROLLBACK_PLAN_STATE_EVALUATED
    host_rows = (
        db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.rollback_id == rollback_row.id)
        .all()
    )
    assert len(host_rows) == 1
    host_row = host_rows[0]
    assert host_row.state == ROLLBACK_HOST_STATE_FEASIBLE
    assert host_row.refusal_reason is None
    pkg_rows = (
        db.query(PatchUpdateExecutionRollbackPackage)
        .filter(PatchUpdateExecutionRollbackPackage.rollback_host_id == host_row.id)
        .all()
    )
    assert len(pkg_rows) == 1
    pkg_row = pkg_rows[0]
    assert pkg_row.state == ROLLBACK_PACKAGE_STATE_FEASIBLE
    assert pkg_row.target_rollback_version == "1.0"
    assert pkg_row.installed_version_before_snapshot == "1.0"
    assert pkg_row.installed_version_after_snapshot == "1.1"
    assert pkg_row.package_manager_family_snapshot == "apt"
    # content_evidence records the matching channel and run.
    assert "matched_channels" in pkg_row.content_evidence
    matched = pkg_row.content_evidence["matched_channels"]
    assert len(matched) == 1
    assert matched[0]["mirror_id"] == mirror.id
    assert matched[0]["mirror_sync_run_id"] == run.id


# ---------------------------------------------------------------------------
# Per-package refusal cascade
# ---------------------------------------------------------------------------


def test_evaluate_package_not_succeeded_refusal(db, admin_user, host_factory):
    """A succeeded host with one failed package row produces an
    ``infeasible`` package row with ``package_not_succeeded``. The
    host's per-package summary still records the refusal."""
    pol = _make_policy_row(db, "rb-pkg-not-succ", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(db, slug="rb-pkg-not-succ-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db,
        exec_host,
        package_name="openssl",
        before="1.0",
        after=None,
        outcome="failed",
        error_code="dispatch_failed",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_PACKAGE_NOT_SUCCEEDED
    assert pkg.refusal_details.get("package_outcome") == "failed"
    assert pkg.target_rollback_version is None


def test_evaluate_missing_before_version_refusal(db, admin_user, host_factory):
    pol = _make_policy_row(db, "rb-mb", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(db, slug="rb-mb-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db,
        exec_host,
        package_name="openssl",
        before=None,
        after="1.1",
        outcome="succeeded",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_MISSING_BEFORE_VERSION


def test_evaluate_missing_after_version_refusal(db, admin_user, host_factory):
    pol = _make_policy_row(db, "rb-ma", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(db, slug="rb-ma-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db,
        exec_host,
        package_name="openssl",
        before="1.0",
        after=None,
        requested=None,
        outcome="succeeded",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_MISSING_AFTER_VERSION


def test_evaluate_version_unchanged_refusal(db, admin_user, host_factory):
    """If the before/after versions match, there is nothing to roll
    back to — record explicitly rather than silently dropping the
    row."""
    pol = _make_policy_row(db, "rb-unchanged", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(db, slug="rb-unchanged-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db,
        exec_host,
        package_name="openssl",
        before="1.0",
        after="1.0",
        outcome="succeeded",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_VERSION_UNCHANGED


def test_evaluate_unsupported_family_refusal(db, admin_user, host_factory):
    pol = _make_policy_row(db, "rb-fam", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(db, slug="rb-fam-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db,
        exec_host,
        package_name="opaque",
        before="1.0",
        after="1.1",
        family="unknown",
        outcome="succeeded",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_UNSUPPORTED_PACKAGE_FAMILY


def test_evaluate_content_profile_missing_refusal(db, admin_user, host_factory):
    """Hosts whose ``content_profile_state`` is not ``resolved`` get
    every package row marked ``content_profile_missing`` — version-
    level availability cannot be proven without a resolved
    profile."""
    pol = _make_policy_row(db, "rb-no-profile", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    h = host_factory()
    # Host has no resolved content profile.
    plan_host = _make_plan_host(
        db,
        plan,
        h,
        content_profile_state="no_profile",
        content_profile_id_snapshot=None,
    )
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_CONTENT_PROFILE_MISSING


def test_evaluate_content_evidence_missing_when_profile_has_no_runs(
    db, admin_user, host_factory
):
    """A host with a resolved content profile but no mirror sync
    runs produces ``content_evidence_missing`` — we cannot prove
    availability either way."""
    pol = _make_policy_row(db, "rb-no-evidence", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    # Build a profile with a mirror but no sync runs at all.
    mirror = MirrorRepo(
        slug="rb-empty-mirror",
        display_name="rb-empty-mirror",
        package_family="deb",
        upstream_url="https://example.com/rb-empty",
        distribution="jammy",
        components="[]",
        architectures="[]",
        sync_schedule_cron="0 4 * * *",
    )
    db.add(mirror)
    db.flush()
    profile = ContentProfile(
        slug="rb-no-evidence-profile",
        display_name="rb-no-evidence-profile",
        package_family="deb",
    )
    db.add(profile)
    db.flush()
    channel = ContentChannel(
        slug="rb-no-evidence-ch", display_name="rb-no-evidence-ch", package_family="deb"
    )
    db.add(channel)
    db.flush()
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(
        ContentChannelRepo(
            channel_id=channel.id, mirror_id=mirror.id, suite_override=None
        )
    )
    db.flush()

    h = host_factory()
    plan_host = _make_plan_host(
        db,
        plan,
        h,
        content_profile_state="resolved",
        content_profile_id_snapshot=profile.id,
    )
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_CONTENT_EVIDENCE_MISSING


def test_evaluate_old_version_unavailable_when_mirror_does_not_publish(
    db, admin_user, host_factory
):
    """The profile resolves and a sync run exists, but the run does
    not publish the requested ``installed_version_before`` — record
    ``old_version_unavailable`` with the checked channels in
    ``refusal_details``."""
    pol = _make_policy_row(db, "rb-unavail", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    # Set up a profile with a sync run that publishes openssl=1.1
    # (the NEW version), not 1.0 (the old one we want to roll back to).
    profile, mirror, run = _setup_content_profile(
        db,
        slug="rb-unavail-profile",
        package_name="openssl",
        old_version="1.1",  # only the new version is published
        publish_old=True,
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_OLD_VERSION_UNAVAILABLE
    assert pkg.refusal_details.get("checked_channel_count", 0) >= 1


# ---------------------------------------------------------------------------
# Host-level state derivation
# ---------------------------------------------------------------------------


def test_evaluate_failed_host_marked_host_not_succeeded(db, admin_user, host_factory):
    """A non-succeeded execution-host gets ``host_not_succeeded`` at
    the host level regardless of per-package outcomes — the read
    surface should explicitly refuse the host rather than silently
    omit it."""
    pol = _make_policy_row(db, "rb-failed-host", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(db, slug="rb-failed-host-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user, state=EXECUTION_STATE_FAILED)
    exec_host = _make_execution_host(
        db, execution, plan_host, state=EXECUTION_HOST_STATE_FAILED
    )
    _make_pkg_row(
        db,
        exec_host,
        package_name="openssl",
        before="1.0",
        after=None,
        outcome="failed",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    host_row = db.query(PatchUpdateExecutionRollbackHost).one()
    assert host_row.state == ROLLBACK_HOST_STATE_INFEASIBLE
    assert host_row.refusal_reason == REFUSAL_HOST_NOT_SUCCEEDED


def test_evaluate_partial_feasible_when_mixed_packages(db, admin_user, host_factory):
    """A succeeded host with one feasible package and one infeasible
    package is ``partial_feasible``."""
    pol = _make_policy_row(db, "rb-partial", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    # The profile only publishes openssl=1.0, not curl=2.0.
    profile, _, _ = _setup_content_profile(
        db,
        slug="rb-partial-profile",
        package_name="openssl",
        old_version="1.0",
        publish_old=True,
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    # openssl is feasible (mirror publishes 1.0).
    _make_pkg_row(
        db,
        exec_host,
        package_name="openssl",
        before="1.0",
        after="1.1",
        family="apt",
    )
    # curl is infeasible (mirror does NOT publish 2.0).
    _make_pkg_row(
        db,
        exec_host,
        package_name="curl",
        before="2.0",
        after="2.1",
        family="apt",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    host_row = db.query(PatchUpdateExecutionRollbackHost).one()
    assert host_row.state == ROLLBACK_HOST_STATE_PARTIAL_FEASIBLE
    assert host_row.package_summary["feasible_count"] == 1
    assert host_row.package_summary["infeasible_count"] == 1


def test_evaluate_skipped_host_gets_explicit_refusal_row(db, admin_user, host_factory):
    """Skipped hosts (state='skipped') still produce a rollback host
    row with ``host_not_succeeded``. The audit trail must not
    silently omit them."""
    pol = _make_policy_row(db, "rb-skipped", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    h = host_factory()
    plan_host = _make_plan_host(
        db,
        plan,
        h,
        content_profile_state="no_profile",
        content_profile_id_snapshot=None,
    )
    execution = _make_execution_row(db, plan, admin_user)
    _make_execution_host(db, execution, plan_host, state=EXECUTION_HOST_STATE_SKIPPED)
    # No package rows — Slice 2 dispatcher never created any.

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    host_row = db.query(PatchUpdateExecutionRollbackHost).one()
    assert host_row.state == ROLLBACK_HOST_STATE_INFEASIBLE
    assert host_row.refusal_reason == REFUSAL_HOST_NOT_SUCCEEDED


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_evaluate_is_idempotent_and_refreshes_decision(db, admin_user, host_factory):
    """Running evaluate twice keeps the same row ids but refreshes
    the decision when evidence changes. No duplicate rows in any
    layer."""
    pol = _make_policy_row(db, "rb-idem", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, mirror, run = _setup_content_profile(
        db,
        slug="rb-idem-profile",
        package_name="openssl",
        old_version="1.0",
        publish_old=False,  # initially the mirror does NOT publish 1.0
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    rollback_row = patch_rollback_service.evaluate_rollback_feasibility(
        db, execution.id
    )
    first_rollback_id = rollback_row.id
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    # Slice 1a fix: a candidate sync run with no per-package index
    # rows is reported as ``content_evidence_missing`` (the rollback
    # path never backfills), not as ``old_version_unavailable``.
    assert pkg.refusal_reason == REFUSAL_CONTENT_EVIDENCE_MISSING
    first_pkg_id = pkg.id

    # Now add the missing index row — the second evaluation should
    # flip the package to feasible without creating duplicates.
    db.add(
        MirrorSyncRunPackage(
            mirror_sync_run_id=run.id,
            mirror_repo_id=mirror.id,
            package_name="openssl",
            version="1.0",
            arch="amd64",
            filename="openssl_1.0_amd64.deb",
            sha256="b" * 64,
            size=1,
        )
    )
    db.commit()

    rollback_row_b = patch_rollback_service.evaluate_rollback_feasibility(
        db, execution.id
    )
    assert rollback_row_b.id == first_rollback_id
    pkg_b = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg_b.id == first_pkg_id
    assert pkg_b.state == ROLLBACK_PACKAGE_STATE_FEASIBLE
    assert pkg_b.target_rollback_version == "1.0"

    # Exactly one row at every layer.
    assert (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id == execution.id)
        .count()
        == 1
    )
    assert (
        db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.rollback_id == first_rollback_id)
        .count()
        == 1
    )
    assert (
        db.query(PatchUpdateExecutionRollbackPackage)
        .filter(PatchUpdateExecutionRollbackPackage.rollback_host_id != 0)
        .count()
        == 1
    )


def test_evaluate_after_refused_replaces_with_evaluated(db, admin_user, host_factory):
    """If a non-terminal execution was previously evaluated (refused)
    and later becomes terminal, a re-evaluate must upgrade the row
    from ``refused`` to ``evaluated`` and add per-host / per-package
    rows."""
    pol = _make_policy_row(db, "rb-refused-then", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db, slug="rb-refused-then-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user, state=EXECUTION_STATE_RUNNING)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    rb = patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    assert rb.state == ROLLBACK_PLAN_STATE_REFUSED
    assert (
        db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.rollback_id == rb.id)
        .count()
        == 0
    )

    # Flip execution to terminal and re-evaluate.
    execution.state = EXECUTION_STATE_SUCCEEDED
    execution.completed_at = datetime.utcnow()
    db.commit()

    rb2 = patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    assert rb2.id == rb.id
    assert rb2.state == ROLLBACK_PLAN_STATE_EVALUATED
    assert rb2.refusal_reason is None
    assert (
        db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.rollback_id == rb.id)
        .count()
        == 1
    )


# ---------------------------------------------------------------------------
# Slice 1a: rollback feasibility must NOT backfill or mutate the
# mirror package index. The Slice 1 review lock requires the
# availability check to read existing DB content indexes only — never
# read mirror manifest files on disk and never insert / update
# ``MirrorSyncRunPackage`` rows during evaluation.
# ---------------------------------------------------------------------------


def test_evaluate_reports_content_evidence_missing_when_run_has_no_index_rows(
    db, admin_user, host_factory
):
    """A candidate sync run that exists and is ``ok`` but has zero
    ``MirrorSyncRunPackage`` rows must be surfaced as
    ``content_evidence_missing`` — the rollback path never backfills
    the index from disk, so the absence of evidence is a refusal,
    not silent ``old_version_unavailable`` false-positive."""
    pol = _make_policy_row(db, "rb-empty-index", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db,
        slug="rb-empty-index-profile",
        package_name="openssl",
        old_version="1.0",
        publish_old=False,  # ok run exists but has NO index rows
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_CONTENT_EVIDENCE_MISSING
    # The structured details record the zero indexed-checked count
    # so the operator UI can render "no usable index evidence yet"
    # without re-querying.
    assert pkg.refusal_details.get("indexed_checked_count", -1) == 0


def test_evaluate_does_not_mutate_mirror_package_index(
    db, admin_user, host_factory, tmp_path
):
    """Slice 1 review lock: rollback feasibility must NOT call
    ``backfill_run_if_missing`` or otherwise insert
    ``MirrorSyncRunPackage`` rows during evaluation. This test
    arranges an ``ok`` sync run with a *real* manifest file on disk
    plus a published package — the very setup PRA-164's preflight
    resolver would backfill from. The rollback path must leave the
    index untouched and report ``content_evidence_missing`` until a
    legitimate index population (PRA-157 sync hook / PRA-164
    preflight) writes rows itself."""
    import json

    from app.db.models import MirrorSyncRunPackage as MSRP

    pol = _make_policy_row(db, "rb-no-mutate", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    # Build a profile + ``ok`` sync run pointing at a real on-disk
    # manifest that contains an entry for (openssl, 1.0). If the
    # rollback path called ``backfill_run_if_missing``, this would
    # be the manifest it reads — and a MirrorSyncRunPackage row
    # would appear post-evaluation.
    profile, mirror, run = _setup_content_profile(
        db,
        slug="rb-no-mutate-profile",
        package_name="openssl",
        old_version="1.0",
        publish_old=False,  # do NOT pre-populate the index
    )
    manifest_path = tmp_path / "rb-no-mutate-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "filename": "openssl_1.0_amd64.deb",
                        "sha256": "a" * 64,
                        "size": 1024,
                        "package": "openssl",
                        "version": "1.0",
                        "arch": "amd64",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    run.manifest_path = str(manifest_path)
    db.commit()

    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    index_count_before = db.query(MSRP).count()
    assert index_count_before == 0  # sanity: empty index pre-evaluate

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)

    # The rollback path must not have written any new
    # MirrorSyncRunPackage rows.
    index_count_after = db.query(MSRP).count()
    assert index_count_after == index_count_before, (
        "rollback feasibility must not mutate MirrorSyncRunPackage "
        f"(before={index_count_before}, after={index_count_after})"
    )
    # And it must report the refusal explicitly, not feasible-by-
    # silent-backfill.
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_CONTENT_EVIDENCE_MISSING


def test_evaluate_old_version_unavailable_requires_indexed_run(
    db, admin_user, host_factory
):
    """``old_version_unavailable`` (vs ``content_evidence_missing``)
    requires at least one candidate sync run to actually have index
    evidence. This proves the cascade: indexed-but-not-publishing →
    ``old_version_unavailable``; empty-index → ``content_evidence_missing``."""
    pol = _make_policy_row(db, "rb-indexed-unavail", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    # The mirror publishes openssl=2.0 (some other version), so the
    # run IS indexed but does not publish 1.0.
    profile, _, _ = _setup_content_profile(
        db,
        slug="rb-indexed-unavail-profile",
        package_name="openssl",
        old_version="2.0",
        publish_old=True,
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.refusal_reason == REFUSAL_OLD_VERSION_UNAVAILABLE
    # ``indexed_checked_count`` reflects that the candidate run did
    # have index rows; just none for the (name, version) we asked
    # about.
    assert pkg.refusal_details.get("indexed_checked_count", 0) >= 1


# ---------------------------------------------------------------------------
# Summary rollup
# ---------------------------------------------------------------------------


def test_feasibility_summary_includes_all_states(db, admin_user, host_factory):
    """The plan-level summary includes every DB-valid host / package
    state with zero counts when absent so polling UIs don't have to
    defensively check for missing keys."""
    pol = _make_policy_row(db, "rb-summary", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db, slug="rb-summary-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    rb = patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    summary = rb.feasibility_summary
    # All host / package states are present even when zero.
    assert ROLLBACK_HOST_STATE_FEASIBLE in summary["host_counts_by_state"]
    assert ROLLBACK_HOST_STATE_PARTIAL_FEASIBLE in summary["host_counts_by_state"]
    assert ROLLBACK_HOST_STATE_INFEASIBLE in summary["host_counts_by_state"]
    assert summary["host_counts_by_state"][ROLLBACK_HOST_STATE_FEASIBLE] == 1
    assert summary["package_counts_by_state"][ROLLBACK_PACKAGE_STATE_FEASIBLE] == 1
    assert summary["package_counts_by_state"][ROLLBACK_PACKAGE_STATE_INFEASIBLE] == 0


# ---------------------------------------------------------------------------
# Read API
# ---------------------------------------------------------------------------


def test_get_rollback_returns_none_before_evaluation(db, admin_user, host_factory):
    pol = _make_policy_row(db, "rb-no-eval", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    _, rollback_row, host_rows, _ = patch_rollback_service.get_rollback_for_execution(
        db, execution.id
    )
    assert rollback_row is None
    assert host_rows == []


def test_get_rollback_404s_on_unknown_execution(db):
    with pytest.raises(PatchUpdateRollbackError) as exc_info:
        patch_rollback_service.get_rollback_for_execution(db, 987_654)
    assert "not found" in str(exc_info.value)


def test_list_rollback_host_packages_404s_on_unknown_host(db):
    with pytest.raises(PatchUpdateRollbackError) as exc_info:
        patch_rollback_service.list_rollback_host_packages(db, 987_654)
    assert "not found" in str(exc_info.value)


def test_get_plan_rollback_summary_returns_zero_when_no_executions(
    db, admin_user, host_factory
):
    pol = _make_policy_row(db, "rb-plan-empty", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    plan_out, pairs, agg = patch_rollback_service.get_plan_rollback_summary(db, plan.id)
    assert plan_out.id == plan.id
    assert pairs == []
    assert agg["execution_count"] == 0
    assert agg["evaluated_count"] == 0
    assert agg["package_count"] == 0
    assert agg["package_counts_by_state"][ROLLBACK_PACKAGE_STATE_FEASIBLE] == 0


def test_get_plan_rollback_summary_aggregates_across_executions(
    db, admin_user, host_factory
):
    pol = _make_policy_row(db, "rb-plan-agg", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db, slug="rb-plan-agg-profile", package_name="openssl", old_version="1.0"
    )

    h_a = host_factory()
    plan_host_a = _make_plan_host(db, plan, h_a, content_profile_id_snapshot=profile.id)
    e_a = _make_execution_row(db, plan, admin_user)
    eh_a = _make_execution_host(db, e_a, plan_host_a)
    _make_pkg_row(db, eh_a, package_name="openssl", before="1.0", after="1.1")
    patch_rollback_service.evaluate_rollback_feasibility(db, e_a.id)

    h_b = host_factory()
    plan_host_b = _make_plan_host(
        db,
        plan,
        h_b,
        content_profile_state="no_profile",
        content_profile_id_snapshot=None,
    )
    e_b = _make_execution_row(db, plan, admin_user)
    eh_b = _make_execution_host(db, e_b, plan_host_b)
    _make_pkg_row(db, eh_b, package_name="curl", before="2.0", after="2.1")
    patch_rollback_service.evaluate_rollback_feasibility(db, e_b.id)

    plan_out, pairs, agg = patch_rollback_service.get_plan_rollback_summary(db, plan.id)
    assert plan_out.id == plan.id
    assert len(pairs) == 2
    assert agg["execution_count"] == 2
    assert agg["evaluated_count"] == 2
    assert agg["host_count"] == 2
    # One feasible host (a), one infeasible host (b: content_profile_missing).
    assert agg["host_counts_by_state"][ROLLBACK_HOST_STATE_FEASIBLE] == 1
    assert agg["host_counts_by_state"][ROLLBACK_HOST_STATE_INFEASIBLE] == 1
    assert agg["package_counts_by_state"][ROLLBACK_PACKAGE_STATE_FEASIBLE] == 1
    assert agg["package_counts_by_state"][ROLLBACK_PACKAGE_STATE_INFEASIBLE] == 1
    assert agg["refusal_counts"].get(REFUSAL_CONTENT_PROFILE_MISSING) == 1


# ---------------------------------------------------------------------------
# UTC wire shape
# ---------------------------------------------------------------------------


def test_utc_iso_handles_naive_and_aware_datetimes():
    from datetime import timezone

    assert patch_rollback_service.utc_iso(None) is None

    naive = datetime(2026, 5, 13, 4, 0, 0)
    out = patch_rollback_service.utc_iso(naive)
    assert out is not None
    assert out.endswith("Z")
    assert out.startswith("2026-05-13T04:00:00")

    aware = datetime(2026, 5, 13, 4, 0, 0, tzinfo=timezone.utc)
    out_aware = patch_rollback_service.utc_iso(aware)
    assert out_aware is not None
    assert out_aware.endswith("Z")
    assert "+00:00" not in out_aware


def test_evaluate_persists_naive_utc_timestamps(db, admin_user, host_factory):
    """The DB column convention is naive-UTC datetimes; the wire-shape
    UTC suffix happens at the serialization boundary, not in the DB
    layer."""
    pol = _make_policy_row(db, "rb-utc", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db, slug="rb-utc-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(db, exec_host, package_name="openssl", before="1.0", after="1.1")

    rb = patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    assert rb.evaluated_at.tzinfo is None
    assert rb.created_at.tzinfo is None
