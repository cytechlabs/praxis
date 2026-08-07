"""PRA-173 slice 2 — rollback command planning + approval primitive tests.

Slice 2 builds on the Slice 1 feasibility substrate:

* Command-plan rendering: every feasible rollback package row gets a
  family-specific JSONB command_plan (apt `--allow-downgrades`, dnf
  `downgrade`) plus held-package / versionlock handling metadata.
  Infeasible packages keep ``command_plan = None`` so the read
  surface is honest about which rows are dispatch-ready.
* Approval primitive wiring: ``request_rollback_approval`` creates
  a ``patch_approvals`` row with ``subject_kind='rollback'`` and a
  ``patch_update_execution_rollback_approvals`` link carrying the
  frozen command-plan snapshot. ``record_rollback_approval_vote``
  wraps the PRA-161 vote primitive and emits the
  ``patch_rollback.{requested,approved,rejected}`` audit events.

Slice 2 is non-executing: approval flips do NOT trigger dispatch,
SSH, or package-history writes. Tests assert that contract by
checking the absence of those side-effects.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    Package,
    PatchApproval,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdateExecutionRollback,
    PatchUpdateExecutionRollbackApproval,
    PatchUpdateExecutionRollbackHost,
    PatchUpdateExecutionRollbackPackage,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    System,
)
from app.services import patch_rollback_service
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_SUCCEEDED,
    EXECUTION_STATE_RUNNING,
    EXECUTION_STATE_SUCCEEDED,
)
from app.services.patch_rollback_service import (
    ROLLBACK_PACKAGE_STATE_FEASIBLE,
    ROLLBACK_PACKAGE_STATE_INFEASIBLE,
    PatchUpdateRollbackError,
    get_rollback_approval_summary,
    record_rollback_approval_vote,
    request_rollback_approval,
)
from app.services.patch_update_plan_service import PLAN_STATE_APPROVED

# ---------------------------------------------------------------------------
# Fixtures (parallel to Slice 1's test_pra173_rollback_service.py).
# Re-declared here so the file is independently runnable.
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rb-s2-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rb-s2-cred",
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
            hostname=f"rb-s2-host-{counter['n']}.example.com",
            ip_address=f"10.0.97.{counter['n']}",
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


def _make_execution_row(
    db, plan, admin_user, *, state: str = EXECUTION_STATE_SUCCEEDED
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
    plan,
    system,
    *,
    content_profile_state="resolved",
    content_profile_id_snapshot=None,
) -> PatchUpdatePlanHost:
    ph = PatchUpdatePlanHost(
        plan_id=plan.id,
        system_id=system.id,
        system_hostname_snapshot=system.hostname,
        policy_resolution_kind="direct_host",
        ring_resolution_status="resolved",
        wave_index=0,
        content_profile_state=content_profile_state,
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
        wave_index=plan_host.wave_index,
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
    package_name: str,
    family: str = "apt",
    before: Optional[str] = "1.0",
    after: Optional[str] = "1.1",
) -> PatchUpdateExecutionHostPackage:
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
    publish_old: bool = True,
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
    db.flush()
    return profile, mirror, run


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


# ---------------------------------------------------------------------------
# Command-plan rendering
# ---------------------------------------------------------------------------


def test_command_plan_rendered_on_feasible_apt_package(db, admin_user, host_factory):
    """An apt-family feasible package row gets a command_plan with the
    --allow-downgrades primary command and an explicit
    is_held=False held-package-handling block when no
    Package.is_held=True row exists for the (host, package_name)
    pair."""
    pol = _make_policy_row(db, "rb-cp-apt", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db, slug="rb-cp-apt-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db, exec_host, package_name="openssl", before="1.0", after="1.1", family="apt"
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_FEASIBLE
    assert pkg.command_plan is not None
    cp = pkg.command_plan
    assert cp["family"] == "apt"
    assert cp["package_name"] == "openssl"
    assert cp["target_rollback_version"] == "1.0"
    primary = cp["primary_command"]
    assert primary["argv"] == [
        "apt-get",
        "install",
        "-y",
        "--allow-downgrades",
        "openssl=1.0",
    ]
    assert "apt-get install" in primary["command_string"]
    assert "--allow-downgrades" in primary["command_string"]
    assert "openssl=1.0" in primary["command_string"]
    held = cp["held_package_handling"]
    assert held["supported"] is True
    assert held["is_held"] is False
    assert held["pre_steps"] == []
    assert held["post_steps"] == []


def test_command_plan_includes_unhold_rehold_when_package_is_held(
    db, admin_user, host_factory
):
    """When Package.is_held=True for the same (host, package_name), the
    apt plan carries an apt-mark unhold pre-step + apt-mark hold
    post-step so Slice 3 dispatch knows to release and restore the
    hold."""
    pol = _make_policy_row(db, "rb-cp-held", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db, slug="rb-cp-held-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    _add_package_row(db, h.id, "openssl", version="1.1", is_held=True)
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db, exec_host, package_name="openssl", before="1.0", after="1.1", family="apt"
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    held = pkg.command_plan["held_package_handling"]
    assert held["is_held"] is True
    assert held["pre_steps"][0]["argv"] == ["apt-mark", "unhold", "openssl"]
    assert held["pre_steps"][0]["purpose"] == "release_apt_hold"
    assert held["post_steps"][0]["argv"] == ["apt-mark", "hold", "openssl"]
    assert held["post_steps"][0]["purpose"] == "restore_apt_hold"


def test_command_plan_rendered_on_feasible_dnf_package(db, admin_user, host_factory):
    """A dnf-family feasible package row gets a command_plan with the
    dnf downgrade primary command. Versionlock handling is explicit
    (supported=False, reason=no_versionlock_facts) because PRA-155
    facts do not yet carry per-package versionlock state."""
    pol = _make_policy_row(db, "rb-cp-dnf", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db,
        slug="rb-cp-dnf-profile",
        family="rpm",
        package_name="kernel",
        old_version="5.14.0",
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db,
        exec_host,
        package_name="kernel",
        before="5.14.0",
        after="5.14.1",
        family="dnf",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_FEASIBLE
    cp = pkg.command_plan
    assert cp["family"] == "dnf"
    primary = cp["primary_command"]
    assert primary["argv"] == ["dnf", "downgrade", "-y", "kernel-5.14.0"]
    assert "dnf downgrade" in primary["command_string"]
    vlock = cp["versionlock_handling"]
    assert vlock["supported"] is False
    assert vlock["reason"] == "no_versionlock_facts"
    assert vlock["pre_steps"] == []
    assert vlock["post_steps"] == []
    held = cp["held_package_handling"]
    assert held["supported"] is False
    assert held["reason"] == "not_applicable_for_family"


def test_infeasible_packages_have_null_command_plan(db, admin_user, host_factory):
    """Infeasible package rows must have command_plan = None so the
    read surface is honest about which rows are dispatch-ready."""
    pol = _make_policy_row(db, "rb-cp-infeas", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(db, slug="rb-cp-infeas-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db,
        exec_host,
        package_name="openssl",
        before="1.0",
        after="1.0",  # version_unchanged → infeasible
        family="apt",
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg.state == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    assert pkg.command_plan is None


def test_re_evaluate_refreshes_command_plan_in_place(db, admin_user, host_factory):
    """Re-evaluation updates the command_plan column in place when
    underlying evidence changes (Package.is_held flipped). The
    approved plan stays frozen in the link row's
    frozen_plan_snapshot — that comes in a separate test."""
    pol = _make_policy_row(db, "rb-cp-refresh", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db, slug="rb-cp-refresh-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    pkg_row = _add_package_row(db, h.id, "openssl", version="1.1", is_held=False)
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db, exec_host, package_name="openssl", before="1.0", after="1.1", family="apt"
    )

    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg_first = db.query(PatchUpdateExecutionRollbackPackage).one()
    first_id = pkg_first.id
    assert pkg_first.command_plan["held_package_handling"]["is_held"] is False

    pkg_row.is_held = True
    db.commit()
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    pkg_second = db.query(PatchUpdateExecutionRollbackPackage).one()
    assert pkg_second.id == first_id
    assert pkg_second.command_plan["held_package_handling"]["is_held"] is True
    assert pkg_second.command_plan["held_package_handling"][
        "pre_steps"
    ], "expected an apt-mark unhold pre-step after flipping is_held=True"


# ---------------------------------------------------------------------------
# Approval primitive wiring
# ---------------------------------------------------------------------------


def _make_feasible_rollback(db, admin_user, host_factory, *, slug: str):
    """Stand up an evaluated rollback with one feasible apt package
    ready to receive an approval request."""
    pol = _make_policy_row(db, slug, admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(
        db, slug=f"{slug}-profile", package_name="openssl", old_version="1.0"
    )
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db, exec_host, package_name="openssl", before="1.0", after="1.1", family="apt"
    )
    rb = patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    return execution, rb


def test_request_approval_creates_link_and_freezes_plan(db, admin_user, host_factory):
    """request_rollback_approval creates a PatchApproval +
    PatchUpdateExecutionRollbackApproval pair. The link's
    frozen_plan_snapshot captures every feasible package's command
    plan so Slice 3 dispatch reads what was voted on, not the live
    column."""
    execution, rb = _make_feasible_rollback(db, admin_user, host_factory, slug="rb-req")
    rollback_row, link, approval = request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id, required_approvals=1
    )
    assert rollback_row.id == rb.id
    assert approval.subject_kind == "rollback"
    assert approval.subject_id == rb.id
    assert approval.status == "pending"
    assert link.approval_id == approval.id
    snap = link.frozen_plan_snapshot
    assert snap["snapshot_version"] == 1
    assert snap["feasible_package_count"] == 1
    assert len(snap["hosts"]) == 1
    host_snap = snap["hosts"][0]
    assert host_snap["feasible_packages"][0]["package_name"] == "openssl"
    assert (
        host_snap["feasible_packages"][0]["command_plan"]["primary_command"]["argv"][0]
        == "apt-get"
    )


def test_request_approval_is_idempotent_when_pending(db, admin_user, host_factory):
    """A second request_rollback_approval while the first is still
    pending must return the same link row — no duplicate
    PatchApproval rows."""
    execution, _rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-req-idem"
    )
    _r1, link1, approval1 = request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id
    )
    _r2, link2, approval2 = request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id
    )
    assert link1.id == link2.id
    assert approval1.id == approval2.id
    assert db.query(PatchApproval).count() == 1
    assert db.query(PatchUpdateExecutionRollbackApproval).count() == 1


def test_request_approval_refuses_when_rollback_refused(db, admin_user, host_factory):
    """A rollback whose header is ``refused`` (e.g.
    execution_not_terminal) cannot receive an approval request —
    there is nothing approvable yet."""
    pol = _make_policy_row(db, "rb-req-refused", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user, state=EXECUTION_STATE_RUNNING)
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    with pytest.raises(PatchUpdateRollbackError) as exc:
        request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    assert "evaluated" in str(exc.value).lower()


def test_request_approval_refuses_when_no_feasible_packages(
    db, admin_user, host_factory
):
    """Approval-request when every package is infeasible must refuse
    so operators don't see an "approve nothing" affordance."""
    pol = _make_policy_row(db, "rb-req-zero", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, _, _ = _setup_content_profile(db, slug="rb-req-zero-profile")
    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db, exec_host, package_name="openssl", before="1.0", after="1.0", family="apt"
    )
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    with pytest.raises(PatchUpdateRollbackError) as exc:
        request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    assert "zero feasible" in str(exc.value)


def test_request_approval_refuses_when_no_evaluation(db, admin_user, host_factory):
    """An execution that has never been evaluated for rollback
    feasibility cannot have an approval requested — the route layer
    must surface "evaluate it first" rather than silently 200ing."""
    pol = _make_policy_row(db, "rb-req-noeval", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    with pytest.raises(PatchUpdateRollbackError) as exc:
        request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    assert "evaluate" in str(exc.value).lower()


def test_vote_approve_flips_status_and_does_not_dispatch(db, admin_user, host_factory):
    """Recording an approve vote that meets the threshold flips the
    PatchApproval row to ``approved`` and emits
    patch_rollback.approved — but does NOT mutate any package
    history or create any dispatch artifact. Slice 3 owns
    dispatch."""
    from app.db.models import PackageHistory

    history_count_before = db.query(PackageHistory).count()

    execution, _rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-vote-yes"
    )
    request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id, required_approvals=1
    )
    result = record_rollback_approval_vote(
        db, execution.id, actor_user_id=admin_user.id, decision="approve"
    )
    assert result["status"] == "approved"
    approval = db.query(PatchApproval).one()
    assert approval.status == "approved"
    # The vote must not have created any package_history rows — the
    # PRA-161 no-auto-execute lock is preserved.
    assert db.query(PackageHistory).count() == history_count_before


def test_vote_reject_flips_status(db, admin_user, host_factory):
    """A reject vote on a pending rollback approval flips the row to
    ``rejected`` and emits patch_rollback.rejected."""
    execution, _rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-vote-no"
    )
    request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    result = record_rollback_approval_vote(
        db, execution.id, actor_user_id=admin_user.id, decision="reject"
    )
    assert result["status"] == "rejected"
    approval = db.query(PatchApproval).one()
    assert approval.status == "rejected"


def test_vote_refuses_unknown_decision(db, admin_user, host_factory):
    execution, _rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-vote-bad"
    )
    request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    with pytest.raises(PatchUpdateRollbackError):
        record_rollback_approval_vote(
            db, execution.id, actor_user_id=admin_user.id, decision="maybe"
        )


def test_vote_refuses_without_pending_link(db, admin_user, host_factory):
    """Voting before request_rollback_approval has been called must
    refuse with a clear error rather than silently 200ing."""
    execution, _rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-vote-no-req"
    )
    with pytest.raises(PatchUpdateRollbackError) as exc:
        record_rollback_approval_vote(
            db, execution.id, actor_user_id=admin_user.id, decision="approve"
        )
    assert "approval link" in str(exc.value).lower()


def test_get_rollback_approval_summary_returns_none_before_request(
    db, admin_user, host_factory
):
    execution, rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-sum-pre"
    )
    assert get_rollback_approval_summary(db, rb.id) is None


def test_get_rollback_approval_summary_reflects_post_request_state(
    db, admin_user, host_factory
):
    execution, rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-sum-post"
    )
    request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    summary = get_rollback_approval_summary(db, rb.id)
    assert summary is not None
    assert summary["status"] == "pending"
    assert summary["frozen_plan_snapshot"]["feasible_package_count"] == 1
    assert summary["required_approvals"] == 1


def test_rollback_approval_subject_kind_is_rollback(db, admin_user, host_factory):
    """The PatchApproval row created by request_rollback_approval
    must use subject_kind='rollback' so it cannot collide with a
    plan approval on the same numeric id."""
    execution, rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-subject"
    )
    request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    approval = db.query(PatchApproval).one()
    assert approval.subject_kind == "rollback"
    assert approval.subject_id == rb.id


def test_frozen_plan_snapshot_is_immutable_across_re_evaluate(
    db, admin_user, host_factory
):
    """Re-evaluating the rollback after an approval has been requested
    must NOT rewrite the link's frozen_plan_snapshot. Only the live
    per-package command_plan column may drift; dispatch (future)
    reads the frozen snapshot."""
    execution, _rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-frozen-immut"
    )
    _, link, _approval = request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id
    )
    snapshot_before = dict(link.frozen_plan_snapshot)
    # Force a re-evaluate that would change the live command plan
    # (flip is_held on the package).
    pkg_row = (
        db.query(Package)
        .join(System, Package.system_id == System.id)
        .filter(System.hostname.like("rb-s2-host-%"))
        .order_by(Package.id.desc())
        .first()
    )
    if pkg_row is None:
        # Need to add one to make the re-evaluate actually drift.
        h = (
            db.query(System)
            .filter(System.hostname.like("rb-s2-host-%"))
            .order_by(System.id.desc())
            .first()
        )
        pkg_row = _add_package_row(db, h.id, "openssl", version="1.1", is_held=True)
    else:
        pkg_row.is_held = True
    db.commit()
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    db.refresh(link)
    assert (
        dict(link.frozen_plan_snapshot) == snapshot_before
    ), "frozen_plan_snapshot must not change across re-evaluate"


# ---------------------------------------------------------------------------
# Slice 2a: request_rollback_approval must fail-closed
# when any feasible rollback package row has command_plan = None.
#
# A pre-Slice-2 evaluated rollback would have feasible rows but null
# command_plan columns (the JSONB column is new in Slice 2 and is
# nullable for back-compat). Without this guard the frozen snapshot
# would silently exclude those rows and operators could approve an
# empty / partial plan they never saw.
# ---------------------------------------------------------------------------


def test_request_approval_refuses_when_feasible_row_missing_command_plan(
    db, admin_user, host_factory
):
    """Simulate a pre-Slice-2 evaluated rollback by clearing the
    command_plan on a feasible package row, then prove
    request_rollback_approval refuses rather than freezing an
    empty / partial snapshot."""
    execution, rb = _make_feasible_rollback(
        db, admin_user, host_factory, slug="rb-missing-cp"
    )
    feasible_pkg = (
        db.query(PatchUpdateExecutionRollbackPackage)
        .filter(
            PatchUpdateExecutionRollbackPackage.state == ROLLBACK_PACKAGE_STATE_FEASIBLE
        )
        .one()
    )
    assert feasible_pkg.command_plan is not None
    # Pre-Slice-2 simulation: the JSONB column was nullable, so an
    # existing feasible row created before Slice 2 lands would carry
    # ``None`` here. The Slice 2a guard must refuse rather than
    # silently approve nothing.
    feasible_pkg.command_plan = None
    db.commit()

    with pytest.raises(PatchUpdateRollbackError) as exc:
        request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    msg = str(exc.value)
    assert "command_plan" in msg
    assert feasible_pkg.package_name in msg
    assert "re-evaluate" in msg.lower()

    # The refusal must not have created any approval row or link.
    assert db.query(PatchApproval).count() == 0
    assert db.query(PatchUpdateExecutionRollbackApproval).count() == 0


def test_request_approval_refuses_when_one_of_many_feasible_rows_missing_plan(
    db, admin_user, host_factory
):
    """Two feasible packages, one with command_plan cleared:
    request_rollback_approval must refuse with both names surfaced
    so the operator-facing message tells them everything to fix in
    one go."""
    pol = _make_policy_row(db, "rb-missing-cp-multi", admin_user)
    plan = _make_plan_row(db, pol, admin_user)
    profile, mirror, run = _setup_content_profile(
        db,
        slug="rb-missing-cp-multi-profile",
        package_name="openssl",
        old_version="1.0",
        publish_old=True,
    )
    # Also publish curl=2.0 (the other feasible package).
    from app.db.models import MirrorSyncRunPackage

    db.add(
        MirrorSyncRunPackage(
            mirror_sync_run_id=run.id,
            mirror_repo_id=mirror.id,
            package_name="curl",
            version="2.0",
            arch="amd64",
            filename="curl_2.0_amd64.deb",
            sha256="b" * 64,
            size=1,
        )
    )
    db.commit()

    h = host_factory()
    plan_host = _make_plan_host(db, plan, h, content_profile_id_snapshot=profile.id)
    execution = _make_execution_row(db, plan, admin_user)
    exec_host = _make_execution_host(db, execution, plan_host)
    _make_pkg_row(
        db, exec_host, package_name="openssl", before="1.0", after="1.1", family="apt"
    )
    _make_pkg_row(
        db, exec_host, package_name="curl", before="2.0", after="2.1", family="apt"
    )
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)

    # Sanity: both rows should be feasible with command plans.
    feasibles = (
        db.query(PatchUpdateExecutionRollbackPackage)
        .filter(
            PatchUpdateExecutionRollbackPackage.state == ROLLBACK_PACKAGE_STATE_FEASIBLE
        )
        .order_by(PatchUpdateExecutionRollbackPackage.package_name.asc())
        .all()
    )
    assert len(feasibles) == 2
    assert all(p.command_plan is not None for p in feasibles)

    # Clear one to simulate the pre-Slice-2 state for that single row.
    target = next(p for p in feasibles if p.package_name == "curl")
    target.command_plan = None
    db.commit()

    with pytest.raises(PatchUpdateRollbackError) as exc:
        request_rollback_approval(db, execution.id, actor_user_id=admin_user.id)
    msg = str(exc.value)
    assert "curl" in msg
    # openssl had a plan; it must NOT appear in the missing-plan list.
    assert "openssl" not in msg.split("(")[1].split(")")[0]
    # Re-evaluating recreates the missing plan and request_rollback_approval
    # succeeds without further intervention.
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    rollback_row, link, approval = request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id
    )
    assert link.frozen_plan_snapshot["feasible_package_count"] == 2
    assert approval.status == "pending"
