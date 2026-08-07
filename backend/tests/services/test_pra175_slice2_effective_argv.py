"""PRA-175 Slice 2 — effective runtime argv audit visibility.

Slice 1 made the dispatchers wrap argv per ``credential.sudo_method``
but recorded only the *planned* argv. Slice 2 surfaces the *effective*
post-wrap argv (e.g. ``["sudo", "-n", "systemctl", "reboot"]``) in
the JSONB evidence fields the orchestrators already maintain:

* ``patch_update_execution_host.error_details.effective_argv``
* ``patch_rollback_dispatch_host_package.details.effective_argv`` and
  the per-phase ``error_details.command_log[*].effective_argv``
* ``patch_update_execution_reboot.dispatch_details.effective_argv``

Locks pinned by the slice:

* Slice 1 semantics unchanged (none / nopasswd / password behavior
  identical, sudo password from ``credential.vault_path``).
* Planned/raw snapshots preserved (``error_details.command`` /
  ``command_log[*].argv`` / reboot ``command_snapshot``).
* The sudo password and the stdin payload are **never** recorded —
  only the argv prefix (``["sudo", "-S", ...]``) is persisted.

Tests use the existing PRA-171 / PRA-173 / PRA-172 fixtures and
inject a fake dispatcher that returns a ``DispatchResult`` /
``RebootDispatchResult`` with an explicit ``effective_argv``.
This proves the orchestrator copies the field through; the
end-to-end wrap is covered by ``test_pra175_dispatch_sudo.py``
(Slice 1).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pytest

from app.db.models import (
    Credential,
    Group,
    PatchPolicy,
    PatchRollbackDispatchHost,
    PatchRollbackDispatchHostPackage,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdateExecutionReboot,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    System,
)
from app.services import (
    patch_execution_service,
    patch_reboot_service,
    patch_rollback_dispatch_service,
    patch_rollback_service,
    patch_update_plan_service,
)
from app.services.dispatch_sudo import (
    SUDO_METHOD_NONE,
    SUDO_METHOD_NOPASSWD,
    SUDO_METHOD_PASSWORD,
    wrap_argv_for_sudo,
)
from app.services.patch_execution_dispatch_service import (
    DispatchResult,
    default_dispatch,
    dispatch_next_batch,
)
from app.services.patch_reboot_dispatch_service import (
    DEFAULT_REBOOT_COMMAND,
    EXIT_SIGNAL_EXIT_ZERO,
    RebootDispatchResult,
    default_reboot_dispatch,
    dispatch_due_reboots,
)

# ---------------------------------------------------------------------------
# Vault stub (shared with Slice 1 tests, redefined locally for isolation)
# ---------------------------------------------------------------------------


class _VaultStub:
    def __init__(self, secrets: Dict[str, Dict[str, Any]]):
        self.secrets = secrets

    def __call__(self, _db) -> "_VaultStub":
        return self

    def read_secret(self, path: str) -> Optional[Dict[str, Any]]:
        return self.secrets.get(path)


@pytest.fixture
def stub_vault(monkeypatch):
    def install(secrets: Dict[str, Dict[str, Any]]) -> _VaultStub:
        stub = _VaultStub(secrets)
        monkeypatch.setattr("app.services.vault_service.VaultService", stub)
        return stub

    return install


# ---------------------------------------------------------------------------
# Recording transport for the end-to-end default_dispatch / default_reboot_dispatch
# integration tests (re-uses the same shape as Slice 1).
# ---------------------------------------------------------------------------


class _RecordingTransport:
    name = "ssh"

    def __init__(self, *, exit_code: int = 0):
        self.calls: List[Tuple[List[str], Optional[bytes]]] = []
        self._exit_code = exit_code

    async def run_command(self, cmd, *, stdin=None, timeout_seconds=None):
        self.calls.append((list(cmd), stdin))
        from app.services.transport.base import CommandResult

        return CommandResult(
            exit_code=self._exit_code, stdout=b"", stderr=b"", duration_ms=7
        )


@pytest.fixture
def patch_default_dispatch_transport(monkeypatch):
    def install(transport: _RecordingTransport):
        async def _fake_factory(system, broker_client, ssh_service=None):
            return transport

        class _FakeBroker:
            def __init__(self, *_a, **_k):
                pass

            async def __aexit__(self, *_a, **_k):
                return None

        class _FakeSSHService:
            def __init__(self, *_a, **_k):
                pass

            def close_all_connections(self):
                return None

        monkeypatch.setattr("app.services.transport.get_transport", _fake_factory)
        monkeypatch.setattr(
            "app.services.transport.factory.get_transport", _fake_factory
        )
        monkeypatch.setattr("app.services.broker_client.BrokerClient", _FakeBroker)
        monkeypatch.setattr("app.services.ssh_service.SSHService", _FakeSSHService)

    return install


# ---------------------------------------------------------------------------
# default_dispatch — DispatchResult.effective_argv is populated
# ---------------------------------------------------------------------------


@pytest.fixture
def cred_factory(db):
    counter = {"n": 0}

    def make(
        *,
        sudo_method: str = SUDO_METHOD_NONE,
        vault_path: Optional[str] = "vault/sudo-cred",
        auth_method: str = "password",
        username: str = "root",
    ) -> Credential:
        counter["n"] += 1
        cred = Credential(
            name=f"pra175s2-cred-{counter['n']}",
            auth_method=auth_method,
            username=username,
            vault_path=vault_path,
            sudo_method=sudo_method,
        )
        db.add(cred)
        db.flush()
        return cred

    return make


@pytest.fixture
def host_factory(db, seed_distro, cred_factory):
    counter = {"n": 0}

    def make(*, credential: Optional[Credential] = None) -> System:
        counter["n"] += 1
        if credential is None:
            credential = cred_factory()
        group = Group(name=f"pra175s2-grp-{counter['n']}", description="x")
        db.add(group)
        db.flush()
        sys_row = System(
            hostname=f"pra175s2-host-{counter['n']}.example.com",
            ip_address=f"10.0.176.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=credential.id,
        )
        db.add(sys_row)
        db.flush()
        return sys_row

    return make


@pytest.mark.parametrize(
    "method,expected_prefix",
    [
        (SUDO_METHOD_NONE, []),
        (SUDO_METHOD_NOPASSWD, ["sudo", "-n"]),
        (SUDO_METHOD_PASSWORD, ["sudo", "-S"]),
    ],
)
def test_default_dispatch_result_carries_effective_argv(
    db,
    host_factory,
    cred_factory,
    patch_default_dispatch_transport,
    stub_vault,
    method,
    expected_prefix,
):
    cred = cred_factory(sudo_method=method, vault_path="vault/pra175s2-dd")
    stub_vault({"vault/pra175s2-dd": {"sudo_password": "pw1"}})
    sys_row = host_factory(credential=cred)
    transport = _RecordingTransport()
    patch_default_dispatch_transport(transport)

    planned = ["apt-get", "install", "-y", "openssl"]
    result = default_dispatch(db, sys_row, planned)

    assert isinstance(result, DispatchResult)
    assert result.effective_argv == expected_prefix + planned
    # Slice 1 lock: the password is never in the argv either at the
    # transport call site or on the result envelope.
    assert "pw1" not in " ".join(result.effective_argv)


def test_default_reboot_dispatch_result_carries_effective_argv_password(
    db, host_factory, cred_factory, stub_vault, monkeypatch
):
    """Reboot path: RebootDispatchResult.effective_argv must reflect
    the post-wrap argv even on the password path, and must not leak
    the sudo password."""
    cred = cred_factory(
        sudo_method=SUDO_METHOD_PASSWORD, vault_path="vault/pra175s2-reboot"
    )
    stub_vault({"vault/pra175s2-reboot": {"sudo_password": "super-secret-pw"}})
    sys_row = host_factory(credential=cred)

    calls: List[Tuple[List[str], Optional[bytes]]] = []

    async def _fake_run_command(self, cmd, *, stdin=None, timeout_seconds=None):
        calls.append((list(cmd), stdin))
        from app.services.transport.base import CommandResult

        return CommandResult(exit_code=0, stdout=b"", stderr=b"", duration_ms=4)

    class _FakeSSHService:
        def __init__(self, *_a, **_k):
            pass

        def get_connection(self, _system_id):
            return ("fake-client", False)

        def close_all_connections(self):
            return None

    monkeypatch.setattr(
        "app.services.transport.ssh.SSHTransport.run_command", _fake_run_command
    )
    monkeypatch.setattr("app.services.ssh_service.SSHService", _FakeSSHService)

    result = default_reboot_dispatch(db, sys_row, list(DEFAULT_REBOOT_COMMAND))

    assert result.exit_signal_kind == EXIT_SIGNAL_EXIT_ZERO
    assert result.effective_argv == ["sudo", "-S", "systemctl", "reboot"]
    # Redaction proof: the password is in stdin, never in argv or on
    # the result envelope.
    assert "super-secret-pw" not in " ".join(result.effective_argv)
    transport_cmd, transport_stdin = calls[0]
    assert transport_cmd == ["sudo", "-S", "systemctl", "reboot"]
    assert transport_stdin == b"super-secret-pw\n"


# ---------------------------------------------------------------------------
# Patch update dispatch — error_details.effective_argv persisted
# ---------------------------------------------------------------------------


def _make_minimal_plan_execution(
    db, admin_user, host, *, slug: str, package_name: str = "openssl"
):
    """Build the absolute minimum plan + execution + plan-host +
    execution-host + selected-package + preflight-snapshot rows the
    dispatcher needs to call ``_process_host`` end-to-end."""
    pol = PatchPolicy(
        slug=slug,
        name=slug,
        scope_kind="full",
        scope_packages=[],
        reboot_policy="never",
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
    db.add(pol)
    db.flush()
    plan = PatchUpdatePlan(
        policy_id=pol.id,
        name=f"plan-{slug}",
        state=patch_update_plan_service.PLAN_STATE_APPROVED,
        policy_snapshot={"id": pol.id, "slug": pol.slug, "name": pol.name},
        ring_sequence_snapshot=[],
        request_snapshot={},
        block_reasons=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    plan_host = PatchUpdatePlanHost(
        plan_id=plan.id,
        system_id=host.id,
        system_hostname_snapshot=host.hostname,
        policy_resolution_kind="direct_host",
        ring_resolution_status="resolved",
        wave_index=0,
        content_profile_state="resolved",
        content_profile_id_snapshot=None,
        content_profile_conflict_snapshot=[],
        state="planned",
        block_reasons=[],
    )
    db.add(plan_host)
    db.flush()
    from app.db.models import (
        PatchUpdatePlanPreflightSnapshot,
        PatchUpdatePlanSelectedPackage,
    )

    # Selected-package snapshot the dispatcher reads.
    db.add(
        PatchUpdatePlanSelectedPackage(
            plan_host_id=plan_host.id,
            package_name=package_name,
            available_version_snapshot=None,
            installed_version_snapshot="0.9",
            selection_reason="policy_full",
            state=patch_update_plan_service.SELECTION_STATE_SELECTED,
        )
    )
    db.add(
        PatchUpdatePlanPreflightSnapshot(
            plan_host_id=plan_host.id,
            package_name=package_name,
            installed_version_at_preflight="0.9",
            package_manager_family_snapshot="apt",
            content_availability_state="available",
            evaluated_at=datetime.utcnow(),
        )
    )
    db.flush()
    now = datetime.utcnow()
    execution = PatchUpdateExecution(
        plan_id=plan.id,
        state=patch_execution_service.EXECUTION_STATE_RUNNING,
        started_by=admin_user.id,
        started_at=now,
        max_parallel_per_wave=1,
        failure_threshold_percent=None,
        plan_state_snapshot=plan.state,
        policy_snapshot=dict(plan.policy_snapshot or {}),
        execution_config_snapshot={},
        progress_summary={},
    )
    db.add(execution)
    db.flush()
    execution_host = PatchUpdateExecutionHost(
        execution_id=execution.id,
        plan_host_id=plan_host.id,
        system_id_snapshot=host.id,
        system_hostname_snapshot=host.hostname,
        wave_index=0,
        state=patch_execution_service.EXECUTION_HOST_STATE_PENDING,
        selected_package_count=1,
        skip_reasons=[],
        error_details={},
    )
    db.add(execution_host)
    db.flush()
    return execution, execution_host


def test_patch_update_dispatch_persists_effective_argv_on_success(
    db, admin_user, host_factory, cred_factory
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    host = host_factory(credential=cred)
    execution, execution_host = _make_minimal_plan_execution(
        db, admin_user, host, slug="pra175s2-success"
    )
    db.commit()

    fake_effective = ["sudo", "-n", "apt-get", "install", "-y", "openssl"]

    def _fake_dispatcher(system, cmd):
        return DispatchResult(
            exit_code=0,
            stdout="ok",
            transport_name="fake",
            effective_argv=list(fake_effective),
        )

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )

    db.refresh(execution_host)
    details = execution_host.error_details
    assert details["command"].startswith("apt-get install -y")  # planned/raw
    assert details["effective_argv"] == fake_effective
    # Planned argv string and effective argv are not the same shape;
    # operators must see both.
    assert "sudo" not in details["command"]
    assert details["effective_argv"][0] == "sudo"


def test_patch_update_dispatch_persists_effective_argv_on_failure(
    db, admin_user, host_factory, cred_factory
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    host = host_factory(credential=cred)
    execution, execution_host = _make_minimal_plan_execution(
        db, admin_user, host, slug="pra175s2-failure"
    )
    db.commit()

    fake_effective = ["sudo", "-n", "apt-get", "install", "-y", "openssl"]

    def _fake_dispatcher(system, cmd):
        return DispatchResult(
            exit_code=100,
            stderr="boom",
            transport_name="fake",
            effective_argv=list(fake_effective),
        )

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )

    db.refresh(execution_host)
    details = execution_host.error_details
    assert details["code"] == "package_manager_failed"
    assert details["effective_argv"] == fake_effective


def test_patch_update_dispatch_records_none_effective_argv_for_fake_without_field(
    db, admin_user, host_factory, cred_factory
):
    """Backward-compat lock: a dispatcher fake that omits
    ``effective_argv`` (default None) results in
    ``error_details.effective_argv = None``, never a crash."""
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    host = host_factory(credential=cred)
    execution, execution_host = _make_minimal_plan_execution(
        db, admin_user, host, slug="pra175s2-noeff"
    )
    db.commit()

    def _fake_dispatcher(system, cmd):
        return DispatchResult(exit_code=0, transport_name="fake")

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )

    db.refresh(execution_host)
    assert execution_host.error_details["effective_argv"] is None


# ---------------------------------------------------------------------------
# Rollback dispatch — frozen argv preserved, effective_argv recorded
# ---------------------------------------------------------------------------


def _setup_content_profile(db, *, slug: str):
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
        package_family="deb",
        upstream_url=f"https://example.com/{slug}",
        distribution="jammy",
        components="[]",
        architectures="[]",
        sync_schedule_cron="0 4 * * *",
    )
    db.add(mirror)
    db.flush()
    profile = ContentProfile(slug=slug, display_name=slug, package_family="deb")
    db.add(profile)
    db.flush()
    channel = ContentChannel(
        slug=f"{slug}-ch", display_name=f"{slug}-ch", package_family="deb"
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
            package_name="openssl",
            version="1.0",
            arch="amd64",
            filename="openssl_1.0_amd64.deb",
            sha256="a" * 64,
            size=1,
        )
    )
    db.flush()
    return profile


def _build_approved_rollback(db, admin_user, host_factory, *, slug: str):
    from app.services.patch_update_plan_service import PLAN_STATE_APPROVED

    pol = PatchPolicy(
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
    db.add(pol)
    db.flush()
    plan = PatchUpdatePlan(
        policy_id=pol.id,
        name=f"plan-{slug}",
        state=PLAN_STATE_APPROVED,
        policy_snapshot={"id": pol.id, "slug": pol.slug, "name": pol.name},
        ring_sequence_snapshot=[],
        request_snapshot={},
        block_reasons=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    profile = _setup_content_profile(db, slug=f"{slug}-profile")
    host = host_factory()
    plan_host = PatchUpdatePlanHost(
        plan_id=plan.id,
        system_id=host.id,
        system_hostname_snapshot=host.hostname,
        policy_resolution_kind="direct_host",
        ring_resolution_status="resolved",
        wave_index=0,
        content_profile_state="resolved",
        content_profile_id_snapshot=profile.id,
        content_profile_conflict_snapshot=[],
        state="planned",
        block_reasons=[],
    )
    db.add(plan_host)
    db.flush()
    now = datetime.utcnow()
    execution = PatchUpdateExecution(
        plan_id=plan.id,
        state=patch_execution_service.EXECUTION_STATE_SUCCEEDED,
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
    db.add(execution)
    db.flush()
    exec_host = PatchUpdateExecutionHost(
        execution_id=execution.id,
        plan_host_id=plan_host.id,
        system_id_snapshot=host.id,
        system_hostname_snapshot=host.hostname,
        wave_index=0,
        state=patch_execution_service.EXECUTION_HOST_STATE_SUCCEEDED,
        selected_package_count=1,
        skip_reasons=[],
        error_details={},
    )
    db.add(exec_host)
    db.flush()
    db.add(
        PatchUpdateExecutionHostPackage(
            execution_host_id=exec_host.id,
            package_name="openssl",
            requested_version_snapshot=None,
            installed_version_before="1.0",
            installed_version_after="1.1",
            package_manager_family_snapshot="apt",
            outcome="succeeded",
            error_code=None,
            details={},
        )
    )
    db.flush()
    patch_rollback_service.evaluate_rollback_feasibility(db, execution.id)
    patch_rollback_service.request_rollback_approval(
        db, execution.id, actor_user_id=admin_user.id
    )
    patch_rollback_service.record_rollback_approval_vote(
        db, execution.id, actor_user_id=admin_user.id, decision="approve"
    )
    return execution


def test_rollback_dispatch_persists_effective_argv_and_keeps_frozen_argv_raw(
    db, admin_user, host_factory
):
    execution = _build_approved_rollback(
        db, admin_user, host_factory, slug="pra175s2-rb"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    fake_effective = [
        "sudo",
        "-n",
        "apt-get",
        "install",
        "-y",
        "--allow-downgrades",
        "openssl=1.0",
    ]

    def _fake_dispatcher(system, cmd):
        return DispatchResult(
            exit_code=0,
            transport_name="fake",
            effective_argv=list(fake_effective),
        )

    patch_rollback_dispatch_service.dispatch_next_batch(
        db, run.id, actor_user_id=admin_user.id, dispatch_callable=_fake_dispatcher
    )

    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(PatchRollbackDispatchHostPackage.package_name == "openssl")
        .one()
    )
    # Primary phase details: planned argv preserved + effective argv added.
    details = pkg_row.details
    assert details["phase"] == "primary"
    assert details["argv"] == [
        "apt-get",
        "install",
        "-y",
        "--allow-downgrades",
        "openssl=1.0",
    ]
    assert details["effective_argv"] == fake_effective

    # The frozen approval snapshot must NOT have been rewritten with
    # the sudo-wrapped argv.
    from app.db.models import PatchUpdateExecutionRollbackApproval

    link = (
        db.query(PatchUpdateExecutionRollbackApproval)
        .filter(
            PatchUpdateExecutionRollbackApproval.id == run.rollback_approval_link_id
        )
        .one()
    )
    snap = link.frozen_plan_snapshot
    for host_entry in snap.get("hosts") or []:
        for pkg in host_entry.get("feasible_packages") or []:
            primary_argv = (pkg.get("command_plan") or {}).get(
                "primary_command", {}
            ).get("argv") or []
            assert "sudo" not in primary_argv

    # The per-host command_log entry mirrors the per-package details.
    host_row = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .one()
    )
    cmd_log = host_row.error_details["command_log"]
    primary_entries = [e for e in cmd_log if e["phase"] == "primary"]
    assert primary_entries[0]["effective_argv"] == fake_effective
    assert primary_entries[0]["argv"] == [
        "apt-get",
        "install",
        "-y",
        "--allow-downgrades",
        "openssl=1.0",
    ]


def test_rollback_dispatch_password_mode_does_not_leak_sudo_password(
    db, admin_user, host_factory
):
    """Even when the wrapper would prepend ``sudo -S`` and pipe a
    sudo password, the password must not appear anywhere in the
    persisted evidence. Simulated by a fake dispatcher returning an
    effective_argv shaped like the password-mode wrap."""
    execution = _build_approved_rollback(
        db, admin_user, host_factory, slug="pra175s2-rb-pw"
    )
    run = patch_rollback_dispatch_service.start_rollback_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    fake_effective = [
        "sudo",
        "-S",
        "apt-get",
        "install",
        "-y",
        "--allow-downgrades",
        "openssl=1.0",
    ]

    def _fake_dispatcher(system, cmd):
        return DispatchResult(
            exit_code=0,
            transport_name="fake",
            effective_argv=list(fake_effective),
        )

    patch_rollback_dispatch_service.dispatch_next_batch(
        db, run.id, actor_user_id=admin_user.id, dispatch_callable=_fake_dispatcher
    )

    pkg_row = (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(PatchRollbackDispatchHostPackage.package_name == "openssl")
        .one()
    )
    host_row = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id == run.id)
        .one()
    )

    sentinel_password = "do-not-record-this-password"
    serialized = json.dumps(
        {
            "pkg_details": pkg_row.details,
            "host_error_details": host_row.error_details,
        },
        default=str,
    )
    assert sentinel_password not in serialized
    # And the effective argv carries sudo -S without any password
    # token concatenated onto it.
    assert pkg_row.details["effective_argv"] == fake_effective
    assert all("password" not in token for token in pkg_row.details["effective_argv"])


# ---------------------------------------------------------------------------
# Reboot dispatch — command_snapshot stays planned, effective_argv in
# dispatch_details
# ---------------------------------------------------------------------------


def _seed_scheduled_reboot_row(
    db, admin_user, host_factory
) -> Tuple[PatchUpdateExecution, PatchUpdateExecutionReboot]:
    host = host_factory()
    pol = PatchPolicy(
        slug="pra175s2-rb-pol",
        name="pra175s2-rb-pol",
        scope_kind="full",
        scope_packages=[],
        reboot_policy="always",
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
    db.add(pol)
    db.flush()
    plan = PatchUpdatePlan(
        policy_id=pol.id,
        name="plan-pra175s2-reboot",
        state=patch_update_plan_service.PLAN_STATE_APPROVED,
        policy_snapshot={"id": pol.id, "slug": pol.slug, "name": pol.name},
        ring_sequence_snapshot=[],
        request_snapshot={},
        block_reasons=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    plan_host = PatchUpdatePlanHost(
        plan_id=plan.id,
        system_id=host.id,
        system_hostname_snapshot=host.hostname,
        policy_resolution_kind="direct_host",
        ring_resolution_status="resolved",
        wave_index=0,
        content_profile_state="resolved",
        content_profile_id_snapshot=None,
        content_profile_conflict_snapshot=[],
        state="planned",
        block_reasons=[],
    )
    db.add(plan_host)
    db.flush()
    now = datetime.utcnow()
    execution = PatchUpdateExecution(
        plan_id=plan.id,
        state=patch_execution_service.EXECUTION_STATE_SUCCEEDED,
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
    db.add(execution)
    db.flush()
    exec_host = PatchUpdateExecutionHost(
        execution_id=execution.id,
        plan_host_id=plan_host.id,
        system_id_snapshot=host.id,
        system_hostname_snapshot=host.hostname,
        wave_index=0,
        state=patch_execution_service.EXECUTION_HOST_STATE_SUCCEEDED,
        selected_package_count=0,
        skip_reasons=[],
        error_details={},
    )
    db.add(exec_host)
    db.flush()
    row = PatchUpdateExecutionReboot(
        execution_id=execution.id,
        execution_host_id=exec_host.id,
        plan_id_snapshot=plan.id,
        system_id_snapshot=host.id,
        system_hostname_snapshot=host.hostname,
        wave_index=0,
        state=patch_reboot_service.REBOOT_STATE_SCHEDULED,
        reboot_policy_snapshot="always",
        decision_code="policy_always",
        scheduled_for_at=now,
    )
    db.add(row)
    db.flush()
    db.commit()
    return execution, row


def test_reboot_dispatch_persists_effective_argv_in_dispatch_details(
    db, admin_user, host_factory
):
    execution, row = _seed_scheduled_reboot_row(db, admin_user, host_factory)

    fake_effective = ["sudo", "-n", "systemctl", "reboot"]

    def _fake_dispatcher(system, cmd):
        return RebootDispatchResult(
            exit_signal_kind=EXIT_SIGNAL_EXIT_ZERO,
            exit_code=0,
            transport_name="fake-ssh",
            effective_argv=list(fake_effective),
        )

    dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )

    db.refresh(row)
    # Planned snapshot preserved.
    assert row.command_snapshot == "systemctl reboot"
    # Effective argv recorded alongside.
    assert row.dispatch_details["effective_argv"] == fake_effective


def test_reboot_dispatch_password_mode_does_not_leak_sudo_password(
    db, admin_user, host_factory
):
    execution, row = _seed_scheduled_reboot_row(db, admin_user, host_factory)

    fake_effective = ["sudo", "-S", "systemctl", "reboot"]
    sentinel = "uber-secret-reboot-pw"

    def _fake_dispatcher(system, cmd):
        return RebootDispatchResult(
            exit_signal_kind=EXIT_SIGNAL_EXIT_ZERO,
            exit_code=0,
            transport_name="fake-ssh",
            effective_argv=list(fake_effective),
        )

    dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )

    db.refresh(row)
    serialized = json.dumps(
        {
            "command_snapshot": row.command_snapshot,
            "dispatch_details": row.dispatch_details,
        },
        default=str,
    )
    assert sentinel not in serialized
    assert row.dispatch_details["effective_argv"] == fake_effective
    # Slice 1 lock: command_snapshot remains the planned argv even on
    # password mode.
    assert row.command_snapshot == "systemctl reboot"


def test_reboot_dispatch_records_none_effective_argv_for_fake_without_field(
    db, admin_user, host_factory
):
    """Backward-compat lock: a reboot dispatcher fake that omits
    ``effective_argv`` results in dispatch_details.effective_argv =
    None, never a crash."""
    execution, row = _seed_scheduled_reboot_row(db, admin_user, host_factory)

    def _fake_dispatcher(system, cmd):
        return RebootDispatchResult(
            exit_signal_kind=EXIT_SIGNAL_EXIT_ZERO,
            exit_code=0,
            transport_name="fake-ssh",
        )

    dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )

    db.refresh(row)
    assert row.dispatch_details["effective_argv"] is None


# ---------------------------------------------------------------------------
# Cross-cutting redaction guard
# ---------------------------------------------------------------------------


def test_wrap_argv_password_mode_never_includes_password_in_argv(
    db, cred_factory, stub_vault
):
    """Direct unit pin: ``wrap_argv_for_sudo`` for password mode must
    not put the sudo password anywhere in the returned argv (it
    travels via the stdin bytes only)."""
    cred = cred_factory(
        sudo_method=SUDO_METHOD_PASSWORD, vault_path="vault/pra175s2-leak"
    )
    sentinel = "do-not-leak-this"
    stub_vault({"vault/pra175s2-leak": {"sudo_password": sentinel}})
    argv, stdin = wrap_argv_for_sudo(db, cred, ["apt-get", "install", "-y", "openssl"])
    assert all(sentinel not in token for token in argv)
    assert stdin == (sentinel + "\n").encode("utf-8")
