"""PRA-405: direct package updates report the host's reboot state.

A direct package update is not governed by the patch-plan reboot queue, so
its response is the only place its operator learns that the update left the
host one reboot behind. These tests cover both mutation paths (ordinary and
security) for a positive, negative, unsupported, and failed observation, and
assert the probe never runs when nothing was mutated.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

import pytest

from app.db.models import Credential, Group, Package, PackageUpdate, System
from app.services import reboot_evidence_service
from app.services.package_service import PackageService

UPDATE_OK = {"status": "success", "exit_code": 0, "stdout": "done", "stderr": ""}


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="pra405-manual-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra405-manual-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def host(db, seed_distro, static_group, credentials) -> System:
    s = System(
        hostname="pra405-manual-1.example.com",
        ip_address="10.0.98.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.flush()
    return s


def _seed_update(db, host: System, name: str = "openssl") -> Package:
    pkg = Package(
        system_id=host.id,
        name=name,
        installed_version="1.0",
        package_type="apt",
    )
    db.add(pkg)
    db.flush()
    db.add(
        PackageUpdate(
            package_id=pkg.id,
            system_id=host.id,
            available_version="1.1",
            update_type="security",
            discovered_on=datetime.utcnow(),
        )
    )
    db.flush()
    return pkg


class _FakeSSH:
    """Answers the update command and the reboot probe distinctly.

    ``probe_result`` is what ``execute_privileged_command`` returns for the
    reboot probe; every other command is a successful update.
    """

    def __init__(self, probe_result: Dict[str, Any]):
        self.probe_result = probe_result
        self.commands: List[str] = []

    def execute_privileged_command(
        self, system_id: int, command: str, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        self.commands.append(command)
        if "PRAXIS_REBOOT_PROBE" in command:
            return self.probe_result
        return dict(UPDATE_OK)

    def close_all_connections(self) -> None:  # pragma: no cover - not exercised
        pass

    @property
    def probe_commands(self) -> List[str]:
        return [c for c in self.commands if "PRAXIS_REBOOT_PROBE" in c]


def _service(
    db, monkeypatch, probe_result: Dict[str, Any], *, versions_change: bool = True
):
    """A PackageService whose SSH layer is a fake and whose post-update
    rescan is simulated, so the test exercises the reboot-status contract
    rather than the package scanner.

    ``versions_change`` models what the real rescan would find. With it set,
    the rescan advances each package's installed version to the available
    one, which is what makes the service's post-update verification count a
    package as actually updated. With it clear, the package-manager command
    still exits zero but no installed version moves, which is the case where
    nothing was really mutated.
    """
    service = PackageService(db)
    ssh = _FakeSSH(probe_result)
    service.ssh_service = ssh

    def _rescan(self, system_id):
        if versions_change:
            for upd in (
                db.query(PackageUpdate)
                .filter(PackageUpdate.system_id == system_id)
                .all()
            ):
                upd.package.installed_version = upd.available_version
            db.flush()
        return {"status": "success"}

    monkeypatch.setattr(PackageService, "scan_packages", _rescan)
    return service, ssh


PROBE_POSITIVE = {
    "status": "success",
    "exit_code": 0,
    "stdout": "PRAXIS_REBOOT_PROBE=true",
    "stderr": "",
}
PROBE_NEGATIVE = {
    "status": "success",
    "exit_code": 0,
    "stdout": "PRAXIS_REBOOT_PROBE=false",
    "stderr": "",
}
PROBE_UNSUPPORTED = {
    "status": "success",
    "exit_code": 0,
    "stdout": "PRAXIS_REBOOT_PROBE=unsupported",
    "stderr": "",
}
PROBE_FAILED = {
    "status": "warning",
    "exit_code": 127,
    "stdout": "",
    "stderr": "sh: needs-restarting: not found",
}
PROBE_TIMEOUT = {
    "status": "failed",
    "outcome": "command_timeout",
    "timed_out": True,
    "exit_code": None,
    "stdout": "",
    "stderr": "timed out",
}


# ---------------------------------------------------------------------------
# Ordinary package updates
# ---------------------------------------------------------------------------


def test_update_reports_a_required_reboot(db, admin_user, host, monkeypatch):
    _seed_update(db, host)
    service, ssh = _service(db, monkeypatch, PROBE_POSITIVE)

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["status"] == "success"
    assert result["packages_updated"] == 1
    assert result["reboot_required"] is True
    assert result["reboot_evidence"]["outcome"] == "success"
    assert result["reboot_evidence"]["source"] == "debian_reboot_required_marker"
    assert result["reboot_evidence"]["collected_at"].endswith("Z")
    assert len(ssh.probe_commands) == 1


def test_update_reports_no_reboot_needed(db, admin_user, host, monkeypatch):
    _seed_update(db, host)
    service, _ = _service(db, monkeypatch, PROBE_NEGATIVE)

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["packages_updated"] == 1
    assert result["reboot_required"] is False
    assert result["reboot_evidence"]["outcome"] == "success"


@pytest.mark.parametrize(
    "probe,expected_outcome",
    [
        (PROBE_UNSUPPORTED, reboot_evidence_service.OUTCOME_UNSUPPORTED),
        (PROBE_FAILED, reboot_evidence_service.OUTCOME_PROBE_FAILED),
        (PROBE_TIMEOUT, reboot_evidence_service.OUTCOME_TIMEOUT),
    ],
)
def test_update_reports_an_unknown_reboot_state_not_a_negative(
    db, admin_user, host, monkeypatch, probe, expected_outcome
):
    """An unsupported or failed probe must not report that no reboot is
    needed. The update still succeeded; only the reboot answer is missing."""
    _seed_update(db, host)
    service, _ = _service(db, monkeypatch, probe)

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["status"] == "success"
    assert result["packages_updated"] == 1
    assert result["reboot_required"] is None
    assert result["reboot_evidence"]["outcome"] == expected_outcome
    assert result["reboot_evidence"]["value"] is None


def test_a_probe_that_raises_does_not_fail_the_update(
    db, admin_user, host, monkeypatch
):
    _seed_update(db, host)
    service, _ = _service(db, monkeypatch, PROBE_NEGATIVE)

    def _boom(*args, **kwargs):
        raise RuntimeError("ssh exploded")

    monkeypatch.setattr(reboot_evidence_service, "collect_over_ssh", _boom)

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["status"] == "success"
    assert result["packages_updated"] == 1
    assert result["reboot_required"] is None
    assert (
        result["reboot_evidence"]["outcome"]
        == reboot_evidence_service.OUTCOME_TRANSPORT_ERROR
    )


def test_probe_detail_from_a_failing_host_is_redacted(
    db, admin_user, host, monkeypatch
):
    _seed_update(db, host)
    leaky = {
        "status": "warning",
        "exit_code": 1,
        "stdout": "",
        "stderr": "auth failed for password=hunter2trombone",
    }
    service, _ = _service(db, monkeypatch, leaky)

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["packages_updated"] == 1
    assert "hunter2trombone" not in str(result["reboot_evidence"])
    assert result["reboot_evidence"]["outcome"] == "probe_failed"


def test_a_failed_update_is_not_probed(db, admin_user, host, monkeypatch):
    """No mutation happened, so there is nothing to observe."""
    _seed_update(db, host)
    service, ssh = _service(db, monkeypatch, PROBE_POSITIVE)

    def _failing(system_id, command, timeout=None):
        ssh.commands.append(command)
        return {"status": "failed", "exit_code": 1, "stdout": "", "stderr": "boom"}

    ssh.execute_privileged_command = _failing

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["status"] == "error"
    assert "reboot_required" not in result
    assert ssh.probe_commands == []


def test_a_no_op_update_is_not_probed(db, admin_user, host, monkeypatch):
    """Every requested package was held, so nothing was mutated."""
    pkg = _seed_update(db, host)
    pkg.is_held = True
    db.flush()
    service, ssh = _service(db, monkeypatch, PROBE_POSITIVE)

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["status"] == "success"
    assert result["packages_updated"] == 0
    assert "reboot_required" not in result
    assert ssh.probe_commands == []


def test_the_probe_runs_after_the_update_command(db, admin_user, host, monkeypatch):
    _seed_update(db, host)
    service, ssh = _service(db, monkeypatch, PROBE_NEGATIVE)

    service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    probe_index = next(
        i for i, c in enumerate(ssh.commands) if "PRAXIS_REBOOT_PROBE" in c
    )
    assert probe_index > 0, "the observation must describe the post-update host"


# ---------------------------------------------------------------------------
# Security updates
# ---------------------------------------------------------------------------


def test_security_update_reports_a_required_reboot(db, admin_user, host, monkeypatch):
    _seed_update(db, host)
    service, ssh = _service(db, monkeypatch, PROBE_POSITIVE)

    result = service.apply_security_updates(host.id, user_id=admin_user.id)

    assert result["status"] == "success"
    assert result["packages_updated"] == 1
    assert result["reboot_required"] is True
    assert result["reboot_evidence"]["outcome"] == "success"
    assert len(ssh.probe_commands) == 1


def test_security_update_reports_no_reboot_needed(db, admin_user, host, monkeypatch):
    _seed_update(db, host)
    service, _ = _service(db, monkeypatch, PROBE_NEGATIVE)

    result = service.apply_security_updates(host.id, user_id=admin_user.id)

    assert result["packages_updated"] == 1
    assert result["reboot_required"] is False


@pytest.mark.parametrize(
    "probe,expected_outcome",
    [
        (PROBE_UNSUPPORTED, reboot_evidence_service.OUTCOME_UNSUPPORTED),
        (PROBE_FAILED, reboot_evidence_service.OUTCOME_PROBE_FAILED),
    ],
)
def test_security_update_reports_unknown_not_negative(
    db, admin_user, host, monkeypatch, probe, expected_outcome
):
    _seed_update(db, host)
    service, _ = _service(db, monkeypatch, probe)

    result = service.apply_security_updates(host.id, user_id=admin_user.id)

    assert result["packages_updated"] == 1
    assert result["reboot_required"] is None
    assert result["reboot_evidence"]["outcome"] == expected_outcome


def test_security_update_with_nothing_to_apply_is_not_probed(
    db, admin_user, host, monkeypatch
):
    service, ssh = _service(db, monkeypatch, PROBE_POSITIVE)

    result = service.apply_security_updates(host.id, user_id=admin_user.id)

    assert result["status"] == "success"
    assert "reboot_required" not in result
    assert ssh.probe_commands == []


# ---------------------------------------------------------------------------
# The direct path stays outside the governed reboot queue
# ---------------------------------------------------------------------------


def test_direct_update_creates_no_reboot_queue_row(db, admin_user, host, monkeypatch):
    from app.db.models import PatchUpdateExecutionReboot

    _seed_update(db, host)
    service, _ = _service(db, monkeypatch, PROBE_POSITIVE)
    before = db.query(PatchUpdateExecutionReboot).count()

    service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert db.query(PatchUpdateExecutionReboot).count() == before


# ---------------------------------------------------------------------------
# A command that exited zero but changed nothing
#
# The package manager can succeed without moving a single installed version
# (a repository that no longer carries the candidate, a package pinned by
# something outside Praxis). Nothing was mutated, so there is no new reboot
# answer to report and no reason to spend a round-trip asking for one.
# ---------------------------------------------------------------------------


def test_update_with_zero_verified_changes_is_not_probed(
    db, admin_user, host, monkeypatch
):
    _seed_update(db, host)
    service, ssh = _service(db, monkeypatch, PROBE_POSITIVE, versions_change=False)

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["status"] == "success"
    assert result["packages_updated"] == 0
    assert "reboot_required" not in result
    assert "reboot_evidence" not in result
    assert ssh.probe_commands == []
    # The update command itself still ran; only the probe was skipped.
    assert any("PRAXIS_REBOOT_PROBE" not in c for c in ssh.commands)


def test_security_update_with_zero_verified_changes_is_not_probed(
    db, admin_user, host, monkeypatch
):
    _seed_update(db, host)
    service, ssh = _service(db, monkeypatch, PROBE_POSITIVE, versions_change=False)

    result = service.apply_security_updates(host.id, user_id=admin_user.id)

    assert result["status"] == "success"
    assert result["packages_updated"] == 0
    assert "reboot_required" not in result
    assert "reboot_evidence" not in result
    assert ssh.probe_commands == []


def test_zero_verified_changes_keeps_the_rest_of_the_response(
    db, admin_user, host, monkeypatch
):
    """Omitting the reboot fields must not disturb the existing contract."""
    _seed_update(db, host)
    service, _ = _service(db, monkeypatch, PROBE_POSITIVE, versions_change=False)

    result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert result["system_id"] == host.id
    assert result["hostname"] == host.hostname
    assert result["status"] == "success"
    assert result["packages_skipped"] == 0
    assert result["applied_at"]


def test_a_partially_applied_update_is_probed(db, admin_user, host, monkeypatch):
    """One package moved and one did not. Something changed, so the host is
    still asked whether it needs a reboot."""
    _seed_update(db, host, name="openssl")
    stuck = _seed_update(db, host, name="curl")
    service, ssh = _service(db, monkeypatch, PROBE_POSITIVE)

    real_rescan = PackageService.scan_packages

    def _partial(self, system_id):
        real_rescan(self, system_id)
        # Roll one package back to where it started.
        stuck.installed_version = "1.0"
        db.flush()
        return {"status": "success"}

    monkeypatch.setattr(PackageService, "scan_packages", _partial)

    result = service.apply_updates(host.id, ["openssl", "curl"], user_id=admin_user.id)

    assert result["packages_updated"] == 1
    assert result["reboot_required"] is True
    assert len(ssh.probe_commands) == 1


# ---------------------------------------------------------------------------
# Log path
# ---------------------------------------------------------------------------


@contextmanager
def capturing_warnings(caplog, *loggers):
    """Capture WARNING records from the given module loggers.

    Running migrations configures logging through ``logging.config.fileConfig``,
    which disables every logger that already exists, so a module logger is
    inert for the rest of the session unless a test re-enables it.
    """
    previous = [(lg, lg.disabled) for lg in loggers]
    for lg, _ in previous:
        lg.disabled = False
    try:
        with caplog.at_level(logging.WARNING):
            yield
    finally:
        for lg, was_disabled in previous:
            lg.disabled = was_disabled


def test_a_raised_probe_is_not_logged_verbatim(
    db, admin_user, host, monkeypatch, caplog
):
    import app.services.package_service as package_service_module

    _seed_update(db, host)
    service, _ = _service(db, monkeypatch, PROBE_NEGATIVE)

    class _LeakyError(RuntimeError):
        pass

    def _boom(*args, **kwargs):
        raise _LeakyError(
            "ssh failed password=hunter2trombone "
            "postgresql://praxis:sup3rs3cr3t@db:5432/praxis"
        )

    monkeypatch.setattr(reboot_evidence_service, "collect_over_ssh", _boom)

    with capturing_warnings(caplog, package_service_module.logger):
        result = service.apply_updates(host.id, ["openssl"], user_id=admin_user.id)

    assert caplog.records, "the failure must still be logged"
    # Nothing of the exception text reaches the log, not even its shape.
    for sentinel in ("sup3rs3cr3t", "hunter2trombone", "postgresql://"):
        assert sentinel not in caplog.text
    # The response keeps a redacted diagnostic: the credential is gone, the
    # host and scheme survive so an operator can still read the failure.
    for secret in ("sup3rs3cr3t", "hunter2trombone"):
        assert secret not in str(result)
    assert "_LeakyError" in caplog.text
    # The update itself still succeeded and reported an unknown reboot state.
    assert result["status"] == "success"
    assert result["reboot_required"] is None
