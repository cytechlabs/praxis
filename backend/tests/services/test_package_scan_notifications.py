"""Characterization of the package and security scan notifications and summaries.

Pins the notification type, title, message and severity that a package scan and
a security scan emit, and the summary fields that depend on whether the APT
metadata was verified, so the scan orchestration can be restructured without
changing what operators are told.
"""

import pytest

from app.db.models import Credential, Group, System
from app.services import package_service as package_module
from app.services.package_service import APT_CACHED, APT_FRESH, PackageService

CLEAN = (
    "Hit:1 http://deb.debian.org/debian trixie InRelease\n" "Reading package lists...\n"
)
INSTALLED = "openssl\t3.0.1\tinstall ok installed\ncurl\t7.0\tinstall ok installed\n"
LISTING = (
    "Listing...\n"
    "openssl/trixie-security 3.0.2 amd64 [upgradable from: 3.0.1]\n"
    "curl/trixie 7.1 amd64 [upgradable from: 7.0]\n"
)


class _SSH:
    def __init__(self, listing=LISTING):
        self.listing = listing

    def _run(self, command):
        ok = {"status": "success", "stderr": "", "exit_code": 0}
        if "apt-get update" in command:
            return {**ok, "stdout": CLEAN}
        if command.startswith("dpkg-query"):
            return {**ok, "stdout": INSTALLED}
        if "apt list" in command:
            return {**ok, "stdout": self.listing}
        raise AssertionError(f"unexpected command: {command}")

    def execute_command(self, system_id, command, timeout=None, user_id=None):
        return self._run(command)

    execute_privileged_command = execute_command


@pytest.fixture
def notices(monkeypatch):
    from app.services import notification_service

    sent = []
    monkeypatch.setattr(
        notification_service,
        "create_notification",
        lambda db, **kwargs: sent.append(kwargs),
    )
    return sent


@pytest.fixture
def service_and_system(db, seed_distro):
    cred = Credential(name="scan-notice-cred", auth_method="ssh_key", username="root")
    group = Group(name="scan-notice-group", description="x")
    db.add_all([cred, group])
    db.flush()
    system = System(
        hostname="scan-notice-host",
        ip_address="10.70.0.1",
        distro_id=seed_distro.id,
        os_version=seed_distro.version,
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(system)
    db.commit()
    service = PackageService(db)
    service.ssh_service = _SSH()
    return service, system


def test_verified_package_scan_notifies_info(service_and_system, notices):
    service, system = service_and_system
    summary = service.scan_packages(system.id)
    assert summary["apt_metadata"]["state"] == APT_FRESH
    assert summary["scan_state"] == package_module.STATE_COMPLETE
    assert summary["evidence_incomplete"] is False
    assert "message" not in summary
    assert notices == [
        {
            "type": "package_scan_complete",
            "title": "Package scan complete: scan-notice-host",
            "message": "Found 2 packages, 2 updates available",
            "severity": "info",
        }
    ]


def test_cached_package_scan_notifies_warning_and_keeps_candidates(
    service_and_system, notices
):
    service, system = service_and_system
    service.scan_packages(system.id)
    notices.clear()
    summary = service.scan_packages(system.id, refresh=False)
    assert summary["apt_metadata"]["state"] == APT_CACHED
    assert summary["scan_state"] == package_module.STATE_PARTIAL
    assert summary["updates_available"] == 2
    assert summary["message"].startswith(
        "Inventory scanned. Showing last-known updates; the APT metadata is cached "
        "and did not replace them."
    )
    assert notices == [
        {
            "type": "package_scan_complete",
            "title": "Package scan complete: scan-notice-host",
            "message": (
                "Found 2 packages, 2 updates available"
                " (unverified: APT metadata was not refreshed)"
            ),
            "severity": "warning",
        }
    ]


def test_security_scan_notifies_and_reports_verified_summary(
    service_and_system, notices
):
    service, system = service_and_system
    service.scan_packages(system.id)
    notices.clear()
    summary = service.scan_security_updates(system.id)
    assert summary["status"] == "success"
    assert summary["scan_state"] == package_module.STATE_COMPLETE
    assert summary["updates_available"] == 1
    assert summary["unreadable_advisories"] == 0
    assert summary["unmatched_packages"] == []
    assert summary["evidence_incomplete"] is False
    assert "message" not in summary
    assert notices == [
        {
            "type": "security_updates",
            "title": "Security updates available: scan-notice-host",
            "message": "1 security update(s) found",
            "severity": "warning",
        }
    ]


def test_cached_security_scan_is_partial_with_unverified_message(
    service_and_system, notices
):
    service, system = service_and_system
    service.scan_packages(system.id)
    summary = service.scan_security_updates(system.id, refresh=False)
    assert summary["scan_state"] == package_module.STATE_PARTIAL
    assert summary["message"].startswith(
        "Security scan stored 1 update(s) from cached APT metadata; the count is "
        "not verified."
    )


def test_security_scan_without_a_package_scan_reports_unmatched(
    service_and_system, notices
):
    service, system = service_and_system
    summary = service.scan_security_updates(system.id)
    assert summary["status"] == "error"
    assert summary["scan_state"] == package_module.STATE_FAILED
    assert summary["unmatched_packages"] == ["openssl"]
    assert "run a package scan first" in summary["message"]
    assert notices == []
