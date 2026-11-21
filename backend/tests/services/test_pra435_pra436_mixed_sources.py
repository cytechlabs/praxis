"""PRA-435 with PRA-436: mixed enabled/disabled sources, failed refresh, recovery.

One native APT source tree is read two ways: APT refreshes it (the freshness
contract) and the repository inventory parser lists it (the repository view).
The two must agree on which sources are active. A deb822 source flagged
``Enabled: no`` is never fetched, so it cannot degrade a refresh and the
repository view lists it as disabled; flipping it on makes APT fail on it, and
the freshness detail and the repository view name the same source.

The tree mixes a one-line ``.list`` file, deb822 ``.sources`` files and a
commented one-line entry, and its files have no trailing newline.
"""

import os
import re
import subprocess

from app.db.models import Credential, Group, System
from app.services import security_scan_status_service as provenance
from app.services.package_service import (
    APT_FAILED,
    APT_FRESH,
    APT_PARTIAL,
    PackageService,
)
from app.services.repo_service import RepoService, apt_list_repos_command
from tests.helpers.native_apt import NativeApt, NativeSSH, needs_apt


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)  # deliberately no trailing newline


def _tree(apt, *, enterprise_enabled, removed_listed):
    d = f"{apt.root}/etc/sources.list.d"
    for name in os.listdir(d):
        os.remove(f"{d}/{name}")
    _write(
        f"{apt.root}/etc/sources.list",
        (
            f"deb [trusted=yes] file:{apt.root}/good ./\n"
            f"# deb [trusted=yes] http://127.0.0.1:{apt.missing.server_port}/old trixie main"
            if not removed_listed
            else f"deb [trusted=yes] file:{apt.root}/good ./\n"
            f"deb [trusted=yes] http://127.0.0.1:{apt.missing.server_port}/old trixie main"
        ),
    )
    _write(
        f"{d}/20-security.sources",
        f"Types: deb\nURIs: file:{apt.root}/sec\nSuites: ./\nTrusted: yes",
    )
    _write(
        f"{d}/30-enterprise.sources",
        f"Types: deb\nURIs: http://127.0.0.1:{apt.unauthorized.server_port}/ent\n"
        "Suites: trixie\nComponents: main\n"
        f"Enabled: {'yes' if enterprise_enabled else 'no'}\nTrusted: yes",
    )


def _repo_view(apt):
    listing = subprocess.run(
        ["sh", "-c", apt_list_repos_command(f"{apt.root}/etc")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    active, disabled = RepoService.__new__(RepoService)._parse_apt_inventory(listing)

    def urls(entries):
        return {e["url"].rstrip("/") for e in entries}

    return urls(active), urls(disabled)


def _host(db, seed_distro):
    cred = Credential(name="pra435-mix-cred", auth_method="ssh_key", username="root")
    group = Group(name="pra435-mix-group", description="x")
    db.add_all([cred, group])
    db.flush()
    system = System(
        hostname="pra435-mix-host",
        ip_address="10.45.0.1",
        distro_id=seed_distro.id,
        os_version=seed_distro.version,
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(system)
    db.commit()
    return system


@needs_apt
def test_disabled_sources_agree_between_refresh_and_repository_view(db, seed_distro):
    apt = NativeApt()
    try:
        system = _host(db, seed_distro)
        service = PackageService(db)
        service.ssh_service = NativeSSH(apt)
        enterprise = f"http://127.0.0.1:{apt.unauthorized.server_port}/ent"

        # Active/disabled mix, nothing failing: the disabled enterprise source
        # is neither fetched nor listed as active, and the refresh is verified.
        _tree(apt, enterprise_enabled=False, removed_listed=False)
        active, disabled = _repo_view(apt)
        assert enterprise in disabled and enterprise not in active
        clean = service.scan_packages(system.id)
        assert clean["apt_metadata"]["state"] == APT_FRESH, clean
        assert clean["scan_state"] == provenance.STATE_COMPLETE
        known = clean["updates_available"]
        assert known == 2

        # Enable it: the repository view now lists it as active, the refresh
        # fails on exactly that source, and last-known updates survive.
        _tree(apt, enterprise_enabled=True, removed_listed=False)
        active, disabled = _repo_view(apt)
        assert enterprise in active and enterprise not in disabled
        failed = service.scan_packages(system.id)
        assert failed["apt_metadata"]["state"] == APT_PARTIAL, failed
        port = str(apt.unauthorized.server_port)
        assert port in failed["apt_metadata"]["detail"]
        assert "401" in failed["apt_metadata"]["detail"]
        assert failed["updates_available"] == known
        assert failed["status"] == "success"

        # A second failing source, removed (404), is reported with the first.
        _tree(apt, enterprise_enabled=True, removed_listed=True)
        both = service.scan_packages(system.id)
        detail = both["apt_metadata"]["detail"]
        assert re.search(r"2 source\(s\) failed", detail), detail

        # Recovery: disable the failing sources again, refresh, verified.
        _tree(apt, enterprise_enabled=False, removed_listed=False)
        recovered = service.scan_packages(system.id)
        assert recovered["apt_metadata"]["state"] == APT_FRESH, recovered
        assert recovered["scan_state"] == provenance.STATE_COMPLETE
        assert recovered["updates_available"] == known
        assert service.scan_security_updates(system.id)["scan_state"] == (
            provenance.STATE_COMPLETE
        )
    finally:
        apt.close()


@needs_apt
def test_every_source_disabled_is_unverified_not_a_clean_zero(db, seed_distro):
    apt = NativeApt()
    try:
        system = _host(db, seed_distro)
        service = PackageService(db)
        service.ssh_service = NativeSSH(apt)
        d = f"{apt.root}/etc/sources.list.d"
        _write(f"{apt.root}/etc/sources.list", "")
        _write(
            f"{d}/30-enterprise.sources",
            "Types: deb\nURIs: http://127.0.0.1:1/x\nSuites: trixie\n"
            "Components: main\nEnabled: no",
        )
        active, disabled = _repo_view(apt)
        assert not active and disabled
        summary = service.scan_packages(system.id)
        assert summary["apt_metadata"]["state"] == APT_FAILED, summary
        assert summary["scan_state"] == provenance.STATE_PARTIAL
    finally:
        apt.close()
