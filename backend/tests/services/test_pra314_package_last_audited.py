"""PRA-314: package inventory ``last_audited`` freshness after scans.

Root cause: a scan set ``System.last_audited`` but never stamped
``Package.last_audited``, so the Package Inventory UI (which renders
``pkg.last_audited``) showed ``Never`` right after a successful scan.

These tests drive ``PackageService.scan_packages()`` with a mocked SSH service and
assert the stamping contract:

- new rows get ``last_audited``;
- unchanged rows refresh ``last_audited`` WITHOUT inflating ``packages_updated``;
- changed-version rows refresh ``last_audited`` AND count as updated;
- a failed scan leaves prior package/system timestamps untouched.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.db.models import Credential, Group, Package, System
from app.services.package_service import PackageService

# --------------------------------------------------------------------- fixtures


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra314-grp").first()
    if not g:
        g = Group(name="pra314-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra314-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.114.0.1",
        distro_id=seed_distro.id,  # seed_distro is Ubuntu -> apt
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _apt_line(name: str, version: str) -> str:
    return f"{name}\t{version}\tinstall ok installed"


def _mock_ssh(svc, *, installed_ok=True, installed_stdout="", updates_stdout=""):
    """Replace the service's SSH execute_command so scan_packages() runs offline.

    ``list_installed`` returns ``installed_stdout`` (or a failure when
    ``installed_ok`` is False); ``check_updates`` returns ``updates_stdout``.
    """

    def _fake(system_id, command, timeout=None, user_id=None):
        if "dpkg-query" in command:  # apt list_installed
            if not installed_ok:
                return {"status": "error", "stdout": "", "stderr": "boom: unreachable"}
            return {"status": "success", "stdout": installed_stdout, "stderr": ""}
        # apt check_updates (and anything else) — empty, no updates.
        return {"status": "success", "stdout": updates_stdout, "stderr": ""}

    svc.ssh_service.execute_command = MagicMock(side_effect=_fake)


def _packages(db, system_id):
    return {
        p.name: p
        for p in db.query(Package).filter(Package.system_id == system_id).all()
    }


# --------------------------------------------------------------------- new rows


def test_new_rows_get_last_audited(db, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "pra314-new")
    svc = PackageService(db)
    _mock_ssh(
        svc,
        installed_stdout="\n".join(
            [_apt_line("bash", "5.1-6"), _apt_line("curl", "7.81-1")]
        ),
    )

    res = svc.scan_packages(system.id)
    assert res["status"] == "success"
    assert res["packages_added"] == 2
    assert res["packages_updated"] == 0

    pkgs = _packages(db, system.id)
    assert set(pkgs) == {"bash", "curl"}
    for p in pkgs.values():
        assert p.last_audited is not None
        # Same timestamp as the system + the returned scanned_at.
        assert p.last_audited == system.last_audited
    assert res["scanned_at"] == system.last_audited.isoformat()


# ---------------------------------------------------------------- unchanged rows


def test_unchanged_rows_refresh_without_count_inflation(db, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "pra314-unchanged")
    stale = datetime.utcnow() - timedelta(days=30)
    db.add(
        Package(
            system_id=system.id,
            name="bash",
            installed_version="5.1-6",
            package_type="deb",
            last_audited=stale,
            created_at=stale,
            updated_at=stale,
        )
    )
    db.flush()

    svc = PackageService(db)
    _mock_ssh(svc, installed_stdout=_apt_line("bash", "5.1-6"))  # same version

    res = svc.scan_packages(system.id)
    assert res["status"] == "success"
    assert res["packages_added"] == 0
    # A mere freshness refresh must NOT be counted as an update.
    assert res["packages_updated"] == 0

    pkg = _packages(db, system.id)["bash"]
    assert pkg.last_audited > stale
    assert pkg.last_audited == system.last_audited
    assert pkg.installed_version == "5.1-6"


# ----------------------------------------------------------------- changed rows


def test_changed_rows_refresh_and_count(db, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "pra314-changed")
    stale = datetime.utcnow() - timedelta(days=30)
    db.add(
        Package(
            system_id=system.id,
            name="bash",
            installed_version="5.1-6",
            package_type="deb",
            last_audited=stale,
            created_at=stale,
            updated_at=stale,
        )
    )
    db.flush()

    svc = PackageService(db)
    _mock_ssh(svc, installed_stdout=_apt_line("bash", "5.2-1"))  # version changed

    res = svc.scan_packages(system.id)
    assert res["status"] == "success"
    assert res["packages_updated"] == 1

    pkg = _packages(db, system.id)["bash"]
    assert pkg.installed_version == "5.2-1"
    assert pkg.last_audited > stale
    assert pkg.last_audited == system.last_audited


# ------------------------------------------------------------------ failed scan


def test_failed_scan_leaves_timestamps_untouched(db, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "pra314-failed")
    stale = datetime.utcnow() - timedelta(days=30)
    system.last_audited = stale
    db.add(
        Package(
            system_id=system.id,
            name="bash",
            installed_version="5.1-6",
            package_type="deb",
            last_audited=stale,
            created_at=stale,
            updated_at=stale,
        )
    )
    db.flush()

    svc = PackageService(db)
    _mock_ssh(svc, installed_ok=False)  # SSH scan fails

    res = svc.scan_packages(system.id)
    assert res["status"] == "error"

    pkg = _packages(db, system.id)["bash"]
    # Neither the package row nor the system freshness moved.
    assert pkg.last_audited == stale
    assert system.last_audited == stale
