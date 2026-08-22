"""PRA-395: DNF/YUM security-advisory parsing on RPM-family hosts.

Root cause: ``scan_security_updates`` ran ``dnf|yum updateinfo list security``
output through the ``check-update`` parser. The two formats share nothing --
``updateinfo`` emits ``advisory  severity/type  NEVRA`` -- so every row parsed
into an advisory id as the "package name", no inventory row matched, and RPM
hosts reported zero security updates however many advisories the host listed.

These tests pin the corrected contract:

- representative Rocky/RHEL/Alma output parses into package rows, keeping the
  advisory, type, severity, epoch, and architecture the output carried;
- the wider DNF5 table, whose type and severity are separate columns and whose
  rows end in an issued date, parses into the same rows;
- banners, mirror lists, plugin chatter, and trailer lines are ignored, while
  advisory rows that cannot be read are counted rather than dropped;
- a scan never reports a trustworthy zero when the host did list advisories;
- APT security parsing and ordinary RPM ``check-update`` parsing are unchanged.

The fixtures below are sanitized captures: real column layouts and NEVRA shapes
with substituted hostnames.
"""

from __future__ import annotations

from datetime import date, datetime
from unittest.mock import MagicMock

import pytest

from app.db.models import Credential, Distro, Group, Package, PackageUpdate, System
from app.services.package_service import PackageService

# ---------------------------------------------------------------- fixtures/data

# Rocky 9, ``dnf updateinfo list security``: metadata banner, one advisory
# fixing two packages, an epoch, a second architecture, and a noarch package.
ROCKY_DNF_SECURITY = """Last metadata expiration check: 0:23:41 ago on Tue 12 Aug 2026 08:14:02 PM UTC.
RLSA-2026:0512 Important/Sec.  bind-libs-9.16.23-18.el9_4.x86_64
RLSA-2026:0512 Important/Sec.  bind-utils-9.16.23-18.el9_4.x86_64
RLSA-2026:0687 Moderate/Sec.   krb5-libs-1.21.1-4.el9_4.x86_64
RLSA-2026:0721 Critical/Sec.   openssl-1:3.0.7-27.el9_4.x86_64
RLSA-2026:0721 Critical/Sec.   openssl-libs-1:3.0.7-27.el9_4.i686
RLSA-2026:0803 Low/Sec.        tzdata-2026a-1.el9.noarch
"""

# RHEL 7, ``yum updateinfo list security``: plugin banners, a mirror list whose
# entries look advisory-shaped, a severity-less advisory, and the trailer line.
RHEL_YUM_SECURITY = """Loaded plugins: fastestmirror, langpacks, product-id, subscription-manager
Loading mirror speeds from cached hostfile
 * base: mirror-1.example.net
 * updates: mirror-2.example.net
RHSA-2026:0198 Important/Sec. bash-4.2.46-35.el7_9.x86_64
RHSA-2026:0244 Sec.           glibc-2.17-326.el7_9.3.x86_64
RHSA-2026:0301 Moderate/Sec.  bind-libs-lite-32:9.11.4-26.P2.el7_9.15.x86_64
updateinfo list done
"""

# AlmaLinux 8: subscription banner, a blank line, a row carrying the installed
# state flag, the lowercase ``severity/type`` spelling, and a numeric-prefixed
# package name.
ALMA_DNF_SECURITY = """Updating Subscription Management repositories.
Last metadata expiration check: 1:02:11 ago on Wed 13 Aug 2026 09:00:00 AM UTC.

i ALSA-2026:1120 Important/Sec. kernel-4.18.0-553.el8_10.x86_64
ALSA-2026:1130 Moderate/Sec.   python3-libs-3.6.8-62.el8_10.aarch64
ALSA-2026:1131 important/security  systemd-239-82.el8_10.x86_64
ALSA-2026:1140 Low/Sec.        389-ds-base-2.1.3-1.el8_10.x86_64
"""

# DNF5 prints a wider table than DNF4: a header row, separate ``Type`` and
# ``Severity`` columns, and the issued date after the package.
DNF5_UPDATEINFO_SECURITY = """Updating and loading repositories:
Repositories loaded.
Name            Type     Severity  Package                                Issued
RLSA-2026:1180  security Important openssl-1:3.2.2-6.el10_0.x86_64        2026-07-14 09:12:03
RLSA-2026:1180  security Important openssl-libs-1:3.2.2-6.el10_0.x86_64   2026-07-14 09:12:03
RLSA-2026:1195  security Moderate  python3-libs-3.12.9-2.el10_0.aarch64   2026-07-21 11:40:55
RLSA-2026:1207  security Low       tzdata-2026b-1.el10.noarch             2026-08-03 06:05:00
"""

# Advisory rows truncated or corrupted in transit: recognizably advisories, but
# with no readable package.
MALFORMED_SECURITY = """RLSA-2026:0900 Important/Sec.
RLSA-2026:0901 Important/Sec. not-a-nevra
RLSA-2026:0902
"""

# A host with no applicable advisories still prints its metadata banner.
CLEAN_HOST_SECURITY = (
    "Last metadata expiration check: 0:04:19 ago on Wed 13 Aug 2026 "
    "09:31:44 AM UTC.\n"
)

DNF_CHECK_UPDATE = """Last metadata expiration check: 0:23:41 ago on Tue 12 Aug 2026 08:14:02 PM UTC.

krb5-libs.x86_64            1.21.1-4.el9_4      baseos
openssl.x86_64              1:3.0.7-27.el9_4    baseos
"""

APT_SECURITY = (
    "openssl/jammy-security 3.0.2-0ubuntu1.15 amd64 "
    "[upgradable from: 3.0.2-0ubuntu1.12]\n"
)


def _parsed_by_name(output):
    updates, unreadable = PackageService._parse_rpm_security_updates(output)
    return {upd["name"]: upd for upd in updates}, unreadable


# ------------------------------------------------------------- parsing contract


def test_rocky_dnf_output_parses_every_advisory_row():
    parsed, unreadable = _parsed_by_name(ROCKY_DNF_SECURITY)

    assert unreadable == 0
    assert set(parsed) == {
        "bind-libs",
        "bind-utils",
        "krb5-libs",
        "openssl",
        "openssl-libs",
        "tzdata",
    }
    assert parsed["bind-libs"]["available_version"] == "9.16.23-18.el9_4"
    assert parsed["bind-libs"]["advisory"] == "RLSA-2026:0512"
    assert parsed["bind-libs"]["severity"] == "Important"
    assert parsed["bind-libs"]["advisory_type"] == "Sec."
    assert parsed["bind-libs"]["type"] == "security"
    assert parsed["tzdata"]["arch"] == "noarch"
    assert parsed["openssl-libs"]["arch"] == "i686"


def test_epoch_is_kept_separate_from_the_stored_version():
    """The inventory stores ``version-release``, so the epoch must not leak in."""
    parsed, _ = _parsed_by_name(ROCKY_DNF_SECURITY)

    assert parsed["openssl"]["epoch"] == "1"
    assert parsed["openssl"]["available_version"] == "3.0.7-27.el9_4"


def test_rhel_yum_output_ignores_banners_mirrors_and_trailer():
    parsed, unreadable = _parsed_by_name(RHEL_YUM_SECURITY)

    assert unreadable == 0
    assert set(parsed) == {"bash", "glibc", "bind-libs-lite"}
    # A hyphenated name plus an epoch: only the last two hyphenated fields are
    # version and release.
    assert parsed["bind-libs-lite"]["epoch"] == "32"
    assert parsed["bind-libs-lite"]["available_version"] == "9.11.4-26.P2.el7_9.15"
    # "Sec." on its own is the advisory type and carries no severity.
    assert parsed["glibc"]["advisory_type"] == "Sec."
    assert parsed["glibc"]["severity"] == ""
    assert parsed["glibc"]["available_version"] == "2.17-326.el7_9.3"


def test_alma_output_handles_state_flag_blank_lines_and_lowercase_type():
    parsed, unreadable = _parsed_by_name(ALMA_DNF_SECURITY)

    assert unreadable == 0
    assert set(parsed) == {"kernel", "python3-libs", "systemd", "389-ds-base"}
    assert parsed["kernel"]["available_version"] == "4.18.0-553.el8_10"
    assert parsed["python3-libs"]["arch"] == "aarch64"
    assert parsed["systemd"]["advisory_type"] == "security"
    assert parsed["systemd"]["severity"] == "important"
    assert parsed["389-ds-base"]["available_version"] == "2.1.3-1.el8_10"


def test_dnf5_five_column_output_keeps_type_severity_and_package():
    """DNF5 splits type and severity apart and appends the issued date."""
    parsed, unreadable = _parsed_by_name(DNF5_UPDATEINFO_SECURITY)

    assert unreadable == 0
    # The header row, the loading banner, and the issued dates are not packages.
    assert set(parsed) == {"openssl", "openssl-libs", "python3-libs", "tzdata"}

    assert parsed["openssl"]["advisory"] == "RLSA-2026:1180"
    assert parsed["openssl"]["advisory_type"] == "security"
    assert parsed["openssl"]["severity"] == "Important"
    assert parsed["openssl"]["epoch"] == "1"
    assert parsed["openssl"]["available_version"] == "3.2.2-6.el10_0"
    assert parsed["openssl"]["arch"] == "x86_64"

    assert parsed["python3-libs"]["severity"] == "Moderate"
    assert parsed["python3-libs"]["arch"] == "aarch64"
    assert parsed["tzdata"]["severity"] == "Low"
    assert parsed["tzdata"]["available_version"] == "2026b-1.el10"


def test_unreadable_advisory_rows_are_counted_not_silently_dropped():
    updates, unreadable = PackageService._parse_rpm_security_updates(MALFORMED_SECURITY)

    assert updates == []
    assert unreadable == 3


def test_readable_rows_survive_alongside_unreadable_ones():
    parsed, unreadable = _parsed_by_name(
        ROCKY_DNF_SECURITY + "RLSA-2026:0904 Important/Sec.\n"
    )

    assert unreadable == 1
    assert "openssl" in parsed


@pytest.mark.parametrize("output", ["", "   \n\n", CLEAN_HOST_SECURITY])
def test_output_without_advisories_is_a_clean_zero(output):
    updates, unreadable = PackageService._parse_rpm_security_updates(output)

    assert updates == []
    assert unreadable == 0


def test_updateinfo_rows_are_unusable_for_the_check_update_parser(db):
    """The regression this fix removes: the old path produced no usable rows.

    Feeding ``updateinfo`` output to the ``check-update`` parser turns advisory
    ids into package names, which match nothing in the inventory, so a host with
    six advisories persisted zero security updates.
    """
    legacy = PackageService(db)._parse_available_updates(ROCKY_DNF_SECURITY, "dnf")
    legacy_names = {upd["name"] for upd in legacy}

    assert "openssl" not in legacy_names
    assert "RLSA-2026:0721" in legacy_names


# ------------------------------------------------------- adjacent parsers intact


def test_rpm_check_update_parsing_is_unchanged(db):
    updates = PackageService(db)._parse_available_updates(DNF_CHECK_UPDATE, "dnf")
    by_name = {upd["name"]: upd for upd in updates if upd["name"] != "Last"}

    assert by_name["krb5-libs"]["available_version"] == "1.21.1-4.el9_4"
    assert by_name["openssl"]["available_version"] == "3.0.7-27.el9_4"
    assert by_name["openssl"]["type"] == "normal"


def test_apt_update_parsing_is_unchanged(db):
    updates = PackageService(db)._parse_available_updates(APT_SECURITY, "apt")

    assert updates == [
        {
            "name": "openssl",
            "available_version": "3.0.2-0ubuntu1.15",
            "current_version": "3.0.2-0ubuntu1.12",
            "type": "security",
        }
    ]


# ------------------------------------------------------------------ scan/persist


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra395-grp").first()
    if not g:
        g = Group(name="pra395-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra395-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


@pytest.fixture
def rocky_distro(db):
    distro = db.query(Distro).filter_by(name="Rocky Linux", version="9.4").first()
    if not distro:
        distro = Distro(
            name="Rocky Linux",
            version="9.4",
            release_date=date(2024, 5, 9),
            end_of_life_date=date(2032, 5, 31),
        )
        db.add(distro)
        db.flush()
    return distro


def _system(db, distro, group, cred, hostname):
    system = System(
        hostname=hostname,
        ip_address="10.114.0.2",
        distro_id=distro.id,
        os_version="9.4",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(system)
    db.flush()
    return system


def _install(db, system, names, version="0.0.1-1"):
    for name in names:
        db.add(
            Package(
                system_id=system.id,
                name=name,
                installed_version=version,
                package_type="rpm",
                last_audited=datetime.utcnow(),
            )
        )
    db.flush()


def _scan(db, system, stdout):
    svc = PackageService(db)
    svc.ssh_service.execute_command = MagicMock(
        return_value={"status": "success", "stdout": stdout, "stderr": ""}
    )
    return svc.scan_security_updates(system.id)


def _stored(db, system):
    return {
        row.package.name: row
        for row in db.query(PackageUpdate)
        .filter(PackageUpdate.system_id == system.id)
        .all()
    }


def test_rpm_scan_persists_every_advisory(db, rocky_distro, group, cred):
    system = _system(db, rocky_distro, group, cred, "pra395-persist")
    _install(
        db,
        system,
        [
            "bind-libs",
            "bind-utils",
            "krb5-libs",
            "openssl",
            "openssl-libs",
            "tzdata",
        ],
    )

    result = _scan(db, system, ROCKY_DNF_SECURITY)

    assert result["status"] == "success"
    assert result["updates_available"] == 6

    stored = _stored(db, system)
    assert len(stored) == 6
    assert all(row.update_type == "security" for row in stored.values())
    assert stored["openssl"].available_version == "3.0.7-27.el9_4"
    assert stored["tzdata"].available_version == "2026a-1.el9"


def test_dnf5_scan_persists_every_advisory(db, rocky_distro, group, cred):
    system = _system(db, rocky_distro, group, cred, "pra395-dnf5")
    _install(db, system, ["openssl", "openssl-libs", "python3-libs", "tzdata"])

    result = _scan(db, system, DNF5_UPDATEINFO_SECURITY)

    assert result["status"] == "success"
    assert result["updates_available"] == 4

    stored = _stored(db, system)
    assert set(stored) == {"openssl", "openssl-libs", "python3-libs", "tzdata"}
    assert all(row.update_type == "security" for row in stored.values())
    assert stored["openssl"].available_version == "3.2.2-6.el10_0"
    assert stored["tzdata"].available_version == "2026b-1.el10"


def test_rpm_scan_promotes_an_existing_normal_update_row(db, rocky_distro, group, cred):
    system = _system(db, rocky_distro, group, cred, "pra395-promote")
    _install(db, system, ["openssl"])
    package = db.query(Package).filter_by(system_id=system.id, name="openssl").one()
    db.add(
        PackageUpdate(
            package_id=package.id,
            system_id=system.id,
            available_version="3.0.7-26.el9_4",
            update_type="normal",
            discovered_on=datetime.utcnow(),
        )
    )
    db.flush()

    result = _scan(
        db,
        system,
        "RLSA-2026:0721 Critical/Sec.   openssl-1:3.0.7-27.el9_4.x86_64\n",
    )

    assert result["status"] == "success"
    assert result["updates_available"] == 1

    stored = _stored(db, system)
    assert len(stored) == 1
    assert stored["openssl"].update_type == "security"
    assert stored["openssl"].available_version == "3.0.7-27.el9_4"


def test_rpm_scan_collapses_repeat_rows_for_one_package(db, rocky_distro, group, cred):
    """A package listed by several advisories or architectures stores one row."""
    system = _system(db, rocky_distro, group, cred, "pra395-repeat")
    _install(db, system, ["kernel"])

    result = _scan(
        db,
        system,
        "ALSA-2026:1120 Important/Sec. kernel-4.18.0-552.el8_10.x86_64\n"
        "ALSA-2026:1150 Critical/Sec.  kernel-4.18.0-553.el8_10.x86_64\n",
    )

    assert result["status"] == "success"
    assert result["updates_available"] == 1

    stored = _stored(db, system)
    assert len(stored) == 1
    # Last advisory row wins, matching the order the package manager printed.
    assert stored["kernel"].available_version == "4.18.0-553.el8_10"


def test_rpm_scan_refuses_to_report_zero_when_no_row_is_readable(
    db, rocky_distro, group, cred
):
    system = _system(db, rocky_distro, group, cred, "pra395-unreadable")
    _install(db, system, ["openssl"])

    result = _scan(db, system, MALFORMED_SECURITY)

    assert result["status"] == "error"
    assert "advisory line" in result["message"]
    assert result["updates_available"] == 0
    assert _stored(db, system) == {}


def test_rpm_scan_reports_packages_missing_from_the_inventory(
    db, rocky_distro, group, cred
):
    system = _system(db, rocky_distro, group, cred, "pra395-uninventoried")

    result = _scan(db, system, ROCKY_DNF_SECURITY)

    assert result["status"] == "error"
    assert "package inventory" in result["message"]
    assert result["updates_available"] == 0
    assert _stored(db, system) == {}


def test_rpm_scan_reports_a_clean_host_as_success(db, rocky_distro, group, cred):
    system = _system(db, rocky_distro, group, cred, "pra395-clean")
    _install(db, system, ["openssl"])

    result = _scan(db, system, CLEAN_HOST_SECURITY)

    assert result["status"] == "success"
    assert result["updates_available"] == 0
    assert _stored(db, system) == {}


def test_apt_security_scan_still_persists(db, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "pra395-apt")
    _install(db, system, ["openssl"])

    result = _scan(db, system, APT_SECURITY)

    assert result["status"] == "success"
    assert result["updates_available"] == 1

    stored = _stored(db, system)
    assert stored["openssl"].update_type == "security"
    assert stored["openssl"].available_version == "3.0.2-0ubuntu1.15"
