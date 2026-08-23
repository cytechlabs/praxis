"""PRA-396 - Debian and RPM package version ordering.

Covers:

* Table-driven ordering fixtures harvested from the supported
  distributions (Ubuntu, Debian, RHEL/Rocky/AlmaLinux). Every expected
  ordering in these tables was confirmed against the real tools:
  ``dpkg --compare-versions`` on debian:12-slim and ubuntu:24.04, and
  ``rpm.labelCompare`` on rockylinux:9 and almalinux:9.
* Epoch, revision/release, distro suffix, Debian ``~`` and ``+really``,
  and RPM ``~`` / ``^`` ordering.
* Equal, greater, and lower comparisons, plus antisymmetry across the
  whole fixture set.
* Malformed versions and unsupported package families raising rather
  than silently ordering.
* Proof that PEP 440 (the implementation this replaced) misorders or
  rejects the representative cases.
"""

from __future__ import annotations

import pytest
from packaging.version import InvalidVersion
from packaging.version import Version as Pep440Version

from app.services.package_version_compare import (
    SCHEME_DEB,
    SCHEME_RPM,
    VALID_SCHEMES,
    InvalidPackageVersion,
    UnsupportedVersionScheme,
    compare_deb_versions,
    compare_rpm_versions,
    compare_versions,
    is_valid_version,
    parse_deb_version,
    parse_rpm_version,
    scheme_for_package_family,
    version_at_least,
)

# ---------------------------------------------------------------------------
# Ordering fixtures: (lower, higher) pairs, strictly ascending.
# ---------------------------------------------------------------------------

DEB_ASCENDING = [
    # Numeric revision segments are numbers, not text: 9 < 15.
    ("3.0.2-0ubuntu1.9", "3.0.2-0ubuntu1.15"),
    # openssl across an Ubuntu LTS boundary.
    ("1.1.1f-1ubuntu2.16", "3.0.2-0ubuntu1.15"),
    # An upstream letter release is newer than the bare version.
    ("1.1.1", "1.1.1f-1ubuntu2.16"),
    # An epoch outranks any upstream version.
    ("2.43.0-1ubuntu7.1", "1:2.34.1-1ubuntu1.11"),
    ("1:9.0.1378-2", "2:8.2.3995-1ubuntu2.15"),
    ("2.39.3-9ubuntu6.5", "1:2.39.3-9ubuntu6.5"),
    ("9.0p1-1ubuntu8.7", "1:9.6p1-3ubuntu13.5"),
    # xz-utils after the 2024 backdoor: +really is a downgrade in
    # content but still orders above the version it replaces.
    ("5.6.1-1", "5.6.1+really5.4.5-1ubuntu0.3"),
    ("5.4.5-0.3", "5.6.1+really5.4.5-1ubuntu0.3"),
    ("5.6.1+really5.4.5-1ubuntu0.3", "5.6.2-1"),
    ("1:1.2.11.dfsg-2ubuntu9.2", "1:1.3.dfsg-3.1ubuntu2.1"),
    ("2023c-0ubuntu0.22.04.1", "2024a-0ubuntu0.22.04.1"),
    ("7.81.0-1ubuntu1.16", "8.5.0-2ubuntu10.6"),
    ("249.11-0ubuntu3.12", "255.4-1ubuntu8.4"),
    ("1.9.9-1ubuntu2.4", "1.9.15p5-3ubuntu5"),
    ("5.1-6ubuntu1.1", "5.2.21-2ubuntu4"),
    # A distro suffix on the revision is newer than the bare revision.
    ("1.10.3-2", "1.10.3-2ubuntu0.1"),
    # ``~`` sorts before everything, including the end of the string.
    ("1.0-1~deb12u1", "1.0-1"),
    ("1.0-1~bpo12+1", "1.0-1"),
    ("1.0~rc1", "1.0"),
    ("1.0~rc1", "1.0~rc2"),
    ("1.0~rc1~git123", "1.0~rc1"),
    # A missing revision sorts below any revision.
    ("1.0", "1.0-1"),
]

DEB_EQUAL = [
    ("0:1.0-1", "1.0-1"),
    # Leading zeros inside a numeric segment do not change its value.
    ("1.010-1", "1.10-1"),
    ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.4"),
]

RPM_ASCENDING = [
    # Release ordering, including the numeric-not-textual rule.
    ("3.0.7-24.el9", "3.0.7-27.el9"),
    ("0.17-9.el9", "0.17-85.el9"),
    ("1.9.5p2-9.el9", "1.9.5p2-10.el9_3"),
    ("3.9.18-1.el9_4", "3.9.18-3.el9_4.1"),
    ("2.34-83.el9_3.7", "2.34-100.el9_4.2"),
    ("5.14.0-427.13.1.el9_4", "5.14.0-427.28.1.el9_4"),
    ("5.14.0-427.28.1.el9_4", "5.14.0-503.11.1.el9_5"),
    # A z-stream respin is newer than the base release.
    ("4.18.0-553.el8_10", "4.18.0-553.5.1.el8_10"),
    # Version ordering.
    ("3.0.7-27.el9", "3.2.2-6.el9"),
    ("8.0.1763-19.el9_1", "9.0.2120-1.el9"),
    ("2.4.6-97.el9", "2.4.62-1.el9"),
    ("1.1.1", "1.1.1b"),
    # Epoch outranks version and release alike.
    ("1:3.0.7-27.el9", "2:3.0.7-27.el9"),
    ("3.0.7-27.el9", "1:3.0.7-24.el9"),
    # ``~`` sorts before, ``^`` sorts after the bare base version.
    ("1.0~rc1", "1.0"),
    ("1.0~rc1", "1.0~rc2"),
    ("1.0", "1.0^git1"),
    ("1.0^", "1.0^git1"),
    ("1.0^git1~pre", "1.0^git1"),
    # A missing release sorts below any release.
    ("1.0", "1.0-1"),
]

RPM_EQUAL = [
    ("0:1.0-1", "1.0-1"),
    ("1.0001-1", "1.1-1"),
    ("3.0.7-27.el9", "3.0.7-27.el9"),
]


# ---------------------------------------------------------------------------
# Family -> scheme selection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "family,expected",
    [
        ("apt", SCHEME_DEB),
        ("APT", SCHEME_DEB),
        (" apt-get ", SCHEME_DEB),
        ("dpkg", SCHEME_DEB),
        ("deb", SCHEME_DEB),
        ("debian", SCHEME_DEB),
        ("dnf", SCHEME_RPM),
        ("yum", SCHEME_RPM),
        ("rpm", SCHEME_RPM),
        ("unknown", None),
        # Families the product does not support must not be guessed at.
        ("zypper", None),
        ("apk", None),
        ("pacman", None),
        ("", None),
        (None, None),
    ],
)
def test_scheme_for_package_family(family, expected):
    assert scheme_for_package_family(family) == expected


def test_valid_schemes_vocabulary():
    assert VALID_SCHEMES == {SCHEME_DEB, SCHEME_RPM}


# ---------------------------------------------------------------------------
# Debian ordering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("lower,higher", DEB_ASCENDING)
def test_deb_ordering_ascending(lower, higher):
    assert compare_deb_versions(lower, higher) == -1
    assert compare_deb_versions(higher, lower) == 1
    assert version_at_least(SCHEME_DEB, higher, lower) is True
    assert version_at_least(SCHEME_DEB, lower, higher) is False


@pytest.mark.parametrize("left,right", DEB_EQUAL)
def test_deb_ordering_equal(left, right):
    assert compare_deb_versions(left, right) == 0
    assert compare_deb_versions(right, left) == 0
    assert version_at_least(SCHEME_DEB, left, right) is True
    assert version_at_least(SCHEME_DEB, right, left) is True


def test_deb_version_is_reflexive_across_fixtures():
    for lower, higher in DEB_ASCENDING:
        assert compare_deb_versions(lower, lower) == 0
        assert compare_deb_versions(higher, higher) == 0


@pytest.mark.parametrize(
    "value,epoch,upstream,revision",
    [
        ("1:2.39.3-9ubuntu6.5", 1, "2.39.3", "9ubuntu6.5"),
        ("2.39.3-9ubuntu6.5", 0, "2.39.3", "9ubuntu6.5"),
        ("1.0", 0, "1.0", ""),
        ("5.6.1+really5.4.5-1ubuntu0.3", 0, "5.6.1+really5.4.5", "1ubuntu0.3"),
        # The revision splits on the LAST hyphen.
        ("1.0-1-2", 0, "1.0-1", "2"),
        # A colon inside the upstream version is legal once an epoch exists.
        ("1:1.2:3-1", 1, "1.2:3", "1"),
        ("  1.0-1  ", 0, "1.0", "1"),
    ],
)
def test_parse_deb_version(value, epoch, upstream, revision):
    parsed = parse_deb_version(value)
    assert (parsed.epoch, parsed.upstream, parsed.revision) == (
        epoch,
        upstream,
        revision,
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        # Upstream version must start with a digit.
        "not-a-version",
        "abc",
        # A colon without a numeric epoch is not an epoch.
        "foo:1.0",
        "-1:1.0",
        # Empty upstream or revision.
        "-1",
        "1.0-",
        ":1.0",
        # Characters outside the grammar.
        "1.0 beta-1",
        "1.0_1-1",
        "1.0-1_2",
        # A colon in the upstream version without an epoch.
        "1.0:2-1",
    ],
)
def test_parse_deb_version_rejects_malformed(value):
    with pytest.raises(InvalidPackageVersion):
        parse_deb_version(value)
    assert is_valid_version(SCHEME_DEB, value) is False


# ---------------------------------------------------------------------------
# RPM ordering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("lower,higher", RPM_ASCENDING)
def test_rpm_ordering_ascending(lower, higher):
    assert compare_rpm_versions(lower, higher) == -1
    assert compare_rpm_versions(higher, lower) == 1
    assert version_at_least(SCHEME_RPM, higher, lower) is True
    assert version_at_least(SCHEME_RPM, lower, higher) is False


@pytest.mark.parametrize("left,right", RPM_EQUAL)
def test_rpm_ordering_equal(left, right):
    assert compare_rpm_versions(left, right) == 0
    assert compare_rpm_versions(right, left) == 0
    assert version_at_least(SCHEME_RPM, left, right) is True
    assert version_at_least(SCHEME_RPM, right, left) is True


def test_rpm_version_is_reflexive_across_fixtures():
    for lower, higher in RPM_ASCENDING:
        assert compare_rpm_versions(lower, lower) == 0
        assert compare_rpm_versions(higher, higher) == 0


@pytest.mark.parametrize(
    "value,epoch,version,release",
    [
        ("1:3.0.7-27.el9", 1, "3.0.7", "27.el9"),
        ("3.0.7-27.el9", 0, "3.0.7", "27.el9"),
        # The collector records VERSION-RELEASE without an epoch.
        ("2.34-100.el9_4.2", 0, "2.34", "100.el9_4.2"),
        # A bare version carries no release at all.
        ("3.0.7", 0, "3.0.7", None),
        ("  1.0-1  ", 0, "1.0", "1"),
    ],
)
def test_parse_rpm_version(value, epoch, version, release):
    parsed = parse_rpm_version(value)
    assert (parsed.epoch, parsed.version, parsed.release) == (epoch, version, release)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "a:1.0-1",
        "-1:1.0",
        ":1.0",
        "1.0-",
        "-1",
        "1.0 beta-1",
        "1.0:2-1",
        "1.0/2-1",
    ],
)
def test_parse_rpm_version_rejects_malformed(value):
    with pytest.raises(InvalidPackageVersion):
        parse_rpm_version(value)
    assert is_valid_version(SCHEME_RPM, value) is False


# ---------------------------------------------------------------------------
# Scheme dispatch
# ---------------------------------------------------------------------------


def test_compare_versions_dispatches_by_scheme():
    assert compare_versions(SCHEME_DEB, "1.0~rc1", "1.0") == -1
    assert compare_versions(SCHEME_RPM, "1.0~rc1", "1.0") == -1
    # ``^`` is an RPM separator only; under Debian rules it is a plain
    # character that sorts after every letter.
    assert compare_versions(SCHEME_RPM, "1.0^git1", "1.0") == 1


@pytest.mark.parametrize("scheme", ["", "unknown", "apk", "pacman", None])
def test_unsupported_scheme_raises(scheme):
    with pytest.raises(UnsupportedVersionScheme):
        compare_versions(scheme, "1.0", "1.0")
    with pytest.raises(UnsupportedVersionScheme):
        version_at_least(scheme, "1.0", "1.0")
    with pytest.raises(UnsupportedVersionScheme):
        is_valid_version(scheme, "1.0")


def test_version_at_least_is_inclusive():
    assert version_at_least(SCHEME_DEB, "1:2.39.3-9ubuntu6.5", "1:2.39.3-9ubuntu6.5")
    assert version_at_least(SCHEME_RPM, "3.0.7-27.el9", "3.0.7-27.el9")


def test_comparison_never_shells_out(monkeypatch):
    """No version string may reach a subprocess."""
    import subprocess

    def _explode(*args, **kwargs):  # pragma: no cover - only runs on regression
        raise AssertionError("version comparison must not spawn a process")

    for name in ("run", "Popen", "check_output", "call", "check_call"):
        monkeypatch.setattr(subprocess, name, _explode)
    monkeypatch.setattr("os.system", _explode)

    # Ordinary comparisons stay entirely in-process.
    assert compare_versions(SCHEME_DEB, "1:2.39.3-9ubuntu6.5", "1.0") == 1
    assert compare_versions(SCHEME_RPM, "3.0.7-27.el9", "3.0.7-24.el9") == 1


@pytest.mark.parametrize(
    "scheme,value",
    [
        (SCHEME_DEB, "1.0; rm -rf /"),
        (SCHEME_DEB, "1.0 && id"),
        (SCHEME_DEB, "$(id)-1"),
        (SCHEME_DEB, "1.0`id`-1"),
        (SCHEME_DEB, "1.0|id"),
        (SCHEME_RPM, "1.0; rm -rf /"),
        (SCHEME_RPM, "1.0 && id"),
        (SCHEME_RPM, "$(id)-1"),
        (SCHEME_RPM, "1.0`id`-1"),
        (SCHEME_RPM, "1.0|id"),
    ],
)
def test_shell_metacharacters_are_malformed_versions(scheme, value):
    """Shell syntax is not a version, and is refused as malformed rather
    than ordered against anything."""
    assert is_valid_version(scheme, value) is False
    with pytest.raises(InvalidPackageVersion):
        compare_versions(scheme, value, "1.0")


# ---------------------------------------------------------------------------
# The defect this replaced: PEP 440 cannot order distro versions.
# ---------------------------------------------------------------------------


def _pep440_compare(left, right):
    """-1/0/1 under PEP 440, or ``None`` when PEP 440 cannot parse."""
    try:
        parsed_l = Pep440Version(left)
        parsed_r = Pep440Version(right)
    except InvalidVersion:
        return None
    if parsed_l < parsed_r:
        return -1
    if parsed_l > parsed_r:
        return 1
    return 0


@pytest.mark.parametrize(
    "scheme,observed,minimum",
    [
        # An upstream letter release. PEP 440 reads the trailing ``b``
        # as a beta marker and orders 1.1.1b BELOW 1.1.1, so a host
        # running openssl 1.1.1b fails a ">= 1.1.1" check.
        (SCHEME_DEB, "1.1.1b", "1.1.1"),
        (SCHEME_RPM, "1.1.1b", "1.1.1"),
        # xz-utils +really. PEP 440 treats the suffix as a local version
        # and the ``-1`` on the right as a post-release, inverting the
        # order dpkg gives.
        (SCHEME_DEB, "5.6.1+really5.4.5-1ubuntu0.3", "5.6.1-1"),
    ],
)
def test_pep440_misorders_real_distro_versions(scheme, observed, minimum):
    pep440 = _pep440_compare(observed, minimum)
    assert pep440 is not None, "case must PARSE under PEP 440 to prove misordering"
    assert pep440 == -1

    # The distro's own ordering says the opposite.
    assert compare_versions(scheme, observed, minimum) == 1
    assert version_at_least(scheme, observed, minimum) is True


@pytest.mark.parametrize(
    "scheme,value",
    [
        (SCHEME_DEB, "1:2.39.3-9ubuntu6.5"),
        (SCHEME_DEB, "1.10.3-2ubuntu0.1"),
        (SCHEME_DEB, "2:8.2.3995-1ubuntu2.15"),
        (SCHEME_DEB, "1.0~rc1"),
        (SCHEME_RPM, "0.17-85.el9"),
        (SCHEME_RPM, "3.0.7-27.el9"),
        (SCHEME_RPM, "5.14.0-427.28.1.el9_4"),
    ],
)
def test_pep440_rejects_versions_the_distro_schemes_accept(scheme, value):
    with pytest.raises(InvalidVersion):
        Pep440Version(value)
    assert is_valid_version(scheme, value) is True
