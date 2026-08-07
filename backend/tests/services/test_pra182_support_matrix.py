"""PRA-182 Slice 1: pin the documented 1.0 Linux support matrix to code.

`docs/support-matrix.md` claims that the deb family (Ubuntu, Debian) and the
EL/dnf family (RHEL, Rocky, AlmaLinux) are the serviceable package-manager
families, and that zypper/pacman/apk are detect-only (resolve to the `unknown`
family and get refused as `unsupported_package_family`).

These assertions guard that claim against code drift: if someone changes the
family maps in ``patch_update_plan_service`` without updating the matrix, this
test fails. It exercises only the pure mapping helpers — no DB.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.patch_update_plan_service import (
    _DISTRO_TO_FAMILY,
    _PACKAGE_MANAGER_TO_FAMILY,
    PACKAGE_MANAGER_FAMILY_APT,
    PACKAGE_MANAGER_FAMILY_DNF,
    PACKAGE_MANAGER_FAMILY_UNKNOWN,
    _derive_package_manager_family,
)


@pytest.mark.parametrize(
    "package_manager, expected",
    [
        ("apt", PACKAGE_MANAGER_FAMILY_APT),
        ("apt-get", PACKAGE_MANAGER_FAMILY_APT),
        ("dpkg", PACKAGE_MANAGER_FAMILY_APT),
        ("dnf", PACKAGE_MANAGER_FAMILY_DNF),
        ("yum", PACKAGE_MANAGER_FAMILY_DNF),
        ("rpm", PACKAGE_MANAGER_FAMILY_DNF),
    ],
)
def test_serviceable_package_managers_map_to_documented_family(
    package_manager, expected
):
    assert _PACKAGE_MANAGER_TO_FAMILY[package_manager] == expected


@pytest.mark.parametrize("package_manager", ["zypper", "pacman", "apk"])
def test_detect_only_package_managers_are_not_serviceable(package_manager):
    """Matrix "Unsupported" tier: these resolve to `unknown`, which patch /
    rollback dispatch refuses as `unsupported_package_family`."""
    assert package_manager not in _PACKAGE_MANAGER_TO_FAMILY
    facts = SimpleNamespace(package_manager=package_manager, distro_id_facts=None)
    assert _derive_package_manager_family(facts) == PACKAGE_MANAGER_FAMILY_UNKNOWN


@pytest.mark.parametrize(
    "distro_id, expected",
    [
        # Supported tier
        ("ubuntu", PACKAGE_MANAGER_FAMILY_APT),
        ("debian", PACKAGE_MANAGER_FAMILY_APT),
        ("rhel", PACKAGE_MANAGER_FAMILY_DNF),
        ("rocky", PACKAGE_MANAGER_FAMILY_DNF),
        ("almalinux", PACKAGE_MANAGER_FAMILY_DNF),
    ],
)
def test_supported_distros_resolve_to_serviceable_family(distro_id, expected):
    """Every distro in the matrix "Supported" tier must fall back to a
    serviceable family when package_manager facts are absent."""
    assert _DISTRO_TO_FAMILY[distro_id] == expected
    facts = SimpleNamespace(package_manager=None, distro_id_facts=distro_id)
    assert _derive_package_manager_family(facts) == expected


def test_unknown_distro_and_pm_resolve_to_unknown():
    facts = SimpleNamespace(package_manager=None, distro_id_facts="gentoo")
    assert _derive_package_manager_family(facts) == PACKAGE_MANAGER_FAMILY_UNKNOWN
    assert _derive_package_manager_family(None) == PACKAGE_MANAGER_FAMILY_UNKNOWN


def test_package_manager_facts_win_over_distro_fallback():
    """If a host reports a serviceable PM, that wins over the distro
    fallback — mirrors the resolver's precedence."""
    facts = SimpleNamespace(package_manager="apt", distro_id_facts="rhel")
    assert _derive_package_manager_family(facts) == PACKAGE_MANAGER_FAMILY_APT
