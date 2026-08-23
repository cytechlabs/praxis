"""PRA-396 - package_version_min evaluates under the host's package family.

Covers:

* Debian-family hosts ordering epochs, Ubuntu revisions, ``~`` and
  ``+really`` forms; RPM-family hosts ordering full EVR.
* Family selection from host facts (``package_manager``, then
  ``distro_id_facts``), falling back to the inventory row's recorded
  ``package_type``.
* The same version pair producing family-appropriate verdicts on a
  Debian host and an RPM host, proving the family drives the semantics.
* Structured errors for an unsupported family, a malformed installed
  version, and a malformed configured minimum. No PEP 440 fallback.
* Write-time definition validation: an RPM minimum carrying ``^`` is
  accepted and evaluated, while shell and control characters are not.
* Observed and expected strings preserved exactly in the evidence row.
* Regression cover for the versions the PEP 440 implementation rejected
  or ordered backwards.
"""

from __future__ import annotations

import itertools
from datetime import datetime

import pytest

from app.db.models import (
    CompliancePolicyEvidence,
    Credential,
    Group,
    HostFacts,
    Package,
    System,
)
from app.services import compliance_evaluation_service, compliance_service
from app.services.compliance_evaluation_service import (
    REASON_MIN_VERSION_UNPARSEABLE,
    REASON_PACKAGE_NOT_INSTALLED,
    REASON_UNSUPPORTED_PACKAGE_FAMILY,
    REASON_VERSION_MISMATCH,
    REASON_VERSION_UNPARSEABLE,
    VERDICT_ERROR,
    VERDICT_FAIL,
    VERDICT_PASS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def make_host(db, seed_distro):
    """Build an evaluable host. Returns a factory so one test can hold
    a Debian-family and an RPM-family host at the same time."""
    counter = {"n": 0}

    def _make(hostname_suffix="a"):
        counter["n"] += 1
        n = counter["n"]
        group = Group(name=f"pra396-eval-{n}", description="x")
        db.add(group)
        db.flush()
        cred = Credential(
            name=f"pra396-cred-{n}", auth_method="ssh_key", username="root"
        )
        db.add(cred)
        db.flush()
        row = System(
            hostname=f"pra396-{hostname_suffix}-{n}.example.com",
            ip_address=f"10.0.96.{n}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=cred.id,
        )
        db.add(row)
        db.flush()
        return row

    return _make


def _set_facts(db, system_id, **fields):
    row = HostFacts(
        system_id=system_id,
        schema_version=1,
        collected_at=datetime.utcnow(),
        source_transport="agent",
        **fields,
    )
    db.add(row)
    db.flush()
    return row


def _install(db, system_id, name, version, package_type="deb"):
    pkg = Package(
        system_id=system_id,
        name=name,
        installed_version=version,
        package_type=package_type,
    )
    db.add(pkg)
    db.flush()
    return pkg


_SLUG_COUNTER = itertools.count(1)


def _evaluate(db, admin_user, system_id, *, package, min_version):
    slug = f"pra396-{next(_SLUG_COUNTER)}"
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug.upper(),
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"{slug}-check",
        title=f"{package} minimum",
        kind="package_version_min",
        definition={"package": package, "min_version": min_version},
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=system_id
    )
    rows = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == system_id,
        )
        .order_by(CompliancePolicyEvidence.id.asc())
        .all()
    )
    assert len(rows) == 1
    return rows[0]


# ---------------------------------------------------------------------------
# Debian-family hosts
# ---------------------------------------------------------------------------


DEB_PASS_CASES = [
    # (installed, min_version)
    ("1:2.39.3-9ubuntu6.5", "2.39.3"),
    ("1:2.39.3-9ubuntu6.5", "1:2.39.3"),
    ("1.10.3-2ubuntu0.1", "1.10.3-2"),
    ("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.9"),
    ("2:8.2.3995-1ubuntu2.15", "1:9.0.1378-2"),
    # An upstream letter release is above the bare version.
    ("1.1.1f-1ubuntu2.16", "1.1.1"),
    # +really still orders above the version it replaced.
    ("5.6.1+really5.4.5-1ubuntu0.3", "5.6.1-1"),
    ("255.4-1ubuntu8.4", "249.11-0ubuntu3.12"),
    # Equal versions satisfy a minimum.
    ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.4"),
]

DEB_FAIL_CASES = [
    ("2.39.3-9ubuntu6.5", "1:2.39.3-9ubuntu6.5"),
    ("3.0.2-0ubuntu1.9", "3.0.2-0ubuntu1.15"),
    ("1.1.1f-1ubuntu2.16", "3.0.2-0ubuntu1.15"),
    # A ~ pre-release does not satisfy the release it precedes.
    ("1.0~rc1", "1.0"),
    ("1.0-1~deb12u1", "1.0-1"),
    ("5.6.1+really5.4.5-1ubuntu0.3", "5.6.2"),
    ("1.10.3-2", "1.10.3-2ubuntu0.1"),
]


@pytest.mark.parametrize("installed,minimum", DEB_PASS_CASES)
def test_deb_host_passes(db, admin_user, make_host, installed, minimum):
    host = make_host("deb")
    _set_facts(db, host.id, package_manager="apt", distro_id_facts="ubuntu")
    _install(db, host.id, "target-pkg", installed)
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version=minimum,
    )
    assert row.verdict == VERDICT_PASS
    assert row.observed_value == installed
    assert row.expected_value == f">= {minimum}"


@pytest.mark.parametrize("installed,minimum", DEB_FAIL_CASES)
def test_deb_host_fails_below_minimum(db, admin_user, make_host, installed, minimum):
    host = make_host("deb")
    _set_facts(db, host.id, package_manager="apt", distro_id_facts="ubuntu")
    _install(db, host.id, "target-pkg", installed)
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version=minimum,
    )
    assert row.verdict == VERDICT_FAIL
    assert row.verdict_reason == REASON_VERSION_MISMATCH
    assert row.observed_value == installed
    assert row.expected_value == f">= {minimum}"


# ---------------------------------------------------------------------------
# RPM-family hosts
# ---------------------------------------------------------------------------


RPM_PASS_CASES = [
    ("3.0.7-27.el9", "3.0.7-24.el9"),
    # ``^`` marks a post-release snapshot and sorts ABOVE the base
    # version, the mirror image of ``~``.
    ("1.0^git1", "1.0"),
    ("1.0^git2", "1.0^git1"),
    ("1.0^git1", "1.0~rc1"),
    ("2.4.0^20240101gitabcdef-1.el9", "2.4.0-1.el9"),
    ("2.4.0^20240202gitbbbbbb-1.el9", "2.4.0^20240101gitabcdef-1.el9"),
    ("0.17-85.el9", "0.17-9.el9"),
    ("2.34-100.el9_4.2", "2.34-83.el9_3.7"),
    ("5.14.0-427.28.1.el9_4", "5.14.0-427.13.1.el9_4"),
    ("4.18.0-553.5.1.el8_10", "4.18.0-553.el8_10"),
    ("1:3.0.7-24.el9", "3.0.7-27.el9"),
    ("1.1.1b", "1.1.1"),
    # The collector records VERSION-RELEASE; a bare minimum still works.
    ("3.9.18-3.el9_4.1", "3.9.18"),
    ("3.0.7-27.el9", "3.0.7-27.el9"),
]

RPM_FAIL_CASES = [
    ("3.0.7-24.el9", "3.0.7-27.el9"),
    ("0.17-9.el9", "0.17-85.el9"),
    ("3.0.7-27.el9", "1:3.0.7-24.el9"),
    ("2.4.6-97.el9", "2.4.62-1.el9"),
    ("1.0~rc1", "1.0"),
    ("3.9.18-1.el9_4", "3.9.18-3.el9_4.1"),
    # The base version does not satisfy a post-release snapshot minimum.
    ("1.0", "1.0^git1"),
    ("1.0^git1", "1.0^git2"),
    ("2.4.0-1.el9", "2.4.0^20240101gitabcdef-1.el9"),
]


@pytest.mark.parametrize("installed,minimum", RPM_PASS_CASES)
def test_rpm_host_passes(db, admin_user, make_host, installed, minimum):
    host = make_host("rpm")
    _set_facts(db, host.id, package_manager="dnf", distro_id_facts="rocky")
    _install(db, host.id, "target-pkg", installed, package_type="rpm")
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version=minimum,
    )
    assert row.verdict == VERDICT_PASS
    assert row.observed_value == installed
    assert row.expected_value == f">= {minimum}"


@pytest.mark.parametrize("installed,minimum", RPM_FAIL_CASES)
def test_rpm_host_fails_below_minimum(db, admin_user, make_host, installed, minimum):
    host = make_host("rpm")
    _set_facts(db, host.id, package_manager="dnf", distro_id_facts="rocky")
    _install(db, host.id, "target-pkg", installed, package_type="rpm")
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version=minimum,
    )
    assert row.verdict == VERDICT_FAIL
    assert row.verdict_reason == REASON_VERSION_MISMATCH


# ---------------------------------------------------------------------------
# The family, not the version string, selects the semantics
# ---------------------------------------------------------------------------


def test_same_versions_differ_by_host_family(db, admin_user, make_host):
    """``1.0+1`` sits below ``1.0.1`` under dpkg, because ``+`` sorts
    below ``.``; under rpm both are separators and the two are equal.
    Identical inputs, different verdicts, decided by the host family.
    """
    deb_host = make_host("deb")
    _set_facts(db, deb_host.id, package_manager="apt", distro_id_facts="ubuntu")
    _install(db, deb_host.id, "target-pkg", "1.0+1")

    rpm_host = make_host("rpm")
    _set_facts(db, rpm_host.id, package_manager="dnf", distro_id_facts="rocky")
    _install(db, rpm_host.id, "target-pkg", "1.0+1", package_type="rpm")

    deb_row = _evaluate(
        db,
        admin_user,
        deb_host.id,
        package="target-pkg",
        min_version="1.0.1",
    )
    rpm_row = _evaluate(
        db,
        admin_user,
        rpm_host.id,
        package="target-pkg",
        min_version="1.0.1",
    )

    assert deb_row.verdict == VERDICT_FAIL
    assert deb_row.verdict_reason == REASON_VERSION_MISMATCH
    assert rpm_row.verdict == VERDICT_PASS
    # Evidence still records the operator-visible strings verbatim.
    assert deb_row.observed_value == rpm_row.observed_value == "1.0+1"
    assert deb_row.expected_value == rpm_row.expected_value == ">= 1.0.1"


# ---------------------------------------------------------------------------
# Family resolution sources
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "facts,package_type,expected_verdict",
    [
        # package_manager is preferred.
        ({"package_manager": "dpkg"}, "deb", VERDICT_FAIL),
        ({"package_manager": "yum"}, "rpm", VERDICT_PASS),
        # distro_id_facts is the fallback within host facts.
        ({"distro_id_facts": "debian"}, "deb", VERDICT_FAIL),
        ({"distro_id_facts": "almalinux"}, "rpm", VERDICT_PASS),
        # Host facts that identify nothing fall through to the
        # inventory row's own recorded package type.
        ({"distro_id_facts": "plan9"}, "deb", VERDICT_FAIL),
        ({"distro_id_facts": "plan9"}, "rpm", VERDICT_PASS),
    ],
)
def test_family_resolution_sources(
    db, admin_user, make_host, facts, package_type, expected_verdict
):
    """``1.0+1`` vs ``1.0.1`` splits deb (below, so fail) from rpm
    (equal, so pass), so the verdict reports which family was
    actually selected."""
    host = make_host("src")
    _set_facts(db, host.id, **facts)
    _install(db, host.id, "target-pkg", "1.0+1", package_type=package_type)
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version="1.0.1",
    )
    assert row.verdict == expected_verdict


def test_family_resolves_from_inventory_when_no_host_facts(db, admin_user, make_host):
    """A host with no facts row still evaluates when the inventory row
    records the package type the collector read it with."""
    host = make_host("nofacts")
    _install(db, host.id, "target-pkg", "1:2.39.3-9ubuntu6.5", package_type="deb")
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version="2.39.3",
    )
    assert row.verdict == VERDICT_PASS
    assert row.observed_value == "1:2.39.3-9ubuntu6.5"


# ---------------------------------------------------------------------------
# Structured errors, with no PEP 440 fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package_type", [None, "", "apk", "pacman", "unknown"])
def test_unsupported_family_is_a_structured_error(
    db, admin_user, make_host, package_type
):
    host = make_host("unsup")
    _set_facts(db, host.id, distro_id_facts="plan9", package_manager="pkg_add")
    _install(db, host.id, "target-pkg", "3.0.2", package_type=package_type)
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version="1.0",
    )
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_UNSUPPORTED_PACKAGE_FAMILY
    # PEP 440 would happily have ordered "3.0.2" against "1.0".
    assert row.observed_value == "3.0.2"
    assert row.expected_value == ">= 1.0"


@pytest.mark.parametrize(
    "family,package_type,installed",
    [
        ("apt", "deb", "not-a-version"),
        ("apt", "deb", "1.0_1"),
        ("apt", "deb", "1.0-"),
        ("dnf", "rpm", "a:1.0-1"),
        ("dnf", "rpm", "1.0 beta-1"),
    ],
)
def test_malformed_installed_version_is_a_structured_error(
    db, admin_user, make_host, family, package_type, installed
):
    host = make_host("badver")
    _set_facts(db, host.id, package_manager=family)
    _install(db, host.id, "target-pkg", installed, package_type=package_type)
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version="1.0",
    )
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_VERSION_UNPARSEABLE
    assert row.observed_value == installed


@pytest.mark.parametrize(
    "family,package_type,minimum",
    [
        ("apt", "deb", "not-a-version"),
        ("apt", "deb", "abc"),
        ("apt", "deb", "1.0_1"),
        ("dnf", "rpm", "a:1.0-1"),
    ],
)
def test_malformed_minimum_version_is_a_distinct_error(
    db, admin_user, make_host, family, package_type, minimum
):
    """A bad configured minimum is the operator's mistake, not the
    host's, and reports separately from an unreadable installed
    version."""
    host = make_host("badmin")
    _set_facts(db, host.id, package_manager=family)
    _install(db, host.id, "target-pkg", "1.0-1", package_type=package_type)
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version=minimum,
    )
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_MIN_VERSION_UNPARSEABLE
    assert row.observed_value == "1.0-1"
    assert row.expected_value == f">= {minimum}"


def test_family_is_resolved_only_for_installed_packages(db, admin_user, make_host):
    """A missing package still reports package_not_installed, without
    needing a resolvable family."""
    host = make_host("absent")
    _set_facts(db, host.id, distro_id_facts="plan9")
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version="1.0",
    )
    assert row.verdict == VERDICT_FAIL
    assert row.verdict_reason == REASON_PACKAGE_NOT_INSTALLED
    assert row.observed_value == "absent"


# ---------------------------------------------------------------------------
# Regression: versions the PEP 440 implementation could not handle
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "family,package_type,installed,minimum",
    [
        # Rejected outright by PEP 440 (epoch, Ubuntu revision, ~, EVR).
        ("apt", "deb", "1:2.39.3-9ubuntu6.5", "1:2.39.3-9ubuntu6.4"),
        ("apt", "deb", "1.10.3-2ubuntu0.1", "1.10.3-2"),
        ("apt", "deb", "2:8.2.3995-1ubuntu2.15", "2:8.2.3995-1ubuntu2.14"),
        ("dnf", "rpm", "0.17-85.el9", "0.17-9.el9"),
        ("dnf", "rpm", "5.14.0-427.28.1.el9_4", "5.14.0-427.13.1.el9_4"),
        # Parsed by PEP 440 but ordered backwards: 1.1.1b reads as a beta
        # of 1.1.1, and +really reads as a local version below a post
        # release. Both are above the minimum for dpkg and rpm.
        ("apt", "deb", "1.1.1b", "1.1.1"),
        ("dnf", "rpm", "1.1.1b", "1.1.1"),
        ("apt", "deb", "5.6.1+really5.4.5-1ubuntu0.3", "5.6.1-1"),
    ],
)
def test_versions_pep440_could_not_order_now_pass(
    db, admin_user, make_host, family, package_type, installed, minimum
):
    host = make_host("pep440")
    _set_facts(db, host.id, package_manager=family)
    _install(db, host.id, "target-pkg", installed, package_type=package_type)
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version=minimum,
    )
    assert row.verdict == VERDICT_PASS
    assert row.observed_value == installed
    assert row.expected_value == f">= {minimum}"


# ---------------------------------------------------------------------------
# Write-time definition validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "minimum",
    [
        # RPM post-release snapshots. These are the forms the comparator
        # orders with ``^`` and that an operator must be able to configure.
        "1.0^git1",
        "2.4.0^20240101gitabcdef-1.el9",
        "1.0^",
        "1.0~rc1^git1",
        # The separators that were already accepted stay accepted.
        "1:2.39.3-9ubuntu6.5",
        "5.6.1+really5.4.5-1ubuntu0.3",
        "1.0~rc1",
        "3.9.18-1.el9_4",
    ],
)
def test_definition_accepts_distro_minimum(minimum):
    normalized = compliance_service.validate_definition(
        "package_version_min", {"package": "target-pkg", "min_version": minimum}
    )
    assert normalized["min_version"] == minimum


@pytest.mark.parametrize(
    "minimum",
    [
        # Shell metacharacters and command substitution.
        "1.0; rm -rf /",
        "1.0 && id",
        "1.0|id",
        "1.0`id`",
        "$(id)",
        "1.0$(id)",
        "1.0 > /etc/passwd",
        "1.0&",
        "1.0'id'",
        '1.0"id"',
        "1.0\\id",
        "1.0*",
        "1.0?",
        "1.0(id)",
        "1.0{id}",
        "1.0[id]",
        "1.0!id",
        "1.0#id",
        "1.0%id",
        "1.0@id",
        "1.0/etc",
        # Control characters and whitespace. A bare trailing newline is
        # included deliberately: regex ``$`` alone would let it through.
        "1.0\n",
        "1.0\n2.0",
        "1.0\r\n",
        "\n1.0",
        "1.0\t2.0",
        "1.0 2.0",
        "1.0\x00",
        "1.0\x1b[31m",
        # A separator may never lead.
        "^1.0",
        "~1.0",
        ".1.0",
        "-1.0",
        # Empty and non-string.
        "",
        " ",
    ],
)
def test_definition_rejects_shell_and_control_characters(minimum):
    with pytest.raises(compliance_service.ComplianceError) as exc:
        compliance_service.validate_definition(
            "package_version_min", {"package": "target-pkg", "min_version": minimum}
        )
    assert "min_version" in str(exc.value)


def test_definition_rejects_over_length_minimum():
    """The length bound the character class carries is still enforced."""
    compliance_service.validate_definition(
        "package_version_min", {"package": "target-pkg", "min_version": "1" * 128}
    )
    with pytest.raises(compliance_service.ComplianceError):
        compliance_service.validate_definition(
            "package_version_min", {"package": "target-pkg", "min_version": "1" * 129}
        )


# ---------------------------------------------------------------------------
# A configured ``^`` minimum evaluates end to end on an RPM host
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "installed,minimum,expected_verdict",
    [
        # A snapshot build satisfies its own base-version minimum.
        ("2.4.0^20240101gitabcdef-1.el9", "2.4.0-1.el9", VERDICT_PASS),
        # A later snapshot satisfies an earlier snapshot minimum.
        (
            "2.4.0^20240202gitbbbbbb-1.el9",
            "2.4.0^20240101gitabcdef-1.el9",
            VERDICT_PASS,
        ),
        # An identical snapshot minimum is satisfied.
        (
            "2.4.0^20240101gitabcdef-1.el9",
            "2.4.0^20240101gitabcdef-1.el9",
            VERDICT_PASS,
        ),
        # The plain base version does NOT satisfy a snapshot minimum.
        ("2.4.0-1.el9", "2.4.0^20240101gitabcdef-1.el9", VERDICT_FAIL),
        # An earlier snapshot does not satisfy a later one.
        (
            "2.4.0^20240101gitabcdef-1.el9",
            "2.4.0^20240202gitbbbbbb-1.el9",
            VERDICT_FAIL,
        ),
        # ``^`` outranks ``~`` on the same base version.
        ("1.0^git1", "1.0~rc1", VERDICT_PASS),
        ("1.0~rc1", "1.0^git1", VERDICT_FAIL),
    ],
)
def test_rpm_host_evaluates_configured_caret_minimum(
    db, admin_user, make_host, installed, minimum, expected_verdict
):
    """The whole path: a ``^`` minimum survives write-time validation,
    reaches the evaluator, and is ordered by RPM semantics."""
    # The definition must be storable before it can ever be evaluated.
    compliance_service.validate_definition(
        "package_version_min", {"package": "target-pkg", "min_version": minimum}
    )

    host = make_host("caret")
    _set_facts(db, host.id, package_manager="dnf", distro_id_facts="rocky")
    _install(db, host.id, "target-pkg", installed, package_type="rpm")
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version=minimum,
    )
    assert row.verdict == expected_verdict
    if expected_verdict == VERDICT_FAIL:
        assert row.verdict_reason == REASON_VERSION_MISMATCH
    assert row.observed_value == installed
    assert row.expected_value == f">= {minimum}"


def test_caret_minimum_on_a_debian_host_is_a_structured_error(
    db, admin_user, make_host
):
    """``^`` is RPM-only. Accepting it at write time must not make it
    orderable under Debian rules, so a Debian host reports the minimum
    as unreadable rather than guessing."""
    host = make_host("caret-deb")
    _set_facts(db, host.id, package_manager="apt", distro_id_facts="ubuntu")
    _install(db, host.id, "target-pkg", "2.4.0-1ubuntu1", package_type="deb")
    row = _evaluate(
        db,
        admin_user,
        host.id,
        package="target-pkg",
        min_version="2.4.0^git1",
    )
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_MIN_VERSION_UNPARSEABLE
    assert row.observed_value == "2.4.0-1ubuntu1"
    assert row.expected_value == ">= 2.4.0^git1"
