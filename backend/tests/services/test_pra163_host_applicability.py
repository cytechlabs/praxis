"""PRA-163 slice 2 — advisory host-applicability resolver tests.

Covers:

* Pure helpers: ``_release_matches`` (ubuntu codename↔version,
  debian codename↔version, rhel major-version, unrelated rejection,
  empty handling) and ``_compare_versions`` (ordering, equality,
  zero-padding, epoch precedence, unparseable→None).
* ``compute_host_applicability`` per-state classification:
  - ``applicable`` (installed older than fix, or no published fix)
  - ``fixed`` (installed meets/exceeds fix)
  - ``not_applicable`` (advisory targets host distro/release but the
    package isn't installed)
  - ``unknown`` (installed_version missing, version compare fails)
* Host with no ``HostFacts`` (or null distro fields) → no rows
  written + ``host_facts_missing=true`` audit context; stale rows
  cleaned up.
* Replace-all idempotency: same inputs twice → no second-call
  audit, no row mutation.
* Delta detection: only the row that changes is updated; counts
  reported correctly via ``rows_added``/``rows_updated``/``rows_removed``.
* Targeted advisory-import recompute fanout: hosts matching
  distro × any touched package get recomputed; hosts that match
  distro but have none of the touched packages installed are
  skipped; hosts with no facts are skipped.
* Digest-equal no-op import does not trigger recompute.
* Audit shape (``patch_advisory.applicable_recomputed``) — action,
  target_kind=``system``, context with counts/deltas/host_facts_missing,
  ``safe_emit`` called without ``db=``.
* Read helpers: ``list_host_advisories`` filter by state +
  invalid-state rejection; ``count_host_advisories_by_state``
  returns all four state keys.
* DB constraints: state CHECK, unique
  (system_id, advisory_id, package_name), CASCADE on system/advisory
  delete, SET NULL on fixed_package delete.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import pytest
from sqlalchemy.exc import IntegrityError

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    Package,
    PatchAdvisory,
    PatchAdvisoryFixedPackage,
    PatchAdvisoryHostApplicability,
    System,
)
from app.services import patch_advisory_service
from app.services.patch_advisory_service import (
    APPLICABILITY_STATE_APPLICABLE,
    APPLICABILITY_STATE_FIXED,
    APPLICABILITY_STATE_NOT_APPLICABLE,
    APPLICABILITY_STATE_UNKNOWN,
    AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED,
    SOURCE_KIND_REDHAT_UPDATEINFO,
    SOURCE_KIND_UBUNTU_USN,
    VALID_APPLICABILITY_STATES,
    PatchAdvisoryError,
    _compare_versions,
    _release_matches,
    compute_host_applicability,
    count_host_advisories_by_state,
    list_host_advisories,
    normalize_redhat_updateinfo,
    normalize_ubuntu_usn,
)

# -- Pure helpers: _release_matches --------------------------------------


@pytest.mark.parametrize(
    "distro,host_release,source_release,expected",
    [
        # Exact equality always matches.
        ("ubuntu", "22.04", "22.04", True),
        ("ubuntu", "jammy", "jammy", True),
        ("rhel", "9", "9", True),
        # Ubuntu codename ↔ version (bidirectional).
        ("ubuntu", "22.04", "jammy", True),
        ("ubuntu", "jammy", "22.04", True),
        ("ubuntu", "noble", "24.04", True),
        ("ubuntu", "20.04", "focal", True),
        ("ubuntu", "16.04", "xenial", True),
        # Debian codename ↔ version.
        ("debian", "12", "bookworm", True),
        ("debian", "bookworm", "12", True),
        ("debian", "11", "bullseye", True),
        # RHEL major-version match.
        ("rhel", "9.3", "9", True),
        ("rhel", "9", "9.3", True),
        ("rhel", "8.10", "8", True),
        # Unrelated releases.
        ("ubuntu", "22.04", "20.04", False),
        ("ubuntu", "jammy", "noble", False),
        ("debian", "12", "11", False),
        ("rhel", "9", "8", False),
        # Empty strings → no match (defensive).
        ("ubuntu", "", "22.04", False),
        ("ubuntu", "22.04", "", False),
        # Unknown distro_id without alias map → exact-only.
        ("alpine", "3.18", "3.18", True),
        ("alpine", "3.18", "edge", False),
    ],
)
def test_release_matches(distro, host_release, source_release, expected):
    assert _release_matches(distro, host_release, source_release) is expected


# -- Pure helpers: _compare_versions -------------------------------------


@pytest.mark.parametrize(
    "a,b,expected",
    [
        # Equality.
        ("3.0.2", "3.0.2", 0),
        ("3.0.2", "3.0.2.0", 0),  # zero-padding
        # Strict ordering.
        ("3.0.2", "3.0.3", -1),
        ("3.0.3", "3.0.2", 1),
        ("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.20", -1),
        ("3.0.2-0ubuntu1.20", "3.0.2-0ubuntu1.15", 1),
        # Major bump.
        ("2.9.99", "3.0.0", -1),
        ("3.0.7-25.el9_3", "3.0.5-1.el9", 1),
        # Epoch precedence.
        ("1:1.0.0", "0:9.0.0", 1),
        ("0:9.0.0", "1:1.0.0", -1),
        ("1:3.0.7", "1:3.0.7", 0),
        # Unparseable → None.
        ("", "3.0.2", None),
        ("3.0.2", "", None),
        ("not-a-version", "3.0.2", None),  # no digits anywhere
        (None, "3.0.2", None),
    ],
)
def test_compare_versions(a, b, expected):
    assert _compare_versions(a, b) == expected


# -- Fixtures ------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="applicability-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="applicability-test-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


def _make_host(
    db,
    seed_distro,
    static_group,
    credentials,
    *,
    hostname: str,
    distro_id_facts: Optional[str] = "ubuntu",
    distro_release: Optional[str] = "22.04",
    write_facts: bool = True,
):
    s = System(
        hostname=hostname,
        ip_address="10.0.0.42",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.flush()
    if write_facts:
        db.add(
            HostFacts(
                system_id=s.id,
                schema_version=1,
                collected_at=datetime.utcnow(),
                source_transport="agent",
                distro_id_facts=distro_id_facts,
                distro_release=distro_release,
            )
        )
        db.flush()
    return s


def _add_package(db, system, *, name, version):
    pkg = Package(
        system_id=system.id,
        name=name,
        installed_version=version,
        package_type="deb",
    )
    db.add(pkg)
    db.flush()
    return pkg


def _import_usn(
    db,
    admin_user,
    *,
    advisory_id: str,
    release_packages: dict,
    severity: str = "High",
):
    raw = {
        "id": advisory_id,
        "title": f"{advisory_id} title",
        "summary": "test",
        "severity": severity,
        "release_packages": release_packages,
    }
    payload = normalize_ubuntu_usn(raw)
    run, _outcomes = patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )
    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id=advisory_id,
    )
    return advisory, run


# -- Per-state classification --------------------------------------------


def test_state_applicable_when_installed_older_than_fixed(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-applicable.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-APP-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    rows = list_host_advisories(db, host.id)
    # The import already triggered a recompute (advisory + matching pkg).
    assert len(rows) == 1
    row = rows[0]
    assert row.state == APPLICABILITY_STATE_APPLICABLE
    assert row.installed_version == "3.0.2-0ubuntu1.10"
    assert row.required_version == "3.0.2-0ubuntu1.15"
    assert row.reason is None


def test_state_fixed_when_installed_meets_or_exceeds(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-fixed.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.20")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-FIX-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    rows = list_host_advisories(db, host.id)
    assert [r.state for r in rows] == [APPLICABILITY_STATE_FIXED]
    assert rows[0].reason is None


def test_state_not_applicable_when_package_absent(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-na.example"
    )
    _add_package(db, host, name="curl", version="7.81.0-1ubuntu1.15")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-NA-1",
        release_packages={
            "jammy": [
                {"name": "openssl", "version": "3.0.2-0ubuntu1.15"},
                {"name": "libssl3", "version": "3.0.2-0ubuntu1.15"},
            ],
        },
    )
    # Targeted recompute fanout requires the host to have at least
    # ONE touched package installed; this host has none of openssl/
    # libssl3, so the import-side fanout skips it. Manual recompute
    # exercises the not_applicable path.
    compute_host_applicability(db, host.id)
    rows = list_host_advisories(db, host.id)
    assert {r.package_name for r in rows} == {"openssl", "libssl3"}
    assert {r.state for r in rows} == {APPLICABILITY_STATE_NOT_APPLICABLE}
    assert all(r.installed_version is None for r in rows)


def test_state_applicable_when_no_published_fix(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-no-fix.example",
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-NOFIX-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": None}],
        },
    )
    rows = list_host_advisories(db, host.id)
    assert [r.state for r in rows] == [APPLICABILITY_STATE_APPLICABLE]
    assert rows[0].required_version is None
    assert rows[0].reason == "no published fix"


def test_state_unknown_when_version_unparseable(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-unknown.example"
    )
    _add_package(db, host, name="openssl", version="not-a-version")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-UNK-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    rows = list_host_advisories(db, host.id)
    assert [r.state for r in rows] == [APPLICABILITY_STATE_UNKNOWN]
    assert rows[0].reason == "version compare failed"


# -- Host with no usable facts -------------------------------------------


def test_host_without_facts_writes_no_rows_and_audits_missing(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-no-facts.example",
        write_facts=False,
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-NOFACTS-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    # The advisory-import recompute won't visit this host because the
    # candidate-systems join requires a HostFacts row. Manual recompute
    # is what surfaces the host_facts_missing audit.
    audits: list = []
    monkeypatch.setattr(
        patch_advisory_service,
        "safe_emit",
        lambda **kw: audits.append(kw),
    )
    # Plant a stale row to prove the resolver cleans it up.
    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-NOFACTS-1",
    )
    db.add(
        PatchAdvisoryHostApplicability(
            system_id=host.id,
            advisory_id=advisory.id,
            package_name="openssl",
            installed_version="3.0.2-0ubuntu1.10",
            required_version="3.0.2-0ubuntu1.15",
            state=APPLICABILITY_STATE_APPLICABLE,
            evaluated_at=datetime.utcnow(),
        )
    )
    db.commit()

    result = compute_host_applicability(db, host.id)
    assert result.host_facts_missing is True
    assert result.rows_removed == 1
    assert result.changed
    assert list_host_advisories(db, host.id) == []
    audit_evs = [
        a for a in audits if a["action"] == AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED
    ]
    assert len(audit_evs) == 1
    ctx = audit_evs[0]["context"]
    assert ctx["host_facts_missing"] is True
    assert ctx["rows_removed"] == 1


def test_host_with_null_distro_facts_treated_as_missing(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-null-distro.example",
        distro_id_facts=None,
        distro_release=None,
    )
    result = compute_host_applicability(db, host.id)
    assert result.host_facts_missing is True
    assert list_host_advisories(db, host.id) == []


def test_unknown_system_id_rejected(db):
    with pytest.raises(PatchAdvisoryError, match="system_id"):
        compute_host_applicability(db, 999999)


# -- Idempotency / replace-all -------------------------------------------


def test_repeated_recompute_is_no_op_no_audit(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-idem.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-IDEM-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    rows_before = list_host_advisories(db, host.id)
    assert len(rows_before) == 1
    original_evaluated_at = rows_before[0].evaluated_at

    audits: list = []
    monkeypatch.setattr(
        patch_advisory_service, "safe_emit", lambda **kw: audits.append(kw)
    )
    result = compute_host_applicability(db, host.id)
    assert not result.changed
    assert result.rows_added == 0
    assert result.rows_updated == 0
    assert result.rows_removed == 0
    # No audit on no-op.
    recompute_audits = [
        a for a in audits if a["action"] == AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED
    ]
    assert recompute_audits == []
    db.refresh(rows_before[0])
    assert rows_before[0].evaluated_at == original_evaluated_at


def test_changed_installed_version_updates_only_that_row(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-update.example"
    )
    pkg = _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-UPD-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    row = list_host_advisories(db, host.id)[0]
    assert row.state == APPLICABILITY_STATE_APPLICABLE

    # Operator patched the host: installed bumped to the fix.
    pkg.installed_version = "3.0.2-0ubuntu1.20"
    db.commit()

    audits: list = []
    monkeypatch.setattr(
        patch_advisory_service, "safe_emit", lambda **kw: audits.append(kw)
    )
    result = compute_host_applicability(db, host.id)
    assert result.rows_updated == 1
    assert result.rows_added == 0
    assert result.rows_removed == 0
    db.refresh(row)
    assert row.state == APPLICABILITY_STATE_FIXED
    assert row.installed_version == "3.0.2-0ubuntu1.20"
    recompute_audits = [
        a for a in audits if a["action"] == AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED
    ]
    assert len(recompute_audits) == 1
    assert recompute_audits[0]["context"]["rows_updated"] == 1


def test_removed_advisory_target_removes_applicability_row(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-shrink.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _add_package(db, host, name="libssl3", version="3.0.2-0ubuntu1.10")
    advisory, _ = _import_usn(
        db,
        admin_user,
        advisory_id="USN-SHRINK-1",
        release_packages={
            "jammy": [
                {"name": "openssl", "version": "3.0.2-0ubuntu1.15"},
                {"name": "libssl3", "version": "3.0.2-0ubuntu1.15"},
            ],
        },
    )
    rows = list_host_advisories(db, host.id)
    assert {r.package_name for r in rows} == {"openssl", "libssl3"}

    # Source published an updated USN that drops libssl3.
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-SHRINK-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    rows_after = list_host_advisories(db, host.id)
    assert {r.package_name for r in rows_after} == {"openssl"}


def test_refresh_to_different_release_clears_stale_rows_for_old_release_hosts(
    db, admin_user, seed_distro, static_group, credentials
):
    """Slice 2-a regression: an advisory refresh that drops the host's
    release entirely (and replaces it with another) must still recompute
    the previously-affected host so its now-orphaned applicability row
    is removed.

    Without the fix, ``touched_targets`` contained only the NEW
    fixed-package targets; a host whose only overlap was with the OLD
    targets fell out of the fanout and kept a stale applicability row
    pointing at a now-deleted ``fixed_package_id`` (SET NULL preserves
    the row).
    """
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-refresh-release.example",
        distro_id_facts="ubuntu",
        distro_release="22.04",
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    advisory, _ = _import_usn(
        db,
        admin_user,
        advisory_id="USN-REFRESH-RELEASE-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    rows = list_host_advisories(db, host.id)
    assert [r.package_name for r in rows] == ["openssl"]
    assert rows[0].state == APPLICABILITY_STATE_APPLICABLE

    # Source republished the advisory: jammy entry dropped, focal added.
    # The host (jammy/22.04) doesn't intersect any NEW target. Pre-fix,
    # the fanout missed the host entirely and left the stale jammy row.
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-REFRESH-RELEASE-1",
        release_packages={
            "focal": [{"name": "openssl", "version": "1.1.1f-1ubuntu2.20"}],
        },
    )
    rows_after = list_host_advisories(db, host.id)
    assert rows_after == []


def test_refresh_to_different_package_clears_stale_rows_for_old_package_hosts(
    db, admin_user, seed_distro, static_group, credentials
):
    """Slice 2-a regression companion: an advisory refresh that swaps
    the affected package on the same release must still recompute the
    previously-affected host even if the host doesn't have the NEW
    package installed.
    """
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-refresh-package.example",
        distro_id_facts="ubuntu",
        distro_release="22.04",
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-REFRESH-PKG-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    rows = list_host_advisories(db, host.id)
    assert [r.package_name for r in rows] == ["openssl"]

    # Refresh swaps openssl out for curl on the same release. Host has
    # openssl (matches the OLD target) but not curl (no match for the
    # NEW target via the candidate-systems × installed-package join).
    # Pre-fix, touched_targets held only ("ubuntu","jammy","curl"), so
    # the host fell out of the fanout entirely and its stale openssl
    # applicability row stayed. With the fix, the OLD ("ubuntu","jammy",
    # "openssl") tuple is also in touched_targets, the host comes back
    # into fanout via its installed openssl, and the per-host
    # replace-all diff drops the stale openssl row and writes a new
    # not_applicable row for curl (advisory targets jammy/curl, host
    # is jammy but has no curl installed).
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-REFRESH-PKG-1",
        release_packages={
            "jammy": [{"name": "curl", "version": "7.81.0-1ubuntu1.20"}],
        },
    )
    rows_after = list_host_advisories(db, host.id)
    # Stale openssl row gone (the fix). Curl row present and
    # not_applicable (the host is in jammy, advisory targets curl on
    # jammy, but curl isn't installed).
    by_pkg = {r.package_name: r for r in rows_after}
    assert "openssl" not in by_pkg
    assert by_pkg["curl"].state == APPLICABILITY_STATE_NOT_APPLICABLE


# -- Targeted advisory-import recompute fanout ---------------------------


def test_advisory_import_recomputes_only_matching_hosts(
    db, admin_user, seed_distro, static_group, credentials
):
    # Three hosts: two ubuntu/jammy, one debian/bookworm.
    h_match = _make_host(
        db, seed_distro, static_group, credentials, hostname="match.example"
    )
    _add_package(db, h_match, name="openssl", version="3.0.2-0ubuntu1.10")

    h_other_distro = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="other-distro.example",
        distro_id_facts="debian",
        distro_release="bookworm",
    )
    _add_package(db, h_other_distro, name="openssl", version="3.0.13-1~deb12u1")

    h_no_pkg = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="no-pkg.example",
    )
    _add_package(db, h_no_pkg, name="curl", version="7.81.0-1ubuntu1.15")

    _import_usn(
        db,
        admin_user,
        advisory_id="USN-FANOUT-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    # Only h_match should have rows.
    assert len(list_host_advisories(db, h_match.id)) == 1
    assert list_host_advisories(db, h_other_distro.id) == []
    assert list_host_advisories(db, h_no_pkg.id) == []


def test_digest_equal_reimport_does_not_trigger_recompute(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-noop.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-NOOP-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )

    audits: list = []
    monkeypatch.setattr(
        patch_advisory_service, "safe_emit", lambda **kw: audits.append(kw)
    )
    # Re-import the identical payload — Slice 1 reports it as
    # ``unchanged`` and Slice 2 must not run a recompute.
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-NOOP-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    recompute_audits = [
        a for a in audits if a["action"] == AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED
    ]
    assert recompute_audits == []


def test_rhel_release_alias_match(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-rhel.example",
        distro_id_facts="rhel",
        distro_release="9.3",
    )
    _add_package(db, host, name="openssl", version="3.0.5-1.el9")
    raw = {
        "id": "RHSA-RHELMATCH-1",
        "type": "security",
        "severity": "Important",
        "title": "Important: openssl",
        "release": "9",
        "distro_id": "rhel",
        "packages": [{"name": "openssl", "version": "3.0.7-25.el9_3"}],
    }
    payload = normalize_redhat_updateinfo(raw)
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_REDHAT_UPDATEINFO,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )
    rows = list_host_advisories(db, host.id)
    assert len(rows) == 1
    assert rows[0].state == APPLICABILITY_STATE_APPLICABLE


# -- Audit shape ---------------------------------------------------------


def test_recompute_audit_shape(
    db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-audit.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")

    audits: list = []
    monkeypatch.setattr(
        patch_advisory_service, "safe_emit", lambda **kw: audits.append(kw)
    )
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-AUDIT-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    recompute_audits = [
        a for a in audits if a["action"] == AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED
    ]
    assert len(recompute_audits) == 1
    ev = recompute_audits[0]
    assert "db" not in ev  # safe_emit session-boundary lock
    assert ev["outcome"] == "success"
    assert ev["actor_user_id"] == admin_user.id
    assert ev["target_kind"] == "system"
    assert ev["target_id"] == str(host.id)
    ctx = ev["context"]
    assert set(ctx["counts"].keys()) == VALID_APPLICABILITY_STATES
    assert ctx["counts"][APPLICABILITY_STATE_APPLICABLE] == 1
    assert ctx["rows_added"] == 1
    assert ctx["rows_updated"] == 0
    assert ctx["rows_removed"] == 0
    assert ctx["advisories_touched"] == 1
    assert ctx["host_facts_missing"] is False


# -- Read helpers --------------------------------------------------------


def test_list_host_advisories_filter_by_state(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-filter.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _add_package(db, host, name="libssl3", version="3.0.2-0ubuntu1.20")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-FILTER-1",
        release_packages={
            "jammy": [
                {"name": "openssl", "version": "3.0.2-0ubuntu1.15"},
                {"name": "libssl3", "version": "3.0.2-0ubuntu1.15"},
            ],
        },
    )
    applicable = list_host_advisories(db, host.id, state=APPLICABILITY_STATE_APPLICABLE)
    fixed = list_host_advisories(db, host.id, state=APPLICABILITY_STATE_FIXED)
    assert {r.package_name for r in applicable} == {"openssl"}
    assert {r.package_name for r in fixed} == {"libssl3"}


def test_list_host_advisories_rejects_invalid_state(db, admin_user):
    with pytest.raises(PatchAdvisoryError, match="state"):
        list_host_advisories(db, 1, state="not-a-state")


def test_count_host_advisories_by_state_includes_zero_keys(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-count.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-COUNT-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    counts = count_host_advisories_by_state(db, host.id)
    assert set(counts.keys()) == VALID_APPLICABILITY_STATES
    assert counts[APPLICABILITY_STATE_APPLICABLE] == 1
    assert counts[APPLICABILITY_STATE_FIXED] == 0
    assert counts[APPLICABILITY_STATE_NOT_APPLICABLE] == 0
    assert counts[APPLICABILITY_STATE_UNKNOWN] == 0


# -- DB constraints + cascade --------------------------------------------


def test_db_check_rejects_invalid_state(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-check.example"
    )
    advisory = PatchAdvisory(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-CHK-1",
        advisory_class="security",
        severity="high",
        title="x",
        distro_family="debian",
        digest="0" * 64,
    )
    db.add(advisory)
    db.flush()
    bad = PatchAdvisoryHostApplicability(
        system_id=host.id,
        advisory_id=advisory.id,
        package_name="openssl",
        state="not-a-state",
        evaluated_at=datetime.utcnow(),
    )
    db.add(bad)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_db_unique_constraint_on_host_advisory_package(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-unique.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-UQ-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-UQ-1",
    )
    dup = PatchAdvisoryHostApplicability(
        system_id=host.id,
        advisory_id=advisory.id,
        package_name="openssl",
        installed_version="x",
        required_version="y",
        state=APPLICABILITY_STATE_UNKNOWN,
        evaluated_at=datetime.utcnow(),
    )
    db.add(dup)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_cascade_on_advisory_delete_removes_applicability_rows(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-casc-adv.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    advisory, _ = _import_usn(
        db,
        admin_user,
        advisory_id="USN-CASC-ADV-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    advisory_id = advisory.id
    assert (
        db.query(PatchAdvisoryHostApplicability)
        .filter(PatchAdvisoryHostApplicability.advisory_id == advisory_id)
        .count()
        > 0
    )
    db.delete(advisory)
    db.commit()
    assert (
        db.query(PatchAdvisoryHostApplicability)
        .filter(PatchAdvisoryHostApplicability.advisory_id == advisory_id)
        .count()
        == 0
    )


def test_cascade_on_system_delete_removes_applicability_rows(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-casc-sys.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-CASC-SYS-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    host_id = host.id
    assert (
        db.query(PatchAdvisoryHostApplicability)
        .filter(PatchAdvisoryHostApplicability.system_id == host_id)
        .count()
        > 0
    )
    # Drop the host's facts + packages first to avoid fk dependent errors,
    # then delete the host so the applicability CASCADE is the surface
    # under test.
    db.query(HostFacts).filter(HostFacts.system_id == host_id).delete()
    db.query(Package).filter(Package.system_id == host_id).delete()
    db.commit()
    db.delete(host)
    db.commit()
    assert (
        db.query(PatchAdvisoryHostApplicability)
        .filter(PatchAdvisoryHostApplicability.system_id == host_id)
        .count()
        == 0
    )


def test_set_null_on_fixed_package_delete_preserves_row(
    db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-setnull.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    advisory, _ = _import_usn(
        db,
        admin_user,
        advisory_id="USN-SETNULL-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    row = list_host_advisories(db, host.id)[0]
    assert row.fixed_package_id is not None

    fp = db.query(PatchAdvisoryFixedPackage).filter_by(id=row.fixed_package_id).one()
    db.delete(fp)
    db.commit()
    db.refresh(row)
    assert row.fixed_package_id is None
    # Row itself survives — historical applicability preserved.
    assert (
        db.query(PatchAdvisoryHostApplicability).filter_by(id=row.id).first()
        is not None
    )
