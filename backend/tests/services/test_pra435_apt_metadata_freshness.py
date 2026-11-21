"""PRA-435: APT scans report how fresh the metadata behind their counts is.

``apt list --upgradable`` reads the host's cached package lists. When the
repository refresh fails the cache still answers, so a scan used to look the
same as one made against current metadata. These tests cover:

* the classification of real ``apt-get update`` output (clean, 401, 404,
  unsigned, privilege, partial) and the redaction of what it reports;
* the write rules for the stored observation (ordering, preserved last verified
  refresh, unknown start);
* the scan contract (refresh versus cached-only, last-known updates preserved,
  security scans never complete on unverified metadata);
* a native APT sequence (success, failure, cached-only, recovery) driven
  against the real ``apt-get`` and ``apt`` binaries in a sandboxed APT
  configuration, with the candidate versions compared to what APT reports.

The native tests need ``apt-get`` and ``apt`` on PATH and skip without them.
"""

import os
import shutil
from datetime import datetime, timedelta

import pytest

from app.db.models import (
    Credential,
    FleetOperation,
    FleetOperationResult,
    Group,
    Package,
    PackageUpdate,
    System,
)
from app.services import security_scan_status_service as provenance
from app.services.package_service import (
    APT_CACHED,
    APT_FAILED,
    APT_FRESH,
    APT_PARTIAL,
    PackageService,
    classify_apt_refresh,
)
from tests.helpers.native_apt import NativeApt, NativeSSH, flat_repo, needs_apt

# ------------------------------------------------------- captured apt output

CLEAN_OUTPUT = (
    "Hit:1 http://deb.debian.org/debian trixie InRelease\n"
    "Get:2 http://security.debian.org/debian-security trixie-security InRelease\n"
    "Reading package lists...\n"
)

UNAUTHORIZED_OUTPUT = (
    "Hit:1 http://deb.debian.org/debian trixie InRelease\n"
    "Ign:2 https://enterprise.example.com/debian/pve trixie InRelease\n"
    "Err:2 https://enterprise.example.com/debian/pve trixie InRelease\n"
    "  401  Unauthorized [IP: 203.0.113.9 443]\n"
    "Reading package lists...\n"
)
UNAUTHORIZED_STDERR = (
    "E: Failed to fetch https://enterprise.example.com/debian/pve/dists/trixie/"
    "InRelease  401  Unauthorized [IP: 203.0.113.9 443]\n"
    "E: Some index files failed to download. They have been ignored, or old "
    "ones used instead.\n"
)

NOT_FOUND_OUTPUT = (
    "Hit:1 http://deb.debian.org/debian trixie InRelease\n"
    "Err:2 http://repo.example.com/old trixie/main amd64 Packages\n"
    "  404  Not Found [IP: 203.0.113.10 80]\n"
)

UNSIGNED_STDERR = (
    "E: The repository 'http://repo.example.com/x ./ Release' is not signed.\n"
)

LOCK_STDERR = (
    "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission "
    "denied)\nE: Unable to lock directory /var/lib/apt/lists/\n"
)


# --------------------------------------------------------------- classifier


def test_clean_refresh_is_fresh():
    assert classify_apt_refresh(CLEAN_OUTPUT, "", 0) == (APT_FRESH, "")


def test_unauthorized_source_with_a_healthy_source_is_partial():
    state, detail = classify_apt_refresh(UNAUTHORIZED_OUTPUT, UNAUTHORIZED_STDERR, 100)
    assert state == APT_PARTIAL
    assert "enterprise.example.com/debian/pve" in detail
    assert "401" in detail
    assert "credentials or subscription" in detail
    # Neither the host address nor apt's bracketed IP belongs in operator text.
    assert "203.0.113.9" not in detail


def test_not_found_source_is_partial_with_removal_guidance():
    state, detail = classify_apt_refresh(NOT_FOUND_OUTPUT, "", 100)
    assert state == APT_PARTIAL
    assert "404" in detail
    assert "removed or the suite renamed" in detail


def test_every_source_failing_is_failed():
    out = "Err:1 https://a.example.com/x trixie InRelease\n  401  Unauthorized\n"
    state, _ = classify_apt_refresh(out, "", 100)
    assert state == APT_FAILED


def test_unsigned_repository_is_failed_with_signing_guidance():
    state, detail = classify_apt_refresh(CLEAN_OUTPUT, UNSIGNED_STDERR, 100)
    assert state == APT_FAILED
    assert "is not signed" in detail
    assert "signing key" in detail


def test_permission_failure_is_failed_with_privilege_guidance():
    state, detail = classify_apt_refresh("", LOCK_STDERR, 100)
    assert state == APT_FAILED
    assert "root or passwordless sudo" in detail


def test_permission_failure_is_failed_even_when_a_source_answered():
    out = CLEAN_OUTPUT + "Err:3 http://x.example.com/y ./ Packages\n  403  Forbidden\n"
    state, _ = classify_apt_refresh(out, LOCK_STDERR, 100)
    assert state == APT_FAILED


def test_nonzero_exit_without_a_recognized_cause_is_never_fresh():
    state, detail = classify_apt_refresh("", "", 100)
    assert state == APT_FAILED
    assert "status 100" in detail


def test_a_failed_source_with_a_zero_exit_is_not_fresh():
    state, _ = classify_apt_refresh(UNAUTHORIZED_OUTPUT, "", 0)
    assert state == APT_PARTIAL


def test_detail_redacts_credentials_and_is_bounded():
    out = (
        "Hit:1 http://ok.example.com/d trixie InRelease\n"
        "Err:2 https://deploy:SentinelPw8f2c@enterprise.example.com/d trixie InRelease\n"
        "  401  Unauthorized\n"
    ) + "".join(
        f"Err:{i} https://r{i}.example.com/{'p' * 90} trixie InRelease\n  404  Not Found\n"
        for i in range(3, 12)
    )
    _, detail = classify_apt_refresh(out, "", 100)
    assert "SentinelPw8f2c" not in detail
    assert "deploy" not in detail
    assert len(detail) <= 500
    assert "more" in detail or detail.endswith("...")


def test_clean_exit_with_no_source_evidence_is_not_fresh():
    """An empty or all-disabled source set refreshes nothing."""
    state, detail = classify_apt_refresh("Reading package lists...\n", "", 0)
    assert state == APT_FAILED
    assert "refreshed no source" in detail


def test_fetch_failure_warning_with_a_zero_exit_is_not_fresh():
    out = "Hit:1 http://deb.debian.org/debian trixie InRelease\n"
    err = (
        "W: Failed to fetch http://repo.example.com/x/InRelease  Could not "
        "connect\nW: Some index files failed to download. They have been "
        "ignored, or old ones used instead.\n"
    )
    state, detail = classify_apt_refresh(out, err, 0)
    assert state == APT_PARTIAL
    assert "Failed to fetch" in detail


def test_signature_warning_with_a_zero_exit_is_not_fresh():
    out = "Hit:1 http://deb.debian.org/debian trixie InRelease\n"
    err = "W: GPG error: http://x.example.com ./ InRelease: NO_PUBKEY ABCDEF\n"
    assert classify_apt_refresh(out, err, 0)[0] == APT_PARTIAL


def test_benign_warnings_do_not_block_a_fresh_result():
    out = "Hit:1 http://deb.debian.org/debian trixie InRelease\n"
    err = (
        "W: Target Packages (main/binary-amd64/Packages) is configured "
        "multiple times in /etc/apt/sources.list:1 and /etc/apt/sources.list:2\n"
    )
    assert classify_apt_refresh(out, err, 0) == (APT_FRESH, "")


# --------------------------------------------------------------- fixtures


@pytest.fixture
def cred(db):
    c = Credential(name="pra435-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def group(db):
    g = Group(name="pra435-group", description="x")
    db.add(g)
    db.flush()
    return g


def _mk_system(db, distro, group, cred, hostname, ip):
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=distro.id,
        os_version=distro.version,
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _stored(db, system_id):
    db.expire_all()
    row = db.query(System).filter(System.id == system_id).one()
    return (
        row.apt_metadata_state,
        row.apt_metadata_refreshed_at,
        row.apt_metadata_checked_at,
        row.apt_metadata_detail,
    )


class ScriptedSSH:
    """Answers each command by kind, so a test controls what the host says."""

    def __init__(self, refresh=None, listing="", installed=""):
        self.refresh = refresh
        self.listing = listing
        self.installed = installed
        self.commands = []

    def _run(self, command):
        self.commands.append(command)
        if "apt-get update" in command:
            return self.refresh or {
                "status": "success",
                "stdout": CLEAN_OUTPUT,
                "stderr": "",
                "exit_code": 0,
            }
        if command.startswith("dpkg-query"):
            return {
                "status": "success",
                "stdout": self.installed,
                "stderr": "",
                "exit_code": 0,
            }
        if "apt list" in command:
            if isinstance(self.listing, dict):
                return self.listing
            return {
                "status": "success",
                "stdout": self.listing,
                "stderr": "",
                "exit_code": 0,
            }
        raise AssertionError(f"unexpected command: {command}")

    def execute_command(self, system_id, command, timeout=None, user_id=None):
        return self._run(command)

    def execute_privileged_command(
        self, system_id, command, timeout=None, user_id=None
    ):
        return self._run(command)


INSTALLED = "openssl\t3.0.1\tinstall ok installed\ncurl\t7.0\tinstall ok installed\n"
LISTING = (
    "Listing...\n"
    "openssl/trixie-security 3.0.2 amd64 [upgradable from: 3.0.1]\n"
    "curl/trixie 7.1 amd64 [upgradable from: 7.0]\n"
)
FAILED_REFRESH = {
    "status": "warning",
    "stdout": UNAUTHORIZED_OUTPUT,
    "stderr": UNAUTHORIZED_STDERR,
    "exit_code": 100,
}


def _service(db, ssh):
    service = PackageService(db)
    service.ssh_service = ssh
    return service


# ------------------------------------------------------------ scan contract


def test_hosts_start_unknown_and_last_audited_keeps_its_meaning(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-new", "10.35.0.1")
    assert _stored(db, system.id) == (None, None, None, None)
    view = PackageService(db).get_apt_metadata(system.id)
    assert view["state"] == "unknown" and view["verified"] is False


def test_refresh_scan_records_a_verified_refresh(db, seed_distro, group, cred):
    system = _mk_system(db, seed_distro, group, cred, "pra435-ok", "10.35.0.2")
    ssh = ScriptedSSH(installed=INSTALLED, listing=LISTING)
    summary = _service(db, ssh).scan_packages(system.id)

    assert summary["status"] == "success"
    assert summary["scan_state"] == provenance.STATE_COMPLETE
    assert summary["updates_available"] == 2
    assert summary["apt_metadata"]["state"] == APT_FRESH
    assert summary["apt_metadata"]["verified"] is True
    state, refreshed, checked, detail = _stored(db, system.id)
    assert state == APT_FRESH and refreshed == checked and detail is None
    # The refresh ran before the candidate list was read.
    refresh_at = next(i for i, c in enumerate(ssh.commands) if "apt-get update" in c)
    list_at = next(i for i, c in enumerate(ssh.commands) if "apt list" in c)
    assert refresh_at < list_at


def test_failed_refresh_keeps_last_known_updates_and_is_not_complete(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-stale", "10.35.0.3")
    _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING)).scan_packages(
        system.id
    )
    verified_at = _stored(db, system.id)[1]

    summary = _service(
        db,
        ScriptedSSH(installed=INSTALLED, listing=LISTING, refresh=FAILED_REFRESH),
    ).scan_packages(system.id)

    assert summary["status"] == "success"  # SSH and inventory are fine
    assert summary["scan_state"] == provenance.STATE_PARTIAL
    assert summary["apt_metadata"]["state"] == APT_PARTIAL
    assert "enterprise.example.com" in summary["message"]
    state, refreshed, checked, detail = _stored(db, system.id)
    assert state == APT_PARTIAL
    assert refreshed == verified_at  # last verified refresh preserved
    assert checked >= verified_at
    assert "401" in detail
    assert (
        db.query(PackageUpdate).filter(PackageUpdate.system_id == system.id).count()
        == 2
    )


def test_empty_cache_never_becomes_a_clean_zero(db, seed_distro, group, cred):
    """No candidates on a failed refresh is unverified, not "no updates"."""
    system = _mk_system(db, seed_distro, group, cred, "pra435-empty", "10.35.0.4")
    summary = _service(
        db, ScriptedSSH(installed=INSTALLED, listing="", refresh=FAILED_REFRESH)
    ).scan_packages(system.id)
    assert summary["updates_available"] == 0
    assert summary["scan_state"] != provenance.STATE_COMPLETE
    assert summary["apt_metadata"]["verified"] is False


def test_cached_only_scan_is_unverified_and_runs_no_refresh(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-cached", "10.35.0.5")
    ssh = ScriptedSSH(installed=INSTALLED, listing=LISTING)
    summary = _service(db, ssh).scan_packages(system.id, refresh=False)
    assert not any("apt-get update" in c for c in ssh.commands)
    assert summary["apt_metadata"]["state"] == APT_CACHED
    assert summary["scan_state"] == provenance.STATE_PARTIAL
    assert _stored(db, system.id)[1] is None  # never verified


def test_unreadable_candidate_list_is_a_failed_observation_not_zero_updates(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-listfail", "10.35.0.6")
    _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING)).scan_packages(
        system.id
    )
    broken = {"status": "warning", "stdout": "", "stderr": "", "exit_code": 100}
    summary = _service(
        db, ScriptedSSH(installed=INSTALLED, listing=broken)
    ).scan_packages(system.id)
    assert summary["apt_metadata"]["state"] == APT_FAILED
    assert summary["scan_state"] == provenance.STATE_PARTIAL
    # The previous candidates survive as last-known data.
    assert (
        db.query(PackageUpdate).filter(PackageUpdate.system_id == system.id).count()
        == 2
    )


def test_older_observation_finishing_late_cannot_overwrite_newer_evidence(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-order", "10.35.0.7")
    service = PackageService(db)
    t0 = datetime.utcnow()
    service._record_apt_observation(
        system.id, t0 + timedelta(minutes=5), APT_FAILED, "newer"
    )
    service._record_apt_observation(system.id, t0, APT_FRESH, "")
    state, refreshed, checked, detail = _stored(db, system.id)
    assert (state, detail) == (APT_FAILED, "newer")
    assert checked == t0 + timedelta(minutes=5)
    # The older check is genuine evidence of a refresh at t0, and only that.
    assert refreshed == t0


def test_refreshed_at_only_moves_forward_and_only_on_fresh(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-mono", "10.35.0.8")
    service = PackageService(db)
    t0 = datetime.utcnow()
    service._record_apt_observation(system.id, t0, APT_FRESH, "")
    for offset, state in ((1, APT_FAILED), (2, APT_CACHED), (3, APT_PARTIAL)):
        service._record_apt_observation(
            system.id, t0 + timedelta(minutes=offset), state, "x"
        )
        assert _stored(db, system.id)[1] == t0
    service._record_apt_observation(system.id, t0 + timedelta(minutes=4), APT_FRESH, "")
    assert _stored(db, system.id)[1] == t0 + timedelta(minutes=4)


def test_security_scan_on_unverified_metadata_is_partial_never_complete(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-sec", "10.35.0.9")
    _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING)).scan_packages(
        system.id
    )
    summary = _service(
        db, ScriptedSSH(installed=INSTALLED, listing=LISTING, refresh=FAILED_REFRESH)
    ).scan_security_updates(system.id)
    assert summary["status"] == "success"
    assert summary["updates_available"] == 1  # last-known candidates, floor not total
    assert summary["scan_state"] == provenance.STATE_PARTIAL
    assert "not verified" in summary["message"]
    assert provenance.result_status_for_scan(summary) == provenance.RESULT_PARTIAL

    cached = _service(
        db, ScriptedSSH(installed=INSTALLED, listing=LISTING)
    ).scan_security_updates(system.id, refresh=False)
    assert cached["scan_state"] == provenance.STATE_PARTIAL

    verified = _service(
        db, ScriptedSSH(installed=INSTALLED, listing=LISTING)
    ).scan_security_updates(system.id)
    assert verified["scan_state"] == provenance.STATE_COMPLETE


def test_a_later_refresh_does_not_certify_an_earlier_unverified_security_scan(
    db, seed_distro, group, cred, admin_user
):
    """Security counts are certified only by a security scan of their own."""
    system = _mk_system(db, seed_distro, group, cred, "pra435-retro", "10.35.0.10")
    service = _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING))
    service.scan_packages(system.id)  # inventory the security scan can match
    unverified = _service(
        db, ScriptedSSH(installed=INSTALLED, listing=LISTING, refresh=FAILED_REFRESH)
    ).scan_security_updates(system.id)

    op = FleetOperation(
        operation_type=provenance.SECURITY_SCAN_OPERATION_SINGLE,
        user_id=admin_user.id,
        target_count=1,
        parameters='{"system_ids": [%d]}' % system.id,
        status="completed",
        created_at=datetime.utcnow(),
    )
    db.add(op)
    db.flush()
    db.add(
        FleetOperationResult(
            fleet_operation_id=op.id,
            system_id=system.id,
            status=provenance.result_status_for_scan(unverified),
            created_at=datetime.utcnow(),
        )
    )
    db.commit()

    recovered = service.scan_packages(system.id)  # a verified refresh
    assert recovered["apt_metadata"]["verified"] is True

    coverage = provenance.get_security_scan_coverage(db, system_ids={system.id})
    assert coverage["counts_trustworthy"] is False
    assert coverage["coverage_complete"] is False
    assert coverage["state"] == provenance.STATE_PARTIAL


def test_coverage_counts_hosts_whose_metadata_is_unverified(
    db, seed_distro, group, cred
):
    a = _mk_system(db, seed_distro, group, cred, "pra435-cov-a", "10.35.0.11")
    b = _mk_system(db, seed_distro, group, cred, "pra435-cov-b", "10.35.0.12")
    _mk_system(db, seed_distro, group, cred, "pra435-cov-c", "10.35.0.13")
    now = datetime.utcnow()
    PackageService(db)._record_apt_observation(a.id, now, APT_FAILED, "x")
    PackageService(db)._record_apt_observation(b.id, now, APT_FRESH, "")
    all_ids = {
        s.id for s in db.query(System).filter(System.hostname.like("pra435-cov-%"))
    }
    coverage = provenance.get_security_scan_coverage(db, system_ids=all_ids)
    assert coverage["systems_metadata_unverified"] == 1  # unknown is not counted
    scoped = provenance.get_security_scan_coverage(db, system_ids={b.id})
    assert scoped["systems_metadata_unverified"] == 0


def test_freshness_listing_is_fleet_scoped(db, seed_distro, group, cred):
    a = _mk_system(db, seed_distro, group, cred, "pra435-sc-a", "10.35.0.14")
    b = _mk_system(db, seed_distro, group, cred, "pra435-sc-b", "10.35.0.15")
    service = PackageService(db)
    service._record_apt_observation(a.id, datetime.utcnow(), APT_FAILED, "d")
    rows = service.list_apt_metadata({a.id})
    assert [r["system_id"] for r in rows] == [a.id]
    assert rows[0]["state"] == APT_FAILED
    assert service.list_apt_metadata(set()) == []
    assert {r["system_id"] for r in service.list_apt_metadata({a.id, b.id})} == {
        a.id,
        b.id,
    }


def _candidate_versions(db, system_id):
    return {
        row.package.name: row.available_version
        for row in db.query(PackageUpdate).filter(PackageUpdate.system_id == system_id)
    }


@pytest.mark.parametrize(
    "listing",
    [
        "Listing...\n",
        "Listing...\ncurl/trixie 7.1 amd64 [upgradable from: 7.0]\n",
    ],
    ids=["empty-listing", "incomplete-listing"],
)
@pytest.mark.parametrize("refresh", [True, False], ids=["failed-refresh", "cached"])
def test_unverified_listing_never_replaces_last_known_candidates(
    db, seed_distro, group, cred, listing, refresh
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-keep", "10.35.2.1")
    _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING)).scan_packages(
        system.id
    )
    known = _candidate_versions(db, system.id)
    assert known == {"openssl": "3.0.2", "curl": "7.1"}

    summary = _service(
        db,
        ScriptedSSH(
            installed=INSTALLED,
            listing=listing,
            refresh=FAILED_REFRESH if refresh else None,
        ),
    ).scan_packages(system.id, refresh=refresh)

    assert _candidate_versions(db, system.id) == known
    assert summary["updates_available"] == 2  # last-known, not a fresh zero
    assert summary["scan_state"] == provenance.STATE_PARTIAL
    assert "last-known" in summary["message"]


def test_a_verified_scan_replaces_candidates_including_with_none(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-replace", "10.35.2.2")
    _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING)).scan_packages(
        system.id
    )
    summary = _service(
        db, ScriptedSSH(installed=INSTALLED, listing="Listing...\n")
    ).scan_packages(system.id)
    assert summary["scan_state"] == provenance.STATE_COMPLETE
    assert summary["updates_available"] == 0
    assert _candidate_versions(db, system.id) == {}


# ----------------------------------------------------------- native APT


@pytest.fixture
def native():
    apt = NativeApt()
    yield apt
    apt.close()


def _native_service(db, apt):
    service = PackageService(db)
    service.ssh_service = NativeSSH(apt)
    return service


def _db_candidates(db, system_id):
    return {
        row.package.name: row.available_version
        for row in db.query(PackageUpdate).filter(PackageUpdate.system_id == system_id)
    }


@needs_apt
def test_native_success_failure_cached_recovery_sequence(
    db, seed_distro, group, cred, native
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-native", "10.35.1.1")
    service = _native_service(db, native)

    # 1. A clean refresh is verified and matches what APT itself reports.
    first = service.scan_packages(system.id)
    assert first["apt_metadata"]["state"] == APT_FRESH, first
    assert first["scan_state"] == provenance.STATE_COMPLETE
    assert (
        _db_candidates(db, system.id)
        == native.candidates()
        == {
            "pra435-demo": "2.0",
            "pra435-sec": "2.0",
        }
    )
    verified_at = _stored(db, system.id)[1]
    assert verified_at is not None

    # 2. An unentitled source starts failing with HTTP 401. The scan still
    # succeeds over SSH, keeps the cached candidates, and says so.
    native.set_sources(native.unentitled_source())
    second = service.scan_packages(system.id)
    assert second["status"] == "success"
    assert second["apt_metadata"]["state"] == APT_PARTIAL, second
    assert second["scan_state"] == provenance.STATE_PARTIAL
    assert "401" in second["apt_metadata"]["detail"]
    assert second["updates_available"] == 2
    assert _db_candidates(db, system.id) == native.candidates()
    state, refreshed, _, _ = _stored(db, system.id)
    assert state == APT_PARTIAL and refreshed == verified_at

    # 3. A cached-only scan reports cached and preserves the verified time.
    third = service.scan_packages(system.id, refresh=False)
    assert third["apt_metadata"]["state"] == APT_CACHED
    assert third["scan_state"] == provenance.STATE_PARTIAL
    assert _stored(db, system.id)[1] == verified_at

    # 4. A security scan against the failing source is never complete.
    sec = service.scan_security_updates(system.id)
    assert sec["scan_state"] == provenance.STATE_PARTIAL
    assert sec["updates_available"] == 1

    # 5. Removing the source and refreshing recovers verified state, advances
    # the verified time, and the stored candidates still match APT.
    native.set_sources()
    recovered = service.scan_packages(system.id)
    assert recovered["apt_metadata"]["state"] == APT_FRESH, recovered
    assert recovered["scan_state"] == provenance.STATE_COMPLETE
    assert _stored(db, system.id)[1] > verified_at
    assert _db_candidates(db, system.id) == native.candidates()
    assert service.scan_security_updates(system.id)["scan_state"] == (
        provenance.STATE_COMPLETE
    )


@needs_apt
def test_native_404_and_unsigned_sources_are_reported_per_source(
    db, seed_distro, group, cred, native
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-native-b", "10.35.1.2")
    service = _native_service(db, native)

    native.set_sources(native.removed_source())
    missing = service.scan_packages(system.id)
    assert missing["apt_metadata"]["state"] == APT_PARTIAL, missing
    assert "404" in missing["apt_metadata"]["detail"]

    native.set_sources(native.unsigned_source())
    unsigned = service.scan_packages(system.id)
    assert unsigned["apt_metadata"]["state"] == APT_FAILED, unsigned
    assert "not signed" in unsigned["apt_metadata"]["detail"]
    assert unsigned["status"] == "success"  # the host stays connected


@needs_apt
def test_native_disabled_source_does_not_degrade_a_refresh(
    db, seed_distro, group, cred, native
):
    """A mixed active/disabled fixture: only enabled sources are refreshed."""
    system = _mk_system(db, seed_distro, group, cred, "pra435-native-c", "10.35.1.3")
    service = _native_service(db, native)
    native.set_sources(native.disabled_source())
    summary = service.scan_packages(system.id)
    assert summary["apt_metadata"]["state"] == APT_FRESH, summary
    assert summary["scan_state"] == provenance.STATE_COMPLETE


@needs_apt
def test_native_listing_without_refresh_failure_matches_old_behavior_control(
    db, seed_distro, group, cred, native
):
    """Control: the previous path (list only, no refresh) cannot see the fault.

    This is what the scan did before refresh semantics existed: the candidate
    list is read from cache and looks identical whether or not the repository
    is reachable. It documents why the cached-only state is never trustworthy.
    """
    native.set_sources(native.unentitled_source())
    cached = native.run("apt list --upgradable 2>/dev/null")
    assert cached["exit_code"] == 0
    refresh = native.run(
        "apt-get update -o Acquire::Retries=0 -o Acquire::http::Timeout=30"
    )
    assert refresh["exit_code"] != 0


@needs_apt
def test_native_sources_that_refresh_nothing_are_not_fresh(
    db, seed_distro, group, cred, native
):
    """Absent and all-disabled sources exit 0 with no source evidence."""
    system = _mk_system(db, seed_distro, group, cred, "pra435-nosrc", "10.35.2.3")
    service = _native_service(db, native)
    service.scan_packages(system.id)  # seed known candidates from a good refresh
    known = _db_candidates(db, system.id)
    assert known

    for lines in ((), (native.disabled_source(),)):
        with open(f"{native.root}/etc/sources.list", "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        # Raw control: apt itself calls this a success.
        assert native.run("apt-get update")["exit_code"] == 0
        summary = service.scan_packages(system.id)
        assert summary["apt_metadata"]["state"] == APT_FAILED, summary
        assert "refreshed no source" in summary["apt_metadata"]["detail"]
        assert summary["scan_state"] == provenance.STATE_PARTIAL
        assert _db_candidates(db, system.id) == known


@needs_apt
def test_native_verified_repository_with_no_updates_is_fresh_zero(
    db, seed_distro, group, cred, native
):
    """Contrast with missing metadata: a refreshed repository with nothing new."""
    system = _mk_system(db, seed_distro, group, cred, "pra435-zero", "10.35.2.4")
    flat_repo(f"{native.root}/good", "pra435-demo", "1.0", "stable")
    flat_repo(f"{native.root}/sec", "pra435-sec", "1.0", "stable-security")
    summary = _native_service(db, native).scan_packages(system.id)
    assert summary["apt_metadata"]["state"] == APT_FRESH, summary
    assert summary["scan_state"] == provenance.STATE_COMPLETE
    assert summary["updates_available"] == 0


@needs_apt
def test_native_empty_cache_with_failed_refresh_keeps_last_known_updates(
    db, seed_distro, group, cred, native
):
    """The failure the review reproduced: no lists, failing source, empty list."""
    system = _mk_system(db, seed_distro, group, cred, "pra435-wipe", "10.35.2.5")
    service = _native_service(db, native)
    service.scan_packages(system.id)
    known = _db_candidates(db, system.id)
    assert known

    shutil.rmtree(f"{native.root}/state/lists")
    os.makedirs(f"{native.root}/state/lists/partial")
    native.set_sources()
    with open(f"{native.root}/etc/sources.list", "w", encoding="utf-8") as fh:
        fh.write(native.unentitled_source() + "\n")
    assert native.candidates() == {}  # the host now lists nothing at all

    summary = service.scan_packages(system.id)
    assert summary["apt_metadata"]["state"] == APT_FAILED, summary
    assert summary["updates_available"] == len(known)
    assert _db_candidates(db, system.id) == known


# ----------------------------------------------- bounded output and locale


def _clipped(result):
    return dict(result, truncated=True)


CLEAN_REFRESH_RESULT = {
    "status": "success",
    "stdout": "Hit:1 http://deb.debian.org/debian trixie InRelease\n",
    "stderr": "",
    "exit_code": 0,
}


def test_clipped_clean_refresh_is_never_fresh(db, seed_distro, group, cred):
    """A successful exit with a clipped Hit line proves nothing about the rest."""
    system = _mk_system(db, seed_distro, group, cred, "pra435-clip-r", "10.35.3.1")
    summary = _service(
        db,
        ScriptedSSH(
            installed=INSTALLED, listing=LISTING, refresh=_clipped(CLEAN_REFRESH_RESULT)
        ),
    ).scan_packages(system.id)
    assert summary["apt_metadata"]["state"] == APT_FAILED
    assert summary["apt_metadata"]["verified"] is False
    assert "capture limit" in summary["apt_metadata"]["detail"]
    assert summary["evidence_incomplete"] is True
    assert summary["scan_state"] == provenance.STATE_PARTIAL
    assert _stored(db, system.id)[1] is None  # no verified refresh recorded


def test_clipped_candidate_listing_keeps_last_known_inventory(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-clip-l", "10.35.3.2")
    _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING)).scan_packages(
        system.id
    )
    known = _candidate_versions(db, system.id)
    clipped = _clipped(
        {
            "status": "success",
            "stdout": "Listing...\nopenssl/trixie-security 3.0.2 amd64 [upgr",
            "stderr": "",
            "exit_code": 0,
        }
    )
    summary = _service(
        db, ScriptedSSH(installed=INSTALLED, listing=clipped)
    ).scan_packages(system.id)
    assert _candidate_versions(db, system.id) == known
    assert summary["updates_available"] == len(known)  # last-known, not zero
    assert summary["evidence_incomplete"] is True
    assert summary["apt_metadata"]["state"] == APT_FAILED
    assert "capture limit" in summary["apt_metadata"]["detail"]
    assert summary["scan_state"] == provenance.STATE_PARTIAL


def test_clipped_installed_inventory_leaves_stored_packages_alone(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-clip-i", "10.35.3.3")
    _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING)).scan_packages(
        system.id
    )
    ssh = ScriptedSSH(
        installed="openssl\t3.0.1\tinstall ok installed\n", listing=LISTING
    )
    original = ssh._run

    def clipped_installed(command):
        result = original(command)
        return _clipped(result) if command.startswith("dpkg-query") else result

    ssh._run = clipped_installed
    summary = _service(db, ssh).scan_packages(system.id)
    assert summary["status"] == "error"
    assert summary["evidence_incomplete"] is True
    names = {p.name for p in db.query(Package).filter(Package.system_id == system.id)}
    assert names == {"openssl", "curl"}  # nothing past the cut was deleted
    assert _candidate_versions(db, system.id) != {}


def test_clipped_refresh_makes_a_security_scan_partial(db, seed_distro, group, cred):
    system = _mk_system(db, seed_distro, group, cred, "pra435-clip-sr", "10.35.3.4")
    _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING)).scan_packages(
        system.id
    )
    summary = _service(
        db,
        ScriptedSSH(
            installed=INSTALLED, listing=LISTING, refresh=_clipped(CLEAN_REFRESH_RESULT)
        ),
    ).scan_security_updates(system.id)
    assert summary["scan_state"] == provenance.STATE_PARTIAL
    assert summary["evidence_incomplete"] is True
    assert provenance.result_status_for_scan(summary) == provenance.RESULT_PARTIAL


def test_clipped_security_listing_fails_and_reports_last_known(
    db, seed_distro, group, cred
):
    system = _mk_system(db, seed_distro, group, cred, "pra435-clip-sl", "10.35.3.5")
    seed = _service(db, ScriptedSSH(installed=INSTALLED, listing=LISTING))
    seed.scan_packages(system.id)
    seed.scan_security_updates(system.id)
    clipped = _clipped(
        {
            "status": "success",
            "stdout": "Listing...\n",
            "stderr": "",
            "exit_code": 0,
        }
    )
    summary = _service(
        db, ScriptedSSH(installed=INSTALLED, listing=clipped)
    ).scan_security_updates(system.id)
    assert summary["status"] == "error"
    assert summary["scan_state"] == provenance.STATE_FAILED
    assert summary["evidence_incomplete"] is True
    assert summary["last_known_updates"] == 1
    assert "capture limit" in summary["message"]
    assert "1 last-known" in summary["message"]
    assert provenance.result_status_for_scan(summary) == provenance.RESULT_FAILURE
    assert _stored(db, system.id)[0] == APT_FAILED


def test_parsed_apt_commands_run_in_the_c_locale(db, seed_distro, group, cred):
    system = _mk_system(db, seed_distro, group, cred, "pra435-locale", "10.35.3.6")
    ssh = ScriptedSSH(installed=INSTALLED, listing=LISTING)
    service = _service(db, ssh)
    service.scan_packages(system.id)
    service.scan_security_updates(system.id)
    parsed = [
        c
        for c in ssh.commands
        if "apt-get update" in c or c.startswith("LC_ALL=C apt list") or "apt list" in c
    ]
    assert len(parsed) == 4
    assert all(c.startswith("LC_ALL=C ") for c in parsed), parsed


@needs_apt
def test_native_commands_parse_under_a_non_english_host_locale(
    db, seed_distro, group, cred, native
):
    """The command's own LC_ALL=C wins over the host's configured language."""
    native.env.update(LANG="de_DE.UTF-8", LANGUAGE="de", LC_MESSAGES="de_DE.UTF-8")
    system = _mk_system(db, seed_distro, group, cred, "pra435-locale-n", "10.35.3.7")
    summary = _native_service(db, native).scan_packages(system.id)
    assert summary["apt_metadata"]["state"] == APT_FRESH, summary
    assert _db_candidates(db, system.id) == native.candidates()
