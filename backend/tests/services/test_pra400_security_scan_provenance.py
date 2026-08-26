"""PRA-400: security-scan provenance separates "unscanned" from "zero updates".

A security count only means something once a security scan has actually asked
the question. These tests cover the derivation that makes that visible:

* a fleet nobody has security-scanned is ``not_scanned``, never a zero;
* an ordinary package scan does not make a fleet look security-scanned;
* an in-flight scan is ``scanning``, and an operation abandoned by a dead
  process stops counting as in flight;
* a failed scan is ``failed`` with sanitized, bounded failure context;
* a scan that could not read or store part of its result is ``partial``;
* a completed scan is ``complete`` with a trustworthy count and timestamp,
  whether it found zero updates or many;
* mixed coverage never reports as complete, and a later failure removes the
  trust an earlier success granted;
* every count and timestamp is constrained to the caller's fleet scope.

The scan side is covered too: the per-host summaries the package service
returns must carry the state that the recorded outcome is derived from.
"""

import json
from datetime import datetime, timedelta

import pytest

from app.db.models import (
    Credential,
    Distro,
    FleetOperation,
    FleetOperationResult,
    Group,
    Package,
    System,
)
from app.services import security_scan_status_service as provenance
from app.services.package_service import PackageService

# --------------------------------------------------------------- fixtures


@pytest.fixture
def cred(db):
    c = Credential(name="pra400-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def group(db):
    g = Group(name="pra400-group", description="x")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def rocky_distro(db):
    from datetime import date

    distro = db.query(Distro).filter_by(name="Rocky", version="9").first()
    if not distro:
        distro = Distro(
            name="Rocky",
            version="9",
            release_date=date(2022, 5, 16),
            end_of_life_date=date(2032, 5, 31),
        )
        db.add(distro)
        db.flush()
    return distro


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
    db.flush()
    return s


@pytest.fixture
def two_hosts(db, seed_distro, group, cred):
    a = _mk_system(db, seed_distro, group, cred, "pra400-a", "10.40.0.1")
    b = _mk_system(db, seed_distro, group, cred, "pra400-b", "10.40.0.2")
    db.commit()
    return a, b


def _mk_operation(
    db,
    admin_user,
    *,
    operation_type=provenance.SECURITY_SCAN_OPERATION_COHORT,
    systems=(),
    status="completed",
    created_at=None,
):
    op = FleetOperation(
        operation_type=operation_type,
        user_id=admin_user.id,
        target_count=len(systems),
        success_count=0,
        failure_count=0,
        parameters=json.dumps({"system_ids": [s.id for s in systems]}),
        status=status,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(op)
    db.flush()
    return op


def _record(db, op, system, status, error_message=None, created_at=None):
    row = FleetOperationResult(
        fleet_operation_id=op.id,
        system_id=system.id,
        status=status,
        error_message=error_message,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def _scan(db, admin_user, system, status, **kwargs):
    """Record one completed security scan of ``system`` with ``status``."""
    op = _mk_operation(db, admin_user, systems=[system])
    row = _record(db, op, system, status, **kwargs)
    db.commit()
    return row


def _coverage(db, system_ids=None, now=None):
    return provenance.get_security_scan_coverage(db, system_ids=system_ids, now=now)


# --------------------------------------------------------------- unscanned


def test_fresh_fleet_is_not_scanned_rather_than_zero(db, two_hosts):
    a, b = two_hosts
    coverage = _coverage(db, {a.id, b.id})

    assert coverage["state"] == provenance.STATE_NOT_SCANNED
    assert coverage["counts_trustworthy"] is False
    assert coverage["coverage_complete"] is False
    assert coverage["systems_total"] == 2
    assert coverage["systems_never_scanned"] == 2
    assert coverage["systems_scanned"] == 0
    assert coverage["last_successful_scan_at"] is None
    assert coverage["last_scan_at"] is None


def test_ordinary_package_scan_does_not_imply_a_security_scan(
    db, admin_user, two_hosts
):
    a, b = two_hosts
    op = _mk_operation(
        db, admin_user, operation_type="cohort_package_scan", systems=[a, b]
    )
    _record(db, op, a, provenance.RESULT_SUCCESS)
    _record(db, op, b, provenance.RESULT_SUCCESS)
    db.commit()

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["state"] == provenance.STATE_NOT_SCANNED
    assert coverage["systems_never_scanned"] == 2
    assert coverage["counts_trustworthy"] is False


def test_skipped_host_is_not_treated_as_scanned(db, admin_user, two_hosts):
    a, b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SKIPPED)

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["state"] == provenance.STATE_NOT_SCANNED
    assert coverage["systems_never_scanned"] == 2


# --------------------------------------------------------------- in flight


def test_running_scan_reports_scanning(db, admin_user, two_hosts):
    a, b = two_hosts
    _mk_operation(db, admin_user, systems=[a, b], status="running")
    db.commit()

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["state"] == provenance.STATE_SCANNING
    assert coverage["systems_scanning"] == 2
    assert coverage["counts_trustworthy"] is False


def test_abandoned_running_scan_stops_counting_as_in_flight(db, admin_user, two_hosts):
    a, b = two_hosts
    stale = datetime.utcnow() - (provenance.RUNNING_SCAN_MAX_AGE + timedelta(minutes=5))
    _mk_operation(db, admin_user, systems=[a, b], status="running", created_at=stale)
    db.commit()

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["systems_scanning"] == 0
    assert coverage["state"] == provenance.STATE_NOT_SCANNED


def test_running_scan_outranks_a_previous_result(db, admin_user, two_hosts):
    a, b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _scan(db, admin_user, b, provenance.RESULT_SUCCESS)
    _mk_operation(db, admin_user, systems=[a], status="running")
    db.commit()

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["state"] == provenance.STATE_SCANNING
    assert coverage["systems_scanning"] == 1
    assert coverage["systems_scanned"] == 1
    assert coverage["counts_trustworthy"] is False


# --------------------------------------------------------------- failure


def test_failed_scan_reports_failed_with_sanitized_detail(db, admin_user, two_hosts):
    a, b = two_hosts
    _scan(
        db,
        admin_user,
        a,
        provenance.RESULT_FAILURE,
        error_message="Failed to scan security updates:\n  connection refused\r\n",
    )
    _scan(db, admin_user, b, provenance.RESULT_FAILURE, error_message="no output")

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["state"] == provenance.STATE_FAILED
    assert coverage["systems_failed"] == 2
    assert coverage["counts_trustworthy"] is False
    assert coverage["last_successful_scan_at"] is None
    assert coverage["last_scan_at"] is not None
    assert "\n" not in coverage["last_failure_detail"]
    assert coverage["last_failure_detail"] == "no output"


def test_a_later_failure_revokes_an_earlier_success(db, admin_user, two_hosts):
    a, _b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _scan(db, admin_user, a, provenance.RESULT_FAILURE, error_message="boom")

    coverage = _coverage(db, {a.id})
    assert coverage["state"] == provenance.STATE_FAILED
    assert coverage["systems_scanned"] == 0
    assert coverage["systems_failed"] == 1
    # The successful scan still happened, so its timestamp survives.
    assert coverage["last_successful_scan_at"] is not None


# --------------------------------------------------------------- partial


def test_partial_scan_is_not_trustworthy(db, admin_user, two_hosts):
    a, b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _scan(
        db,
        admin_user,
        b,
        provenance.RESULT_PARTIAL,
        error_message="skipped 3 unreadable advisory line(s)",
    )

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["state"] == provenance.STATE_PARTIAL
    assert coverage["systems_partial"] == 1
    assert coverage["systems_scanned"] == 1
    assert coverage["coverage_complete"] is False
    assert coverage["counts_trustworthy"] is False
    assert "unreadable" in coverage["last_failure_detail"]


def test_mixed_coverage_never_reports_complete(db, admin_user, two_hosts):
    a, b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["state"] == provenance.STATE_PARTIAL
    assert coverage["systems_scanned"] == 1
    assert coverage["systems_never_scanned"] == 1
    assert coverage["coverage_complete"] is False
    assert coverage["counts_trustworthy"] is False
    assert "1 of 2" in coverage["coverage_detail"]


# --------------------------------------------------------------- complete


def test_completed_scan_with_zero_findings_is_a_trustworthy_zero(
    db, admin_user, two_hosts
):
    a, b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _scan(db, admin_user, b, provenance.RESULT_SUCCESS)

    posture = provenance.build_security_posture(
        db,
        system_ids={a.id, b.id},
        systems_with_security_updates=0,
        pending_security_updates=0,
    )
    assert posture["state"] == provenance.STATE_COMPLETE
    assert posture["counts_trustworthy"] is True
    assert posture["coverage_complete"] is True
    assert posture["pending_security_updates"] == 0
    assert posture["last_successful_scan_at"] is not None
    assert "All 2 systems" in posture["coverage_detail"]


def test_completed_scan_with_findings_keeps_the_count(db, admin_user, two_hosts):
    a, b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _scan(db, admin_user, b, provenance.RESULT_SUCCESS)

    posture = provenance.build_security_posture(
        db,
        system_ids={a.id, b.id},
        systems_with_security_updates=1,
        pending_security_updates=7,
    )
    assert posture["state"] == provenance.STATE_COMPLETE
    assert posture["counts_trustworthy"] is True
    assert posture["systems_with_security_updates"] == 1
    assert posture["pending_security_updates"] == 7


# --------------------------------------------------------------- scope


def test_counts_and_timestamps_are_limited_to_the_callers_scope(
    db, admin_user, two_hosts
):
    a, b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _scan(db, admin_user, b, provenance.RESULT_FAILURE, error_message="out of scope")

    scoped = _coverage(db, {a.id})
    assert scoped["systems_total"] == 1
    assert scoped["state"] == provenance.STATE_COMPLETE
    assert scoped["systems_failed"] == 0
    # The other host's failure text must not reach a caller who cannot see it.
    assert scoped["last_failure_detail"] is None

    both = _coverage(db, {a.id, b.id})
    assert both["state"] == provenance.STATE_PARTIAL
    assert both["last_failure_detail"] == "out of scope"


def test_empty_scope_yields_no_state_and_no_rows(db, admin_user, two_hosts):
    a, _b = two_hosts
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)

    coverage = _coverage(db, set())
    assert coverage["systems_total"] == 0
    assert coverage["state"] == provenance.STATE_NOT_SCANNED
    assert coverage["counts_trustworthy"] is False
    assert coverage["last_successful_scan_at"] is None
    assert coverage["coverage_detail"] == "No systems in scope."


def test_retired_hosts_do_not_hold_the_fleet_in_partial_coverage(
    db, admin_user, group, cred, seed_distro, two_hosts
):
    a, b = two_hosts
    retired = _mk_system(db, seed_distro, group, cred, "pra400-retired", "10.40.0.9")
    retired.status = "Decommissioned"
    db.commit()
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _scan(db, admin_user, b, provenance.RESULT_SUCCESS)

    coverage = _coverage(db, {a.id, b.id, retired.id})
    assert coverage["systems_total"] == 2
    assert coverage["state"] == provenance.STATE_COMPLETE
    assert coverage["counts_trustworthy"] is True


def test_scanning_hosts_outside_the_scope_are_ignored(db, admin_user, two_hosts):
    a, b = two_hosts
    _mk_operation(db, admin_user, systems=[b], status="running")
    _scan(db, admin_user, a, provenance.RESULT_SUCCESS)

    coverage = _coverage(db, {a.id})
    assert coverage["systems_scanning"] == 0
    assert coverage["state"] == provenance.STATE_COMPLETE


# --------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    "summary,expected",
    [
        ({"status": "success"}, provenance.RESULT_SUCCESS),
        (
            {"status": "success", "scan_state": provenance.STATE_COMPLETE},
            provenance.RESULT_SUCCESS,
        ),
        (
            {"status": "success", "scan_state": provenance.STATE_PARTIAL},
            provenance.RESULT_PARTIAL,
        ),
        (
            {"status": "error", "scan_state": provenance.STATE_FAILED},
            provenance.RESULT_FAILURE,
        ),
        ({"status": "already_running"}, provenance.RESULT_SKIPPED),
    ],
)
def test_result_status_for_scan(summary, expected):
    assert provenance.result_status_for_scan(summary) == expected


def test_sanitize_detail_flattens_and_bounds_failure_text():
    assert provenance.sanitize_detail(None) is None
    assert provenance.sanitize_detail("   ") is None
    assert provenance.sanitize_detail("a\tb\n c\x00d") == "a b c d"

    long_detail = provenance.sanitize_detail("x" * 500)
    assert len(long_detail) == provenance.FAILURE_DETAIL_MAX_CHARS
    assert long_detail.endswith("...")


# Sentinels shaped like the credential material an SSH or package-manager
# failure can drag into an exception string. Each is a literal that must not
# survive to a dashboard reader.
SECRET_SENTINELS = [
    (
        "sudo password assignment",
        "sudo: a password is required: password=Sentinel-PW-8f2c1d9a4b7e",
        "Sentinel-PW-8f2c1d9a4b7e",
    ),
    (
        "authorization header",
        'curl -H "Authorization: Bearer SentinelBearer8f2c1d9a4b7e" https://repo',
        "SentinelBearer8f2c1d9a4b7e",
    ),
    (
        "vault service token",
        "vault read failed: token s.SentinelVaultToken8f2c1d9a4b7e rejected",
        "s.SentinelVaultToken8f2c1d9a4b7e",
    ),
    (
        "license or access JWT",
        "refresh rejected: eyJhbGciOiJIUzI1NiJ9.SentinelJwtBody8f2c.SentinelJwtSig4b7e",
        "SentinelJwtBody8f2c",
    ),
    (
        "repository URL with inline credentials",
        "dnf: cannot open https://mirroruser:SentinelDsnPw8f2c1d9a@repo.internal/os",
        "SentinelDsnPw8f2c1d9a",
    ),
    (
        "api key assignment",
        'repo config invalid: api_key: "SentinelApiKey8f2c1d9a4b7e"',
        "SentinelApiKey8f2c1d9a4b7e",
    ),
    (
        "private key block",
        "agent key rejected:\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "SentinelPrivateKeyBody8f2c\n-----END OPENSSH PRIVATE KEY-----",
        "SentinelPrivateKeyBody8f2c",
    ),
]


@pytest.mark.parametrize(
    "label,message,secret",
    SECRET_SENTINELS,
    ids=[case[0] for case in SECRET_SENTINELS],
)
def test_sanitize_detail_redacts_secret_shapes(label, message, secret):
    """No secret-shaped literal survives the display boundary."""
    detail = provenance.sanitize_detail(message)
    assert secret not in detail
    assert "redacted" in detail


@pytest.mark.parametrize(
    "label,message,secret",
    SECRET_SENTINELS,
    ids=[case[0] for case in SECRET_SENTINELS],
)
def test_redact_result_message_strips_secrets_before_recording(label, message, secret):
    """Nothing secret-shaped is handed to the row writer.

    Unlike the display boundary, this keeps the message unflattened and
    unbounded: the stored row is diagnostics, and only the credential in it is
    unwanted.
    """
    recorded = provenance.redact_result_message(message)
    assert secret not in recorded
    assert "redacted" in recorded


def test_redact_result_message_passes_through_empty_messages():
    assert provenance.redact_result_message(None) is None
    assert provenance.redact_result_message("") == ""
    assert (
        provenance.redact_result_message("Permission denied (publickey,password).")
        == "Permission denied (publickey,password)."
    )


def test_sanitize_detail_keeps_non_secret_diagnostics():
    """Redaction must not cost the operator the reason the scan failed.

    These are the categories that make a failure actionable: which auth methods
    the host offered, which host could not be resolved, and what the package
    manager exited with. None is a secret, and all must survive intact.
    """
    for message in (
        "Permission denied (publickey,password).",
        "Could not resolve host: archive.ubuntu.com",
        "dnf updateinfo exited 141 with no output",
        "Connection timed out after 30s to 10.41.1.2:22",
    ):
        assert provenance.sanitize_detail(message) == message


def test_sanitize_detail_redacts_a_secret_that_straddles_the_length_bound():
    """Truncation is not redaction.

    A secret that begins inside the bound and runs past it would be cut in
    half by truncation alone, leaving a usable prefix on screen. Redaction
    runs first, on the text as recorded, so nothing of it remains.
    """
    secret = "SentinelStraddle8f2c1d9a4b7e6053f1a2b3c4d5e6f708"
    message = f"{'scan failed: ' * 14}password={secret} trailing context"
    assert message.index(secret) < provenance.FAILURE_DETAIL_MAX_CHARS
    assert message.index(secret) + len(secret) > provenance.FAILURE_DETAIL_MAX_CHARS

    detail = provenance.sanitize_detail(message)
    assert secret not in detail
    assert secret[:16] not in detail
    assert len(detail) <= provenance.FAILURE_DETAIL_MAX_CHARS


def test_secret_in_a_persisted_result_never_reaches_the_dashboard(
    db, admin_user, two_hosts
):
    """The display boundary redacts whatever a producer already stored.

    Rows recorded before this contract existed, or by any path that did not
    redact on the way in, are still read back through the same boundary.
    """
    a, _b = two_hosts
    secret = "SentinelStored8f2c1d9a4b7e"
    _scan(
        db,
        admin_user,
        a,
        provenance.RESULT_FAILURE,
        error_message=f"ssh failed: password={secret} for deploy@host",
    )

    coverage = _coverage(db)
    assert coverage["state"] == provenance.STATE_FAILED
    assert secret not in json.dumps(coverage)
    assert "redacted" in coverage["last_failure_detail"]
    # The non-secret half of the message is what makes it worth showing.
    assert "ssh failed" in coverage["last_failure_detail"]


def test_running_operation_with_unreadable_targets_marks_no_host_scanning(
    db, admin_user, two_hosts
):
    a, b = two_hosts
    op = FleetOperation(
        operation_type=provenance.SECURITY_SCAN_OPERATION_COHORT,
        user_id=admin_user.id,
        target_count=1,
        parameters="{not json",
        status="running",
        created_at=datetime.utcnow(),
    )
    db.add(op)
    db.commit()

    coverage = _coverage(db, {a.id, b.id})
    assert coverage["systems_scanning"] == 0
    assert coverage["state"] == provenance.STATE_NOT_SCANNED


# --------------------------------------------------------------- scan states


def _ssh_stub(monkeypatch, stdout, status="success", stderr=""):
    def fake_exec(self, system_id, command, timeout=60):
        return {"status": status, "stdout": stdout, "stderr": stderr}

    monkeypatch.setattr(
        "app.services.ssh_service.SSHService.execute_command", fake_exec
    )


def _mk_package(db, system, name):
    pkg = Package(system_id=system.id, name=name, installed_version="1.0")
    db.add(pkg)
    db.flush()
    return pkg


def test_scan_reports_complete_when_every_row_is_stored(
    db, group, cred, rocky_distro, monkeypatch
):
    host = _mk_system(db, rocky_distro, group, cred, "pra400-rpm-a", "10.40.1.1")
    _mk_package(db, host, "openssl")
    db.commit()
    _ssh_stub(
        monkeypatch,
        "RLSA-2024:7106 security Important openssl-1:3.0.7-27.el9.x86_64\n",
    )

    summary = PackageService(db).scan_security_updates(host.id)
    assert summary["status"] == "success"
    assert summary["scan_state"] == "complete"
    assert summary["updates_available"] == 1
    assert summary["unreadable_advisories"] == 0
    assert summary["unmatched_packages"] == []


def test_scan_reports_partial_when_an_advisory_row_is_unreadable(
    db, group, cred, rocky_distro, monkeypatch
):
    host = _mk_system(db, rocky_distro, group, cred, "pra400-rpm-b", "10.40.1.2")
    _mk_package(db, host, "openssl")
    db.commit()
    _ssh_stub(
        monkeypatch,
        "RLSA-2024:7106 security Important openssl-1:3.0.7-27.el9.x86_64\n"
        "RLSA-2024:7107 security Important garbled-advisory-row\n",
    )

    summary = PackageService(db).scan_security_updates(host.id)
    assert summary["status"] == "success"
    assert summary["scan_state"] == "partial"
    assert summary["unreadable_advisories"] == 1
    assert "incomplete" in summary["message"]


def test_scan_reports_partial_when_a_package_is_missing_from_inventory(
    db, group, cred, rocky_distro, monkeypatch
):
    host = _mk_system(db, rocky_distro, group, cred, "pra400-rpm-c", "10.40.1.3")
    _mk_package(db, host, "openssl")
    db.commit()
    _ssh_stub(
        monkeypatch,
        "RLSA-2024:7106 security Important openssl-1:3.0.7-27.el9.x86_64\n"
        "RLSA-2024:7108 security Moderate kernel-5.14.0-427.el9.x86_64\n",
    )

    summary = PackageService(db).scan_security_updates(host.id)
    assert summary["status"] == "success"
    assert summary["scan_state"] == "partial"
    assert summary["unmatched_packages"] == ["kernel"]
    assert provenance.result_status_for_scan(summary) == provenance.RESULT_PARTIAL


def test_scan_reports_failed_when_no_advisory_row_can_be_read(
    db, group, cred, rocky_distro, monkeypatch
):
    host = _mk_system(db, rocky_distro, group, cred, "pra400-rpm-d", "10.40.1.4")
    _mk_package(db, host, "openssl")
    db.commit()
    _ssh_stub(monkeypatch, "RLSA-2024:7107 security Important garbled-advisory-row\n")

    summary = PackageService(db).scan_security_updates(host.id)
    assert summary["status"] == "error"
    assert summary["scan_state"] == "failed"
    assert summary["unreadable_advisories"] == 1
    assert provenance.result_status_for_scan(summary) == provenance.RESULT_FAILURE


def test_scan_reports_failed_when_the_host_produced_no_usable_output(
    db, group, cred, seed_distro, monkeypatch
):
    host = _mk_system(db, seed_distro, group, cred, "pra400-apt-a", "10.40.1.5")
    db.commit()
    _ssh_stub(monkeypatch, "", status="success", stderr="connection reset")

    summary = PackageService(db).scan_security_updates(host.id)
    assert summary["status"] == "error"
    assert summary["scan_state"] == "failed"


def test_apt_scan_with_no_findings_is_a_complete_scan(
    db, group, cred, seed_distro, monkeypatch
):
    host = _mk_system(db, seed_distro, group, cred, "pra400-apt-b", "10.40.1.6")
    db.commit()
    _ssh_stub(monkeypatch, "\n")

    summary = PackageService(db).scan_security_updates(host.id)
    assert summary["status"] == "success"
    assert summary["scan_state"] == "complete"
    assert summary["updates_available"] == 0
    assert provenance.result_status_for_scan(summary) == provenance.RESULT_SUCCESS
