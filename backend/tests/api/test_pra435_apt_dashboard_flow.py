"""PRA-435: fleet security coverage follows APT evidence through failure and recovery.

The scan routes run against a scripted APT host while operation recording
writes real rows, so ``/fleet/dashboard`` is derived exactly as in production.
The sequence covers a host migrated with unknown freshness, a verified security
scan, a later failed ordinary refresh, an ordinary recovery that must not
re-certify the older counts, and a fresh security scan that does.
"""

import json
from datetime import datetime

import pytest

from app.db.models import (
    Credential,
    FleetOperation,
    FleetOperationResult,
    Group,
    System,
)
from app.services import fleet_operation_service as fos
from app.services import security_scan_status_service as provenance
from tests.helpers.apt_scripted_host import (
    CLEAN_REFRESH,
    UNAUTHORIZED_REFRESH,
    ScriptedHost,
)


@pytest.fixture
def host_script(monkeypatch):
    script = ScriptedHost()
    script.install(monkeypatch)
    return script


@pytest.fixture(autouse=True)
def recorded_operations(db, monkeypatch):
    """Persist operation rows on the test session so coverage can read them."""

    def start(operation_type, user_id, target_count, parameters=None):
        op = FleetOperation(
            operation_type=operation_type,
            user_id=user_id,
            target_count=target_count,
            parameters=json.dumps(parameters or {}),
            status="running",
            created_at=datetime.utcnow(),
        )
        db.add(op)
        db.flush()
        return op.id

    def record(op_id, system_id, status, error_message=None):
        db.add(
            FleetOperationResult(
                fleet_operation_id=op_id,
                system_id=system_id,
                status=status,
                error_message=error_message,
                created_at=datetime.utcnow(),
            )
        )
        db.flush()

    def complete(op_id, success_count, failure_count, status=None):
        op = db.query(FleetOperation).filter(FleetOperation.id == op_id).one()
        op.status = status or "completed"
        db.flush()

    monkeypatch.setattr(fos, "start_operation", start)
    monkeypatch.setattr(fos, "record_result", record)
    monkeypatch.setattr(fos, "complete_operation", complete)


@pytest.fixture
def apt_host(db, seed_distro):
    cred = Credential(name="pra435-flow-cred", auth_method="ssh_key", username="root")
    group = Group(name="pra435-flow-group", description="x")
    db.add_all([cred, group])
    db.flush()
    system = System(
        hostname="pra435-flow-host",
        ip_address="10.44.0.1",
        distro_id=seed_distro.id,
        os_version=seed_distro.version,
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(system)
    db.commit()
    return system


def _posture(client, system):
    body = client.get("/fleet/dashboard").json()["security_posture"]
    return body


def _freshness(client, system):
    rows = client.get("/packages/metadata-freshness").json()
    return next(r for r in rows if r["system_id"] == system.id)


def _legacy_success(db, user, system):
    """A security success recorded before freshness existed."""
    op = FleetOperation(
        operation_type=provenance.SECURITY_SCAN_OPERATION_SINGLE,
        user_id=user.id,
        target_count=1,
        parameters=json.dumps({"system_ids": [system.id]}),
        status="completed",
        created_at=datetime.utcnow(),
    )
    db.add(op)
    db.flush()
    db.add(
        FleetOperationResult(
            fleet_operation_id=op.id,
            system_id=system.id,
            status=provenance.RESULT_SUCCESS,
            created_at=datetime.utcnow(),
        )
    )
    db.commit()


def test_migrated_host_with_a_legacy_success_is_not_trusted_until_scanned(
    authed_client, db, admin_user, apt_host, host_script
):
    _legacy_success(db, admin_user, apt_host)

    assert _freshness(authed_client, apt_host)["state"] == "unknown"
    posture = _posture(authed_client, apt_host)
    assert posture["counts_trustworthy"] is False
    assert posture["coverage_complete"] is False
    assert posture["state"] != provenance.STATE_COMPLETE

    # The host's inventory must exist before a security scan can match rows.
    assert authed_client.post(f"/packages/{apt_host.id}/scan").status_code == 200
    assert _posture(authed_client, apt_host)["counts_trustworthy"] is False

    scanned = authed_client.post(f"/packages/{apt_host.id}/scan-security").json()
    assert scanned["scan_state"] == provenance.STATE_COMPLETE
    posture = _posture(authed_client, apt_host)
    assert posture["counts_trustworthy"] is True
    assert posture["coverage_complete"] is True
    assert posture["state"] == provenance.STATE_COMPLETE


def test_failure_then_ordinary_recovery_cannot_recertify_older_counts(
    authed_client, db, apt_host, host_script
):
    assert authed_client.post(f"/packages/{apt_host.id}/scan").status_code == 200
    first = authed_client.post(f"/packages/{apt_host.id}/scan-security").json()
    assert first["scan_state"] == provenance.STATE_COMPLETE
    assert _posture(authed_client, apt_host)["counts_trustworthy"] is True
    verified_at = _freshness(authed_client, apt_host)["refreshed_at"]

    # An ordinary refresh now fails: the earlier security success no longer
    # stands on verified metadata, and the dashboard says so.
    host_script.refresh = UNAUTHORIZED_REFRESH
    failed = authed_client.post(f"/packages/{apt_host.id}/scan").json()
    assert failed["status"] == "success"  # SSH is fine
    assert failed["scan_state"] == provenance.STATE_PARTIAL
    fresh = _freshness(authed_client, apt_host)
    assert fresh["state"] == "partial" and fresh["refreshed_at"] == verified_at
    posture = _posture(authed_client, apt_host)
    assert posture["counts_trustworthy"] is False
    assert posture["coverage_complete"] is False
    assert posture["state"] == provenance.STATE_PARTIAL
    assert posture["systems_metadata_unverified"] >= 1

    # An ordinary recovery alone does not re-certify the older security counts.
    host_script.refresh = CLEAN_REFRESH
    recovered = authed_client.post(f"/packages/{apt_host.id}/scan").json()
    assert recovered["scan_state"] == provenance.STATE_COMPLETE
    assert _freshness(authed_client, apt_host)["state"] == "fresh"
    posture = _posture(authed_client, apt_host)
    assert posture["counts_trustworthy"] is False
    assert posture["coverage_complete"] is False

    # Only a security scan against the refreshed metadata certifies counts.
    again = authed_client.post(f"/packages/{apt_host.id}/scan-security").json()
    assert again["scan_state"] == provenance.STATE_COMPLETE
    posture = _posture(authed_client, apt_host)
    assert posture["counts_trustworthy"] is True
    assert posture["coverage_complete"] is True


def test_security_scan_against_failing_metadata_is_recorded_partial(
    authed_client, apt_host, host_script
):
    authed_client.post(f"/packages/{apt_host.id}/scan")
    host_script.refresh = UNAUTHORIZED_REFRESH
    result = authed_client.post(f"/packages/{apt_host.id}/scan-security").json()
    assert result["scan_state"] == provenance.STATE_PARTIAL
    assert "enterprise.example.com" in result["apt_metadata"]["detail"]
    posture = _posture(authed_client, apt_host)
    assert posture["counts_trustworthy"] is False
    assert posture["systems_partial"] >= 1
