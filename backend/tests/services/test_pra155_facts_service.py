"""PRA-155 #2a: FactsService.ingest unit tests.

Covers the canonical persistence path's locked rules:
  * Unknown payload keys dropped, recorded in audit.
  * Cloud metadata sanitizer keeps only the v1 allowlist; rejected
    keys are reported (names only, never values).
  * Stale-write rejection (older collected_at no-ops by default).
  * No silent merge — fields absent from a fresh ingest land NULL on
    the upserted row, regardless of what the prior row had.
  * Disks shape enforcement: malformed entries land in partial_errors.
  * Audit row emitted on every call (success + denied + noop_empty).
  * source_transport must be one of agent/ssh/manual.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.access_models import AuditEvent
from app.db.models import Credential, Group, HostFacts, System
from app.services import facts_service

# ---------------------------------------------------------------- fixtures


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra155-facts", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-facts", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="facts-host.example.com",
        ip_address="10.0.0.50",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    db.commit()
    return sys_row


def _audit_rows(db, system_id):
    return (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "host_facts.ingest",
            AuditEvent.target_system_id == system_id,
        )
        .order_by(AuditEvent.id.asc())
        .all()
    )


# ---------------------------------------------------------------- happy path


def test_ingest_upserts_and_normalizes(db, host):
    payload = {
        "schema_version": 1,
        "collected_at": "2026-05-01T12:00:00",
        "cpu_model": "AMD EPYC 7B12",
        "cpu_cores": 8,
        "ram_total_bytes": 16 * 1024 * 1024 * 1024,
        "kernel_version": "5.15.0-101-generic",
        "distro_id": "ubuntu",
        "distro_release": "22.04",
        "uptime_seconds": 12345,
        "reboot_required": False,
        "package_manager": "apt",
        "package_manager_version": "2.4.10",
        "virtualization": "kvm",
        "cloud_provider": "aws",
        "cloud_instance_metadata": {
            "cloud_provider": "aws",
            "instance_id": "i-0123456789abcdef0",
            "region": "us-east-1",
            "zone": "us-east-1a",
        },
        "disks": [
            {
                "mountpoint": "/",
                "filesystem": "ext4",
                "total_bytes": 100_000_000_000,
                "free_bytes": 60_000_000_000,
            }
        ],
    }
    result = facts_service.ingest(
        db, system_id=host.id, payload=payload, source_transport="agent"
    )
    assert result.status == "upserted"
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert row.cpu_model == "AMD EPYC 7B12"
    assert row.cpu_cores == 8
    assert row.distro_id_facts == "ubuntu"
    assert row.cloud_provider == "aws"
    # Sanitizer preserves v1 keys verbatim.
    assert set(row.cloud_instance_metadata.keys()) == {
        "cloud_provider",
        "instance_id",
        "region",
        "zone",
    }
    assert row.disks and row.disks[0]["mountpoint"] == "/"
    assert row.source_transport == "agent"
    audits = _audit_rows(db, host.id)
    assert len(audits) == 1
    assert audits[0].outcome == "success"


# ---------------------------------------------------------------- sanitizer


def test_unknown_scalar_keys_dropped_and_recorded(db, host):
    payload = {
        "cpu_model": "x",
        "package_inventory": ["nginx", "openssh"],  # dropped — not in allowlist
        "totally_made_up": 42,
    }
    result = facts_service.ingest(
        db, system_id=host.id, payload=payload, source_transport="agent"
    )
    assert result.status == "upserted"
    assert "package_inventory" in result.rejected_keys
    assert "totally_made_up" in result.rejected_keys
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    # Unknown keys did not become columns; cpu_model stuck.
    assert row.cpu_model == "x"


def test_cloud_metadata_strips_credentials_and_records_rejected_keys(db, host):
    payload = {
        "cpu_model": "x",
        "cloud_instance_metadata": {
            "cloud_provider": "aws",
            "instance_id": "i-abc",
            "region": "us-west-2",
            # Anything below MUST be scrubbed.
            "iam_role_credentials": {"access_key": "AKIA...", "secret": "..."},
            "user_data": "#!/bin/bash\nrm -rf /",
            "ssh_keys": ["ssh-rsa AAAAB..."],
            "instance_profile_arn": "arn:aws:iam::...",
        },
    }
    result = facts_service.ingest(
        db, system_id=host.id, payload=payload, source_transport="agent"
    )
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert row.cloud_instance_metadata == {
        "cloud_provider": "aws",
        "instance_id": "i-abc",
        "region": "us-west-2",
    }
    # Rejected key names recorded in result + audit context.
    assert "iam_role_credentials" in result.rejected_keys
    assert "user_data" in result.rejected_keys
    assert "ssh_keys" in result.rejected_keys
    audits = _audit_rows(db, host.id)
    ctx = audits[-1].context_json
    # Audit context lists rejected key NAMES; values never appear.
    assert "iam_role_credentials" in ctx
    assert "AKIA" not in ctx
    assert "rm -rf" not in ctx


def test_disks_malformed_entries_land_in_partial_errors(db, host):
    payload = {
        "disks": [
            {
                "mountpoint": "/",
                "filesystem": "ext4",
                "total_bytes": 100,
                "free_bytes": 50,
            },
            {"mountpoint": "/data"},  # missing keys
            "not-an-object",  # not a dict
            {
                "mountpoint": "/var",
                "filesystem": "xfs",
                "total_bytes": "lots",  # non-numeric
                "free_bytes": 0,
            },
        ]
    }
    result = facts_service.ingest(
        db, system_id=host.id, payload=payload, source_transport="agent"
    )
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert len(row.disks) == 1
    assert row.disks[0]["mountpoint"] == "/"
    error_keys = [e["key"] for e in row.partial_errors]
    assert "disks[1]" in error_keys
    assert "disks[2]" in error_keys
    assert "disks[3]" in error_keys
    # Result mirrors what the row carries.
    assert len(result.partial_errors) >= 3


# ---------------------------------------------------------------- stale rejection


def test_stale_collected_at_is_rejected_no_op(db, host):
    fresh = datetime(2026, 5, 1, 12, 0, 0)
    stale = fresh - timedelta(hours=1)

    facts_service.ingest(
        db,
        system_id=host.id,
        payload={"cpu_cores": 16, "collected_at": fresh.isoformat()},
        source_transport="agent",
    )
    result = facts_service.ingest(
        db,
        system_id=host.id,
        payload={"cpu_cores": 4, "collected_at": stale.isoformat()},
        source_transport="agent",
    )
    assert result.status == "rejected_stale"
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    # Row unchanged — the stale write didn't overwrite cpu_cores=16.
    assert row.cpu_cores == 16
    audits = _audit_rows(db, host.id)
    assert audits[-1].outcome == "denied"
    assert "rejected_stale" in audits[-1].context_json


def test_force_overrides_stale_rejection(db, host):
    fresh = datetime(2026, 5, 1, 12, 0, 0)
    stale = fresh - timedelta(hours=1)

    facts_service.ingest(
        db,
        system_id=host.id,
        payload={"cpu_cores": 16, "collected_at": fresh.isoformat()},
        source_transport="agent",
    )
    result = facts_service.ingest(
        db,
        system_id=host.id,
        payload={"cpu_cores": 4, "collected_at": stale.isoformat()},
        source_transport="agent",
        force=True,
    )
    assert result.status == "upserted"
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert row.cpu_cores == 4


# ---------------------------------------------------------------- no silent merge


def test_no_silent_merge_missing_fields_become_null(db, host):
    facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            "cpu_model": "first",
            "kernel_version": "5.15.0",
            "ram_total_bytes": 8 * 1024**3,
            "collected_at": "2026-05-01T10:00:00",
        },
        source_transport="agent",
    )
    facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            # Only kernel reported on the second pass.
            "kernel_version": "5.15.1",
            "collected_at": "2026-05-01T11:00:00",
        },
        source_transport="agent",
    )
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert row.kernel_version == "5.15.1"
    # cpu_model and ram_total_bytes were on the prior row; the new
    # ingest didn't carry them. They must be NULL, not stale-merged.
    assert row.cpu_model is None
    assert row.ram_total_bytes is None


# ---------------------------------------------------------------- empty / errors


def test_empty_payload_audits_as_noop_empty(db, host):
    result = facts_service.ingest(
        db, system_id=host.id, payload={}, source_transport="agent"
    )
    assert result.status == "noop_empty"
    audits = _audit_rows(db, host.id)
    assert audits[-1].outcome == "success"
    assert "noop_empty" in audits[-1].context_json


def test_invalid_source_transport_raises(db, host):
    with pytest.raises(facts_service.FactsIngestError):
        facts_service.ingest(
            db,
            system_id=host.id,
            payload={"cpu_model": "x"},
            source_transport="usb-stick",
        )


def test_unknown_system_id_raises(db):
    with pytest.raises(facts_service.FactsIngestError):
        facts_service.ingest(
            db,
            system_id=999_999,
            payload={"cpu_model": "x"},
            source_transport="agent",
        )


def test_scalar_type_mismatch_lands_in_partial_errors(db, host):
    """Bad agent payloads must not poison the whole flush — a
    string in cpu_cores or a dict in cloud_provider lands in
    partial_errors and the rest of the row persists."""
    payload = {
        "cpu_model": "good string",
        "cpu_cores": "many",  # type mismatch — should be int
        "ram_total_bytes": True,  # bool-as-int trap
        "reboot_required": "false",  # string, should be bool
        "cloud_provider": {"oops": "object"},  # dict, should be str
        "uptime_seconds": -5,  # negative — violates CHECK
    }
    result = facts_service.ingest(
        db, system_id=host.id, payload=payload, source_transport="agent"
    )
    assert result.status == "upserted"
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    # Good field stuck.
    assert row.cpu_model == "good string"
    # All malformed fields landed NULL — none reached the DB.
    assert row.cpu_cores is None
    assert row.ram_total_bytes is None
    assert row.reboot_required is None
    assert row.cloud_provider is None
    assert row.uptime_seconds is None
    err_keys = {e["key"] for e in row.partial_errors}
    assert {
        "cpu_cores",
        "ram_total_bytes",
        "reboot_required",
        "cloud_provider",
        "uptime_seconds",
    } <= err_keys


def test_invalid_collected_at_with_existing_row_is_rejected(db, host):
    """A malformed/missing collected_at must NOT overwrite a real row
    — utcnow() would otherwise look fresher than any real timestamp."""
    facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            "cpu_cores": 16,
            "collected_at": "2026-05-01T12:00:00",
        },
        source_transport="agent",
    )
    result = facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            "cpu_cores": 4,
            "collected_at": "not-a-timestamp",
        },
        source_transport="agent",
    )
    assert result.status == "rejected_invalid_timestamp"
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert row.cpu_cores == 16  # unchanged
    audits = _audit_rows(db, host.id)
    assert audits[-1].outcome == "denied"
    assert "rejected_invalid_timestamp" in audits[-1].context_json


def test_invalid_only_payload_with_bad_timestamp_does_not_overwrite_row(db, host):
    """A report whose ONLY content is malformed scalars (no valid
    fields land) plus a bad timestamp must not slip past the
    fallback-rejection check. Without this, partial_errors makes
    has_anything True downstream and an upsert would clobber a real
    row with NULL fields and utcnow()."""
    # Establish a real row first.
    facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            "cpu_cores": 32,
            "kernel_version": "6.1.0",
            "collected_at": "2026-05-01T12:00:00",
        },
        source_transport="agent",
    )
    real = db.query(HostFacts).filter_by(system_id=host.id).one()
    real_ts = real.collected_at

    # Invalid-only payload + malformed timestamp.
    result = facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            "cpu_cores": "many",  # type mismatch
            "collected_at": "not-a-timestamp",
        },
        source_transport="agent",
    )
    assert result.status == "rejected_invalid_timestamp"
    db.expire_all()
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    # Real row preserved end-to-end.
    assert row.cpu_cores == 32
    assert row.kernel_version == "6.1.0"
    assert row.collected_at == real_ts


def test_invalid_collected_at_first_ingest_accepted_with_partial_error(db, host):
    """First ingest has no row to protect; we accept the fallback
    timestamp but the substitution is recorded in partial_errors so
    operators can spot a chronically-broken collector."""
    result = facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            "cpu_cores": 4,
            "collected_at": "garbage",
        },
        source_transport="agent",
    )
    assert result.status == "upserted"
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert row.cpu_cores == 4
    keys = [e["key"] for e in row.partial_errors]
    assert "collected_at" in keys


def test_disks_strip_extras_to_locked_v1_shape(db, host):
    """Storage contract matches API contract: disks rows must contain
    EXACTLY the four allowed keys — nothing collector-specific leaks
    into the canonical JSONB."""
    payload = {
        "disks": [
            {
                "mountpoint": "/",
                "filesystem": "ext4",
                "total_bytes": 100,
                "free_bytes": 50,
                # All of these MUST be stripped:
                "uuid": "abc-123",
                "device": "/dev/sda1",
                "label": "root",
                "vendor_specific_blob": {"weird": True},
            }
        ]
    }
    result = facts_service.ingest(
        db, system_id=host.id, payload=payload, source_transport="agent"
    )
    assert result.status == "upserted"
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert len(row.disks) == 1
    assert set(row.disks[0].keys()) == {
        "mountpoint",
        "filesystem",
        "total_bytes",
        "free_bytes",
    }


def test_partial_errors_from_collector_preserved(db, host):
    """Caller-supplied per-key errors (e.g. SSH collector probe failed)
    must be preserved verbatim alongside any sanitizer-found ones."""
    payload = {
        "cpu_model": "x",
        "partial_errors": [
            {"key": "uptime_seconds", "error": "/proc/uptime unreadable"},
        ],
    }
    result = facts_service.ingest(
        db, system_id=host.id, payload=payload, source_transport="agent"
    )
    row = db.query(HostFacts).filter_by(system_id=host.id).one()
    keys = [e["key"] for e in row.partial_errors]
    assert "uptime_seconds" in keys
    assert result.partial_errors[0]["key"] == "uptime_seconds"
