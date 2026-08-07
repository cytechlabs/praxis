"""PRA-155 #2c: GET /systems/{id}/facts.

Pins the read-endpoint contract:
  * Authenticated readable (any user, not admin-only).
  * Missing row → 200 with freshness="missing", facts=null. NOT 404.
  * Freshness verdict driven server-side from collected_at vs the
    24h staleness threshold.
  * Cloud metadata re-sanitized on read (defense-in-depth) — only
    allowlisted keys leak out, even if a row was somehow stored
    with extras.
  * Read MUST NOT trigger collection or mutate host_facts (no SSH
    spawn, no broker call, no row writes).
  * is_partial mirrors the presence of partial_errors; partial
    errors round-trip {key, error} verbatim.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.access_models import AuditEvent
from app.db.models import Credential, Group, HostFacts, System


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra155-read", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra155-read", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="read.example.com",
        ip_address="10.0.0.80",
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


def _seed_row(db, system_id, *, collected_at, **kwargs):
    row = HostFacts(
        system_id=system_id,
        schema_version=1,
        collected_at=collected_at,
        source_transport=kwargs.pop("source_transport", "ssh"),
        **kwargs,
    )
    db.add(row)
    db.commit()
    return row


# ---------------------------------------------------------------- happy


def test_read_returns_full_row_when_facts_exist(authed_client, db, host):
    _seed_row(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=10),
        cpu_model="AMD EPYC",
        cpu_cores=8,
        ram_total_bytes=16 * 1024**3,
        kernel_version="5.15.0",
        distro_id_facts="ubuntu",
        distro_release="22.04",
        package_manager="apt",
        virtualization="kvm",
        cloud_provider="aws",
        cloud_instance_metadata={
            "cloud_provider": "aws",
            "instance_id": "i-abc",
            "region": "us-east-1",
        },
        disks=[
            {
                "mountpoint": "/",
                "filesystem": "ext4",
                "total_bytes": 100,
                "free_bytes": 50,
            }
        ],
    )
    resp = authed_client.get(f"/systems/{host.id}/facts")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["system_id"] == host.id
    assert body["schema_version"] == 1
    assert body["freshness"] == "fresh"
    assert body["source_transport"] == "ssh"
    assert body["is_partial"] is False
    assert body["staleness_threshold_seconds"] == 24 * 60 * 60
    facts = body["facts"]
    assert facts["cpu_model"] == "AMD EPYC"
    assert facts["cpu_cores"] == 8
    # Wire shape mirrors ingest payload — distro_id, not distro_id_facts.
    assert facts["distro_id"] == "ubuntu"
    assert facts["package_manager"] == "apt"
    assert facts["cloud_instance_metadata"]["instance_id"] == "i-abc"
    assert len(facts["disks"]) == 1
    assert facts["disks"][0]["mountpoint"] == "/"


def test_read_missing_row_returns_200_with_missing_freshness(authed_client, db, host):
    """First-run state: no host_facts row yet. Must NOT 404 — UI
    treats 'missing' as a normal state with the same Refresh button."""
    resp = authed_client.get(f"/systems/{host.id}/facts")
    assert resp.status_code == 200
    body = resp.json()
    assert body["freshness"] == "missing"
    assert body["facts"] is None
    assert body["collected_at"] is None
    assert body["source_transport"] is None
    assert body["is_partial"] is False
    assert body["partial_errors"] == []
    assert body["staleness_threshold_seconds"] == 24 * 60 * 60


def test_read_unknown_system_returns_404(authed_client):
    resp = authed_client.get("/systems/999999/facts")
    assert resp.status_code == 404


# ---------------------------------------------------------------- freshness


def test_read_stale_when_collected_at_older_than_threshold(authed_client, db, host):
    _seed_row(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(hours=25),  # past 24h
        cpu_cores=2,
    )
    resp = authed_client.get(f"/systems/{host.id}/facts")
    assert resp.json()["freshness"] == "stale"


def test_read_fresh_at_threshold_boundary(authed_client, db, host):
    """Verdict: ``> threshold`` is stale; equal-to-or-younger is fresh."""
    _seed_row(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(hours=23, minutes=59),
        cpu_cores=2,
    )
    resp = authed_client.get(f"/systems/{host.id}/facts")
    assert resp.json()["freshness"] == "fresh"


# ---------------------------------------------------------------- partials


def test_read_round_trips_partial_errors(authed_client, db, host):
    _seed_row(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=5),
        cpu_cores=2,
        partial_errors=[
            {"key": "cloud_metadata", "error": "no cloud metadata service responded"},
            {"key": "uptime_seconds", "error": "/proc/uptime unreadable"},
        ],
    )
    body = authed_client.get(f"/systems/{host.id}/facts").json()
    assert body["is_partial"] is True
    err_keys = {e["key"] for e in body["partial_errors"]}
    assert err_keys == {"cloud_metadata", "uptime_seconds"}


# ---------------------------------------------------------------- defense


def test_read_strips_non_allowlisted_cloud_keys(authed_client, db, host):
    """Defense-in-depth: even if a row was somehow stored with
    credential-shaped cloud metadata (schema-change race, restored
    backup pre-allowlist), the read endpoint never leaks them."""
    _seed_row(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=5),
        cloud_provider="aws",
        cloud_instance_metadata={
            "cloud_provider": "aws",
            "instance_id": "i-abc",
            "region": "us-east-1",
            # These should be filtered defensively even though
            # FactsService's write-side sanitizer would have stripped
            # them in the first place.
            "iam_role_credentials": {"access_key": "AKIA"},
            "user_data": "#!/bin/bash",
            "ssh_keys": ["ssh-rsa AAAA"],
        },
    )
    body = authed_client.get(f"/systems/{host.id}/facts").json()
    md = body["facts"]["cloud_instance_metadata"]
    assert set(md.keys()) <= {
        "cloud_provider",
        "instance_id",
        "region",
        "zone",
    }
    # No rejected key names exposed (operator-facing read API, not
    # an audit endpoint).
    body_text = str(body)
    assert "iam_role_credentials" not in body_text
    assert "AKIA" not in body_text
    assert "ssh_keys" not in body_text


# ---------------------------------------------------------------- read is read


def test_read_does_not_trigger_collection_or_mutate_row(authed_client, db, host):
    """The read endpoint MUST be a pure read. No SSH spawn, no broker
    call, no INSERT/UPDATE on host_facts."""
    seeded_at = datetime.utcnow() - timedelta(minutes=10)
    row = _seed_row(db, host.id, collected_at=seeded_at, cpu_cores=4)
    row_pk = row.id

    audit_count_before = (
        db.query(AuditEvent).filter(AuditEvent.target_system_id == host.id).count()
    )

    with patch(
        "app.services.ssh_facts_collector_service.collect_and_ingest"
    ) as ssh_mock, patch(
        "app.services.broker_client.BrokerClient.facts"
    ) as broker_facts_mock, patch(
        "app.services.facts_service.ingest"
    ) as ingest_mock:
        resp = authed_client.get(f"/systems/{host.id}/facts")

    assert resp.status_code == 200
    assert ssh_mock.call_count == 0
    assert broker_facts_mock.call_count == 0
    assert ingest_mock.call_count == 0

    # Row identity + collected_at unchanged.
    db.expire_all()
    refreshed = db.query(HostFacts).filter_by(system_id=host.id).one()
    assert refreshed.id == row_pk
    assert refreshed.collected_at == seeded_at
    # No new audit rows from a read.
    audit_count_after = (
        db.query(AuditEvent).filter(AuditEvent.target_system_id == host.id).count()
    )
    assert audit_count_after == audit_count_before
