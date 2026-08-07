"""PRA-155 #2b-b: facts refresh scheduler sweep.

Pins the skip-fresh / refresh-stale logic. The sweep is intentionally
SSH-only (the scheduler doesn't drive agent ops on a 30-min cadence;
those are operator-triggered) so we can assert routing without
broker plumbing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.models import Credential, Group, HostFacts, System
from app.services import facts_refresh_sweep, facts_service


@pytest.fixture
def fleet(db, seed_distro):
    g = Group(name="pra155-sweep", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra155-sweep", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    rows = []
    for i in range(3):
        s = System(
            hostname=f"sweep-{i}.example.com",
            ip_address=f"10.0.0.{100 + i}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=g.id,
            credentials_id=cred.id,
        )
        db.add(s)
        rows.append(s)
    # One decommissioned host — sweep MUST skip.
    decom = System(
        hostname="sweep-decom.example.com",
        ip_address="10.0.0.200",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Decommissioned",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(decom)
    db.flush()
    db.commit()
    return rows


def _stub_ingest(*_a, **_kw):
    """Replace collect_and_ingest with a no-op that returns a fake
    ingest result. The sweep doesn't inspect the result; it just
    increments the refreshed counter on success."""
    return facts_service.IngestResult(
        status="upserted", row=None, rejected_keys=[], partial_errors=[]
    )


def test_sweep_refreshes_all_when_no_facts_rows(db, fleet):
    """Cold start: no host_facts rows yet → every Active host should
    get refreshed; the decommissioned host should be skipped."""
    with patch(
        "app.services.ssh_facts_collector_service.collect_and_ingest", new=_stub_ingest
    ):
        stats = facts_refresh_sweep.run_facts_refresh_sweep(db)
    assert stats["considered"] == 3  # decommissioned host filtered out
    assert stats["skipped_fresh"] == 0
    assert stats["refreshed"] == 3
    assert stats["ssh_failed"] == 0


def test_sweep_skips_fresh_hosts(db, fleet):
    """A host whose host_facts.collected_at is younger than the
    interval must NOT get re-probed."""
    fresh = datetime.utcnow() - timedelta(minutes=30)  # well within 6h
    db.add(
        HostFacts(
            system_id=fleet[0].id,
            schema_version=1,
            collected_at=fresh,
            source_transport="ssh",
        )
    )
    db.commit()

    called_system_ids: set = set()

    def _record_ingest(_db, *, system_id):
        called_system_ids.add(system_id)
        return _stub_ingest()

    with patch(
        "app.services.ssh_facts_collector_service.collect_and_ingest",
        new=_record_ingest,
    ):
        stats = facts_refresh_sweep.run_facts_refresh_sweep(db)
    assert stats["considered"] == 3
    assert stats["skipped_fresh"] == 1
    assert stats["refreshed"] == 2
    # Fresh host did not get an ingest call.
    assert fleet[0].id not in called_system_ids


def test_sweep_refreshes_stale_hosts(db, fleet):
    """A host whose collected_at is OLDER than the interval gets
    refreshed."""
    stale = datetime.utcnow() - timedelta(hours=12)  # past 6h cadence
    db.add(
        HostFacts(
            system_id=fleet[0].id,
            schema_version=1,
            collected_at=stale,
            source_transport="ssh",
        )
    )
    db.commit()
    with patch(
        "app.services.ssh_facts_collector_service.collect_and_ingest", new=_stub_ingest
    ):
        stats = facts_refresh_sweep.run_facts_refresh_sweep(db)
    assert stats["refreshed"] == 3
    assert stats["skipped_fresh"] == 0


def test_sweep_records_ssh_failures_and_keeps_going(db, fleet):
    """One bad host shouldn't abort the rest of the sweep."""
    from app.services.ssh_facts_collector_service import SshFactsCollectionError

    call_count = {"n": 0}

    def _maybe_fail(*_a, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise SshFactsCollectionError("transient")
        return _stub_ingest()

    with patch(
        "app.services.ssh_facts_collector_service.collect_and_ingest",
        new=_maybe_fail,
    ):
        stats = facts_refresh_sweep.run_facts_refresh_sweep(db)
    assert stats["considered"] == 3
    assert stats["refreshed"] == 2
    assert stats["ssh_failed"] == 1
