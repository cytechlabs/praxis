"""PRA-240: GET /lifecycle/summary unknown-reason breakdown + 1.0 seed coverage.

The dashboard's "Unknown" tile must be actionable, so the summary aggregates WHY
hosts are unknown (stale facts / missing distro facts / no lifecycle seed row)
alongside the existing flat bucket counts. Also pins that the shipped seed now
covers current 1.0-era releases so a fresh supported host resolves to
``supported`` rather than ``unknown``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import app.db as app_db
from app.db.models import Credential, DistroLifecycle, Group, HostFacts, System


@pytest.fixture
def lifecycle_seed(db):
    """Wipe + seed a current-release row (Ubuntu 26.04, well in the future)."""
    db.query(DistroLifecycle).delete()
    db.flush()
    today = datetime.utcnow().date()
    db.add(
        DistroLifecycle(
            distro_id="ubuntu",
            release="26.04",
            eol_date=today + timedelta(days=1500),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        )
    )
    db.commit()


@pytest.fixture
def mixed_fleet(db, seed_distro, lifecycle_seed):
    """One host per outcome: supported, and each of the three unknown reasons."""
    g = Group(name="pra240", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra240", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()

    def _mk(hostname, ip):
        s = System(
            hostname=hostname,
            ip_address=ip,
            distro_id=seed_distro.id,
            os_version="26.04",
            status="Active",
            group_id=g.id,
            credentials_id=cred.id,
        )
        db.add(s)
        db.flush()
        return s

    h_supported = _mk("sup-240.example.com", "10.2.40.1")
    h_stale = _mk("stale-240.example.com", "10.2.40.2")
    h_missing_distro = _mk("nodistro-240.example.com", "10.2.40.3")
    h_no_row = _mk("norow-240.example.com", "10.2.40.4")

    fresh_at = datetime.utcnow() - timedelta(minutes=5)
    stale_at = datetime.utcnow() - timedelta(hours=48)  # > 24h staleness threshold
    db.add_all(
        [
            # Current supported release from the (test) seed -> supported.
            HostFacts(
                system_id=h_supported.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="26.04",
            ),
            # Fresh distro/release but the facts are stale -> freshness.
            HostFacts(
                system_id=h_stale.id,
                schema_version=1,
                collected_at=stale_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="26.04",
            ),
            # Fresh facts row but no distro id/release -> missing_distro_facts.
            HostFacts(
                system_id=h_missing_distro.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts=None,
                distro_release=None,
            ),
            # Fresh facts, distro/release not in the seed -> no_lifecycle_row.
            HostFacts(
                system_id=h_no_row.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="fedora",
                distro_release="42",
            ),
        ]
    )
    db.commit()
    return {
        "supported": h_supported,
        "stale": h_stale,
        "missing_distro": h_missing_distro,
        "no_row": h_no_row,
    }


def test_summary_exposes_stable_unknown_reasons_shape(authed_client, mixed_fleet):
    body = authed_client.get("/lifecycle/summary").json()
    assert "unknown_reasons" in body
    assert set(body["unknown_reasons"].keys()) == {
        "freshness",
        "missing_distro_facts",
        "no_lifecycle_row",
        "other",
    }
    # Existing flat shape stays backward-compatible.
    assert set(body["counts"].keys()) == {
        "supported",
        "approaching_eol",
        "unsupported",
        "unknown",
    }


def test_summary_breakdown_counts_each_unknown_reason(authed_client, mixed_fleet):
    body = authed_client.get("/lifecycle/summary").json()
    counts = body["counts"]
    reasons = body["unknown_reasons"]

    # The current supported release resolves to supported (seed coverage works).
    assert counts["supported"] >= 1

    # Each unknown reason my fixture creates is represented. Uses >= (not ==)
    # because compute_for_all_systems aggregates the whole DB and other fixtures
    # may add no-facts hosts; the structural invariant below is the exact check.
    assert reasons["freshness"] >= 1
    assert reasons["missing_distro_facts"] >= 1
    assert reasons["no_lifecycle_row"] >= 1

    # Structural invariant: the reason breakdown exactly partitions the unknown
    # bucket (this must hold regardless of how many hosts exist).
    assert sum(reasons.values()) == counts["unknown"]
    assert counts["unknown"] >= 3


def test_summary_requires_authentication(client):
    assert client.get("/lifecycle/summary").status_code in (401, 403)


# ---------------------------------------------------------------- seed coverage


def _seed_entries():
    path = Path(app_db.__file__).parent / "seed_data" / "distro_lifecycle.json"
    return json.loads(path.read_text())


@pytest.mark.parametrize(
    "distro_id,release",
    [
        ("ubuntu", "26.04"),
        ("debian", "13"),
        ("rhel", "10"),
        ("rocky", "10"),
        ("almalinux", "10"),
    ],
)
def test_shipped_seed_covers_current_release(distro_id, release):
    """Each current 1.0-era release has at least one standard-support row whose
    EOL is in the future relative to the seed's as_of date."""
    data = _seed_entries()
    as_of = datetime.strptime(data["_meta"]["as_of"], "%Y-%m-%d").date()
    rows = [
        e
        for e in data["entries"]
        if e["distro_id"] == distro_id
        and e["release"] == release
        and e["support_kind"] == "standard"
    ]
    assert rows, f"no standard-support seed row for {distro_id} {release}"
    eol = datetime.strptime(rows[0]["eol_date"], "%Y-%m-%d").date()
    assert eol > as_of, f"{distro_id} {release} standard EOL {eol} is not in the future"
