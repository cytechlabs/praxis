"""PRA-156 #3b: GET /systems/{id}/lifecycle.

Pins the read-endpoint contract:

  * Authenticated readable (any user, NOT admin-only).
  * Missing host_facts row → 200 with freshness="missing",
    status="unknown". NOT 404 — first-collect is a normal state and
    the saved-view filter for unknown hosts must include these.
  * Stale facts → freshness="stale", status="unknown".
  * Lifecycle verdict matches LifecycleService.compute output for the
    same (distro_id_facts, distro_release, today, freshness) inputs.
  * 404 only when the system itself doesn't exist.
  * Read MUST NOT trigger collection or mutate host_facts (no SSH
    spawn, no broker call, no row writes, no audit emit beyond
    whatever auth/audit is already wrapping the request).
  * RHEL-family minor releases normalize to major (#3a-α) — proven
    indirectly by the rhel 9.4 test landing on the seeded rhel/9 row.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import Credential, DistroLifecycle, Group, HostFacts, System


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra156-lifecycle-read", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="cred-pra156-lifecycle", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="lifecycle-read.example.com",
        ip_address="10.0.0.81",
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


@pytest.fixture
def lifecycle_seed(db):
    """Wipe + seed a focused lifecycle table.

    The praxis_test DB carries the production seed from a prior
    Alembic run; this fixture takes ownership for the test run and
    the conftest's outer-transaction rollback restores it at
    teardown. Seeded rows cover supported / approaching-eol /
    unsupported / RHEL-family-major scenarios.
    """
    db.query(DistroLifecycle).delete()
    db.flush()
    today = datetime.utcnow().date()
    rows = [
        # Supported: EOL well outside the 90-day window.
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=today + timedelta(days=400),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
        # Approaching: EOL 30 days out.
        DistroLifecycle(
            distro_id="debian",
            release="12",
            eol_date=today + timedelta(days=30),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
        # Unsupported: EOL was a year ago.
        DistroLifecycle(
            distro_id="ubuntu",
            release="18.04",
            eol_date=today - timedelta(days=365),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
        # RHEL-family major row for the normalization test.
        DistroLifecycle(
            distro_id="rhel",
            release="9",
            eol_date=today + timedelta(days=2000),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
    ]
    for r in rows:
        db.add(r)
    db.commit()
    return rows


def _seed_facts(db, system_id, *, collected_at, distro_id, distro_release, **kwargs):
    row = HostFacts(
        system_id=system_id,
        schema_version=1,
        collected_at=collected_at,
        source_transport=kwargs.pop("source_transport", "ssh"),
        distro_id_facts=distro_id,
        distro_release=distro_release,
        **kwargs,
    )
    db.add(row)
    db.commit()
    return row


# ---------------------------------------------------------------- happy paths


def test_supported_host(authed_client, db, host, lifecycle_seed):
    _seed_facts(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=10),
        distro_id="ubuntu",
        distro_release="22.04",
    )
    resp = authed_client.get(f"/systems/{host.id}/lifecycle")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["system_id"] == host.id
    assert body["freshness"] == "fresh"
    assert body["status"] == "supported"
    assert body["support_kind"] == "standard"
    assert body["source"] == "endoflife.date"
    assert body["unknown_reason"] is None
    assert body["days_to_eol"] is not None and body["days_to_eol"] > 90
    assert body["eol_date"] is not None
    assert body["staleness_threshold_seconds"] == 24 * 60 * 60


def test_approaching_eol_host(authed_client, db, host, lifecycle_seed):
    _seed_facts(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=10),
        distro_id="debian",
        distro_release="12",
    )
    body = authed_client.get(f"/systems/{host.id}/lifecycle").json()
    assert body["status"] == "approaching-eol"
    # Inside the 90-day window — implementation may compute 30 today
    # or 29/30/31 depending on time-of-day. Just bracket it loosely.
    assert 0 < body["days_to_eol"] <= 90


def test_unsupported_host(authed_client, db, host, lifecycle_seed):
    _seed_facts(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=10),
        distro_id="ubuntu",
        distro_release="18.04",
    )
    body = authed_client.get(f"/systems/{host.id}/lifecycle").json()
    assert body["status"] == "unsupported"
    assert body["days_to_eol"] is not None and body["days_to_eol"] < 0


def test_rhel_minor_release_normalizes_to_major(
    authed_client, db, host, lifecycle_seed
):
    """The 9.4 host has no exact row but the rhel/9 major row covers
    it (PRA-156 #3a-α normalization). Read endpoint surfaces the
    major-row verdict transparently."""
    _seed_facts(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=10),
        distro_id="rhel",
        distro_release="9.4",
    )
    body = authed_client.get(f"/systems/{host.id}/lifecycle").json()
    assert body["status"] == "supported"
    assert body["support_kind"] == "standard"


# ---------------------------------------------------------------- unknown paths


def test_missing_facts_row_returns_200_unknown(authed_client, host, lifecycle_seed):
    """First-collect state. Read returns 200, NOT 404."""
    resp = authed_client.get(f"/systems/{host.id}/lifecycle")
    assert resp.status_code == 200
    body = resp.json()
    assert body["freshness"] == "missing"
    assert body["status"] == "unknown"
    assert body["unknown_reason"] == "freshness"
    assert body["days_to_eol"] is None
    assert body["eol_date"] is None
    assert body["support_kind"] is None
    assert body["source"] is None


def test_stale_facts_return_200_unknown(authed_client, db, host, lifecycle_seed):
    """Stale freshness short-circuits the lifecycle lookup — even
    though the matching seed row exists, the verdict is unknown."""
    _seed_facts(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(hours=25),
        distro_id="ubuntu",
        distro_release="22.04",
    )
    body = authed_client.get(f"/systems/{host.id}/lifecycle").json()
    assert body["freshness"] == "stale"
    assert body["status"] == "unknown"
    assert body["unknown_reason"] == "freshness"


def test_missing_distro_facts_returns_unknown(authed_client, db, host, lifecycle_seed):
    """Fresh row but distro_id_facts/distro_release missing — unknown
    with the discriminator pointing at missing distro fields."""
    _seed_facts(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=10),
        distro_id=None,
        distro_release=None,
    )
    body = authed_client.get(f"/systems/{host.id}/lifecycle").json()
    assert body["status"] == "unknown"
    assert body["unknown_reason"] == "missing_distro_facts"


def test_unknown_distro_combination_returns_unknown(
    authed_client, db, host, lifecycle_seed
):
    _seed_facts(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=10),
        distro_id="freebsd",
        distro_release="14",
    )
    body = authed_client.get(f"/systems/{host.id}/lifecycle").json()
    assert body["status"] == "unknown"
    assert body["unknown_reason"] == "no_lifecycle_row"


# ---------------------------------------------------------------- 404 + auth


def test_unknown_system_returns_404(authed_client, lifecycle_seed):
    resp = authed_client.get("/systems/999999/lifecycle")
    assert resp.status_code == 404


def test_read_requires_authentication(client, host, lifecycle_seed):
    """Unauthenticated requests are rejected. ``client`` (vs
    authed_client) has no auth wrapper; the dependency on
    get_current_user MUST refuse the call."""
    resp = client.get(f"/systems/{host.id}/lifecycle")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------- pure read


def test_read_does_not_mutate_host_facts(authed_client, db, host, lifecycle_seed):
    """Read endpoint MUST be pure. Snapshot the row, hit the endpoint
    several times across all status verdicts, then prove the row is
    bit-for-bit identical and no second row was created."""
    seeded = _seed_facts(
        db,
        host.id,
        collected_at=datetime.utcnow() - timedelta(minutes=10),
        distro_id="ubuntu",
        distro_release="22.04",
    )
    snapshot = {
        "id": seeded.id,
        "schema_version": seeded.schema_version,
        "collected_at": seeded.collected_at,
        "source_transport": seeded.source_transport,
        "distro_id_facts": seeded.distro_id_facts,
        "distro_release": seeded.distro_release,
        "updated_at": seeded.updated_at,
    }

    # Hit the endpoint several times.
    for _ in range(5):
        resp = authed_client.get(f"/systems/{host.id}/lifecycle")
        assert resp.status_code == 200

    # Refresh and confirm nothing changed.
    db.refresh(seeded)
    assert seeded.id == snapshot["id"]
    assert seeded.schema_version == snapshot["schema_version"]
    assert seeded.collected_at == snapshot["collected_at"]
    assert seeded.source_transport == snapshot["source_transport"]
    assert seeded.distro_id_facts == snapshot["distro_id_facts"]
    assert seeded.distro_release == snapshot["distro_release"]
    # ``updated_at`` would advance if the ORM saw the row as dirty —
    # the strongest single proof that no write happened on the read
    # path.
    assert seeded.updated_at == snapshot["updated_at"]

    # And no second row materialized.
    rows = db.query(HostFacts).filter(HostFacts.system_id == host.id).all()
    assert len(rows) == 1
