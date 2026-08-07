"""PRA-156 #3d: GET /lifecycle/summary + GET /lifecycle/systems.

Pins the locked behavior:

  * Summary key spelling — hyphenated ``approaching-eol`` is the
    canonical lifecycle.status value (predicates, per-host read,
    URL query params), but the JSON dict key in the summary uses
    ``approaching_eol`` (Python idiom). The test asserts both the
    key spelling and the round-trip mapping.
  * The unknown bucket includes hosts with NO host_facts row —
    matches the namespace lock that ``unknown`` is a real value of
    lifecycle.status.
  * ``GET /lifecycle/systems`` rides the smart-group predicate
    compile path (no parallel computation). Validation rejects
    unknown status values up-front so a typo can't silently match
    nothing.
  * Authentication required.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import Credential, DistroLifecycle, Group, HostFacts, System


@pytest.fixture
def lifecycle_seed(db):
    """Wipe + seed the lifecycle table to known boundary values."""
    db.query(DistroLifecycle).delete()
    db.flush()
    today = datetime.utcnow().date()
    rows = [
        DistroLifecycle(
            distro_id="ubuntu",
            release="22.04",
            eol_date=today + timedelta(days=400),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
        DistroLifecycle(
            distro_id="debian",
            release="12",
            eol_date=today + timedelta(days=30),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
        DistroLifecycle(
            distro_id="ubuntu",
            release="18.04",
            eol_date=today - timedelta(days=365),
            support_kind="standard",
            source="endoflife.date",
            as_of=today,
        ),
    ]
    for r in rows:
        db.add(r)
    db.commit()
    return rows


@pytest.fixture
def fleet(db, seed_distro, lifecycle_seed):
    """Four hosts covering every lifecycle bucket — mirrors the
    smart-group test fixture so the bucket assertions exercise the
    same shape both endpoints have to honor."""
    g = Group(name="pra156-3d", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra156-3d", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()

    def _mk(hostname, ip):
        s = System(
            hostname=hostname,
            ip_address=ip,
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=g.id,
            credentials_id=cred.id,
        )
        db.add(s)
        db.flush()
        return s

    h_supported = _mk("supported-3d.example.com", "10.0.3.1")
    h_approaching = _mk("approaching-3d.example.com", "10.0.3.2")
    h_unsupported = _mk("unsupported-3d.example.com", "10.0.3.3")
    h_unknown = _mk("unknown-3d.example.com", "10.0.3.4")

    fresh_at = datetime.utcnow() - timedelta(minutes=5)
    db.add_all(
        [
            HostFacts(
                system_id=h_supported.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="22.04",
            ),
            HostFacts(
                system_id=h_approaching.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="debian",
                distro_release="12",
            ),
            HostFacts(
                system_id=h_unsupported.id,
                schema_version=1,
                collected_at=fresh_at,
                source_transport="ssh",
                distro_id_facts="ubuntu",
                distro_release="18.04",
            ),
            # h_unknown intentionally has NO host_facts row.
        ]
    )
    db.commit()
    return {
        "supported": h_supported,
        "approaching": h_approaching,
        "unsupported": h_unsupported,
        "unknown": h_unknown,
    }


# ---------------------------------------------------------------- summary


def test_summary_returns_all_four_buckets(authed_client, fleet):
    body = authed_client.get("/lifecycle/summary").json()
    counts = body["counts"]
    # Locked key spelling: hyphenated lifecycle.status value
    # ``approaching-eol`` becomes underscore key ``approaching_eol``
    # in the summary response.
    assert set(counts.keys()) == {
        "supported",
        "approaching_eol",
        "unsupported",
        "unknown",
    }


def test_summary_counts_match_fixture_distribution(authed_client, fleet):
    body = authed_client.get("/lifecycle/summary").json()
    c = body["counts"]
    assert c["supported"] == 1
    assert c["approaching_eol"] == 1
    assert c["unsupported"] == 1
    # Unknown includes h_unknown (no host_facts row) — locked.
    assert c["unknown"] >= 1
    # Total counts every system in the fleet.
    assert body["total"] >= sum(c.values())
    assert body["staleness_threshold_seconds"] == 24 * 60 * 60


def test_summary_unknown_bucket_includes_host_with_no_facts(authed_client, fleet, db):
    """The whole point of the unknown bucket: hosts with NO
    host_facts row are findable. Without this guarantee, the
    saved-view filter would orphan those hosts."""
    from app.db.models import HostFacts as _HF

    # Sanity: h_unknown really has no host_facts row.
    assert (
        db.query(_HF).filter(_HF.system_id == fleet["unknown"].id).one_or_none() is None
    )
    counts = authed_client.get("/lifecycle/summary").json()["counts"]
    assert counts["unknown"] >= 1


def test_summary_requires_authentication(client):
    resp = client.get("/lifecycle/summary")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------- systems


def test_systems_endpoint_returns_supported_bucket_ids(authed_client, fleet):
    body = authed_client.get("/lifecycle/systems?status=supported").json()
    assert body["status"] == "supported"
    assert fleet["supported"].id in body["system_ids"]
    assert fleet["approaching"].id not in body["system_ids"]


def test_systems_endpoint_uses_canonical_hyphenated_query_value(authed_client, fleet):
    """Wire-side query value is the canonical lifecycle.status form
    (hyphenated). Even though the summary key is ``approaching_eol``,
    the lookup query is ``?status=approaching-eol``."""
    body = authed_client.get("/lifecycle/systems?status=approaching-eol").json()
    assert body["status"] == "approaching-eol"
    assert fleet["approaching"].id in body["system_ids"]
    # Sanity: not_in supported only.
    assert fleet["supported"].id not in body["system_ids"]


def test_systems_endpoint_unknown_bucket_includes_missing_facts(authed_client, fleet):
    """Same locked semantics as the smart-group predicate: hosts
    with no host_facts row are members of the unknown bucket."""
    body = authed_client.get("/lifecycle/systems?status=unknown").json()
    assert fleet["unknown"].id in body["system_ids"]


def test_systems_endpoint_unsupported_bucket(authed_client, fleet):
    body = authed_client.get("/lifecycle/systems?status=unsupported").json()
    assert fleet["unsupported"].id in body["system_ids"]


def test_systems_endpoint_rejects_unknown_status_value(authed_client):
    resp = authed_client.get("/lifecycle/systems?status=approaching")
    assert resp.status_code == 400
    body = resp.json()
    assert "status" in body["detail"].lower()


def test_systems_endpoint_requires_status_query(authed_client):
    resp = authed_client.get("/lifecycle/systems")
    # FastAPI returns 422 for missing required query param.
    assert resp.status_code == 422


def test_systems_endpoint_requires_authentication(client):
    resp = client.get("/lifecycle/systems?status=supported")
    assert resp.status_code in (401, 403)


def test_systems_endpoint_truth_matches_smart_group_evaluate(authed_client, fleet, db):
    """Locked: the endpoint MUST ride the smart-group predicate
    compile path. Verified by calling smart_group_service.evaluate
    with the same predicate shape and asserting the IDs match — if
    a future refactor accidentally branches the truth, this test
    will catch it."""
    from app.services import smart_group_service

    rule = {"field": "lifecycle.status", "op": "in", "value": ["supported"]}
    direct = set(smart_group_service.evaluate(rule, db))
    via_endpoint = set(
        authed_client.get("/lifecycle/systems?status=supported").json()["system_ids"]
    )
    assert direct == via_endpoint
