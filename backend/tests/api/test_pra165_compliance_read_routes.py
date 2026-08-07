"""PRA-165 Slice 3 — read + export route tests.

Covers:

* GET /compliance/policies/{id}/evidence — paginated, filterable; 404
  on missing policy; any-auth read (auditor allowed).
* GET /compliance/policies/{id}/summary — empty-no-runs shape; 404
  on missing policy.
* GET /compliance/systems/{id}/evidence — paginated, filterable;
  any-auth read.
* GET /compliance/fleet/summary — counts + stale flag + Z timestamps.
* GET /compliance/exports/evidence.jsonl + .csv — streaming, RBAC
  (admin/maintainer only), schema stable, audit emit AFTER stream.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import Credential, Group, Package, System
from app.services import compliance_evaluation_service, compliance_service

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra165-routes-s3", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="routes-s3-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="routes-s3-host.example.com",
        ip_address="10.0.0.66",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _seed_policy_with_evidence(db, admin_user, host, slug="rt-policy"):
    p = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug=slug, name=slug.upper()
    )
    compliance_service.add_check(
        db,
        p.id,
        actor_user_id=admin_user.id,
        slug="ssh",
        title="ssh",
        kind="package_installed",
        definition={"package": "openssh-server"},
    )
    db.add(
        Package(
            system_id=host.id,
            name="openssh-server",
            installed_version="9.0",
            package_type="apt",
        )
    )
    db.flush()
    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=p.id)
    return p


# ---------------------------------------------------------------------------
# Policy evidence
# ---------------------------------------------------------------------------


def test_get_policy_evidence_returns_paginated(authed_client, db, admin_user, host):
    p = _seed_policy_with_evidence(db, admin_user, host)
    res = authed_client.get(f"/compliance/policies/{p.id}/evidence")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    assert body["limit"] == 100
    assert body["offset"] == 0
    assert body["items"][0]["policy_slug"] == p.slug
    # Read shape: timestamps end in Z; runner_owner AND runner_status
    # both present (P2 fix).
    assert body["items"][0]["evaluated_at"].endswith("Z")
    assert body["items"][0]["runner_owner"]
    assert body["items"][0]["runner_status"] == "runner_executed"


def test_get_policy_evidence_filters_verdict(authed_client, db, admin_user, host):
    p = _seed_policy_with_evidence(db, admin_user, host)
    # The seeded check is package_installed pass — fail filter should be empty.
    res = authed_client.get(f"/compliance/policies/{p.id}/evidence?verdict=fail")
    assert res.status_code == 200
    assert res.json()["total"] == 0
    res = authed_client.get(f"/compliance/policies/{p.id}/evidence?verdict=pass")
    assert res.json()["total"] >= 1


def test_get_policy_evidence_404_on_missing(authed_client):
    res = authed_client.get("/compliance/policies/999999/evidence")
    assert res.status_code == 404


def test_get_policy_evidence_auditor_can_read(
    client, auditor_user, db, admin_user, host
):
    p = _seed_policy_with_evidence(db, admin_user, host)
    token = _login(client, auditor_user)
    res = client.get(f"/compliance/policies/{p.id}/evidence", headers=_bearer(token))
    assert res.status_code == 200, res.text


# ---------------------------------------------------------------------------
# Policy summary
# ---------------------------------------------------------------------------


def test_get_policy_summary_never_run(authed_client, db, admin_user):
    p = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug="sum-empty", name="X"
    )
    res = authed_client.get(f"/compliance/policies/{p.id}/summary")
    assert res.status_code == 200
    body = res.json()
    assert body["latest_run_at"] is None
    assert body["latest_run_id"] is None
    assert body["per_check"] == []


def test_get_policy_summary_after_run(authed_client, db, admin_user, host):
    p = _seed_policy_with_evidence(db, admin_user, host, slug="sum-run")
    res = authed_client.get(f"/compliance/policies/{p.id}/summary")
    assert res.status_code == 200
    body = res.json()
    assert body["latest_run_at"].endswith("Z")
    assert body["pass_count"] >= 1
    assert len(body["per_host"]) >= 1


def test_get_policy_summary_404(authed_client):
    res = authed_client.get("/compliance/policies/999999/summary")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# System evidence
# ---------------------------------------------------------------------------


def test_get_system_evidence_paginated(authed_client, db, admin_user, host):
    p = _seed_policy_with_evidence(db, admin_user, host, slug="sys-ev")
    res = authed_client.get(f"/compliance/systems/{host.id}/evidence")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    assert all(item["system_id"] == host.id for item in body["items"])


def test_get_system_evidence_filters_policy(authed_client, db, admin_user, host):
    p1 = _seed_policy_with_evidence(db, admin_user, host, slug="sys-p1")
    res = authed_client.get(f"/compliance/systems/{host.id}/evidence?policy_id={p1.id}")
    assert res.status_code == 200
    body = res.json()
    assert all(item["policy_id"] == p1.id for item in body["items"])


# ---------------------------------------------------------------------------
# Fleet summary
# ---------------------------------------------------------------------------


def test_get_fleet_summary(authed_client, db, admin_user, host):
    _seed_policy_with_evidence(db, admin_user, host, slug="fleet-ok")
    res = authed_client.get("/compliance/fleet/summary")
    assert res.status_code == 200
    body = res.json()
    assert body["generated_at"].endswith("Z")
    assert body["policy_count"] >= 1
    assert any(p["policy_slug"] == "fleet-ok" for p in body["per_policy"])


def test_fleet_summary_auditor_can_read(client, auditor_user):
    token = _login(client, auditor_user)
    res = client.get("/compliance/fleet/summary", headers=_bearer(token))
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------


def test_export_jsonl_streams_one_line_per_row(authed_client, db, admin_user, host):
    _seed_policy_with_evidence(db, admin_user, host, slug="exp-jsonl")
    res = authed_client.get("/compliance/exports/evidence.jsonl")
    assert res.status_code == 200
    body = res.text.strip()
    lines = body.split("\n") if body else []
    assert len(lines) >= 1
    import json

    first = json.loads(lines[0])
    assert first["policy_slug"] == "exp-jsonl"
    assert first["evaluated_at"].endswith("Z")
    assert "runner_owner" in first
    # P2 fix: every JSONL row surfaces a stable runner_status.
    assert first["runner_status"] == "runner_executed"


def test_export_jsonl_invalid_verdict_returns_422_before_stream(authed_client):
    """Slice 3 P2 fix: a bad ``verdict`` filter must surface as a
    normal 422 BEFORE any StreamingResponse is constructed — no
    partial bytes on the wire.
    """
    res = authed_client.get("/compliance/exports/evidence.jsonl?verdict=amazing")
    assert res.status_code == 422
    assert "verdict" in res.json()["detail"]


def test_export_csv_invalid_verdict_returns_422_before_header(authed_client):
    """Same as above for CSV: header line must never reach the
    client when the verdict filter is invalid.
    """
    res = authed_client.get("/compliance/exports/evidence.csv?verdict=amazing")
    assert res.status_code == 422
    # 422 body is JSON; confirm no CSV header leaked.
    assert "id,policy_id" not in res.text


def test_export_csv_has_stable_header(authed_client, db, admin_user, host):
    _seed_policy_with_evidence(db, admin_user, host, slug="exp-csv")
    res = authed_client.get("/compliance/exports/evidence.csv")
    assert res.status_code == 200
    first_line, *_ = res.text.splitlines()
    expected_first = "id,policy_id,check_id,system_id,policy_slug,policy_version"
    assert first_line.startswith(expected_first)
    # P2 fix: runner_status sits adjacent to runner_owner in the CSV
    # header so deferral signals land together.
    assert "runner_owner,runner_status" in first_line


def test_export_requires_admin_or_maintainer(client, auditor_user, db):
    token = _login(client, auditor_user)
    res = client.get("/compliance/exports/evidence.jsonl", headers=_bearer(token))
    assert res.status_code in (401, 403)


def test_export_window_too_large_returns_422(authed_client):
    far_past = (datetime.utcnow() - timedelta(days=10_000)).isoformat()
    res = authed_client.get(
        f"/compliance/exports/evidence.jsonl?evaluated_after={far_past}"
    )
    assert res.status_code == 422
    assert "export window" in res.json()["detail"]


def test_export_window_inverted_returns_422(authed_client):
    after = datetime.utcnow().isoformat()
    before = (datetime.utcnow() - timedelta(days=1)).isoformat()
    res = authed_client.get(
        "/compliance/exports/evidence.jsonl"
        f"?evaluated_after={after}&evaluated_before={before}"
    )
    assert res.status_code == 422


def test_export_jsonl_emits_audit_after_stream(
    authed_client, db, admin_user, host, monkeypatch
):
    _seed_policy_with_evidence(db, admin_user, host, slug="exp-audit")
    captured = []

    def fake_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(compliance_evaluation_service, "safe_emit", fake_emit)
    res = authed_client.get("/compliance/exports/evidence.jsonl")
    # Force the response generator to fully iterate.
    _ = res.text
    assert res.status_code == 200
    audit_calls = [c for c in captured if c["action"] == "compliance_export.requested"]
    assert len(audit_calls) == 1
    assert audit_calls[0]["context"]["format"] == "jsonl"
    assert audit_calls[0]["context"]["row_count"] >= 1
    # Session boundary lock.
    assert "db" not in audit_calls[0]
