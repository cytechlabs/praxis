"""PRA-163 slice 4 — operator UI route tests.

Covers:

* `GET /patch/advisories` happy path + filters (source_kind /
  advisory_class / severity / distro_family) + limit/offset bounds
  + invalid-vocab filter rejection (422).
* `GET /patch/advisories/{id}` returns the advisory with its
  fixed-package targets + 404 on unknown id.
* `GET /patch/advisories/counts` returns severity / advisory_class
  / total grids (always full grid, including zeros).
* `GET /systems/{id}/patch-advisories` returns joined per-host
  applicability rows + state filter + 404 on unknown system_id.
* `GET /systems/{id}/patch-advisories/counts` returns all four
  state keys (zero-default).
* `POST /systems/{id}/patch-advisories/recompute` calls the Slice 2
  resolver, returns the ApplicabilityResult shape, and emits the
  existing `patch_advisory.applicable_recomputed` audit (no new
  audit event).
* Route ordering — `/patch/advisories/counts` resolves to the
  fleet-counts handler, not the `{advisory_id}` handler that would
  422 on "counts" not being an int.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import pytest

from app.db.models import Credential, Group, HostFacts, Package, System
from app.services import patch_advisory_service
from app.services.patch_advisory_service import (
    AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED,
    SOURCE_KIND_REDHAT_UPDATEINFO,
    SOURCE_KIND_UBUNTU_USN,
    normalize_redhat_updateinfo,
    normalize_ubuntu_usn,
)

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="advisory-route-group", description="t")
    db.add(g)
    db.commit()
    db.refresh(g)
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="advisory-route-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


def _make_host(
    db,
    seed_distro,
    static_group,
    credentials,
    *,
    hostname: str,
    distro_id_facts: Optional[str] = "ubuntu",
    distro_release: Optional[str] = "22.04",
    write_facts: bool = True,
):
    s = System(
        hostname=hostname,
        ip_address="10.0.0.44",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=static_group.id,
        credentials_id=credentials.id,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    if write_facts:
        db.add(
            HostFacts(
                system_id=s.id,
                schema_version=1,
                collected_at=datetime.utcnow(),
                source_transport="agent",
                distro_id_facts=distro_id_facts,
                distro_release=distro_release,
            )
        )
        db.commit()
    return s


def _add_package(db, system, *, name, version):
    db.add(
        Package(
            system_id=system.id,
            name=name,
            installed_version=version,
            package_type="deb",
        )
    )
    db.commit()


def _import_usn(
    db,
    admin_user,
    *,
    advisory_id: str,
    release_packages: dict,
    severity: str = "High",
):
    raw = {
        "id": advisory_id,
        "title": f"{advisory_id} title",
        "summary": "test",
        "severity": severity,
        "release_packages": release_packages,
    }
    payload = normalize_ubuntu_usn(raw)
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )


def _import_rhsa(db, admin_user, *, advisory_id: str, severity: str = "Important"):
    raw = {
        "id": advisory_id,
        "type": "security",
        "severity": severity,
        "title": f"{advisory_id} title",
        "release": "9",
        "distro_id": "rhel",
        "packages": [{"name": "openssl", "version": "3.0.7-25.el9_3"}],
    }
    payload = normalize_redhat_updateinfo(raw)
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_REDHAT_UPDATEINFO,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )


# -- GET /patch/advisories --------------------------------------------------


def test_list_advisories_happy_path(authed_client, db, admin_user):
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-LIST-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    res = authed_client.get("/patch/advisories")
    assert res.status_code == 200, res.text
    body = res.json()
    assert any(a["source_advisory_id"] == "USN-LIST-1" for a in body)


def test_list_advisories_filter_source_kind(authed_client, db, admin_user):
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-FLT-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    _import_rhsa(db, admin_user, advisory_id="RHSA-FLT-1")
    res = authed_client.get("/patch/advisories?source_kind=ubuntu_usn")
    assert res.status_code == 200
    body = res.json()
    assert all(a["source_kind"] == "ubuntu_usn" for a in body)


def test_list_advisories_filter_severity(authed_client, db, admin_user):
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-CRIT-1",
        severity="Critical",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-LOW-1",
        severity="Low",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    res = authed_client.get("/patch/advisories?severity=critical")
    assert res.status_code == 200
    body = res.json()
    assert all(a["severity"] == "critical" for a in body)


def test_list_advisories_rejects_invalid_filter(authed_client):
    res = authed_client.get("/patch/advisories?severity=not-a-severity")
    assert res.status_code == 422


def test_list_advisories_rejects_invalid_offset(authed_client):
    res = authed_client.get("/patch/advisories?offset=-1")
    assert res.status_code == 422


def test_list_advisories_rejects_invalid_limit(authed_client):
    res = authed_client.get("/patch/advisories?limit=0")
    assert res.status_code == 422


# -- GET /patch/advisories/{id} ---------------------------------------------


def test_get_advisory_includes_fixed_packages(authed_client, db, admin_user):
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-DETAIL-1",
        release_packages={
            "jammy": [
                {"name": "openssl", "version": "3.0.2-0ubuntu1.15"},
                {"name": "libssl3", "version": "3.0.2-0ubuntu1.15"},
            ],
        },
    )
    advisory = patch_advisory_service.get_advisory_by_source(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-DETAIL-1",
    )
    res = authed_client.get(f"/patch/advisories/{advisory.id}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["source_advisory_id"] == "USN-DETAIL-1"
    assert len(body["fixed_packages"]) == 2
    assert {fp["package_name"] for fp in body["fixed_packages"]} == {
        "openssl",
        "libssl3",
    }


def test_get_advisory_404_on_unknown(authed_client):
    res = authed_client.get("/patch/advisories/999999")
    assert res.status_code == 404


# -- GET /patch/advisories/counts -------------------------------------------


def test_fleet_counts_route_does_not_collide_with_detail_route(
    authed_client, db, admin_user
):
    """`/patch/advisories/counts` must resolve to the fleet-counts
    handler — not the `{advisory_id}` handler that would 422 on
    'counts' not being a valid integer.
    """
    res = authed_client.get("/patch/advisories/counts")
    assert res.status_code == 200, res.text
    body = res.json()
    assert "severity" in body
    assert "advisory_class" in body
    assert "total" in body


def test_fleet_counts_full_grid_with_zeros(authed_client):
    res = authed_client.get("/patch/advisories/counts")
    body = res.json()
    # Full vocab grid is returned even when no rows exist.
    assert set(body["severity"].keys()) == {
        "critical",
        "high",
        "medium",
        "low",
        "negligible",
        "unknown",
    }
    assert set(body["advisory_class"].keys()) == {
        "security",
        "bugfix",
        "enhancement",
        "other",
    }


def test_fleet_counts_reflects_applicable_rows(
    authed_client, db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="fleet-count-host.example",
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-FLEET-COUNT-1",
        severity="Critical",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    res = authed_client.get("/patch/advisories/counts")
    body = res.json()
    # The import-side recompute fanout produced one applicable row at
    # severity=critical / advisory_class=security.
    assert body["severity"]["critical"] >= 1
    assert body["advisory_class"]["security"] >= 1
    assert body["total"] >= 1


# -- GET /systems/{id}/patch-advisories -------------------------------------


def test_host_advisory_list_returns_joined_rows(
    authed_client, db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-list.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-HOST-LIST-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    res = authed_client.get(f"/systems/{host.id}/patch-advisories")
    assert res.status_code == 200, res.text
    body = res.json()
    assert len(body) == 1
    row = body[0]
    assert row["state"] == "applicable"
    assert row["package_name"] == "openssl"
    assert row["installed_version"] == "3.0.2-0ubuntu1.10"
    assert row["required_version"] == "3.0.2-0ubuntu1.15"
    # Joined advisory metadata present.
    assert row["advisory"]["source_advisory_id"] == "USN-HOST-LIST-1"
    assert row["advisory"]["severity"] == "high"


def test_host_advisory_list_filter_by_state(
    authed_client, db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-state-filter.example",
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.20")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-STATE-FIXED-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    fixed = authed_client.get(f"/systems/{host.id}/patch-advisories?state=fixed")
    assert fixed.status_code == 200
    assert all(r["state"] == "fixed" for r in fixed.json())

    applicable = authed_client.get(
        f"/systems/{host.id}/patch-advisories?state=applicable"
    )
    assert applicable.status_code == 200
    assert applicable.json() == []


def test_host_advisory_list_invalid_state_rejected(
    authed_client, db, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-bad-state.example"
    )
    res = authed_client.get(f"/systems/{host.id}/patch-advisories?state=not-a-state")
    assert res.status_code == 422


def test_host_advisory_list_404_on_unknown_system(authed_client):
    res = authed_client.get("/systems/999999/patch-advisories")
    assert res.status_code == 404


# -- GET /systems/{id}/patch-advisories/counts ------------------------------


def test_host_counts_returns_all_four_state_keys(
    authed_client, db, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-counts.example"
    )
    res = authed_client.get(f"/systems/{host.id}/patch-advisories/counts")
    assert res.status_code == 200
    body = res.json()
    assert body["system_id"] == host.id
    assert set(body["counts"].keys()) == {
        "applicable",
        "fixed",
        "not_applicable",
        "unknown",
    }
    assert all(v == 0 for v in body["counts"].values())
    # Slice 4-a: facts-presence signal must be available on initial
    # load so the per-host card renders the callout without an
    # operator-triggered recompute. Host has facts → False.
    assert body["host_facts_missing"] is False


def test_host_counts_404_on_unknown_system(authed_client):
    res = authed_client.get("/systems/999999/patch-advisories/counts")
    assert res.status_code == 404


# -- Slice 4-a regressions: host_facts_missing surfaced on initial load -----


def test_host_counts_reports_facts_missing_when_no_facts_row(
    authed_client, db, seed_distro, static_group, credentials
):
    """Slice 4-a regression: a host with no ``HostFacts`` row at all
    must report ``host_facts_missing: true`` on the counts endpoint
    so the per-host card renders the callout on first paint.
    Pre-fix, the card learned this only after the operator clicked
    Recompute.
    """
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-counts-no-facts.example",
        write_facts=False,
    )
    res = authed_client.get(f"/systems/{host.id}/patch-advisories/counts")
    assert res.status_code == 200
    body = res.json()
    assert body["host_facts_missing"] is True
    assert all(v == 0 for v in body["counts"].values())


def test_host_counts_reports_facts_missing_when_distro_fields_null(
    authed_client, db, seed_distro, static_group, credentials
):
    """Slice 4-a regression companion: a host that has a HostFacts row
    but with null ``distro_id_facts`` / ``distro_release`` is also
    unresolvable (the Slice 2 resolver short-circuits on the same
    predicate). The counts endpoint must surface the same boolean.
    """
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-counts-null-distro.example",
        distro_id_facts=None,
        distro_release=None,
    )
    res = authed_client.get(f"/systems/{host.id}/patch-advisories/counts")
    assert res.status_code == 200
    body = res.json()
    assert body["host_facts_missing"] is True


# -- POST /systems/{id}/patch-advisories/recompute --------------------------


def test_manual_recompute_returns_applicability_result(
    authed_client, db, admin_user, seed_distro, static_group, credentials
):
    host = _make_host(
        db, seed_distro, static_group, credentials, hostname="host-recompute.example"
    )
    _add_package(db, host, name="openssl", version="3.0.2-0ubuntu1.10")
    _import_usn(
        db,
        admin_user,
        advisory_id="USN-RECOMPUTE-1",
        release_packages={
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    )
    res = authed_client.post(f"/systems/{host.id}/patch-advisories/recompute")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["system_id"] == host.id
    assert set(body["counts"].keys()) == {
        "applicable",
        "fixed",
        "not_applicable",
        "unknown",
    }
    # Idempotent re-trigger after the import-side recompute already
    # placed the row → no delta on this call.
    assert body["rows_added"] == 0
    assert body["rows_removed"] == 0
    assert body["host_facts_missing"] is False


def test_manual_recompute_uses_existing_audit_event(
    authed_client, db, admin_user, seed_distro, static_group, credentials, monkeypatch
):
    host = _make_host(
        db,
        seed_distro,
        static_group,
        credentials,
        hostname="host-recompute-audit.example",
        write_facts=False,
    )
    # Plant a stale row so recompute has a real delta to clean up.
    from app.db.models import (  # local import to avoid top-level pull
        PatchAdvisory,
        PatchAdvisoryHostApplicability,
    )

    advisory = PatchAdvisory(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id="USN-AUDIT-1",
        advisory_class="security",
        severity="high",
        title="x",
        distro_family="debian",
        digest="0" * 64,
    )
    db.add(advisory)
    db.flush()
    db.add(
        PatchAdvisoryHostApplicability(
            system_id=host.id,
            advisory_id=advisory.id,
            package_name="openssl",
            installed_version="3.0.2-0ubuntu1.10",
            required_version="3.0.2-0ubuntu1.15",
            state="applicable",
            evaluated_at=datetime.utcnow(),
        )
    )
    db.commit()

    audits: list = []
    monkeypatch.setattr(
        patch_advisory_service,
        "safe_emit",
        lambda **kw: audits.append(kw),
    )
    res = authed_client.post(f"/systems/{host.id}/patch-advisories/recompute")
    assert res.status_code == 200
    body = res.json()
    assert body["host_facts_missing"] is True
    assert body["rows_removed"] == 1
    # Existing audit event fires; no new event was added in Slice 4.
    recompute_audits = [
        a for a in audits if a["action"] == AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED
    ]
    assert len(recompute_audits) == 1
    ev = recompute_audits[0]
    assert ev["target_kind"] == "system"
    assert ev["target_id"] == str(host.id)
    assert ev["actor_user_id"] == admin_user.id


def test_manual_recompute_404_on_unknown_system(authed_client):
    res = authed_client.post("/systems/999999/patch-advisories/recompute")
    assert res.status_code == 404


# -- PRA-239: operator import route -----------------------------------------


def _raw_usn(advisory_id: str = "USN-9001-1", **overrides):
    raw = {
        "id": advisory_id,
        "title": f"{advisory_id} title",
        "summary": "test import",
        "severity": "High",
        "cves": ["CVE-2026-9001"],
        "release_packages": {
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
        },
    }
    raw.update(overrides)
    return raw


def _raw_dsa(advisory_id: str = "DSA-9002-1", **overrides):
    raw = {
        "id": advisory_id,
        "title": "openssl - security update",
        "description": "test dsa import",
        "severity": "important",
        "releases": {
            "bookworm": {
                "fixed_version": "3.0.13-1~deb12u1",
                "packages": ["openssl"],
            },
        },
    }
    raw.update(overrides)
    return raw


def test_import_route_imports_usn_and_surfaces_in_list_and_runs(
    authed_client, db, admin_user  # noqa: ARG001
):
    """End-to-end: POST a raw USN through the production import route,
    then confirm the advisory is listed and the import run is recorded."""
    res = authed_client.post(
        "/patch/advisories/imports",
        json={"source_kind": "ubuntu_usn", "payload": _raw_usn()},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["run"]["status"] == "success"
    assert body["run"]["imported_count"] == 1
    assert body["run"]["error_count"] == 0
    assert body["run"]["created_by"] == admin_user.id
    assert [o["action"] for o in body["outcomes"]] == ["imported"]
    assert body["outcomes"][0]["source_advisory_id"] == "USN-9001-1"
    assert body["outcomes"][0]["advisory_id"] is not None

    # Advisory now appears in the read list.
    listed = authed_client.get("/patch/advisories?source_kind=ubuntu_usn")
    assert listed.status_code == 200
    assert any(a["source_advisory_id"] == "USN-9001-1" for a in listed.json())

    # Import run recorded and visible in history.
    runs = authed_client.get("/patch/advisories/imports?source_kind=ubuntu_usn")
    assert runs.status_code == 200
    runs_body = runs.json()
    assert len(runs_body) >= 1
    assert runs_body[0]["source_kind"] == "ubuntu_usn"
    assert runs_body[0]["imported_count"] == 1


def test_import_route_accepts_list_of_payloads(authed_client):
    res = authed_client.post(
        "/patch/advisories/imports",
        json={
            "source_kind": "ubuntu_usn",
            "payloads": [
                _raw_usn(advisory_id="USN-LIST-1"),
                _raw_usn(advisory_id="USN-LIST-2"),
            ],
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["run"]["imported_count"] == 2
    assert {o["source_advisory_id"] for o in body["outcomes"]} == {
        "USN-LIST-1",
        "USN-LIST-2",
    }


def test_import_route_reimport_is_unchanged(authed_client):
    payload = {"source_kind": "debian_security", "payload": _raw_dsa()}
    first = authed_client.post("/patch/advisories/imports", json=payload)
    assert first.status_code == 201, first.text
    assert first.json()["run"]["imported_count"] == 1

    second = authed_client.post("/patch/advisories/imports", json=payload)
    assert second.status_code == 201, second.text
    body = second.json()
    assert body["run"]["imported_count"] == 0
    assert body["run"]["unchanged_count"] == 1
    assert body["outcomes"][0]["action"] == "unchanged"


def test_import_route_rejects_invalid_source_kind(authed_client):
    res = authed_client.post(
        "/patch/advisories/imports",
        json={"source_kind": "not-a-source", "payload": _raw_usn()},
    )
    assert res.status_code == 422


def test_import_route_rejects_malformed_payload(authed_client):
    # USN normalizer requires an id; a payload missing it is rejected up
    # front (422) and no import run is recorded.
    res = authed_client.post(
        "/patch/advisories/imports",
        json={"source_kind": "ubuntu_usn", "payload": {"title": "no id"}},
    )
    assert res.status_code == 422
    assert "normalize" in res.json()["detail"].lower()


def test_import_route_rejects_missing_and_double_payload(authed_client):
    neither = authed_client.post(
        "/patch/advisories/imports", json={"source_kind": "ubuntu_usn"}
    )
    assert neither.status_code == 422

    both = authed_client.post(
        "/patch/advisories/imports",
        json={
            "source_kind": "ubuntu_usn",
            "payload": _raw_usn(),
            "payloads": [_raw_usn()],
        },
    )
    assert both.status_code == 422


def test_import_route_requires_auth(client):
    res = client.post(
        "/patch/advisories/imports",
        json={"source_kind": "ubuntu_usn", "payload": _raw_usn()},
    )
    assert res.status_code in (401, 403)


def test_import_route_forbidden_for_auditor(client, auditor_user):
    login = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    res = client.post(
        "/patch/advisories/imports",
        headers={"Authorization": f"Bearer {token}"},
        json={"source_kind": "ubuntu_usn", "payload": _raw_usn()},
    )
    assert res.status_code == 403


def test_import_runs_route_rejects_invalid_source_kind(authed_client):
    res = authed_client.get("/patch/advisories/imports?source_kind=bogus")
    assert res.status_code == 422
