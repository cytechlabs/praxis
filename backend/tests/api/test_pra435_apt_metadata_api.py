"""PRA-435: the APT metadata freshness API and the scan refresh option.

Covers the per-host freshness listing (literal route ahead of the parameterized
ones, fleet-scoped, unknown until a check is recorded) and that the scan routes
pass the refresh option through to the service, defaulting to a refresh.
"""

from datetime import datetime

import pytest

from app.db.models import AccessGrant, Credential, FleetRole, Group, System
from app.services.package_service import APT_FAILED, APT_FRESH, PackageService


@pytest.fixture
def cred(db):
    c = Credential(name="pra435-api-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def group(db):
    g = Group(name="pra435-api-group", description="x")
    db.add(g)
    db.flush()
    return g


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
def hosts(db, seed_distro, group, cred):
    a = _mk_system(db, seed_distro, group, cred, "pra435-api-a", "10.43.0.1")
    b = _mk_system(db, seed_distro, group, cred, "pra435-api-b", "10.43.0.2")
    db.commit()
    return a, b


def _grant(db, user, system):
    role = FleetRole(
        name=f"pra435-role-{system.id}",
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    db.add(
        AccessGrant(
            user_id=user.id,
            system_id=system.id,
            fleet_role_id=role.id,
            login=user.username,
        )
    )
    db.commit()


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


def test_freshness_listing_reports_unknown_then_the_recorded_observation(
    authed_client, db, hosts
):
    a, b = hosts
    PackageService(db)._record_apt_observation(
        a.id, datetime.utcnow(), APT_FAILED, "1 source(s) failed to refresh"
    )
    res = authed_client.get("/packages/metadata-freshness")
    assert res.status_code == 200, res.text
    rows = {r["system_id"]: r for r in res.json()}
    assert rows[a.id]["state"] == APT_FAILED
    assert rows[a.id]["verified"] is False
    assert rows[a.id]["checked_at"].endswith("Z")
    assert rows[a.id]["refreshed_at"] is None
    assert "failed to refresh" in rows[a.id]["detail"]
    assert rows[b.id]["state"] == "unknown"
    assert rows[b.id]["checked_at"] is None


def test_freshness_listing_keeps_the_verified_time_after_a_failed_check(
    authed_client, db, hosts
):
    a, _ = hosts
    service = PackageService(db)
    verified = datetime(2026, 11, 19, 8, 0, 0)
    service._record_apt_observation(a.id, verified, APT_FRESH, "")
    service._record_apt_observation(a.id, datetime.utcnow(), APT_FAILED, "x")
    row = next(
        r
        for r in authed_client.get("/packages/metadata-freshness").json()
        if r["system_id"] == a.id
    )
    assert row["state"] == APT_FAILED
    assert row["refreshed_at"] == "2026-11-19T08:00:00Z"


def test_freshness_listing_is_scoped_to_the_callers_hosts(
    client, db, hosts, maintainer_user, admin_user
):
    a, b = hosts
    _grant(db, maintainer_user, a)
    _login(client, maintainer_user)
    scoped = client.get("/packages/metadata-freshness").json()
    assert {r["system_id"] for r in scoped} == {a.id}
    assert b.hostname not in str(scoped)

    _login(client, admin_user)
    everyone = {
        r["system_id"] for r in client.get("/packages/metadata-freshness").json()
    }
    assert {a.id, b.id} <= everyone


def test_scan_routes_pass_the_refresh_option_through(authed_client, hosts, monkeypatch):
    a, _ = hosts
    seen = []

    def fake_scan(self, system_id, refresh=True):
        seen.append(refresh)
        return {"system_id": system_id, "status": "success"}

    monkeypatch.setattr(PackageService, "scan_packages", fake_scan)
    assert authed_client.post(f"/packages/{a.id}/scan").status_code == 200
    assert authed_client.post(f"/packages/{a.id}/scan?refresh=false").status_code == 200
    assert seen == [True, False]


def test_cohort_scan_passes_the_refresh_option_and_echoes_it(
    authed_client, hosts, monkeypatch
):
    seen = []

    def fake_scan(self, system_id, refresh=True):
        seen.append(refresh)
        return {"system_id": system_id, "status": "success", "scan_state": "complete"}

    monkeypatch.setattr(PackageService, "scan_packages", fake_scan)
    from app.services import fleet_operation_service as fos

    monkeypatch.setattr(fos, "start_operation", lambda *a, **k: 1)
    monkeypatch.setattr(fos, "record_result", lambda *a, **k: None)
    monkeypatch.setattr(fos, "complete_operation", lambda *a, **k: None)

    res = authed_client.post(
        "/packages/scope/scan",
        json={"scope_type": "all", "refresh": False},
    )
    assert res.status_code == 200, res.text
    assert res.json()["refresh"] is False
    assert seen and not any(seen)


def test_cohort_scan_reports_hosts_with_unverified_metadata(
    authed_client, hosts, monkeypatch
):
    """A scanned host on unverified metadata is visible, not a plain success."""
    a, _ = hosts

    def fake_scan(self, system_id, refresh=True):
        state = "partial" if system_id == a.id else "complete"
        return {"system_id": system_id, "status": "success", "scan_state": state}

    monkeypatch.setattr(PackageService, "scan_packages", fake_scan)
    from app.services import fleet_operation_service as fos

    monkeypatch.setattr(fos, "start_operation", lambda *a, **k: 1)
    monkeypatch.setattr(fos, "record_result", lambda *a, **k: None)
    monkeypatch.setattr(fos, "complete_operation", lambda *a, **k: None)

    body = authed_client.post("/packages/scope/scan", json={"scope_type": "all"}).json()
    by_id = {r["system_id"]: r for r in body["results"]}
    assert by_id[a.id]["scan_state"] == "partial"
    assert body["partial_count"] >= 1
    assert body["partial_count"] <= body["success_count"]
