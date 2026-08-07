"""PRA-363: safe cohort package-state refresh (group/smart-group scan).

Proves the cohort scan endpoint (`POST /packages/scope/scan`):

- reuses the PRA-356 scope resolver, so a scoped caller can only scan hosts they
  hold; a group/smart-group cohort is intersected with the caller's fleet scope;
- rejects an incomplete cohort (400) and scans NOTHING for an empty intersection
  — never the whole fleet;
- snapshots the resolved targets on a FleetOperation for auditability;
- treats partial failure as normal and reports per-host status/counts;
- runs the EXISTING single-host scan per host (mocked here — no real SSH) and
  never applies updates.
"""

import pytest

from app.db.models import (
    AccessGrant,
    Credential,
    FleetRole,
    Group,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from app.services.package_service import PackageService

# --------------------------------------------------------------- fixtures


@pytest.fixture
def cred(db):
    c = Credential(name="pra363-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


def _mk_group(db, name):
    g = Group(name=name, description="x")
    db.add(g)
    db.flush()
    return g


def _mk_system(db, seed_distro, group, cred, hostname, ip):
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _mk_role(db, name):
    r = FleetRole(
        name=name, login_mode="per_user", allowed_actions_json="[]", os_groups_json="[]"
    )
    db.add(r)
    db.flush()
    return r


def _grant(db, user, system, role):
    db.add(
        AccessGrant(
            user_id=user.id,
            system_id=system.id,
            fleet_role_id=role.id,
            login=user.username,
        )
    )
    db.commit()


def _mk_smart_group(db, name, systems):
    sg = SmartGroup(name=name, description="x", rule_json="[]")
    db.add(sg)
    db.flush()
    for s in systems:
        db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=s.id))
    db.commit()
    return sg


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


@pytest.fixture
def fleet(db, seed_distro, cred):
    """g1={a, c}, g2={b}; smart group sg={a, b}."""
    g1 = _mk_group(db, "pra363-g1")
    g2 = _mk_group(db, "pra363-g2")
    a = _mk_system(db, seed_distro, g1, cred, "pra363-a", "10.63.0.1")
    b = _mk_system(db, seed_distro, g2, cred, "pra363-b", "10.63.0.2")
    c = _mk_system(db, seed_distro, g1, cred, "pra363-c", "10.63.0.3")
    sg = _mk_smart_group(db, "pra363-sg", [a, b])
    db.commit()
    return {"g1": g1, "g2": g2, "a": a, "b": b, "c": c, "sg": sg}


@pytest.fixture
def fake_scan(monkeypatch):
    """Replace the real (SSH) single-host scans with a controllable stub.

    ``outcomes`` maps system_id -> status; unlisted hosts default to success.
    Records the system_ids scanned so tests can assert the exact cohort touched.
    """
    calls = {"scan": [], "security": []}
    outcomes = {}

    def _fake(kind):
        def inner(self, system_id):
            calls[kind].append(system_id)
            return {
                "system_id": system_id,
                "status": outcomes.get(system_id, "success"),
            }

        return inner

    monkeypatch.setattr(PackageService, "scan_packages", _fake("scan"))
    monkeypatch.setattr(PackageService, "scan_security_updates", _fake("security"))
    return calls, outcomes


@pytest.fixture(autouse=True)
def capture_ops(monkeypatch):
    """Stub ``fleet_operation_service`` for the in-transaction test DB.

    The real service opens its own ``SessionLocal`` (a separate connection) to
    write the FleetOperation, which cannot see the test transaction's uncommitted
    user/systems. Capture the calls instead so the resolved-target SNAPSHOT and
    per-host recording are asserted without a cross-session FK write.
    """
    from app.services import fleet_operation_service as fos

    captured = {"start": None, "results": [], "completed": None}

    def _start(operation_type, user_id, target_count, parameters=None):
        captured["start"] = {
            "operation_type": operation_type,
            "target_count": target_count,
            "parameters": parameters,
        }
        return 4242

    def _record(op_id, system_id, status, error_message=None):
        captured["results"].append((system_id, status))

    def _complete(op_id, success_count, failure_count, status=None):
        captured["completed"] = (success_count, failure_count, status)

    monkeypatch.setattr(fos, "start_operation", _start)
    monkeypatch.setattr(fos, "record_result", _record)
    monkeypatch.setattr(fos, "complete_operation", _complete)
    return captured


# --------------------------------------------------------------- permission


def test_cohort_scan_requires_admin_or_maintainer(client, db, auditor_user, fleet):
    _grant(db, auditor_user, fleet["a"], _mk_role(db, "r-aud"))
    _login(client, auditor_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "group", "scope_id": fleet["g1"].id},
    )
    assert res.status_code == 403


# --------------------------------------------------------------- scope


def test_cohort_scan_group_scans_only_members(client, db, admin_user, fleet, fake_scan):
    calls, _ = fake_scan
    _login(client, admin_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "group", "scope_id": fleet["g1"].id},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert {r["hostname"] for r in body["results"]} == {"pra363-a", "pra363-c"}
    assert set(calls["scan"]) == {fleet["a"].id, fleet["c"].id}
    assert fleet["b"].id not in calls["scan"]
    assert body["total"] == 2 and body["success_count"] == 2


def test_cohort_scan_intersects_caller_scope(
    client, db, maintainer_user, fleet, fake_scan
):
    calls, _ = fake_scan
    # Maintainer can only see A; group g1 = {A, C} -> only A is scanned.
    _grant(db, maintainer_user, fleet["a"], _mk_role(db, "r-int"))
    _login(client, maintainer_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "group", "scope_id": fleet["g1"].id},
    )
    assert res.status_code == 200
    assert set(calls["scan"]) == {fleet["a"].id}
    assert res.json()["total"] == 1


def test_cohort_scan_incomplete_scope_is_400(client, db, admin_user, fleet, fake_scan):
    _login(client, admin_user)
    res = client.post("/packages/scope/scan", json={"scope_type": "group"})
    assert res.status_code == 400


def test_cohort_scan_empty_intersection_scans_nothing(
    client, db, maintainer_user, fleet, fake_scan
):
    calls, _ = fake_scan
    # Maintainer granted A only; requests g2 = {B}. Empty intersection.
    _grant(db, maintainer_user, fleet["a"], _mk_role(db, "r-empty"))
    _login(client, maintainer_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "group", "scope_id": fleet["g2"].id},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 0 and body["results"] == []
    assert body["fleet_operation_id"] is None
    # Fail closed: nothing was scanned, never the whole fleet.
    assert calls["scan"] == []


def test_cohort_scan_smart_group(client, db, admin_user, fleet, fake_scan):
    calls, _ = fake_scan
    _login(client, admin_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "smart_group", "scope_id": fleet["sg"].id},
    )
    assert res.status_code == 200
    assert set(calls["scan"]) == {fleet["a"].id, fleet["b"].id}


# --------------------------------------------------------------- partial failure


def test_cohort_scan_partial_failure_is_visible(
    client, db, admin_user, fleet, fake_scan
):
    calls, outcomes = fake_scan
    outcomes[fleet["a"].id] = "success"
    outcomes[fleet["c"].id] = "error"
    _login(client, admin_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "group", "scope_id": fleet["g1"].id},
    )
    body = res.json()
    assert body["success_count"] == 1
    assert body["failure_count"] == 1
    assert body["skipped_count"] == 0
    by_host = {r["hostname"]: r["status"] for r in body["results"]}
    assert by_host["pra363-a"] == "success"
    assert by_host["pra363-c"] == "error"


def test_cohort_scan_already_running_counts_as_skipped(
    client, db, admin_user, fleet, fake_scan, capture_ops
):
    _calls, outcomes = fake_scan
    outcomes[fleet["a"].id] = "already_running"
    _login(client, admin_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "group", "scope_id": fleet["g1"].id},
    )
    body = res.json()
    assert body["skipped_count"] == 1
    assert body["success_count"] == 1  # C still succeeds
    assert body["failure_count"] == 0
    # Audit: an already-running host is recorded as ``skipped`` (never failure)
    # and does not inflate the operation's failure_count.
    recorded = dict(capture_ops["results"])  # system_id -> recorded status
    assert recorded[fleet["a"].id] == "skipped"
    assert recorded[fleet["c"].id] == "success"
    _success, failure_count, _status = capture_ops["completed"]
    assert failure_count == 0


# --------------------------------------------------------------- audit snapshot


def test_cohort_scan_snapshots_targets_for_audit(
    client, db, admin_user, fleet, fake_scan, capture_ops
):
    _login(client, admin_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "group", "scope_id": fleet["g1"].id},
    )
    assert res.json()["fleet_operation_id"] == 4242
    start = capture_ops["start"]
    assert start["operation_type"] == "cohort_package_scan"
    assert set(start["parameters"]["system_ids"]) == {fleet["a"].id, fleet["c"].id}
    assert set(start["parameters"]["hostnames"]) == {"pra363-a", "pra363-c"}
    # Every resolved host is recorded on the operation for result visibility.
    assert {sid for sid, _ in capture_ops["results"]} == {fleet["a"].id, fleet["c"].id}


def test_cohort_security_scan_uses_security_path(
    client, db, admin_user, fleet, fake_scan, capture_ops
):
    calls, _ = fake_scan
    _login(client, admin_user)
    res = client.post(
        "/packages/scope/scan",
        json={"scope_type": "group", "scope_id": fleet["g1"].id, "security": True},
    )
    assert res.status_code == 200
    # Security path only; the normal package scan is untouched.
    assert set(calls["security"]) == {fleet["a"].id, fleet["c"].id}
    assert calls["scan"] == []
    assert capture_ops["start"]["operation_type"] == "cohort_security_scan"
