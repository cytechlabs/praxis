"""PRA-358 — package report exports + report catalog.

Covers the two new report kinds (``package_outdated`` / ``package_compliance``)
and the discoverable report-kind catalog:

* CSV / JSON export shape + pinned CSV header order;
* durable ``report_runs`` recording (Recent Reports consistency);
* format validation (bad ``?format=`` → 422);
* RBAC — admin/maintainer generate, auditor denied;
* fleet scope — in-scope rows only, out-of-scope ``system_id`` → 404,
  empty-scope caller → empty export;
* ``GET /reports/catalog`` exposes the contract incl. the new kinds;
* the compliance evidence manual export now records a run too.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime

import pytest

from app.db.access_models import AccessGrant, FleetRole
from app.db.models import Credential, Group, Package, PackageUpdate, ReportRun, System
from app.services import report_run_service

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def grp(db) -> Group:
    g = Group(name="pra358-grp", description="x")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def cred(db) -> Credential:
    c = Credential(name="pra358-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


def _mk_system(db, seed_distro, grp, cred, hostname, ip) -> System:
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


@pytest.fixture
def two_systems(db, seed_distro, grp, cred):
    a = _mk_system(db, seed_distro, grp, cred, "pra358-a", "10.58.0.1")
    b = _mk_system(db, seed_distro, grp, cred, "pra358-b", "10.58.0.2")
    return a, b


def _mk_update(db, system, name, sec=False) -> None:
    pkg = Package(
        system_id=system.id,
        name=name,
        installed_version="1.0",
        is_security_critical=sec,
    )
    db.add(pkg)
    db.flush()
    db.add(
        PackageUpdate(
            package_id=pkg.id,
            system_id=system.id,
            available_version="2.0",
            update_type="security" if sec else "normal",
            discovered_on=datetime.utcnow(),
        )
    )
    db.commit()


def _mk_role(db, name) -> FleetRole:
    r = FleetRole(
        name=name,
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(r)
    db.flush()
    return r


def _grant(db, user, system, role) -> None:
    db.add(
        AccessGrant(
            user_id=user.id,
            system_id=system.id,
            fleet_role_id=role.id,
            login=user.username,
        )
    )
    db.commit()


def _login(client, user) -> None:
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


def _latest_run(db, kind):
    return (
        db.query(ReportRun)
        .filter(ReportRun.report_kind == kind)
        .order_by(ReportRun.id.desc())
        .first()
    )


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


def test_catalog_lists_all_kinds_incl_package(authed_client):
    res = authed_client.get("/reports/catalog")
    assert res.status_code == 200
    entries = res.json()["report_kinds"]
    kinds = {e["report_kind"] for e in entries}
    assert kinds == set(report_run_service.VALID_REPORT_KINDS)
    assert "package_outdated" in kinds
    assert "package_compliance" in kinds
    outdated = next(e for e in entries if e["report_kind"] == "package_outdated")
    assert outdated["label"] == "Outdated Packages"
    assert "csv" in outdated["formats"] and "json" in outdated["formats"]
    assert outdated["records_run"] is True


def test_catalog_auditor_allowed(client, auditor_user):
    _login(client, auditor_user)
    assert client.get("/reports/catalog").status_code == 200


def test_catalog_requires_auth(client):
    client.headers.pop("Authorization", None)
    assert client.get("/reports/catalog").status_code in (401, 403)


# ---------------------------------------------------------------------------
# Outdated packages export
# ---------------------------------------------------------------------------


def test_outdated_export_csv_shape_and_records_run(
    authed_client, db, admin_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "openssl", sec=True)
    _mk_update(db, b, "bash", sec=False)

    res = authed_client.get("/package-reports/outdated/export?format=csv")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert (
        "attachment; filename=outdated-packages-export.csv"
        in res.headers["content-disposition"]
    )
    lines = res.text.splitlines()
    assert lines[0] == (
        "package_name,installed_version,available_version,"
        "system_id,system_hostname,is_security_critical"
    )
    rows = list(csv.DictReader(io.StringIO(res.text)))
    assert {r["package_name"] for r in rows} == {"openssl", "bash"}

    run = _latest_run(db, "package_outdated")
    assert run is not None
    assert run.row_count == 2
    assert run.format == "csv"
    assert run.triggered_by == "user"
    assert run.state == "succeeded"
    assert run.triggered_by_user_id == admin_user.id


def test_outdated_export_json_security_only(authed_client, db, two_systems):
    a, b = two_systems
    _mk_update(db, a, "openssl", sec=True)
    _mk_update(db, b, "bash", sec=False)

    res = authed_client.get(
        "/package-reports/outdated/export?format=json&security_only=true"
    )
    assert res.status_code == 200
    rows = res.json()
    assert len(rows) == 1
    assert rows[0]["package_name"] == "openssl"
    assert rows[0]["is_security_critical"] is True
    run = _latest_run(db, "package_outdated")
    assert run.row_count == 1
    assert run.format == "json"


def test_outdated_export_bad_format_422(authed_client):
    res = authed_client.get("/package-reports/outdated/export?format=pdf")
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Update compliance export
# ---------------------------------------------------------------------------


def test_compliance_export_csv_shape_and_records_run(authed_client, db, two_systems):
    a, b = two_systems
    _mk_update(db, a, "openssl")  # a is now partially outdated

    res = authed_client.get("/package-reports/compliance/export?format=csv")
    assert res.status_code == 200
    lines = res.text.splitlines()
    assert lines[0] == (
        "system_id,hostname,total_packages,up_to_date_count,"
        "outdated_count,held_count,compliance_percentage"
    )
    rows = list(csv.DictReader(io.StringIO(res.text)))
    hostnames = {r["hostname"] for r in rows}
    assert {a.hostname, b.hostname}.issubset(hostnames)

    run = _latest_run(db, "package_compliance")
    assert run is not None
    assert run.row_count == len(rows)
    assert run.format == "csv"
    assert run.triggered_by == "user"


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def test_outdated_export_auditor_denied(client, auditor_user):
    _login(client, auditor_user)
    assert client.get("/package-reports/outdated/export").status_code in (401, 403)


def test_compliance_export_auditor_denied(client, auditor_user):
    _login(client, auditor_user)
    assert client.get("/package-reports/compliance/export").status_code in (401, 403)


def test_outdated_export_maintainer_allowed(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _mk_update(db, a, "openssl")
    _grant(db, maintainer_user, a, _mk_role(db, "r-pkg-allow"))
    _login(client, maintainer_user)
    res = client.get("/package-reports/outdated/export?format=json")
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# Fleet scope
# ---------------------------------------------------------------------------


def test_outdated_export_scope_in_scope_only(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _mk_update(db, a, "a-only-pkg")
    _mk_update(db, b, "b-only-pkg")
    _grant(db, maintainer_user, a, _mk_role(db, "r-pkg-scope"))
    _login(client, maintainer_user)

    res = client.get("/package-reports/outdated/export?format=json")
    assert res.status_code == 200
    rows = res.json()
    assert {r["system_id"] for r in rows} == {a.id}
    # No out-of-scope hostname / package name leaks into the body.
    assert b.hostname not in res.text
    assert "b-only-pkg" not in res.text

    # Explicit out-of-scope system_id is a non-disclosing 404.
    assert (
        client.get(f"/package-reports/outdated/export?system_id={b.id}").status_code
        == 404
    )


def test_outdated_export_empty_scope_is_empty(client, db, seed_roles, two_systems):
    a, b = two_systems
    _mk_update(db, a, "openssl")
    empty = _mk_user(db, seed_roles, "pra358-empty", ["maintainer"])
    db.commit()
    _login(client, empty)
    res = client.get("/package-reports/outdated/export?format=json")
    assert res.status_code == 200
    assert res.json() == []


def test_compliance_export_empty_scope_is_empty(client, db, seed_roles, two_systems):
    empty = _mk_user(db, seed_roles, "pra358-empty-cmp", ["maintainer"])
    db.commit()
    _login(client, empty)
    res = client.get("/package-reports/compliance/export?format=json")
    assert res.status_code == 200
    assert res.json() == []


# ---------------------------------------------------------------------------
# Compliance evidence export now records a run (consistency)
# ---------------------------------------------------------------------------


def test_evidence_export_still_streams_after_run_recording(authed_client):
    """PRA-358 added a ``safe_record_completed_run`` call in the evidence
    export's streaming ``finally`` (so the evidence export shows up in Recent
    Reports like every other report kind). This is a regression guard that the
    added recording did not break the stream.

    The run row itself is written via ``safe_record_completed_run(db=None)`` — a
    separate ``SessionLocal`` opened inside the generator's finally, because the
    request session is already closed by the time a StreamingResponse finishes.
    That path is production-correct but cannot be asserted here: the test's
    actor user lives in an uncommitted SAVEPOINT transaction, so the separate
    session can't see the FK target and the swallow-errors helper no-ops (the
    identical constraint already applies to the pre-existing evidence AUDIT
    emit). Scope/RBAC for evidence export are covered in
    test_pra281_fleet_scope_authorization.py.
    """
    res = authed_client.get("/compliance/exports/evidence.jsonl")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/x-ndjson")
    _ = res.text  # drain the stream so the generator's finally runs cleanly

    csv_res = authed_client.get("/compliance/exports/evidence.csv")
    assert csv_res.status_code == 200
    assert csv_res.headers["content-type"].startswith("text/csv")


# ---------------------------------------------------------------------------
# Scheduled package_outdated system scope (send-back #1)
#
# The catalog advertises package_outdated as schedulable with a system_id scope;
# the scheduled dispatcher must honor system_id + smart_group_id with the same
# intersection semantics as the manual route, and fail safely on a bad id rather
# than silently broadening scope.
# ---------------------------------------------------------------------------


def _mk_smart_group(db, name, member_systems):
    from app.db.models import SmartGroup, SmartGroupMembership

    sg = SmartGroup(name=name, rule_json="[]", enabled=True)
    db.add(sg)
    db.flush()
    for s in member_systems:
        db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=s.id))
    db.commit()
    return sg


def test_scheduled_outdated_no_filters_is_fleet_wide(db, two_systems):
    from app.services import report_schedule_service

    a, b = two_systems
    _mk_update(db, a, "a1")
    _mk_update(db, b, "b1")
    assert report_schedule_service._dispatch_package_outdated(db, {}) == 2


def test_scheduled_outdated_system_id_counts_only_that_system(db, two_systems):
    from app.services import report_schedule_service

    a, b = two_systems
    _mk_update(db, a, "a1")
    _mk_update(db, a, "a2")
    _mk_update(db, b, "b1")
    assert (
        report_schedule_service._dispatch_package_outdated(db, {"system_id": a.id}) == 2
    )
    assert (
        report_schedule_service._dispatch_package_outdated(db, {"system_id": b.id}) == 1
    )


def test_scheduled_outdated_smart_group_only(db, two_systems):
    from app.services import report_schedule_service

    a, b = two_systems
    _mk_update(db, a, "a1")
    _mk_update(db, b, "b1")
    sg = _mk_smart_group(db, "pra358-sg-only", [a])
    assert (
        report_schedule_service._dispatch_package_outdated(
            db, {"smart_group_id": sg.id}
        )
        == 1
    )


def test_scheduled_outdated_system_and_smart_group_intersection(db, two_systems):
    from app.services import report_schedule_service

    a, b = two_systems
    _mk_update(db, a, "a1")
    _mk_update(db, b, "b1")
    sg = _mk_smart_group(db, "pra358-sg-a", [a])  # group holds only system a
    # system a IS in the group → intersection {a} → a's one outdated row.
    assert (
        report_schedule_service._dispatch_package_outdated(
            db, {"system_id": a.id, "smart_group_id": sg.id}
        )
        == 1
    )
    # system b is NOT in the group → empty intersection → zero rows (not broadened).
    assert (
        report_schedule_service._dispatch_package_outdated(
            db, {"system_id": b.id, "smart_group_id": sg.id}
        )
        == 0
    )


def test_scheduled_outdated_invalid_system_id_raises(db, two_systems):
    from app.services import report_schedule_service

    a, b = two_systems
    _mk_update(db, a, "a1")
    _mk_update(db, b, "b1")
    # A non-integer / bool system_id must fail safely, never silently broaden.
    with pytest.raises(report_schedule_service.ReportScheduleError):
        report_schedule_service._dispatch_package_outdated(
            db, {"system_id": "not-an-int"}
        )
    with pytest.raises(report_schedule_service.ReportScheduleError):
        report_schedule_service._dispatch_package_outdated(db, {"system_id": True})


def _mk_user(db, seed_roles, username, roles):
    from app.core.auth import get_password_hash
    from app.db.models import User

    user = User(
        username=username,
        email=f"{username}@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    for r in roles:
        user.roles.append(seed_roles[r])
    db.add(user)
    db.flush()
    return user
