"""PRA-281: fleet-scope authorization spine + high-risk route coverage.

Proves the shared fleet-scope policy is authoritative for the packages,
command-execution, and sessions route families, across roles and scope:

- app admins are tenant-wide (see/act on every system);
- a scoped maintainer/auditor only sees or operates on systems they hold an
  ``AccessGrant`` on;
- out-of-scope direct identifiers get a NON-DISCLOSING 404 (indistinguishable
  from nonexistent), never a 403 that would confirm the system exists;
- fleet-aggregate reads exclude inaccessible systems from both rows AND counts.

The scope primitive is ``access_authorization_service.scoped_system_ids`` (None =
tenant-wide admin, else the grant set). Admins reach tenant-wide scope through
that policy function, not a route-level bypass.
"""

import json
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from app.api.routes import mirrors as mirrors_routes
from app.db.access_models import (
    AccessGrant,
    FileTransferAudit,
    FleetRole,
    HostUserState,
    Recording,
)
from app.db.access_models import Session as SessionRow
from app.db.access_models import SessionApproval, SessionLock
from app.db.command_execution_models import (
    CommandExecutionMetrics,
    CommandExecutionResult,
)
from app.db.compliance_models import CompliancePolicyEvidence
from app.db.models import (
    Baseline,
    BaselineCheck,
    CommandApproval,
    Credential,
    FleetOperation,
    FleetOperationResult,
    Group,
    Job,
    JobHistory,
    MaintenanceWindow,
    Package,
    PackageHistory,
    PackageUpdate,
    PatchAdvisory,
    PatchAdvisoryHostApplicability,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    SavedView,
    SmartGroup,
    SmartGroupMembership,
    System,
    SystemAudit,
    Tag,
)
from app.db.ssh_security_models import SSHHostKey, SSHSecurityLog
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_execution_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
    drift_service,
    patch_policy_service,
    patch_update_plan_service,
)
from app.services.access_authorization_service import (
    scoped_system_ids,
    user_can_access_system,
    user_is_tenant_admin,
)

# --------------------------------------------------------------- fixtures


@pytest.fixture
def grp(db):
    g = db.query(Group).filter_by(name="pra281-grp").first()
    if not g:
        g = Group(name="pra281-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = Credential(name="pra281-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


def _mk_system(db, seed_distro, grp, cred, hostname, ip):
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


def _mk_role(db, name):
    r = FleetRole(
        name=name,
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
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


def _mk_update(db, system, name, sec=False):
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


def _mk_exec_result(db, user, system, command="echo hi"):
    row = CommandExecutionResult(
        system_id=system.id,
        user_id=user.id,
        command=command,
        command_hash="0" * 64,
        started_at=datetime.utcnow(),
        risk_level="low",
        execution_status="success",
        validation_status="passed",
        timeout_seconds=30,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_session(db, user, system, role):
    row = SessionRow(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=role.id,
        login=user.username,
        status="active",
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


@pytest.fixture
def two_systems(db, seed_distro, grp, cred):
    a = _mk_system(db, seed_distro, grp, cred, "pra281-a", "10.28.0.1")
    b = _mk_system(db, seed_distro, grp, cred, "pra281-b", "10.28.0.2")
    return a, b


# --------------------------------------------------------------- spine unit


def test_admin_scope_is_tenant_wide(db, admin_user, two_systems):
    a, b = two_systems
    assert user_is_tenant_admin(admin_user) is True
    assert scoped_system_ids(db, admin_user) is None  # None = all systems
    assert user_can_access_system(db, admin_user, a.id) is True
    assert user_can_access_system(db, admin_user, b.id) is True
    # Admin scope even covers a nonexistent id (existence is checked separately).
    assert user_can_access_system(db, admin_user, 999999) is True


def test_maintainer_scope_is_only_granted_systems(db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-a"))
    assert user_is_tenant_admin(maintainer_user) is False
    assert scoped_system_ids(db, maintainer_user) == {a.id}
    assert user_can_access_system(db, maintainer_user, a.id) is True
    assert user_can_access_system(db, maintainer_user, b.id) is False


def test_user_without_grants_has_empty_scope(db, auditor_user, two_systems):
    a, b = two_systems
    assert scoped_system_ids(db, auditor_user) == set()
    assert user_can_access_system(db, auditor_user, a.id) is False


# --------------------------------------------------------------- packages


def test_packages_per_system_out_of_scope_is_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-pa"))
    _login(client, maintainer_user)
    # In scope -> not a scope 404 (200 with package list).
    assert client.get(f"/packages/{a.id}").status_code == 200
    # Out of scope existing system -> non-disclosing 404 (same as nonexistent).
    assert client.get(f"/packages/{b.id}").status_code == 404
    assert client.get("/packages/98765").status_code == 404


def test_packages_aggregate_excludes_out_of_scope_counts(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "pkg-a", sec=False)
    _mk_update(db, b, "pkg-b", sec=False)
    _mk_update(db, b, "pkg-b2", sec=True)
    _grant(db, maintainer_user, a, _mk_role(db, "r-agg"))
    _login(client, maintainer_user)

    updates = client.get("/packages/updates/all").json()
    sys_ids = {u["system_id"] for u in updates}
    assert sys_ids == {a.id}, "maintainer must not see updates from out-of-scope B"

    # Search total must not count B's packages.
    search = client.get("/packages/search?name=pkg").json()
    assert {r["system_id"] for r in search["results"]} == {a.id}
    assert search["total"] == 1


def test_packages_aggregate_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b")
    _login(client, admin_user)
    sys_ids = {u["system_id"] for u in client.get("/packages/updates/all").json()}
    assert {a.id, b.id} <= sys_ids


def test_packages_bulk_rejects_out_of_scope_non_disclosing(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-bulk"))
    _login(client, maintainer_user)
    res = client.post("/packages/bulk/update", json={"system_ids": [a.id, b.id]})
    assert res.status_code == 404
    # Non-disclosing: the response must not reveal which ids exist / are in scope.
    assert str(b.id) not in res.text and str(a.id) not in res.text


# --------------------------------------------------------------- command exec


def test_command_test_out_of_scope_is_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmd"))
    _login(client, maintainer_user)
    # Out of scope -> 404 before any SSH attempt.
    assert client.post(f"/command-execution/test/{b.id}").status_code == 404


def test_command_history_system_filter_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-hist"))
    _login(client, maintainer_user)
    assert client.get(f"/command-execution/history?system_id={b.id}").status_code == 404
    assert client.get(f"/command-execution/history?system_id={a.id}").status_code == 200


def test_command_test_auditor_forbidden_by_role(client, db, auditor_user, two_systems):
    a, b = two_systems
    _grant(db, auditor_user, a, _mk_role(db, "r-aud"))
    _login(client, auditor_user)
    # Auditor holds scope on A but lacks the maintainer/admin role -> 403 (role
    # gate runs before the scope gate; role failure is not system-disclosing).
    assert client.post(f"/command-execution/test/{a.id}").status_code == 403


def test_command_result_own_but_out_of_scope_is_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    # The maintainer's OWN result, but on system B which is outside current scope.
    res_b = _mk_exec_result(db, maintainer_user, b)
    _grant(db, maintainer_user, a, _mk_role(db, "r-res-a"))  # scoped to A only
    _login(client, maintainer_user)
    assert (
        client.get(f"/command-execution/result/{res_b.id}").status_code == 404
    ), "own result on an out-of-scope system must be a non-disclosing 404"


def test_command_result_in_scope_other_user_denied(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    # Another user's result on system A (in the maintainer's scope).
    res_a = _mk_exec_result(db, admin_user, a)
    _grant(db, maintainer_user, a, _mk_role(db, "r-res-b"))
    _login(client, maintainer_user)
    # Ownership is preserved within scope: a non-admin may not view another user's
    # result even on a system they can access.
    assert client.get(f"/command-execution/result/{res_a.id}").status_code == 403


def test_command_result_admin_tenant_wide(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    # A maintainer's result on B; admin has no explicit grant but is tenant-wide.
    res_b = _mk_exec_result(db, maintainer_user, b)
    _login(client, admin_user)
    got = client.get(f"/command-execution/result/{res_b.id}")
    assert got.status_code == 200
    assert got.json()["id"] == res_b.id and got.json()["system_id"] == b.id


# --------------------------------------------------------------- sessions


def test_session_operator_out_of_scope_is_404(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-sess")
    row_b = _mk_session(db, admin_user, b, role)  # session on out-of-scope B
    _grant(db, maintainer_user, a, role)  # maintainer scoped only to A
    _login(client, maintainer_user)

    # A maintainer out of scope for B's system cannot see or force-close it.
    assert client.get(f"/sessions/{row_b.id}").status_code == 404
    assert client.post(f"/sessions/{row_b.id}/force-close").status_code == 404
    assert (
        client.post(f"/sessions/{row_b.id}/join-ticket?mode=observe").status_code == 404
    )


def test_session_list_scoped_to_grants(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-list")
    _mk_session(db, admin_user, a, role)
    _mk_session(db, admin_user, b, role)
    _grant(db, maintainer_user, a, role)  # scoped to A only
    _login(client, maintainer_user)

    res = client.get("/sessions?mine_only=false&active_only=false")
    assert res.status_code == 200
    sys_ids = {s["system_id"] for s in res.json()["sessions"]}
    assert sys_ids <= {a.id}, "operator list must exclude out-of-scope B sessions"


def test_session_list_admin_sees_all(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-list-admin")
    _mk_session(db, maintainer_user, a, role)
    _mk_session(db, maintainer_user, b, role)
    _login(client, admin_user)
    res = client.get("/sessions?mine_only=false&active_only=false")
    sys_ids = {s["system_id"] for s in res.json()["sessions"]}
    assert {a.id, b.id} <= sys_ids


# ================================================================= SLICE 2
# Systems, health, and status inventory surfaces (PRA-281 Slice 2).


# --------------------------------------------------------------- systems.py


def test_systems_all_scoped_to_grants(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-all"))
    _login(client, maintainer_user)
    ids = {s["id"] for s in client.get("/systems/all").json()}
    assert ids == {a.id}, "scoped maintainer must only list granted systems"


def test_systems_all_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _login(client, admin_user)
    ids = {s["id"] for s in client.get("/systems/all").json()}
    assert {a.id, b.id} <= ids


def test_systems_detail_out_of_scope_is_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-detail"))
    _login(client, maintainer_user)
    assert client.get(f"/systems/{a.id}").status_code == 200
    # Out-of-scope existing system -> non-disclosing 404 (same as nonexistent).
    assert client.get(f"/systems/{b.id}").status_code == 404
    assert client.get("/systems/98765").status_code == 404


def test_systems_eol_status_excludes_out_of_scope(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-eol"))
    _login(client, maintainer_user)
    body = client.get("/systems/eol-status").json()
    # total_checked counts only in-scope systems; B must not inflate the rollup.
    assert body["total_checked"] == 1


def test_systems_eol_status_admin_tenant_wide(client, db, admin_user, two_systems):
    a, b = two_systems
    _login(client, admin_user)
    body = client.get("/systems/eol-status").json()
    assert body["total_checked"] >= 2


# --------------------------------------------------------------- health.py


def test_health_dashboard_excludes_out_of_scope_counts(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "pkg-a", sec=False)
    _mk_update(db, b, "pkg-b", sec=False)
    _mk_update(db, b, "pkg-b2", sec=True)
    _grant(db, maintainer_user, a, _mk_role(db, "r-dash"))
    _login(client, maintainer_user)

    body = client.get("/fleet/dashboard").json()
    pc = body["patch_compliance"]
    # Only A is in scope: 1 system total, 1 affected, 1 pending row, none security.
    assert pc["total"] == 1
    assert pc["with_updates"] == 1
    assert pc["pending_package_updates"] == 1
    assert pc["pending_security_updates"] == 0
    # No attention/status row may reveal out-of-scope B.
    assert str(b.hostname) not in client.get("/fleet/dashboard").text


def test_health_dashboard_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b")
    _login(client, admin_user)
    pc = client.get("/fleet/dashboard").json()["patch_compliance"]
    assert pc["total"] >= 2
    assert pc["with_updates"] >= 2


def test_health_fleet_health_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-fh"))
    _login(client, maintainer_user)
    assert client.get("/fleet/health").json()["total_systems"] == 1


def test_health_check_single_out_of_scope_is_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-chk"))
    _login(client, maintainer_user)
    # Out-of-scope existing system -> non-disclosing 404 before any SSH attempt.
    assert client.post(f"/fleet/check/{b.id}").status_code == 404


def test_health_bulk_rejects_mixed_scope_non_disclosing(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-bulkchk"))
    _login(client, maintainer_user)
    res = client.post("/fleet/bulk/check", json={"system_ids": [a.id, b.id]})
    assert res.status_code == 404
    # Non-disclosing: never reveal which requested id was in/out of scope.
    assert str(a.id) not in res.text and str(b.id) not in res.text


def test_health_check_all_targets_only_in_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-callall"))

    captured = {}

    from app.services.health_service import HealthService

    def _fake_check_systems(self, system_ids):
        captured["ids"] = list(system_ids)
        return {"total": len(system_ids), "ok": 0, "failed": 0, "results": []}

    monkeypatch.setattr(HealthService, "check_systems", _fake_check_systems)
    _login(client, maintainer_user)
    assert client.post("/fleet/check-all").status_code == 200
    # check-all only ever targets systems inside the caller's fleet scope.
    assert set(captured["ids"]) <= {a.id}
    assert b.id not in captured["ids"]


# --------------------------------------------------------------- system_status.py


def test_status_overview_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-ov"))
    _login(client, maintainer_user)
    body = client.get("/system-status/overview").json()
    assert body["patch_compliance"]["total"] == 1


def test_status_systems_list_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-sl"))
    _login(client, maintainer_user)
    body = client.get("/system-status/systems").json()
    ids = {row["id"] for row in body["items"]}
    assert ids == {a.id}
    assert body["total"] == 1


def test_status_systems_list_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _login(client, admin_user)
    ids = {row["id"] for row in client.get("/system-status/systems").json()["items"]}
    assert {a.id, b.id} <= ids


def test_status_history_out_of_scope_is_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-hist2"))
    _login(client, maintainer_user)
    assert client.get(f"/system-status/systems/{a.id}/history").status_code == 200
    assert client.get(f"/system-status/systems/{b.id}/history").status_code == 404
    assert client.get("/system-status/systems/98765/history").status_code == 404


# ================================================================= SLICE 3
# Analytics, system compare, and dashboard job summaries (PRA-281 Slice 3).


def _mk_audit(db, system, user, audit_type="status_change"):
    db.add(
        SystemAudit(
            system_id=system.id,
            audit_type=audit_type,
            changed_by=user.id,
            changed_at=datetime.utcnow(),
            operation="update",
        )
    )
    db.commit()


def _mk_pkg_history(db, system, user, operation="update", job_history=None):
    pkg = Package(
        system_id=system.id,
        name=f"ph-{system.id}-{operation}",
        installed_version="1.0",
    )
    db.add(pkg)
    db.flush()
    db.add(
        PackageHistory(
            package_id=pkg.id,
            system_id=system.id,
            operation=operation,
            performed_at=datetime.utcnow(),
            performed_by=user.id,
            job_history_id=job_history.id if job_history else None,
        )
    )
    db.commit()


def _mk_fleet_failure(db, system, user, error):
    op = FleetOperation(
        operation_type="bulk_update",
        user_id=user.id,
        target_count=1,
        status="failed",
    )
    db.add(op)
    db.flush()
    db.add(
        FleetOperationResult(
            fleet_operation_id=op.id,
            system_id=system.id,
            status="failure",
            error_message=error,
        )
    )
    db.commit()
    return op


def _mk_job_history(db, user, status="running", name="job-x"):
    job = Job(
        name=name,
        job_type="update",
        status=status,
        target_type="all",
        created_by=user.id,
    )
    db.add(job)
    db.flush()
    h = JobHistory(
        job_id=job.id,
        start_time=datetime.utcnow(),
        status=status,
        systems_targeted=5,
        systems_completed=2,
        systems_failed=1,
    )
    db.add(h)
    db.commit()
    db.refresh(h)
    return job, h


# --------------------------------------------------------------- analytics.py


def test_analytics_overview_stats_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b")
    _mk_update(db, b, "pkg-b2")
    _grant(db, maintainer_user, a, _mk_role(db, "r-ov-stats"))
    _login(client, maintainer_user)
    body = client.get("/analytics/overview-stats").json()
    assert body["total_systems"] == 1  # only A is in scope
    assert body["total_packages"] == 1  # only A's single package


def test_analytics_overview_stats_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b")
    _login(client, admin_user)
    body = client.get("/analytics/overview-stats").json()
    assert body["total_systems"] >= 2
    assert body["total_packages"] >= 2


def test_analytics_health_trends_snapshot_scoped(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-trends"))
    _login(client, maintainer_user)
    snap = client.get("/analytics/system-health-trends").json()["current_snapshot"]
    # Both systems are Active, but only A is in scope.
    assert snap.get("Active") == 1


def test_analytics_top_active_excludes_out_of_scope(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_audit(db, a, maintainer_user)
    _mk_audit(db, b, maintainer_user)
    _mk_pkg_history(db, a, maintainer_user)
    _mk_pkg_history(db, b, maintainer_user)
    _grant(db, maintainer_user, a, _mk_role(db, "r-top"))
    _login(client, maintainer_user)
    systems = client.get("/analytics/top-active-systems").json()["systems"]
    ids = {s["system_id"] for s in systems}
    assert ids == {a.id}, "top-active must exclude out-of-scope activity"


def test_analytics_top_active_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_pkg_history(db, a, admin_user)
    _mk_pkg_history(db, b, admin_user)
    _login(client, admin_user)
    ids = {
        s["system_id"]
        for s in client.get("/analytics/top-active-systems").json()["systems"]
    }
    assert {a.id, b.id} <= ids


def test_analytics_common_failures_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _mk_fleet_failure(db, a, maintainer_user, "in-scope-error")
    _mk_fleet_failure(db, b, maintainer_user, "out-of-scope-error")
    _grant(db, maintainer_user, a, _mk_role(db, "r-fail"))
    _login(client, maintainer_user)
    res = client.get("/analytics/common-failures")
    errors = {f["error"] for f in res.json()["failures"]}
    assert "in-scope-error" in errors
    assert "out-of-scope-error" not in res.text


def test_analytics_common_failures_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_fleet_failure(db, a, admin_user, "err-a")
    _mk_fleet_failure(db, b, admin_user, "err-b")
    _login(client, admin_user)
    errors = {
        f["error"] for f in client.get("/analytics/common-failures").json()["failures"]
    }
    assert {"err-a", "err-b"} <= errors


# --------------------------------------------------------------- system_compare.py


def test_compare_rejects_out_of_scope_non_disclosing(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp"))
    _login(client, maintainer_user)
    res = client.get(f"/systems/compare?system_ids={a.id},{b.id}")
    assert res.status_code == 404
    # Non-disclosing: never reveal which requested id was out of scope.
    assert str(a.id) not in res.text and str(b.id) not in res.text


def test_compare_export_rejects_out_of_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmpx"))
    _login(client, maintainer_user)
    res = client.get(f"/systems/compare/export?system_ids={a.id},{b.id}")
    assert res.status_code == 404
    assert str(a.id) not in res.text and str(b.id) not in res.text


def test_compare_in_scope_ok(client, db, maintainer_user, two_systems):
    a, b = two_systems
    role = _mk_role(db, "r-cmp-ok")
    _grant(db, maintainer_user, a, role)
    _grant(db, maintainer_user, b, role)
    _login(client, maintainer_user)
    res = client.get(f"/systems/compare?system_ids={a.id},{b.id}")
    assert res.status_code == 200
    got = {s["id"] for s in res.json()["systems"]}
    assert got == {a.id, b.id}


def test_compare_admin_tenant_wide(client, db, admin_user, two_systems):
    a, b = two_systems
    _login(client, admin_user)
    res = client.get(f"/systems/compare?system_ids={a.id},{b.id}")
    assert res.status_code == 200


# --------------------------------------------------------------- dashboard jobs


def test_dashboard_broad_job_summaries_suppressed_for_scoped(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    # _mk_job_history creates target_type="all" jobs — never fully in a scoped
    # caller's scope, so Slice 4 still suppresses them (mixed/out-of-scope rows).
    _mk_job_history(db, maintainer_user, status="running", name="active-job")
    _mk_job_history(db, maintainer_user, status="completed", name="done-job")
    _grant(db, maintainer_user, a, _mk_role(db, "r-jobs"))
    _login(client, maintainer_user)
    body = client.get("/fleet/dashboard").json()
    assert body["active_jobs"] == []
    assert body["recent_jobs"] == []
    assert "active-job" not in client.get("/fleet/dashboard").text
    assert "done-job" not in client.get("/fleet/dashboard").text


def test_dashboard_job_summaries_visible_to_admin(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_job_history(db, admin_user, status="running", name="admin-active-job")
    _mk_job_history(db, admin_user, status="completed", name="admin-done-job")
    _login(client, admin_user)
    body = client.get("/fleet/dashboard").json()
    names = {j["name"] for j in body["active_jobs"]}
    hist_names = {j["job_name"] for j in body["recent_jobs"]}
    assert "admin-active-job" in names
    assert "admin-done-job" in hist_names


# ================================================================= SLICE 4
# Jobs API family + execution controls + dashboard job visibility (PRA-281 S4).


def _mk_job(
    db,
    user,
    target_type="system",
    target_ids=None,
    name="job",
    job_type="package_scan",
    status="scheduled",
):
    job = Job(
        name=name,
        job_type=job_type,
        status=status,
        target_type=target_type,
        target_ids=json.dumps(target_ids) if target_ids else None,
        created_by=user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _mk_hist(
    db, job, status="completed", targeted=1, completed=1, failed=0, error=None
):
    h = JobHistory(
        job_id=job.id,
        start_time=datetime.utcnow(),
        status=status,
        systems_targeted=targeted,
        systems_completed=completed,
        systems_failed=failed,
        error_message=error,
    )
    db.add(h)
    db.commit()
    db.refresh(h)
    return h


def _scope(db, user):
    return scoped_system_ids(db, user)


# --------------------------------------------------------------- visibility


def test_jobs_list_hides_out_of_scope_and_mixed(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_job(db, maintainer_user, "system", [a.id], name="job-a")
    _mk_job(db, maintainer_user, "system", [b.id], name="job-b-secret")
    _mk_job(db, maintainer_user, "system", [a.id, b.id], name="job-ab-secret")
    _mk_job(db, maintainer_user, "all", None, name="job-all-secret")
    _grant(db, maintainer_user, a, _mk_role(db, "r-jl"))
    _login(client, maintainer_user)
    res = client.get("/jobs")
    names = {j["name"] for j in res.json()["jobs"]}
    assert names == {"job-a"}
    assert res.json()["total"] == 1
    for leaked in ("job-b-secret", "job-ab-secret", "job-all-secret"):
        assert leaked not in res.text
    # No visible job may reference the out-of-scope system id in its targets.
    referenced = set()
    for j in res.json()["jobs"]:
        referenced.update(j.get("target_ids") or [])
    assert b.id not in referenced


def test_jobs_list_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_job(db, admin_user, "system", [a.id], name="ja")
    _mk_job(db, admin_user, "system", [b.id], name="jb")
    _login(client, admin_user)
    names = {j["name"] for j in client.get("/jobs").json()["jobs"]}
    assert {"ja", "jb"} <= names


def test_jobs_detail_out_of_scope_and_mixed_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="d-a")
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="d-b")
    job_ab = _mk_job(db, maintainer_user, "system", [a.id, b.id], name="d-ab")
    _grant(db, maintainer_user, a, _mk_role(db, "r-jd"))
    _login(client, maintainer_user)
    assert client.get(f"/jobs/{job_a.id}").status_code == 200
    # Out-of-scope-only and mixed-scope are both non-disclosing 404 — the body
    # echoes only the requested job id (no system targets / hostnames).
    r_b = client.get(f"/jobs/{job_b.id}")
    r_ab = client.get(f"/jobs/{job_ab.id}")
    assert r_b.status_code == 404
    assert r_ab.status_code == 404
    assert "hostname" not in r_ab.text and "target_ids" not in r_ab.text
    assert client.get("/jobs/998877").status_code == 404


# --------------------------------------------------------------- create/update


def test_jobs_create_out_of_scope_system_rejected(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-jc"))
    _login(client, maintainer_user)
    # Targeting an out-of-scope system fails without disclosing the id.
    res = client.post(
        "/jobs",
        json={
            "name": "x",
            "job_type": "package_scan",
            "target_type": "system",
            "target_ids": [b.id],
        },
    )
    assert res.status_code == 400
    assert str(b.id) not in res.text
    # Mixed also rejected.
    res2 = client.post(
        "/jobs",
        json={
            "name": "x",
            "job_type": "package_scan",
            "target_type": "system",
            "target_ids": [a.id, b.id],
        },
    )
    assert res2.status_code == 400


def test_jobs_create_all_rejected_for_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-jca"))
    _login(client, maintainer_user)
    res = client.post(
        "/jobs",
        json={"name": "x", "job_type": "package_scan", "target_type": "all"},
    )
    assert res.status_code == 400


def test_jobs_create_in_scope_ok(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-jci"))
    _login(client, maintainer_user)
    res = client.post(
        "/jobs",
        json={
            "name": "ok",
            "job_type": "package_scan",
            "target_type": "system",
            "target_ids": [a.id],
        },
    )
    assert res.status_code == 200, res.text


def test_jobs_admin_create_all_ok(client, db, admin_user, two_systems):
    _login(client, admin_user)
    res = client.post(
        "/jobs",
        json={"name": "adm-all", "job_type": "package_scan", "target_type": "all"},
    )
    assert res.status_code == 200, res.text


def test_jobs_update_repoint_out_of_scope_rejected(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="u-a")
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="u-b")
    _grant(db, maintainer_user, a, _mk_role(db, "r-ju"))
    _login(client, maintainer_user)
    # Cannot repoint an owned job to an out-of-scope system.
    res = client.put(f"/jobs/{job_a.id}", json={"target_ids": [b.id]})
    assert res.status_code == 400
    assert str(b.id) not in res.text
    # Cannot update an out-of-scope job at all -> non-disclosing 404.
    assert client.put(f"/jobs/{job_b.id}", json={"name": "z"}).status_code == 404


# --------------------------------------------------------------- run/dry/cancel/delete


def test_jobs_run_out_of_scope_and_mixed_fail_closed(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="run-b")
    job_ab = _mk_job(db, maintainer_user, "system", [a.id, b.id], name="run-ab")
    _grant(db, maintainer_user, a, _mk_role(db, "r-jr"))
    _login(client, maintainer_user)
    assert client.post(f"/jobs/{job_b.id}/run").status_code == 404
    assert client.post(f"/jobs/{job_ab.id}/run").status_code == 404
    assert client.post(f"/jobs/{job_b.id}/dry-run").status_code == 404
    assert client.post(f"/jobs/{job_ab.id}/dry-run").status_code == 404


def test_jobs_start_job_runtime_reenforces_scope(db, maintainer_user, two_systems):
    """Runtime execution re-checks scope: a job targeting an out-of-scope system
    is rejected at start_job even if it exists (grants/targets may have changed)."""
    from app.services.job_service import JobNotFound, JobService

    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-jsr"))
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="s-a")
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="s-b")
    svc = JobService(db, scope=_scope(db, maintainer_user))
    assert isinstance(svc.start_job(job_a.id), int)
    with pytest.raises(JobNotFound):
        svc.start_job(job_b.id)


def test_jobs_cancel_out_of_scope_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="c-b", status="running")
    _mk_hist(db, job_b, status="running", targeted=1, completed=0)
    _grant(db, maintainer_user, a, _mk_role(db, "r-jcn"))
    _login(client, maintainer_user)
    assert client.post(f"/jobs/{job_b.id}/cancel").status_code == 404


def test_jobs_delete_out_of_scope_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="del-b")
    _grant(db, maintainer_user, a, _mk_role(db, "r-jdl"))
    _login(client, maintainer_user)
    assert client.delete(f"/jobs/{job_b.id}").status_code == 404


def test_jobs_rollback_out_of_scope_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    job_b = _mk_job(
        db, maintainer_user, "update", [b.id], name="rb-b", job_type="update"
    )
    hist = _mk_hist(db, job_b, status="completed")
    # A completed update package op on B, eligible for rollback.
    pkg = Package(system_id=b.id, name="rb-pkg", installed_version="2.0")
    db.add(pkg)
    db.flush()
    db.add(
        PackageHistory(
            package_id=pkg.id,
            system_id=b.id,
            operation="update",
            old_version="1.0",
            new_version="2.0",
            status="completed",
            performed_at=datetime.utcnow(),
            job_history_id=hist.id,
        )
    )
    db.commit()
    _grant(db, maintainer_user, a, _mk_role(db, "r-jrb"))
    _login(client, maintainer_user)
    assert client.post(f"/jobs/history/{hist.id}/rollback").status_code == 404


# --------------------------------------------------------------- active/failed/history


def test_jobs_active_excludes_out_of_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    job_a = _mk_job(
        db, maintainer_user, "system", [a.id], name="act-a", status="running"
    )
    job_b = _mk_job(
        db, maintainer_user, "system", [b.id], name="act-b", status="running"
    )
    _mk_hist(db, job_a, status="running", completed=0)
    _mk_hist(db, job_b, status="running", completed=0)
    _grant(db, maintainer_user, a, _mk_role(db, "r-jac"))
    _login(client, maintainer_user)
    res = client.get("/jobs/active")
    names = {j["name"] for j in res.json()}
    assert names == {"act-a"}
    assert "act-b" not in res.text


def test_jobs_failed_excludes_out_of_scope_failure_text(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="f-a")
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="f-b")
    _mk_hist(db, job_a, status="failed", completed=0, failed=1, error="a-failtext")
    _mk_hist(
        db, job_b, status="failed", completed=0, failed=1, error="b-secret-failtext"
    )
    _grant(db, maintainer_user, a, _mk_role(db, "r-jf"))
    _login(client, maintainer_user)
    res = client.get("/jobs/failed")
    assert res.json()["total"] == 1
    assert "b-secret-failtext" not in res.text
    assert "a-failtext" in res.text


def test_jobs_all_history_excludes_out_of_scope(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="h-a")
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="h-b")
    _mk_hist(db, job_a, status="completed")
    _mk_hist(db, job_b, status="completed")
    _grant(db, maintainer_user, a, _mk_role(db, "r-jah"))
    _login(client, maintainer_user)
    res = client.get("/jobs/history")
    job_ids = {h["job_id"] for h in res.json()["history"]}
    assert job_ids == {job_a.id}


def test_jobs_per_job_history_out_of_scope_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="ph-b")
    _mk_hist(db, job_b, status="completed")
    _grant(db, maintainer_user, a, _mk_role(db, "r-jph"))
    _login(client, maintainer_user)
    assert client.get(f"/jobs/{job_b.id}/history").status_code == 404


# --------------------------------------------------------------- dashboard restore


def test_dashboard_job_summaries_show_visible_scoped_jobs(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_a = _mk_job(
        db, maintainer_user, "system", [a.id], name="vis-a", status="running"
    )
    job_b = _mk_job(
        db, maintainer_user, "system", [b.id], name="hid-b", status="running"
    )
    _mk_hist(db, job_a, status="running", completed=0)
    _mk_hist(db, job_b, status="running", completed=0)
    done_a = _mk_job(db, maintainer_user, "system", [a.id], name="done-a")
    done_b = _mk_job(db, maintainer_user, "system", [b.id], name="done-b")
    _mk_hist(db, done_a, status="completed")
    _mk_hist(db, done_b, status="completed")
    _grant(db, maintainer_user, a, _mk_role(db, "r-jdash"))
    _login(client, maintainer_user)
    body = client.get("/fleet/dashboard").json()
    active_names = {j["name"] for j in body["active_jobs"]}
    recent_names = {j["job_name"] for j in body["recent_jobs"]}
    assert active_names == {"vis-a"}
    assert recent_names == {"done-a"}
    assert "hid-b" not in client.get("/fleet/dashboard").text
    assert "done-b" not in client.get("/fleet/dashboard").text


# ----------------------------------------------- dependency metadata (S4 fix)


def _find_chain_node(nodes, name):
    for n in nodes:
        if n["name"] == name:
            return n
        found = _find_chain_node(n.get("children", []), name)
        if found:
            return found
    return None


def test_jobs_dependency_hidden_not_leaked_in_list_detail(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="dep-secret")
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="child-a")
    job_a.depends_on_job_id = job_b.id
    db.commit()
    _grant(db, maintainer_user, a, _mk_role(db, "r-dep1"))
    _login(client, maintainer_user)

    res = client.get("/jobs")
    entry = next(j for j in res.json()["jobs"] if j["name"] == "child-a")
    assert entry["depends_on_job_id"] is None
    assert entry["dependency_name"] is None
    assert "dep-secret" not in res.text

    detail = client.get(f"/jobs/{job_a.id}")
    dj = detail.json()["job"]
    assert dj["depends_on_job_id"] is None
    assert dj["dependency_name"] is None
    assert "dep-secret" not in detail.text


def test_jobs_chains_no_hidden_parent_leak(client, db, maintainer_user, two_systems):
    a, b = two_systems
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="chain-secret")
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="chain-child")
    job_a.depends_on_job_id = job_b.id
    db.commit()
    _grant(db, maintainer_user, a, _mk_role(db, "r-dep2"))
    _login(client, maintainer_user)

    res = client.get("/jobs/chains")
    assert "chain-secret" not in res.text
    node = _find_chain_node(res.json(), "chain-child")
    assert node is not None
    assert node["depends_on_job_id"] is None


def test_jobs_create_hidden_dependency_rejected(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="cdep-secret")
    _grant(db, maintainer_user, a, _mk_role(db, "r-dep3"))
    _login(client, maintainer_user)
    res = client.post(
        "/jobs",
        json={
            "name": "new-child",
            "job_type": "package_scan",
            "target_type": "system",
            "target_ids": [a.id],
            "depends_on_job_id": job_b.id,
        },
    )
    assert res.status_code == 400
    assert "cdep-secret" not in res.text


def test_jobs_update_hidden_dependency_rejected(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="udep-secret")
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="u-child")
    _grant(db, maintainer_user, a, _mk_role(db, "r-dep4"))
    _login(client, maintainer_user)
    res = client.put(f"/jobs/{job_a.id}", json={"depends_on_job_id": job_b.id})
    assert res.status_code == 400
    assert "udep-secret" not in res.text


def test_jobs_dependency_visible_when_both_in_scope(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-dep5")
    _grant(db, maintainer_user, a, role)
    _grant(db, maintainer_user, b, role)
    job_b = _mk_job(db, maintainer_user, "system", [b.id], name="visdep")
    job_a = _mk_job(db, maintainer_user, "system", [a.id], name="vischild")
    job_a.depends_on_job_id = job_b.id
    db.commit()
    _login(client, maintainer_user)
    dj = client.get(f"/jobs/{job_a.id}").json()["job"]
    # Dependency is in scope -> shown normally.
    assert dj["depends_on_job_id"] == job_b.id
    assert dj["dependency_name"] == "visdep"


def test_jobs_dependency_admin_sees_name_and_chain(client, db, admin_user, two_systems):
    a, b = two_systems
    job_b = _mk_job(db, admin_user, "system", [b.id], name="adep-parent")
    job_a = _mk_job(db, admin_user, "system", [a.id], name="achild")
    job_a.depends_on_job_id = job_b.id
    db.commit()
    _login(client, admin_user)
    dj = client.get(f"/jobs/{job_a.id}").json()["job"]
    assert dj["depends_on_job_id"] == job_b.id
    assert dj["dependency_name"] == "adep-parent"
    # Admin chains still expose the parent.
    chains = client.get("/jobs/chains")
    assert "adep-parent" in chains.text
    node = _find_chain_node(chains.json(), "achild")
    assert node is not None and node["depends_on_job_id"] == job_b.id


# ================================================================= SLICE 5
# Facts, lifecycle, advisory/policy/ring read surfaces (PRA-281 Slice 5).


def _mk_advisory(db, severity="high", advisory_class="security", tag="a"):
    adv = PatchAdvisory(
        source_kind="ubuntu_usn",
        source_advisory_id=f"USN-pra281-{tag}",
        advisory_class=advisory_class,
        severity=severity,
        title=f"advisory-{tag}",
        distro_family="debian",
        digest="0" * 64,
    )
    db.add(adv)
    db.commit()
    db.refresh(adv)
    return adv


def _mk_applicability(db, system, advisory, state="applicable", pkg="openssl"):
    row = PatchAdvisoryHostApplicability(
        system_id=system.id,
        advisory_id=advisory.id,
        package_name=pkg,
        state=state,
        evaluated_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    return row


# --------------------------------------------------------------- facts.py


def test_facts_read_scoped_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-facts"))
    _login(client, maintainer_user)
    # In-scope existing system with no facts row still 200 (freshness=missing).
    assert client.get(f"/systems/{a.id}/facts").status_code == 200
    assert client.get(f"/systems/{b.id}/facts").status_code == 404
    assert client.get("/systems/987654/facts").status_code == 404


def test_facts_read_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _login(client, admin_user)
    assert client.get(f"/systems/{a.id}/facts").status_code == 200
    assert client.get(f"/systems/{b.id}/facts").status_code == 200


def test_facts_refresh_role_denied_403(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-factsref"))
    _login(client, maintainer_user)
    # Refresh is admin-only; the role gate fires before any transport work.
    assert client.post(f"/systems/{a.id}/facts/refresh").status_code == 403


def test_facts_refresh_admin_reaches_route_404_for_missing(
    client, db, admin_user, two_systems
):
    # Admin is tenant-wide, so a nonexistent system reaches the route body and
    # returns the route's own 404 (no transport attempt).
    _login(client, admin_user)
    assert client.post("/systems/987654/facts/refresh").status_code == 404


# --------------------------------------------------------------- lifecycle.py


def test_lifecycle_per_host_out_of_scope_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-lc"))
    _login(client, maintainer_user)
    assert client.get(f"/systems/{a.id}/lifecycle").status_code == 200
    assert client.get(f"/systems/{b.id}/lifecycle").status_code == 404
    assert client.get("/systems/987654/lifecycle").status_code == 404


def test_lifecycle_summary_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-lcs"))
    _login(client, maintainer_user)
    body = client.get("/lifecycle/summary").json()
    # Only A is in scope: exactly one system counted (unknown, no facts).
    assert body["total"] == 1


def test_lifecycle_summary_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _login(client, admin_user)
    assert client.get("/lifecycle/summary").json()["total"] >= 2


def test_lifecycle_summary_empty_scope_zero(client, db, auditor_user, two_systems):
    a, b = two_systems
    _login(client, auditor_user)
    body = client.get("/lifecycle/summary").json()
    assert body["total"] == 0
    assert all(v == 0 for v in body["counts"].values())


def test_lifecycle_systems_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-lcsys"))
    _login(client, maintainer_user)
    ids = client.get("/lifecycle/systems?status=unknown").json()["system_ids"]
    assert a.id in ids
    assert b.id not in ids


def test_lifecycle_systems_admin_and_empty_scope(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    _login(client, admin_user)
    admin_ids = client.get("/lifecycle/systems?status=unknown").json()["system_ids"]
    assert {a.id, b.id} <= set(admin_ids)
    _login(client, auditor_user)
    assert client.get("/lifecycle/systems?status=unknown").json()["system_ids"] == []


# ------------------------------------------------- system_patch_advisories.py


def test_host_advisories_out_of_scope_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-hadv"))
    _login(client, maintainer_user)
    assert client.get(f"/systems/{a.id}/patch-advisories/counts").status_code == 200
    assert client.get(f"/systems/{b.id}/patch-advisories/counts").status_code == 404
    assert client.get(f"/systems/{a.id}/patch-advisories").status_code == 200
    assert client.get(f"/systems/{b.id}/patch-advisories").status_code == 404
    # Recompute: in-scope runs (maintainer role ok), out-of-scope 404.
    assert client.post(f"/systems/{a.id}/patch-advisories/recompute").status_code == 200
    assert client.post(f"/systems/{b.id}/patch-advisories/recompute").status_code == 404


def test_host_advisories_recompute_role_denied_403(
    client, db, auditor_user, two_systems
):
    a, b = two_systems
    _grant(db, auditor_user, a, _mk_role(db, "r-hadvaud"))
    _login(client, auditor_user)
    # Auditor holds scope on A but lacks admin/maintainer -> role gate 403.
    assert client.post(f"/systems/{a.id}/patch-advisories/recompute").status_code == 403


# ------------------------------------------- system_patch_policy / ring


def test_patch_policy_effective_out_of_scope_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-pol"))
    _login(client, maintainer_user)
    assert client.get(f"/systems/{a.id}/patch-policy/effective").status_code == 200
    assert client.get(f"/systems/{b.id}/patch-policy/effective").status_code == 404
    assert client.get("/systems/987654/patch-policy/effective").status_code == 404


def test_patch_ring_effective_out_of_scope_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-ring"))
    _login(client, maintainer_user)
    assert client.get(f"/systems/{a.id}/patch-ring").status_code == 200
    assert client.get(f"/systems/{b.id}/patch-ring").status_code == 404
    assert client.get("/systems/987654/patch-ring").status_code == 404


# --------------------------------------------------------------- patch_advisories.py


def test_fleet_advisory_counts_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    adv_a = _mk_advisory(db, severity="high", tag="ha")
    adv_b = _mk_advisory(db, severity="critical", tag="cb")
    _mk_applicability(db, a, adv_a, state="applicable")
    _mk_applicability(db, b, adv_b, state="applicable")
    _grant(db, maintainer_user, a, _mk_role(db, "r-fcounts"))
    _login(client, maintainer_user)
    body = client.get("/patch/advisories/counts").json()
    # Only A's applicable advisory counts; B's (critical) is excluded.
    assert body["severity"]["high"] == 1
    assert body["severity"]["critical"] == 0
    assert body["total"] == 1


def test_fleet_advisory_counts_admin_and_empty_scope(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    adv_a = _mk_advisory(db, severity="high", tag="ha2")
    adv_b = _mk_advisory(db, severity="critical", tag="cb2")
    _mk_applicability(db, a, adv_a, state="applicable")
    _mk_applicability(db, b, adv_b, state="applicable")
    _login(client, admin_user)
    body = client.get("/patch/advisories/counts").json()
    assert body["severity"]["high"] >= 1 and body["severity"]["critical"] >= 1
    # Empty-scope auditor sees zeroed counts.
    _login(client, auditor_user)
    zbody = client.get("/patch/advisories/counts").json()
    assert zbody["total"] == 0
    assert all(v == 0 for v in zbody["severity"].values())


def test_advisory_catalog_is_global_no_system_data(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    adv = _mk_advisory(db, severity="high", tag="cat")
    # Applicability only on out-of-scope B; the global catalog must still list the
    # advisory (it is not fleet-inventory) and must carry no system-derived fields.
    _mk_applicability(db, b, adv, state="applicable")
    _grant(db, maintainer_user, a, _mk_role(db, "r-cat"))
    _login(client, maintainer_user)
    listing = client.get("/patch/advisories").json()
    match = next((x for x in listing if x["id"] == adv.id), None)
    assert match is not None, "advisory catalog is global, not fleet-scoped"
    assert "system_id" not in match and "state" not in match
    detail = client.get(f"/patch/advisories/{adv.id}").json()
    assert "system_id" not in detail and "state" not in detail


# ================================================================= SLICE 6
# Patch execution / reboot / rollback / export workflows (PRA-281 Slice 6).

_EXEC_SEQ = {"n": 0}
_EXE_BASE = "/patch/update-executions"


def _mk_execution(db, admin_user, target_systems, state="succeeded"):
    """Materialize a patch update execution (policy -> plan -> plan hosts ->
    execution -> execution hosts) whose hosts snapshot ``target_systems``.
    Returns (execution, plan, [execution_host_id,...])."""
    _EXEC_SEQ["n"] += 1
    n = _EXEC_SEQ["n"]
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"pra281-s6-{n}",
        name=f"pra281-s6-{n}",
        scope_kind="full",
        rollout_cadence="immediate",
        requires_approval=False,
    )
    plan = PatchUpdatePlan(
        policy_id=policy.id,
        name=f"plan-{n}",
        state="approved",
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    exe = PatchUpdateExecution(
        plan_id=plan.id,
        state=state,
        started_by=admin_user.id,
        started_at=datetime.utcnow() - timedelta(minutes=5),
        max_parallel_per_wave=1,
        plan_state_snapshot="approved",
    )
    db.add(exe)
    db.flush()
    host_ids = []
    for s in target_systems:
        ph = PatchUpdatePlanHost(
            plan_id=plan.id,
            system_id=s.id,
            policy_resolution_kind="direct_host",
            ring_resolution_status="no_ring",
            wave_index=0,
            content_profile_state="no_profile",
            state="planned",
        )
        db.add(ph)
        db.flush()
        eh = PatchUpdateExecutionHost(
            execution_id=exe.id,
            plan_host_id=ph.id,
            system_id_snapshot=s.id,
            wave_index=0,
            state="pending",
        )
        db.add(eh)
        db.flush()
        host_ids.append(eh.id)
    db.commit()
    return exe, plan, host_ids


def _mk_plan(db, admin_user, target_systems):
    """A plan (no execution) whose plan hosts target ``target_systems``."""
    _EXEC_SEQ["n"] += 1
    n = _EXEC_SEQ["n"]
    policy = patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"pra281-s6p-{n}",
        name=f"pra281-s6p-{n}",
        scope_kind="full",
        rollout_cadence="immediate",
        requires_approval=False,
    )
    plan = PatchUpdatePlan(
        policy_id=policy.id,
        name=f"planp-{n}",
        state="approved",
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    for s in target_systems:
        db.add(
            PatchUpdatePlanHost(
                plan_id=plan.id,
                system_id=s.id,
                policy_resolution_kind="direct_host",
                ring_resolution_status="no_ring",
                wave_index=0,
                content_profile_state="no_profile",
                state="planned",
            )
        )
    db.commit()
    return plan


# --------------------------------------------------------------- detail / reads


def test_patch_execution_detail_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    exe_a, _, _ = _mk_execution(db, admin_user, [a])
    exe_b, _, _ = _mk_execution(db, admin_user, [b])
    exe_ab, _, _ = _mk_execution(db, admin_user, [a, b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-exe"))
    _login(client, maintainer_user)
    assert client.get(f"{_EXE_BASE}/{exe_a.id}").status_code == 200
    # out-of-scope-only and mixed-scope are both non-disclosing 404.
    assert client.get(f"{_EXE_BASE}/{exe_b.id}").status_code == 404
    assert client.get(f"{_EXE_BASE}/{exe_ab.id}").status_code == 404
    assert client.get(f"{_EXE_BASE}/99887766").status_code == 404


def test_patch_execution_detail_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    exe_b, _, _ = _mk_execution(db, admin_user, [b])
    exe_ab, _, _ = _mk_execution(db, admin_user, [a, b])
    _login(client, admin_user)
    assert client.get(f"{_EXE_BASE}/{exe_b.id}").status_code == 200
    assert client.get(f"{_EXE_BASE}/{exe_ab.id}").status_code == 200


def test_patch_execution_host_packages_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    exe_a, _, hosts_a = _mk_execution(db, admin_user, [a])
    exe_b, _, hosts_b = _mk_execution(db, admin_user, [b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-exepkg"))
    _login(client, maintainer_user)
    assert (
        client.get(f"{_EXE_BASE}/{exe_a.id}/hosts/{hosts_a[0]}/packages").status_code
        == 200
    )
    assert (
        client.get(f"{_EXE_BASE}/{exe_b.id}/hosts/{hosts_b[0]}/packages").status_code
        == 404
    )


def test_patch_execution_reads_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    exe_a, _, _ = _mk_execution(db, admin_user, [a])
    exe_b, _, _ = _mk_execution(db, admin_user, [b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-exeread"))
    _login(client, maintainer_user)
    assert client.get(f"{_EXE_BASE}/{exe_a.id}/reboots").status_code == 200
    for path in ("/reboots", "/rollback", "/rollback/dispatch"):
        assert client.get(f"{_EXE_BASE}/{exe_b.id}{path}").status_code == 404


# --------------------------------------------------------------- state changes


def test_patch_execution_state_changes_fail_closed(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    exe_b, _, _ = _mk_execution(db, admin_user, [b])
    exe_ab, _, _ = _mk_execution(db, admin_user, [a, b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-exestate"))
    _login(client, maintainer_user)
    # No-body POST controls: dependency 404 fires before any DB/SSH side effect.
    nobody = [
        "/dispatch-next",
        "/reboots/reconcile",
        "/reboots/dispatch-due",
        "/reboots/verify-due",
        "/rollback/evaluate",
        "/rollback/dispatch-next",
        "/rollback/verify-due",
    ]
    for hidden in (exe_b.id, exe_ab.id):
        for path in nobody:
            assert (
                client.post(f"{_EXE_BASE}/{hidden}{path}").status_code == 404
            ), f"{hidden}{path}"
        # Controls with an (empty-valid) body.
        assert client.post(f"{_EXE_BASE}/{hidden}/pause", json={}).status_code == 404
        assert client.post(f"{_EXE_BASE}/{hidden}/cancel", json={}).status_code == 404


# --------------------------------------------------------------- exports


def test_patch_execution_per_exec_exports_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    exe_b, _, _ = _mk_execution(db, admin_user, [b])
    exe_ab, _, _ = _mk_execution(db, admin_user, [a, b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-exeexp"))
    _login(client, maintainer_user)
    # 404 fires in the scope dependency, before any audit / report_run side effect.
    for hidden in (exe_b.id, exe_ab.id):
        assert client.get(f"{_EXE_BASE}/{hidden}/reboots/export").status_code == 404
        assert client.get(f"{_EXE_BASE}/{hidden}/rollback/export").status_code == 404


def test_patch_execution_review_export_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    exe_a, _, _ = _mk_execution(db, admin_user, [a])
    exe_b, _, _ = _mk_execution(db, admin_user, [b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-exerev"))
    _login(client, maintainer_user)
    rows = client.get(f"{_EXE_BASE}/export?format=json").json()
    ids = {r["id"] for r in rows}
    assert exe_a.id in ids
    assert exe_b.id not in ids


def test_patch_execution_review_export_admin_and_empty_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    exe_a, _, _ = _mk_execution(db, admin_user, [a])
    exe_b, _, _ = _mk_execution(db, admin_user, [b])
    _login(client, admin_user)
    admin_ids = {r["id"] for r in client.get(f"{_EXE_BASE}/export?format=json").json()}
    assert {exe_a.id, exe_b.id} <= admin_ids
    # Maintainer with NO grants: role passes, empty scope -> empty export.
    _login(client, maintainer_user)
    assert client.get(f"{_EXE_BASE}/export?format=json").json() == []


# --------------------------------------------------------------- start / by-plan


def test_patch_execution_start_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    plan_b = _mk_plan(db, admin_user, [b])
    plan_ab = _mk_plan(db, admin_user, [a, b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-exestart"))
    _login(client, maintainer_user)
    assert (
        client.post(f"{_EXE_BASE}/start", json={"plan_id": plan_b.id}).status_code
        == 404
    )
    assert (
        client.post(f"{_EXE_BASE}/start", json={"plan_id": plan_ab.id}).status_code
        == 404
    )


def test_patch_execution_by_plan_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    exe_a, plan_a, _ = _mk_execution(db, admin_user, [a])
    exe_b, plan_b, _ = _mk_execution(db, admin_user, [b])
    plan_b_noexec = _mk_plan(db, admin_user, [b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-exebyplan"))
    _login(client, maintainer_user)
    assert client.get(f"{_EXE_BASE}/by-plan/{plan_a.id}").status_code == 200
    # Hidden execution's plan, and an out-of-scope plan with no execution: both 404.
    assert client.get(f"{_EXE_BASE}/by-plan/{plan_b.id}").status_code == 404
    assert client.get(f"{_EXE_BASE}/by-plan/{plan_b_noexec.id}").status_code == 404


# ================================================================= SLICE 7
# Drift baselines, baseline checks, and drift aggregates (PRA-281 Slice 7).

_BL_SEQ = {"n": 0}
_BL = "/baselines"
_BL_RULES = {"packages": [{"name": "openssh-server", "check": "required"}]}


def _mk_smart_group(db, admin_user, systems, label):
    _BL_SEQ["n"] += 1
    sg = SmartGroup(
        name=f"pra281-sg-{label}-{_BL_SEQ['n']}",
        rule_json="{}",
        created_by=admin_user.id,
    )
    db.add(sg)
    db.flush()
    for s in systems:
        db.add(SmartGroupMembership(smart_group_id=sg.id, system_id=s.id))
    db.commit()
    return sg


def _mk_baseline(db, admin_user, scope_sg=None, label="bl"):
    _BL_SEQ["n"] += 1
    b = Baseline(
        name=f"pra281-{label}-{_BL_SEQ['n']}",
        rules_json=json.dumps(_BL_RULES),
        enabled=True,
        schedule_interval_hours=24,
        scope_smart_group_id=(scope_sg.id if scope_sg else None),
        created_by=admin_user.id,
    )
    db.add(b)
    db.commit()
    db.refresh(b)
    return b


def _mk_check(db, baseline, system, status="drifted"):
    db.add(
        BaselineCheck(
            baseline_id=baseline.id,
            system_id=system.id,
            run_at=datetime.utcnow(),
            status=status,
            drift_details_json=(
                json.dumps([{"reason": "x"}]) if status == "drifted" else None
            ),
        )
    )
    db.commit()


# --------------------------------------------------------------- list


def test_baseline_list_scope(client, db, admin_user, maintainer_user, two_systems):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "a")
    sg_b = _mk_smart_group(db, admin_user, [b], "b")
    sg_ab = _mk_smart_group(db, admin_user, [a, b], "ab")
    bl_a = _mk_baseline(db, admin_user, sg_a, "visible")
    bl_b = _mk_baseline(db, admin_user, sg_b, "hidden")
    bl_ab = _mk_baseline(db, admin_user, sg_ab, "mixed")
    bl_un = _mk_baseline(db, admin_user, None, "unscoped")
    _grant(db, maintainer_user, a, _mk_role(db, "r-bl"))
    _login(client, maintainer_user)
    names = {x["name"] for x in client.get(_BL).json()["baselines"]}
    assert bl_a.name in names
    for hidden in (bl_b, bl_ab, bl_un):
        assert hidden.name not in names


def test_baseline_list_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    sg_b = _mk_smart_group(db, admin_user, [b], "adminb")
    bl_b = _mk_baseline(db, admin_user, sg_b, "adminhidden")
    bl_un = _mk_baseline(db, admin_user, None, "adminunscoped")
    _login(client, admin_user)
    names = {x["name"] for x in client.get(_BL).json()["baselines"]}
    assert {bl_b.name, bl_un.name} <= names


# --------------------------------------------------------------- checks


def test_baseline_checks_scope(client, db, admin_user, maintainer_user, two_systems):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "ck")
    bl = _mk_baseline(db, admin_user, sg_a, "ck")
    # A historical check exists for BOTH A and B under this baseline.
    _mk_check(db, bl, a, "drifted")
    _mk_check(db, bl, b, "drifted")
    _grant(db, maintainer_user, a, _mk_role(db, "r-blck"))
    _login(client, maintainer_user)
    checks = client.get(f"{_BL}/{bl.id}/checks").json()["checks"]
    sys_ids = {c["system_id"] for c in checks}
    assert sys_ids == {a.id}
    assert client.get(f"{_BL}/99887766/checks").status_code == 404


def test_baseline_checks_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    bl = _mk_baseline(db, admin_user, None, "ckadmin")
    _mk_check(db, bl, a, "drifted")
    _mk_check(db, bl, b, "compliant")
    _login(client, admin_user)
    sys_ids = {
        c["system_id"] for c in client.get(f"{_BL}/{bl.id}/checks").json()["checks"]
    }
    assert {a.id, b.id} <= sys_ids


# --------------------------------------------------------------- drift summary


def test_baseline_drift_summary_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "suma")
    sg_b = _mk_smart_group(db, admin_user, [b], "sumb")
    bl_a = _mk_baseline(db, admin_user, sg_a, "suma")
    bl_b = _mk_baseline(db, admin_user, sg_b, "sumb")
    _mk_check(db, bl_a, a, "drifted")
    _mk_check(db, bl_b, b, "drifted")
    _grant(db, maintainer_user, a, _mk_role(db, "r-blsum"))
    _login(client, maintainer_user)
    body = client.get(f"{_BL}/-/drift/summary").json()
    assert body["drifted_systems"] == 1
    assert body["baselines"] == 1


def test_baseline_drift_summary_admin_and_empty(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "sa2")
    sg_b = _mk_smart_group(db, admin_user, [b], "sb2")
    bl_a = _mk_baseline(db, admin_user, sg_a, "sa2")
    bl_b = _mk_baseline(db, admin_user, sg_b, "sb2")
    _mk_check(db, bl_a, a, "drifted")
    _mk_check(db, bl_b, b, "drifted")
    _login(client, admin_user)
    admin_body = client.get(f"{_BL}/-/drift/summary").json()
    assert admin_body["drifted_systems"] >= 2
    _login(client, auditor_user)
    empty = client.get(f"{_BL}/-/drift/summary").json()
    assert empty["drifted_systems"] == 0 and empty["baselines"] == 0


# --------------------------------------------------------------- by-system


def test_baseline_by_system_scope(client, db, admin_user, maintainer_user, two_systems):
    a, b = two_systems
    bl = _mk_baseline(db, admin_user, None, "bysys")
    _mk_check(db, bl, a, "drifted")
    _mk_check(db, bl, b, "drifted")
    _grant(db, maintainer_user, a, _mk_role(db, "r-blbs"))
    _login(client, maintainer_user)
    rows = client.get(f"{_BL}/-/drift/by-system").json()["rows"]
    ids = {r["system_id"] for r in rows}
    assert a.id in ids
    assert b.id not in ids


def test_baseline_by_system_empty_scope(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    bl = _mk_baseline(db, admin_user, None, "bysysempty")
    _mk_check(db, bl, a, "drifted")
    _login(client, auditor_user)
    assert client.get(f"{_BL}/-/drift/by-system").json()["rows"] == []


# --------------------------------------------------------------- direct system drift


def test_baseline_drift_for_system_scope(
    client, db, admin_user, maintainer_user, auditor_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-blds"))
    _login(client, maintainer_user)
    assert client.get(f"{_BL}/-/drift/system/{a.id}").status_code == 200
    assert client.get(f"{_BL}/-/drift/system/{b.id}").status_code == 404
    assert client.get(f"{_BL}/-/drift/system/99887766").status_code == 404
    # Empty-scope auditor: even an existing system is a non-disclosing 404.
    _login(client, auditor_user)
    assert client.get(f"{_BL}/-/drift/system/{a.id}").status_code == 404


# --------------------------------------------------------------- CRUD scope


def test_baseline_create_scope(client, db, admin_user, maintainer_user, two_systems):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "cra")
    sg_b = _mk_smart_group(db, admin_user, [b], "crb")
    sg_ab = _mk_smart_group(db, admin_user, [a, b], "crab")
    _grant(db, maintainer_user, a, _mk_role(db, "r-blcr"))
    _login(client, maintainer_user)

    def _create(sg, name):
        body = {"name": name, "rules_json": _BL_RULES}
        if sg is not None:
            body["scope_smart_group_id"] = sg.id
        return client.post(_BL, json=body)

    assert _create(sg_b, "cr-out").status_code == 400
    assert _create(sg_ab, "cr-mixed").status_code == 400
    assert _create(None, "cr-unscoped").status_code == 400
    assert _create(sg_a, "cr-ok").status_code == 200


def test_baseline_admin_create_unscoped_ok(client, db, admin_user):
    _login(client, admin_user)
    res = client.post(_BL, json={"name": "adm-unscoped-ok", "rules_json": _BL_RULES})
    assert res.status_code == 200, res.text


def test_baseline_update_delete_run_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "ura")
    sg_b = _mk_smart_group(db, admin_user, [b], "urb")
    bl_a = _mk_baseline(db, admin_user, sg_a, "ura")
    bl_b = _mk_baseline(db, admin_user, sg_b, "urb")
    _grant(db, maintainer_user, a, _mk_role(db, "r-blur"))
    _login(client, maintainer_user)
    # Hidden baseline: update/delete/run all non-disclosing 404.
    assert client.put(f"{_BL}/{bl_b.id}", json={"description": "x"}).status_code == 404
    assert client.delete(f"{_BL}/{bl_b.id}").status_code == 404
    assert client.post(f"{_BL}/{bl_b.id}/run").status_code == 404
    # Visible baseline: cannot widen scope (clear) or repoint out of scope.
    assert client.put(f"{_BL}/{bl_a.id}", json={"clear_scope": True}).status_code == 400
    assert (
        client.put(
            f"{_BL}/{bl_a.id}", json={"scope_smart_group_id": sg_b.id}
        ).status_code
        == 400
    )
    # Valid in-scope update succeeds.
    assert client.put(f"{_BL}/{bl_a.id}", json={"description": "ok"}).status_code == 200


# --------------------------------------------------------------- scheduler stays global


def test_baseline_scheduler_helpers_unscoped(db, admin_user, two_systems):
    a, b = two_systems
    bl_un = _mk_baseline(db, admin_user, None, "sched")
    _mk_check(db, bl_un, a, "drifted")
    _mk_check(db, bl_un, b, "drifted")
    # No request scope -> tenant-wide (scheduler/background behavior).
    assert drift_service.baseline_visible_to_scope(db, bl_un, None) is True
    # A partially-scoped caller cannot see the tenant-wide baseline.
    assert drift_service.baseline_visible_to_scope(db, bl_un, {a.id}) is False
    summary = drift_service.drift_summary(db)
    assert summary["drifted_systems"] >= 2


def _grant_all_active(db, user, role):
    """Grant ``user`` a fleet grant on EVERY currently-active system."""
    for s in db.query(System).filter(System.status == "Active").all():
        db.add(
            AccessGrant(
                user_id=user.id,
                system_id=s.id,
                fleet_role_id=role.id,
                login=user.username,
            )
        )
    db.commit()


def test_baseline_all_active_maintainer_cannot_create_unscoped(
    client, db, admin_user, maintainer_user, two_systems
):
    # Even if the caller's grants currently cover every active system, an unscoped
    # baseline auto-widens as new systems appear, so it stays admin-only (P1 fix).
    _grant_all_active(db, maintainer_user, _mk_role(db, "r-blall-c"))
    _login(client, maintainer_user)
    res = client.post(
        _BL, json={"name": "all-active-unscoped", "rules_json": _BL_RULES}
    )
    assert res.status_code == 400


def test_baseline_all_active_maintainer_cannot_clear_or_widen(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "clrwiden")
    bl = _mk_baseline(db, admin_user, sg_a, "clrwiden")
    _grant_all_active(db, maintainer_user, _mk_role(db, "r-blall-u"))
    _login(client, maintainer_user)
    # The baseline is fully in scope (so visible), but clearing scope -> unscoped
    # is rejected even though the caller currently covers every active system.
    assert client.put(f"{_BL}/{bl.id}", json={"clear_scope": True}).status_code == 400
    # A non-scope-changing update is still allowed.
    assert client.put(f"{_BL}/{bl.id}", json={"description": "ok"}).status_code == 200


def test_baseline_all_active_maintainer_unscoped_hidden_and_uneditable(
    client, db, admin_user, maintainer_user, two_systems
):
    # Structural rule: an unscoped (tenant-wide) baseline is admin-only for scoped
    # callers even when their grants currently cover every active system, because
    # it auto-widens. It must not appear in the list, be counted in the drift
    # summary, or pass delete/run visibility gates.
    a, b = two_systems
    bl_un = _mk_baseline(db, admin_user, None, "allhidden")
    sg_a = _mk_smart_group(db, admin_user, [a], "allvis")
    bl_scoped = _mk_baseline(db, admin_user, sg_a, "allvis")
    _mk_check(db, bl_un, a, "drifted")
    _mk_check(db, bl_scoped, a, "drifted")
    _grant_all_active(db, maintainer_user, _mk_role(db, "r-blall-h"))
    _login(client, maintainer_user)

    names = {x["name"] for x in client.get(_BL).json()["baselines"]}
    assert bl_un.name not in names
    assert bl_scoped.name in names

    assert client.delete(f"{_BL}/{bl_un.id}").status_code == 404
    assert client.post(f"{_BL}/{bl_un.id}/run").status_code == 404

    summary = client.get(f"{_BL}/-/drift/summary").json()
    # Only the smart-group-scoped baseline is visible/counted (not the unscoped one).
    assert summary["baselines"] == 1
    assert summary["drifted_systems"] == 1


# ================================================================= SLICE 8
# Command approvals, result processing, and command policy (PRA-281 Slice 8).

_CA = "/command-approvals"
_CR = "/command-results"
_CW = "/command-whitelist"


def _mk_approval(db, requester, system, command="rm -rf /tmp/x", status="pending"):
    a = CommandApproval(
        command=command,
        system_id=system.id,
        requested_by=requester.id,
        status=status,
        required_approvals=1,
        requested_at=datetime.utcnow(),
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _mk_metrics(db, system, user, total=5, successful=5):
    m = CommandExecutionMetrics(
        system_id=system.id,
        user_id=user.id,
        metric_date=datetime.utcnow().replace(minute=0, second=0, microsecond=0),
        metric_hour=datetime.utcnow().hour,
        total_executions=total,
        successful_executions=successful,
        failed_executions=0,
        timeout_executions=0,
        avg_execution_time_ms=100,
        validation_failures=0,
        high_risk_executions=0,
        sudo_executions=0,
    )
    db.add(m)
    db.commit()
    return m


# --------------------------------------------------------------- approvals


def test_command_approvals_list_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _mk_approval(db, maintainer_user, a, command="cmd-in-scope")
    _mk_approval(db, maintainer_user, b, command="cmd-out-scope-secret")
    _grant(db, maintainer_user, a, _mk_role(db, "r-capprv"))
    _login(client, maintainer_user)
    res = client.get(_CA)
    sys_ids = {x["system_id"] for x in res.json()["approvals"]}
    assert sys_ids == {a.id}
    assert "cmd-out-scope-secret" not in res.text


def test_command_approvals_list_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_approval(db, admin_user, a, command="adm-a")
    _mk_approval(db, admin_user, b, command="adm-b")
    _login(client, admin_user)
    sys_ids = {x["system_id"] for x in client.get(_CA).json()["approvals"]}
    assert {a.id, b.id} <= sys_ids


def test_command_approvals_pending_count_scope(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_approval(db, maintainer_user, a)
    _mk_approval(db, maintainer_user, b)
    _grant(db, maintainer_user, a, _mk_role(db, "r-capc"))
    _login(client, maintainer_user)
    assert client.get(f"{_CA}/pending-count").json()["pending_count"] == 1


def test_command_approvals_vote_role_and_scope_gate(
    client, db, admin_user, maintainer_user, two_systems
):
    from app.api.routes.command_approvals import _enforce_approval_scope

    a, b = two_systems
    appr_b = _mk_approval(db, admin_user, b)
    _grant(db, maintainer_user, a, _mk_role(db, "r-cavote"))
    _login(client, maintainer_user)
    # Vote/approve/reject are admin-only: a maintainer is stopped by the role gate.
    assert client.post(f"{_CA}/{appr_b.id}/approve", json={}).status_code == 403
    # The scope helper is ready for any future non-admin path: out-of-scope
    # approval -> non-disclosing 404; admin (tenant-wide) -> no-op.
    with pytest.raises(HTTPException) as exc:
        _enforce_approval_scope(db, maintainer_user, appr_b.id)
    assert exc.value.status_code == 404
    assert _enforce_approval_scope(db, admin_user, appr_b.id) is None


# --------------------------------------------------------------- result direct


def test_command_result_process_scope_before_ownership(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    res_b_own = _mk_exec_result(db, maintainer_user, b, command="own-oos")
    res_a_own = _mk_exec_result(db, maintainer_user, a, command="own-in")
    res_a_other = _mk_exec_result(db, admin_user, a, command="other-in")
    _grant(db, maintainer_user, a, _mk_role(db, "r-crproc"))
    _login(client, maintainer_user)
    # Own result on out-of-scope system -> non-disclosing 404 (scope before owner).
    assert client.post(f"{_CR}/process/{res_b_own.id}").status_code == 404
    assert client.get(f"{_CR}/analysis/{res_b_own.id}").status_code == 404
    # Own result in scope -> allowed.
    assert client.post(f"{_CR}/process/{res_a_own.id}").status_code == 200
    # In-scope but not owned -> ownership 403 preserved.
    assert client.post(f"{_CR}/process/{res_a_other.id}").status_code == 403


def test_command_result_history_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _mk_exec_result(db, maintainer_user, a, command="hist-a")
    _mk_exec_result(db, maintainer_user, b, command="hist-b-secret")
    _grant(db, maintainer_user, a, _mk_role(db, "r-crhist"))
    _login(client, maintainer_user)
    res = client.get(f"{_CR}/history")
    sys_none = res.json()["executions"]
    assert all(e["command"] != "hist-b-secret" for e in sys_none)
    assert "hist-b-secret" not in res.text
    # system_id filter out of scope -> non-disclosing 404 before aggregation.
    assert client.get(f"{_CR}/history?system_id={b.id}").status_code == 404
    assert client.get(f"{_CR}/history?system_id={a.id}").status_code == 200


def test_command_result_metrics_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _mk_metrics(db, a, maintainer_user, total=5)
    _mk_metrics(db, b, maintainer_user, total=3)
    _grant(db, maintainer_user, a, _mk_role(db, "r-crmetrics"))
    _login(client, maintainer_user)
    report = client.get(f"{_CR}/metrics/report").json()
    assert report["summary"]["total_executions"] == 5
    assert client.get(f"{_CR}/metrics/report?system_id={b.id}").status_code == 404


def test_command_result_summary_system_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-crsum"))
    _login(client, maintainer_user)
    assert client.get(f"{_CR}/summary/system/{a.id}").status_code == 200
    assert client.get(f"{_CR}/summary/system/{b.id}").status_code == 404
    assert client.get(f"{_CR}/summary/system/99887766").status_code == 404


def test_command_result_empty_scope(client, db, auditor_user, two_systems):
    a, b = two_systems
    # A result and metrics OWNED by the auditor, but the auditor has no grants ->
    # empty scope must beat ownership: empty history + zeroed metrics + 404 direct.
    _mk_exec_result(db, auditor_user, a, command="auditor-own")
    _mk_metrics(db, a, auditor_user, total=7)
    _login(client, auditor_user)
    assert client.get(f"{_CR}/history").json()["executions"] == []
    assert (
        client.get(f"{_CR}/metrics/report").json()["summary"]["total_executions"] == 0
    )
    assert client.get(f"{_CR}/summary/system/{a.id}").status_code == 404


def test_command_result_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_exec_result(db, admin_user, a, command="adm-hist-a")
    _mk_exec_result(db, admin_user, b, command="adm-hist-b")
    _login(client, admin_user)
    cmds = {e["command"] for e in client.get(f"{_CR}/history").json()["executions"]}
    assert {"adm-hist-a", "adm-hist-b"} <= cmds


# --------------------------------------------------------------- whitelist (global)


def test_command_whitelist_is_global_no_system_fields(client, db, admin_user):
    # Command policy/reference data is intentionally global admin-only — it carries
    # no system_id / hostname / host-derived field, so it is not fleet-scoped.
    _login(client, admin_user)
    created = client.post(
        f"{_CW}/whitelist",
        json={
            "name": "pra281-wl",
            "command_pattern": "uptime",
            "risk_level": "low",
            "category": "system_info",
        },
    )
    assert created.status_code == 201, created.text
    entry = created.json()
    assert "system_id" not in entry and "system_hostname" not in entry
    listing = client.get(f"{_CW}/whitelist").json()["entries"]
    assert all("system_id" not in e for e in listing)


# ================================================================= SLICE 9
# Session approvals, session locks, and recordings (PRA-281 Slice 9).

_SA = "/session-approvals"
_SL = "/session-locks"
_RC = "/recordings"


def _mk_session_approval(db, requester, system, role, state="pending"):
    row = SessionApproval(
        requester_id=requester.id,
        system_id=system.id,
        fleet_role_id=role.id,
        login=requester.username,
        state=state,
        reason="need access",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_lock(db, creator, subject_user, reason="emergency"):
    lock = SessionLock(
        subject_user_id=subject_user.id,
        reason=reason,
        created_by=creator.id,
    )
    db.add(lock)
    db.commit()
    db.refresh(lock)
    return lock


def _mk_recording(db, user, system, role, status="active"):
    sess = _mk_session(db, user, system, role)
    rec = Recording(
        session_id=sess.id,
        user_id=user.id,
        system_id=system.id,
        file_path=f"/tmp/pra281-rec-{sess.id}.cast",
        retention_expires_at=datetime.utcnow() + timedelta(days=30),
        status=status,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


# --------------------------------------------------------------- approvals


def test_session_approval_list_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-sa")
    _mk_session_approval(db, admin_user, a, role)
    _mk_session_approval(db, admin_user, b, role)
    _grant(db, maintainer_user, a, role)
    _login(client, maintainer_user)
    res = client.get(_SA)
    sys_ids = {x["system_id"] for x in res.json()["approvals"]}
    assert sys_ids <= {a.id}
    assert b.hostname not in res.text


def test_session_approval_get_scope_before_ownership(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-saget")
    appr_b = _mk_session_approval(db, admin_user, b, role)
    appr_a = _mk_session_approval(db, admin_user, a, role)
    _grant(db, maintainer_user, a, role)  # maintainer is admin/maintainer -> queue view
    _login(client, maintainer_user)
    # Out-of-scope approval -> non-disclosing 404 (before ownership/enrichment).
    assert client.get(f"{_SA}/{appr_b.id}").status_code == 404
    # In-scope approval visible to the maintainer queue.
    assert client.get(f"{_SA}/{appr_a.id}").status_code == 200


def test_session_approval_grant_deny_scope_gate(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-sagd")
    appr_b = _mk_session_approval(db, admin_user, b, role)
    _grant(db, maintainer_user, a, role)
    _login(client, maintainer_user)
    # Out-of-scope approval -> 404 before state change / audit.
    assert client.post(f"{_SA}/{appr_b.id}/grant", json={}).status_code == 404
    assert client.post(f"{_SA}/{appr_b.id}/deny", json={}).status_code == 404
    # State unchanged.
    db.refresh(appr_b)
    assert appr_b.state == "pending"


def test_session_approval_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    role = _mk_role(db, "r-saadm")
    _mk_session_approval(db, admin_user, a, role)
    _mk_session_approval(db, admin_user, b, role)
    _login(client, admin_user)
    sys_ids = {x["system_id"] for x in client.get(_SA).json()["approvals"]}
    assert {a.id, b.id} <= sys_ids


def test_session_approval_empty_scope(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-saempty")
    _mk_session_approval(db, auditor_user, a, role)  # owned by the auditor
    _login(client, auditor_user)
    # Empty scope beats ownership: no approvals visible.
    assert client.get(_SA).json()["approvals"] == []


# --------------------------------------------------------------- session locks


def test_session_locks_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    lock = _mk_lock(db, admin_user, maintainer_user)
    _grant(db, maintainer_user, a, _mk_role(db, "r-sl"))
    _login(client, maintainer_user)
    # Fail closed: a scoped maintainer sees no locks, cannot create, cannot release.
    assert client.get(_SL).json()["locks"] == []
    assert (
        client.post(
            _SL, json={"reason": "x", "subject_username": admin_user.username}
        ).status_code
        == 403
    )
    assert client.post(f"{_SL}/{lock.id}/release").status_code == 404
    # Release did not mutate the lock.
    db.refresh(lock)
    assert lock.released_at is None


def test_session_locks_admin_tenant_wide(client, db, admin_user, maintainer_user):
    lock = _mk_lock(db, admin_user, maintainer_user)
    _login(client, admin_user)
    ids = {x["id"] for x in client.get(_SL).json()["locks"]}
    assert lock.id in ids
    assert client.post(f"{_SL}/{lock.id}/release").status_code == 200


# --------------------------------------------------------------- recordings


def test_recording_list_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    role = _mk_role(db, "r-rc")
    _mk_recording(db, maintainer_user, a, role)
    _mk_recording(db, maintainer_user, b, role)
    _grant(db, maintainer_user, a, role)
    _login(client, maintainer_user)
    res = client.get(f"{_RC}?mine_only=true")
    sys_ids = {r["system_id"] for r in res.json()["recordings"]}
    assert sys_ids == {a.id}
    # Explicit out-of-scope system_id filter -> non-disclosing 404 before query.
    assert client.get(f"{_RC}?system_id={b.id}").status_code == 404
    assert client.get(f"{_RC}?system_id={a.id}").status_code == 200


def test_recording_direct_own_out_of_scope_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    role = _mk_role(db, "r-rcown")
    rec_b = _mk_recording(db, maintainer_user, b, role)  # OWN recording, system B
    rec_a = _mk_recording(db, maintainer_user, a, role)
    _grant(db, maintainer_user, a, role)
    _login(client, maintainer_user)
    # Own recording on out-of-scope system -> 404 (not 403), before cast bytes.
    assert client.get(f"{_RC}/{rec_b.id}").status_code == 404
    assert client.get(f"{_RC}/{rec_b.id}/cast").status_code == 404
    # In-scope own recording is visible (cast may 410 if file missing, not 404).
    assert client.get(f"{_RC}/{rec_a.id}").status_code == 200
    assert client.get(f"{_RC}/{rec_a.id}/cast").status_code in (200, 410)


def test_recording_delete_scope(client, db, admin_user, maintainer_user, two_systems):
    a, b = two_systems
    role = _mk_role(db, "r-rcdel")
    rec_b = _mk_recording(db, admin_user, b, role)
    # Admin (tenant-wide) can delete.
    _login(client, admin_user)
    assert client.delete(f"{_RC}/{rec_b.id}").status_code == 200
    db.refresh(rec_b)
    assert rec_b.status == "pruned"


def test_recording_empty_scope(client, db, auditor_user, two_systems):
    a, b = two_systems
    role = _mk_role(db, "r-rcempty")
    rec = _mk_recording(db, auditor_user, a, role)  # owned by the auditor
    _login(client, auditor_user)
    # Empty scope beats ownership: empty list + 404 on direct id.
    assert client.get(f"{_RC}?mine_only=true").json()["recordings"] == []
    assert client.get(f"{_RC}/{rec.id}").status_code == 404


def test_recording_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    role = _mk_role(db, "r-rcadm")
    _mk_recording(db, admin_user, a, role)
    _mk_recording(db, admin_user, b, role)
    _login(client, admin_user)
    sys_ids = {
        r["system_id"]
        for r in client.get(f"{_RC}?mine_only=false").json()["recordings"]
    }
    assert {a.id, b.id} <= sys_ids


# ================================================================= SLICE 10
# SSH / credential / host-key / maintenance-window surfaces (PRA-281 Slice 10).

_SSH = "/ssh"
_SID = "/ssh-identity"
_SSEC = "/ssh-security"
_CRED = "/credentials"
_MW = "/maintenance-windows"


def _mk_cred(db, name):
    c = Credential(name=name, auth_method="ssh_key", username="root")
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


def _mk_ssh_log(db, system, event_type="auth"):
    row = SSHSecurityLog(system_id=system.id, event_type=event_type, success=True)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_host_key(db, system):
    row = SSHHostKey(
        system_id=system.id,
        hostname=system.hostname,
        key_type="ssh-ed25519",
        public_key="AAAA",
        fingerprint=f"SHA256:{system.id}",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_window(db, admin_user, target_type, target_id=None, name="win"):
    w = MaintenanceWindow(
        name=f"{name}-{target_type}-{target_id}",
        target_type=target_type,
        target_id=target_id,
        schedule=json.dumps(
            {
                "day_of_week": [0, 1, 2, 3, 4, 5, 6],
                "start_time": "00:00",
                "end_time": "23:59",
            }
        ),
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return w


# --------------------------------------------------------------- ssh direct


def test_ssh_direct_out_of_scope_404(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-ssh"))
    _login(client, maintainer_user)
    # Out-of-scope direct actions 404 at the scope gate BEFORE any SSH connection.
    assert client.get(f"{_SSH}/test/{b.id}").status_code == 404
    assert client.post(f"{_SSH}/execute/{b.id}?command=echo+hi").status_code == 404
    assert client.delete(f"{_SSH}/close/{b.id}").status_code == 404
    # In-scope close is a pool lookup (no network) -> 200.
    assert client.delete(f"{_SSH}/close/{a.id}").status_code == 200


def test_ssh_close_all_scope_empty(client, db, auditor_user, two_systems):
    # Empty-scope caller sweeps nothing (no network); returns zero.
    _login(client, auditor_user)
    # auditor lacks admin/maintainer role -> 403 (role gate preserved).
    assert client.delete(f"{_SSH}/close-all").status_code == 403


def test_ssh_close_all_scoped_maintainer(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-sshall"))
    _login(client, maintainer_user)
    res = client.delete(f"{_SSH}/close-all")
    assert res.status_code == 200
    assert res.json()["closed_count"] == 0


# --------------------------------------------------------------- ssh identity


def test_ssh_identity_role_gate_preserved(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-sid"))
    _login(client, maintainer_user)
    # SSH identity routes are admin-only; a maintainer is stopped by the role gate.
    assert client.post(f"{_SID}/deploy/{a.id}").status_code == 403
    assert (
        client.post(f"{_SID}/deploy-bulk", json={"system_ids": [a.id]}).status_code
        == 403
    )
    assert client.get(f"{_SID}/status").status_code == 403


# --------------------------------------------------------------- ssh security


def test_ssh_security_logs_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    log_a = _mk_ssh_log(db, a)
    log_b = _mk_ssh_log(db, b)
    _grant(db, maintainer_user, a, _mk_role(db, "r-sseclog"))
    _login(client, maintainer_user)
    res = client.get(f"{_SSEC}/logs")
    sys_ids = {row["system_id"] for row in res.json()["logs"]}
    assert sys_ids <= {a.id}
    assert client.get(f"{_SSEC}/logs?system_id={b.id}").status_code == 404
    assert client.get(f"{_SSEC}/logs/{log_b.id}").status_code == 404
    assert client.get(f"{_SSEC}/logs/{log_a.id}").status_code == 200


def test_ssh_security_host_keys_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    hk_a = _mk_host_key(db, a)
    hk_b = _mk_host_key(db, b)
    _grant(db, maintainer_user, a, _mk_role(db, "r-ssechk"))
    _login(client, maintainer_user)
    res = client.get(f"{_SSEC}/host-keys")
    sys_ids = {row["system_id"] for row in res.json()["host_keys"]}
    assert sys_ids <= {a.id}
    assert client.get(f"{_SSEC}/host-keys?system_id={b.id}").status_code == 404
    assert client.get(f"{_SSEC}/host-keys/{hk_b.id}").status_code == 404
    # Mutations on out-of-scope host key 404 before any change / hostname message.
    assert client.post(f"{_SSEC}/host-keys/{hk_b.id}/verify").status_code == 404
    assert client.delete(f"{_SSEC}/host-keys/{hk_b.id}").status_code == 404
    db.refresh(hk_b)
    assert hk_b.verified is False
    # In-scope verify works.
    assert client.post(f"{_SSEC}/host-keys/{hk_a.id}/verify").status_code == 200


def test_ssh_security_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_ssh_log(db, a)
    _mk_ssh_log(db, b)
    _login(client, admin_user)
    sys_ids = {row["system_id"] for row in client.get(f"{_SSEC}/logs").json()["logs"]}
    assert {a.id, b.id} <= sys_ids


# --------------------------------------------------------------- credentials


def test_credential_visibility_scope(
    client, db, seed_distro, grp, maintainer_user, two_systems
):
    a, b = two_systems
    cred_a = _mk_cred(db, "pra281-cred-a")
    cred_b = _mk_cred(db, "pra281-cred-b")
    cred_ab = _mk_cred(db, "pra281-cred-ab")
    cred_un = _mk_cred(db, "pra281-cred-unattached")
    sys_a = _mk_system(db, seed_distro, grp, cred_a, "cred-a-host", "10.29.0.1")
    sys_b = _mk_system(db, seed_distro, grp, cred_b, "cred-b-host", "10.29.0.2")
    sys_ab_in = _mk_system(db, seed_distro, grp, cred_ab, "cred-ab-in", "10.29.0.3")
    sys_ab_out = _mk_system(db, seed_distro, grp, cred_ab, "cred-ab-out", "10.29.0.4")
    role = _mk_role(db, "r-cred")
    _grant(db, maintainer_user, sys_a, role)
    _grant(db, maintainer_user, sys_ab_in, role)
    _login(client, maintainer_user)
    names = {c["name"] for c in client.get(_CRED).json()}
    assert cred_a.name in names
    for hidden in (cred_b, cred_ab, cred_un):
        assert hidden.name not in names
    # Direct: in-scope 200, mixed/out-of-scope/unattached -> 404.
    assert client.get(f"{_CRED}/{cred_a.id}").status_code == 200
    assert client.get(f"{_CRED}/{cred_b.id}").status_code == 404
    assert client.get(f"{_CRED}/{cred_ab.id}").status_code == 404
    assert client.get(f"{_CRED}/{cred_un.id}").status_code == 404


def test_credential_secret_delete_scope_gate(
    client, db, seed_distro, grp, maintainer_user, two_systems
):
    a, b = two_systems
    cred_b = _mk_cred(db, "pra281-secret-b")
    _mk_system(db, seed_distro, grp, cred_b, "secret-b-host", "10.29.1.1")
    _grant(db, maintainer_user, a, _mk_role(db, "r-credsec"))
    _login(client, maintainer_user)
    # Reveal/update/delete on an out-of-scope credential -> 404 before Vault.
    assert client.get(f"{_CRED}/{cred_b.id}/secret").status_code == 404
    assert client.put(f"{_CRED}/{cred_b.id}", json={"username": "x"}).status_code == 404
    assert client.delete(f"{_CRED}/{cred_b.id}").status_code == 404


def test_credential_admin_sees_all(client, db, seed_distro, grp, admin_user):
    cred = _mk_cred(db, "pra281-cred-admin")
    _mk_system(db, seed_distro, grp, cred, "cred-admin-host", "10.29.2.1")
    _login(client, admin_user)
    names = {c["name"] for c in client.get(_CRED).json()}
    assert cred.name in names


# --------------------------------------------------------------- maintenance windows


def test_maintenance_window_scope(client, db, admin_user, maintainer_user, two_systems):
    a, b = two_systems
    win_a = _mk_window(db, admin_user, "system", a.id, "w")
    win_b = _mk_window(db, admin_user, "system", b.id, "w")
    win_all = _mk_window(db, admin_user, "all", None, "w")
    _grant(db, maintainer_user, a, _mk_role(db, "r-mw"))
    _login(client, maintainer_user)
    res = client.get(_MW)
    names = {w["name"] for w in res.json()["windows"]}
    assert win_a.name in names
    assert win_b.name not in names and win_all.name not in names
    assert b.hostname not in res.text
    # Direct ops on out-of-scope / tenant-wide windows.
    assert client.put(f"{_MW}/{win_b.id}", json={"name": "z"}).status_code == 404
    assert client.delete(f"{_MW}/{win_b.id}").status_code == 404
    assert client.put(f"{_MW}/{win_all.id}", json={"name": "z"}).status_code == 404


def test_maintenance_window_create_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-mwc"))
    _login(client, maintainer_user)
    sched = {"day_of_week": [0], "start_time": "01:00", "end_time": "02:00"}
    # Out-of-scope system target -> 404; tenant-wide 'all' -> 403; in-scope -> 200.
    assert (
        client.post(
            _MW,
            json={
                "name": "x",
                "target_type": "system",
                "target_id": b.id,
                "schedule": sched,
            },
        ).status_code
        == 404
    )
    assert (
        client.post(
            _MW, json={"name": "y", "target_type": "all", "schedule": sched}
        ).status_code
        == 403
    )
    assert (
        client.post(
            _MW,
            json={
                "name": "z",
                "target_type": "system",
                "target_id": a.id,
                "schedule": sched,
            },
        ).status_code
        == 200
    )


def test_maintenance_window_check_scope(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-mwck"))
    _login(client, maintainer_user)
    assert client.get(f"{_MW}/check/{a.id}").status_code == 200
    assert client.get(f"{_MW}/check/{b.id}").status_code == 404
    assert client.get(f"{_MW}/check/99887766").status_code == 404


def test_maintenance_window_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    win_all = _mk_window(db, admin_user, "all", None, "adm")
    win_b = _mk_window(db, admin_user, "system", b.id, "adm")
    _login(client, admin_user)
    names = {w["name"] for w in client.get(_MW).json()["windows"]}
    assert {win_all.name, win_b.name} <= names


def test_credential_create_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    # PRA-281 Slice 10 fix: credential create is tenant-wide-admin-only for scoped
    # callers, stopped BEFORE the duplicate-name check (name-enumeration) and
    # BEFORE any linked-mode Vault read (path/key-shape probing).
    a, b = two_systems
    _mk_cred(db, "pra281-hidden-cred")
    _grant(db, maintainer_user, a, _mk_role(db, "r-credcr"))
    _login(client, maintainer_user)
    dup = client.post(
        _CRED,
        json={
            "name": "pra281-hidden-cred",
            "auth_method": "password",
            "username": "root",
            "password": "x",
        },
    )
    assert dup.status_code == 403
    assert "already exists" not in dup.text
    linked = client.post(
        _CRED,
        json={
            "name": "pra281-probe",
            "auth_method": "password",
            "vault_path": "praxis/credentials/probe",
        },
    )
    assert linked.status_code == 403


def test_ssh_security_unverified_host_keys_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    # PRA-281 Slice 10 fix: /host-keys/unverified is now reachable (declared before
    # /host-keys/{host_key_id}) AND row-scoped.
    a, b = two_systems
    _mk_host_key(db, a)  # verified defaults False -> unverified
    hk_b = _mk_host_key(db, b)
    _grant(db, maintainer_user, a, _mk_role(db, "r-ssecunv"))
    _login(client, maintainer_user)
    res = client.get(f"{_SSEC}/host-keys/unverified")
    assert res.status_code == 200
    sys_ids = {row["system_id"] for row in res.json()["host_keys"]}
    assert sys_ids <= {a.id}
    assert hk_b.system_id not in sys_ids
    # Admin tenant-wide sees both.
    _login(client, admin_user)
    admin_ids = {
        row["system_id"]
        for row in client.get(f"{_SSEC}/host-keys/unverified").json()["host_keys"]
    }
    assert {a.id, b.id} <= admin_ids


# ================================================================= SLICE 11
# Grouping + saved-selector system surfaces (PRA-281 Slice 11):
# groups.py, smart_groups.py, tags.py, views.py.
#
# Principle: pure-label CRUD (group/tag name+color) stays global taxonomy;
# host-derived reads (list/detail/members/counts) are scoped and fail closed;
# system-association batches reject the whole request non-disclosingly if any
# target is out of scope; membership-materializing / host-count-leaking
# mutations (smart-group create/update/delete/recompute, group delete) are
# tenant-wide-admin-only for scoped callers; saved views expose an arbitrary
# filter blob so scoped callers see/operate only their OWN views.

_GRP = "/groups"
_TAG = "/tags"
_SG = "/smart-groups"
_VIEW = "/views"


def _mk_group_with(db, systems, label):
    _BL_SEQ["n"] += 1
    g = Group(name=f"pra281-g11-{label}-{_BL_SEQ['n']}", description="x")
    db.add(g)
    db.flush()
    for s in systems:
        s.group_id = g.id
    db.commit()
    db.refresh(g)
    return g


def _mk_tag(db, user, name):
    t = Tag(
        name=name,
        color="#6B7280",
        created_by=user.id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def _mk_view(db, user, name, is_shared=False, filters=None):
    v = SavedView(
        name=name,
        user_id=user.id,
        filters=json.dumps(filters if filters is not None else {"status": ["Active"]}),
        is_shared=is_shared,
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    return v


# --------------------------------------------------------------- groups.py


def test_group_list_detail_systems_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    g_a = _mk_group_with(db, [a], "vis")  # members {a}
    g_b = _mk_group_with(db, [b], "hid")  # members {b}
    _grant(db, maintainer_user, a, _mk_role(db, "r-g11l"))
    _login(client, maintainer_user)

    ids = {g["id"] for g in client.get(_GRP).json()}
    assert g_a.id in ids  # fully-in-scope group visible
    assert g_b.id not in ids  # out-of-scope group hidden
    # Detail: in-scope 200; out-of-scope + nonexistent both non-disclosing 404.
    assert client.get(f"{_GRP}/{g_a.id}").status_code == 200
    assert client.get(f"{_GRP}/{g_b.id}").status_code == 404
    assert client.get(f"{_GRP}/99887766").status_code == 404
    # Systems listing under a hidden group is a non-disclosing 404; a visible
    # group never leaks an out-of-scope hostname.
    assert client.get(f"{_GRP}/{g_a.id}/systems").status_code == 200
    assert client.get(f"{_GRP}/{g_b.id}/systems").status_code == 404
    assert b.hostname not in client.get(f"{_GRP}/{g_a.id}/systems").text


def test_group_mixed_and_empty_hidden_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    g_ab = _mk_group_with(db, [a, b], "mix")  # mixed membership
    # The default fixture group `pra281-grp` is now empty (both moved to g_ab).
    _grant(db, maintainer_user, a, _mk_role(db, "r-g11mix"))
    _login(client, maintainer_user)
    ids = {g["id"] for g in client.get(_GRP).json()}
    # A mixed-scope group leaks out-of-scope membership -> hidden (fail closed).
    assert g_ab.id not in ids
    assert client.get(f"{_GRP}/{g_ab.id}").status_code == 404
    assert client.get(f"{_GRP}/{g_ab.id}/systems").status_code == 404


def test_group_list_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    g_a = _mk_group_with(db, [a], "adma")
    g_b = _mk_group_with(db, [b], "admb")
    _login(client, admin_user)
    ids = {g["id"] for g in client.get(_GRP).json()}
    assert {g_a.id, g_b.id} <= ids
    assert client.get(f"{_GRP}/{g_b.id}").status_code == 200


def test_group_assign_rejects_out_of_scope_batch(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    g_a = _mk_group_with(db, [a], "asg")
    _grant(db, maintainer_user, a, _mk_role(db, "r-g11asg"))
    _login(client, maintainer_user)
    # Mixed batch -> reject the whole request non-disclosingly, no partial move.
    res = client.post(f"{_GRP}/{g_a.id}/systems", json={"system_ids": [a.id, b.id]})
    assert res.status_code == 404
    assert str(a.id) not in res.text and str(b.id) not in res.text
    db.refresh(b)
    assert b.group_id != g_a.id  # B was not reassigned
    # In-scope-only assignment succeeds.
    assert (
        client.post(f"{_GRP}/{g_a.id}/systems", json={"system_ids": [a.id]}).status_code
        == 200
    )


def test_group_delete_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    g_a = _mk_group_with(db, [a], "del")
    _mk_group_with(db, [a], "park")  # re-park A -> g_a is now empty & deletable
    _grant(db, maintainer_user, a, _mk_role(db, "r-g11del"))
    _login(client, maintainer_user)
    # Delete surfaces a fleet-wide host-count guard -> tenant-wide-admin-only.
    assert client.delete(f"{_GRP}/{g_a.id}").status_code == 403
    # Admin can delete the now-empty group.
    _login(client, admin_user)
    assert client.delete(f"{_GRP}/{g_a.id}").status_code == 204


def test_group_empty_scope_sees_no_groups(client, db, auditor_user, two_systems):
    a, b = two_systems
    g_a = _mk_group_with(db, [a], "empt")
    _login(client, auditor_user)  # no grants -> empty scope
    assert g_a.id not in {g["id"] for g in client.get(_GRP).json()}
    assert client.get(f"{_GRP}/{g_a.id}").status_code == 404


# --------------------------------------------------------------- smart_groups.py


def test_smart_group_list_and_members_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "s11a")
    sg_b = _mk_smart_group(db, admin_user, [b], "s11b")
    sg_ab = _mk_smart_group(db, admin_user, [a, b], "s11ab")
    sg_empty = _mk_smart_group(db, admin_user, [], "s11empty")
    _grant(db, maintainer_user, a, _mk_role(db, "r-sg11l"))
    _login(client, maintainer_user)

    ids = {g["id"] for g in client.get(_SG).json()["smart_groups"]}
    assert sg_a.id in ids  # fully-in-scope, non-empty
    for hidden in (sg_b, sg_ab, sg_empty):
        assert hidden.id not in ids
    # members: in-scope 200 (no out-of-scope hostname); mixed/out/empty -> 404.
    assert client.get(f"{_SG}/{sg_a.id}/members").status_code == 200
    assert b.hostname not in client.get(f"{_SG}/{sg_a.id}/members").text
    for hidden in (sg_b, sg_ab, sg_empty):
        assert client.get(f"{_SG}/{hidden.id}/members").status_code == 404


def test_smart_group_list_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "s11adma")
    sg_b = _mk_smart_group(db, admin_user, [b], "s11admb")
    _login(client, admin_user)
    ids = {g["id"] for g in client.get(_SG).json()["smart_groups"]}
    assert {sg_a.id, sg_b.id} <= ids
    assert client.get(f"{_SG}/{sg_b.id}/members").status_code == 200


def test_smart_group_preview_scoped_total_and_members(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-sg11p"))
    _login(client, maintainer_user)
    # Rule matches BOTH hostnames (pra281-a / pra281-b); scope filters to A only.
    rule = {"field": "hostname", "op": "contains", "value": "pra281"}
    body = client.post(f"{_SG}/preview", json={"rule_json": rule}).json()
    assert body["total"] == 1
    member_ids = {m["id"] for m in body["members"]}
    assert member_ids == {a.id}
    assert b.hostname not in json.dumps(body)


def test_smart_group_preview_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _login(client, admin_user)
    rule = {"field": "hostname", "op": "contains", "value": "pra281"}
    body = client.post(f"{_SG}/preview", json={"rule_json": rule}).json()
    assert body["total"] >= 2
    assert {a.id, b.id} <= {m["id"] for m in body["members"]}


def test_smart_group_mutations_tenant_wide_admin_only(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    sg_a = _mk_smart_group(db, admin_user, [a], "s11mut")
    _grant(db, maintainer_user, a, _mk_role(db, "r-sg11m"))
    _login(client, maintainer_user)
    # Create/update/delete/recompute materialize GLOBAL membership -> 403 for a
    # scoped caller (even one holding the maintainer role) BEFORE any mutation.
    rule = {"field": "hostname", "op": "contains", "value": "pra281"}
    assert (
        client.post(_SG, json={"name": "s11-new", "rule_json": rule}).status_code == 403
    )
    assert client.put(f"{_SG}/{sg_a.id}", json={"description": "x"}).status_code == 403
    assert client.post(f"{_SG}/{sg_a.id}/recompute").status_code == 403
    assert client.delete(f"{_SG}/{sg_a.id}").status_code == 403


def test_smart_group_mutations_admin_ok(client, db, admin_user, two_systems):
    a, b = two_systems
    _login(client, admin_user)
    rule = {"field": "hostname", "op": "contains", "value": "pra281"}
    res = client.post(_SG, json={"name": "s11-admin-new", "rule_json": rule})
    assert res.status_code == 200, res.text
    gid = res.json()["smart_group"]["id"]
    assert client.post(f"{_SG}/{gid}/recompute").status_code == 200
    assert client.delete(f"{_SG}/{gid}").status_code == 200


# --------------------------------------------------------------- tags.py


def test_tag_list_get_counts_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    tag = _mk_tag(db, admin_user, "pra281-t11")
    a.tags.append(tag)
    b.tags.append(tag)
    db.commit()
    _grant(db, maintainer_user, a, _mk_role(db, "r-t11"))
    _login(client, maintainer_user)
    listed = {t["id"]: t for t in client.get(_TAG).json()}
    # system_count includes only in-scope systems (A), never out-of-scope B.
    assert listed[tag.id]["system_count"] == 1
    assert client.get(f"{_TAG}/{tag.id}").json()["system_count"] == 1
    # Admin sees the full count.
    _login(client, admin_user)
    assert client.get(f"{_TAG}/{tag.id}").json()["system_count"] == 2


def test_tag_get_empty_scope_zero_count(client, db, auditor_user, two_systems):
    a, b = two_systems
    tag = _mk_tag(db, auditor_user, "pra281-t11empty")
    a.tags.append(tag)
    db.commit()
    _login(client, auditor_user)  # no grants -> empty scope
    assert client.get(f"{_TAG}/{tag.id}").json()["system_count"] == 0


def test_tag_assign_remove_bulk_reject_mixed(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    tag = _mk_tag(db, admin_user, "pra281-t11b")
    _grant(db, maintainer_user, a, _mk_role(db, "r-t11b"))
    _login(client, maintainer_user)
    # Assign a mixed batch -> reject whole request non-disclosingly, no partial.
    res = client.post(f"{_TAG}/{tag.id}/systems", json={"system_ids": [a.id, b.id]})
    assert res.status_code == 404
    assert str(b.id) not in res.text
    db.refresh(a)
    assert tag not in a.tags  # A was not tagged either
    # Remove mixed batch -> also rejected.
    assert (
        client.request(
            "DELETE", f"{_TAG}/{tag.id}/systems", json={"system_ids": [a.id, b.id]}
        ).status_code
        == 404
    )
    # Bulk-assign mixed batch -> rejected.
    assert (
        client.post(
            f"{_TAG}/bulk-assign",
            json={"tag_ids": [tag.id], "system_ids": [a.id, b.id]},
        ).status_code
        == 404
    )
    # In-scope-only assignment succeeds.
    assert (
        client.post(f"{_TAG}/{tag.id}/systems", json={"system_ids": [a.id]}).status_code
        == 200
    )


def test_tag_delete_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    # PRA-281 Slice 11 fix-pass: DELETE /tags/{id} CASCADE-removes system
    # associations (including out-of-scope hosts), so it is a system-association
    # mutation, not pure taxonomy -> tenant-wide-admin-only for scoped callers.
    a, b = two_systems
    tag = _mk_tag(db, admin_user, "pra281-t11del")
    a.tags.append(tag)
    b.tags.append(tag)  # tag attached to an OUT-OF-SCOPE system
    db.commit()
    _grant(db, maintainer_user, a, _mk_role(db, "r-t11del"))
    _login(client, maintainer_user)
    # Scoped maintainer is refused (403) before any lookup or cascade.
    res = client.delete(f"{_TAG}/{tag.id}")
    assert res.status_code == 403
    # The tag and BOTH associations remain intact (no hidden host was mutated).
    db.expire_all()
    assert db.query(Tag).filter(Tag.id == tag.id).first() is not None
    assert tag in db.query(System).filter(System.id == a.id).first().tags
    assert tag in db.query(System).filter(System.id == b.id).first().tags
    # Admin (tenant-wide) can still delete the tag.
    _login(client, admin_user)
    assert client.delete(f"{_TAG}/{tag.id}").status_code == 204
    db.expire_all()
    assert db.query(Tag).filter(Tag.id == tag.id).first() is None


# --------------------------------------------------------------- views.py


def test_views_scoped_see_and_operate_own_only(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    own = _mk_view(db, maintainer_user, "own-view")
    # A shared view whose filter blob references an out-of-scope system id.
    shared = _mk_view(
        db,
        admin_user,
        "shared-secret-view",
        is_shared=True,
        filters={"system_ids": [b.id]},
    )
    _grant(db, maintainer_user, a, _mk_role(db, "r-v11"))
    _login(client, maintainer_user)

    names = {v["name"] for v in client.get(_VIEW).json()["views"]}
    assert names == {"own-view"}  # shared/global views hidden from scoped callers
    assert "shared-secret-view" not in client.get(_VIEW).text
    # Update/set-default on a hidden view are non-disclosing (same as nonexistent
    # -> 400 "View not found"); delete maps not-found to 404.
    assert client.put(f"{_VIEW}/{shared.id}", json={"name": "z"}).status_code == 400
    assert client.put(f"{_VIEW}/99887766", json={"name": "z"}).status_code == 400
    assert client.put(f"{_VIEW}/{shared.id}/default").status_code == 400
    assert client.delete(f"{_VIEW}/{shared.id}").status_code == 404
    assert client.delete(f"{_VIEW}/99887766").status_code == 404
    # Own-view operations still work.
    assert client.put(f"{_VIEW}/{own.id}", json={"name": "own2"}).status_code == 200
    assert client.put(f"{_VIEW}/{own.id}/default").status_code == 200


def test_views_admin_sees_and_operates_shared(client, db, admin_user, maintainer_user):
    shared = _mk_view(db, maintainer_user, "sh-adm-view", is_shared=True)
    _login(client, admin_user)
    names = {v["name"] for v in client.get(_VIEW).json()["views"]}
    assert "sh-adm-view" in names  # admin sees own + shared
    # Admin (tenant-wide) may operate on a shared view it does not own.
    assert client.put(f"{_VIEW}/{shared.id}/default").status_code == 200


# ================================================================= SLICE 12
# Audit / reporting aggregate surfaces (PRA-281 Slice 12):
# reports.py, fleet_operations.py, audits.py, file_transfer.py /audits.
#
# Principle: report runs/schedules are tenant-wide reporting metadata (arbitrary
# filters_snapshot + fleet-wide counts, not attributable to one system) ->
# tenant-wide-admin-only for scoped callers. Fleet operations are host-derived
# through their result rows (set-visibility, fail closed for mixed/empty). System
# audits and file-transfer audits carry a direct system_id -> row/total scoped,
# explicit out-of-scope system_id filter is a non-disclosing 404.

_REP = "/reports"
_FOP = "/fleet/operations"
_AUD = "/audits"
_XFER = "/transfer"


def _mk_report_run(db, user, kind="patch_executions", filters=None):
    from app.db.report_models import ReportRun

    row = ReportRun(
        report_kind=kind,
        triggered_by="user",
        triggered_by_user_id=user.id,
        triggered_by_username=user.username,
        filters_snapshot=filters if filters is not None else {},
        state="succeeded",
        row_count=5,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_fleet_op(db, user, result_systems, op_type="bulk_update", status="completed"):
    op = FleetOperation(
        operation_type=op_type,
        user_id=user.id,
        target_count=len(result_systems),
        success_count=len(result_systems),
        failure_count=0,
        status=status,
    )
    db.add(op)
    db.flush()
    for s in result_systems:
        db.add(
            FleetOperationResult(
                fleet_operation_id=op.id,
                system_id=s.id,
                status="success",
                error_message=f"ferr-{s.id}",
            )
        )
    db.commit()
    db.refresh(op)
    return op


def _mk_xfer_audit(db, user, system, remote_path="/etc/x", status="success"):
    row = FileTransferAudit(
        user_id=user.id,
        system_id=system.id,
        login="root",
        direction="download",
        remote_path=remote_path,
        local_filename="x.txt",
        status=status,
        transport="ssh",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# --------------------------------------------------------------- reports.py


def test_reports_runs_and_schedules_hidden_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    from app.services import report_schedule_service

    _mk_report_run(db, admin_user, filters={"system_ids": [b.id]})
    report_schedule_service.create_schedule(
        db,
        name="pra281-sched-vis",
        report_kind="patch_executions",
        cadence="daily",
        filters_snapshot={"system_ids": [b.id]},
        format="csv",
        enabled=True,
        created_by_user_id=admin_user.id,
    )
    _grant(db, maintainer_user, a, _mk_role(db, "r-rep"))
    _login(client, maintainer_user)
    # Scoped callers see NO report runs or schedules (tenant-wide metadata).
    runs = client.get(f"{_REP}/runs")
    assert runs.status_code == 200
    assert runs.json()["items"] == [] and runs.json()["total"] == 0
    scheds = client.get(f"{_REP}/schedules")
    assert scheds.status_code == 200
    assert scheds.json()["items"] == [] and scheds.json()["total"] == 0
    # Admin (tenant-wide) sees them.
    _login(client, admin_user)
    assert client.get(f"{_REP}/runs").json()["total"] >= 1
    assert client.get(f"{_REP}/schedules").json()["total"] >= 1


def test_reports_schedule_mutations_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    from app.db.report_models import ReportSchedule
    from app.services import report_schedule_service

    sched = report_schedule_service.create_schedule(
        db,
        name="pra281-sched-mut",
        report_kind="patch_executions",
        cadence="daily",
        filters_snapshot={},
        format="csv",
        enabled=True,
        created_by_user_id=admin_user.id,
    )
    _grant(db, maintainer_user, a, _mk_role(db, "r-repmut"))
    _login(client, maintainer_user)
    # Create/update/delete schedules are tenant-wide-admin-only for scoped callers.
    assert (
        client.post(
            f"{_REP}/schedules",
            json={"name": "x", "report_kind": "patch_executions", "cadence": "daily"},
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"{_REP}/schedules/{sched.id}", json={"enabled": False}
        ).status_code
        == 403
    )
    assert client.delete(f"{_REP}/schedules/{sched.id}").status_code == 403
    # The schedule is unchanged (403 fired before any mutation).
    db.expire_all()
    assert (
        db.query(ReportSchedule).filter(ReportSchedule.id == sched.id).first().enabled
        is True
    )


# --------------------------------------------------------------- fleet_operations.py


def test_fleet_operations_list_and_detail_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    op_a = _mk_fleet_op(db, admin_user, [a], op_type="scope_a_op")
    op_b = _mk_fleet_op(db, admin_user, [b], op_type="scope_b_op")
    op_ab = _mk_fleet_op(db, admin_user, [a, b], op_type="scope_ab_op")
    op_empty = _mk_fleet_op(db, admin_user, [], op_type="scope_empty_op")
    _grant(db, maintainer_user, a, _mk_role(db, "r-fop"))
    _login(client, maintainer_user)
    listed = client.get(_FOP)
    ids = {o["id"] for o in listed.json()["items"]}
    assert ids == {op_a.id}  # only the fully-in-scope operation
    assert listed.json()["total"] == 1
    # No hidden operation type, out-of-scope hostname, or error text leaks.
    txt = listed.text
    for hidden in ("scope_b_op", "scope_ab_op", "scope_empty_op", f"ferr-{b.id}"):
        assert hidden not in txt
    # Detail: in-scope 200; out-of-scope-only, mixed, empty, nonexistent -> 404.
    assert client.get(f"{_FOP}/{op_a.id}").status_code == 200
    for hidden_op in (op_b, op_ab, op_empty):
        assert client.get(f"{_FOP}/{hidden_op.id}").status_code == 404
    assert client.get(f"{_FOP}/99887766").status_code == 404
    assert b.hostname not in client.get(f"{_FOP}/{op_a.id}").text


def test_fleet_operations_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    op_a = _mk_fleet_op(db, admin_user, [a], op_type="adm_a")
    op_b = _mk_fleet_op(db, admin_user, [b], op_type="adm_b")
    _login(client, admin_user)
    ids = {o["id"] for o in client.get(_FOP).json()["items"]}
    assert {op_a.id, op_b.id} <= ids
    assert client.get(f"{_FOP}/{op_b.id}").status_code == 200


def test_fleet_operations_filter_options_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_fleet_op(db, admin_user, [a], op_type="visible_type")
    _mk_fleet_op(db, admin_user, [b], op_type="hidden_type")
    _grant(db, maintainer_user, a, _mk_role(db, "r-fopopt"))
    _login(client, maintainer_user)
    opts = client.get(f"{_FOP}/filters/options").json()
    assert "visible_type" in opts["operation_types"]
    assert "hidden_type" not in opts["operation_types"]


def test_fleet_operations_empty_scope(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    _mk_fleet_op(db, admin_user, [a], op_type="sometype")
    _login(client, auditor_user)  # no grants -> empty scope
    assert client.get(_FOP).json()["total"] == 0
    opts = client.get(f"{_FOP}/filters/options").json()
    assert opts["operation_types"] == [] and opts["users"] == []


# --------------------------------------------------------------- audits.py


def test_audits_list_and_direct_scope(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    _mk_audit(db, a, admin_user, audit_type="type_a")
    _mk_audit(db, b, admin_user, audit_type="type_b")
    _grant(db, auditor_user, a, _mk_role(db, "r-aud12"))
    _login(client, auditor_user)
    listed = client.get(_AUD)
    sys_ids = {row["system_id"] for row in listed.json()["items"]}
    assert sys_ids == {a.id}
    assert listed.json()["total"] == 1
    assert b.hostname not in listed.text
    # Explicit out-of-scope system_id filter -> non-disclosing 404.
    assert client.get(f"{_AUD}?system_id={b.id}").status_code == 404
    assert client.get(f"{_AUD}?system_id={a.id}").status_code == 200
    # Direct per-system: in-scope 200; out-of-scope + nonexistent 404.
    assert client.get(f"{_AUD}/{a.id}").status_code == 200
    assert client.get(f"{_AUD}/{b.id}").status_code == 404
    assert client.get(f"{_AUD}/99887766").status_code == 404


def test_audits_filter_options_scoped(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    _mk_audit(db, a, admin_user, audit_type="atype")
    _mk_audit(db, b, admin_user, audit_type="btype")
    _grant(db, auditor_user, a, _mk_role(db, "r-aud12opt"))
    _login(client, auditor_user)
    opts = client.get(f"{_AUD}/filters/options").json()
    assert "atype" in opts["audit_types"]
    assert "btype" not in opts["audit_types"]
    sys_ids = {s["id"] for s in opts["systems"]}
    assert sys_ids == {a.id}
    assert b.hostname not in json.dumps(opts)


def test_audits_empty_scope_options_empty(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    _mk_audit(db, a, admin_user)
    _login(client, auditor_user)  # no grants -> empty scope
    assert client.get(_AUD).json()["total"] == 0
    opts = client.get(f"{_AUD}/filters/options").json()
    assert opts["audit_types"] == []
    assert opts["systems"] == []
    assert opts["users"] == []


def test_audits_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    _mk_audit(db, a, admin_user)
    _mk_audit(db, b, admin_user)
    _login(client, admin_user)
    sys_ids = {row["system_id"] for row in client.get(_AUD).json()["items"]}
    assert {a.id, b.id} <= sys_ids
    assert client.get(f"{_AUD}/{b.id}").status_code == 200


# --------------------------------------------------------------- file_transfer.py /audits


def test_file_transfer_audits_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    # Both transfers are the maintainer's OWN, but one is on an out-of-scope host.
    _mk_xfer_audit(db, maintainer_user, a, remote_path="/in-scope-path")
    _mk_xfer_audit(db, maintainer_user, b, remote_path="/hidden-path")
    _grant(db, maintainer_user, a, _mk_role(db, "r-xfer"))
    _login(client, maintainer_user)
    res = client.get(f"{_XFER}/audits")  # mine_only default True
    sys_ids = {r["system_id"] for r in res.json()["audits"]}
    assert sys_ids == {a.id}
    assert "hidden-path" not in res.text
    # Explicit out-of-scope system_id filter -> non-disclosing 404.
    assert client.get(f"{_XFER}/audits?system_id={b.id}").status_code == 404
    assert client.get(f"{_XFER}/audits?system_id={a.id}").status_code == 200


def test_file_transfer_audits_admin_sees_all(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_xfer_audit(db, maintainer_user, a)
    _mk_xfer_audit(db, admin_user, b)
    _login(client, admin_user)
    res = client.get(f"{_XFER}/audits?mine_only=false")
    sys_ids = {r["system_id"] for r in res.json()["audits"]}
    assert {a.id, b.id} <= sys_ids


# ================================================================= SLICE 13
# Compliance evidence, remediation, exports, and summaries (PRA-281 Slice 13).
#
# Every host-derived compliance row (evidence / remediation request / plan /
# execution attempt) carries a direct system_id, so scoping is set membership:
# lists/exports/summaries are restricted to in-scope systems (empty scope →
# empty/zero), and out-of-scope direct ids / explicit system_id filters are
# non-disclosing 404s before serialization or side effects. Policy / check /
# starter-pack routes are pure taxonomy and stay global.

_CMP = "/compliance"


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


def _mk_policy_evidence(db, admin_user, systems, slug):
    """Create one policy+check and evaluate it on each system, returning
    (policy, {system_id: failing_evidence_row})."""
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"pra281-{slug}",
        name=f"pra281 {slug}",
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"c-{slug}",
        title=f"c {slug}",
        kind="package_installed",
        definition={"package": f"missing-{slug}"},
    )
    # Evaluate across the whole fleet in ONE run so every host shares a single
    # evaluated_at — the policy/fleet summaries anchor on the latest run, so
    # per-host evaluation (distinct timestamps) would drop all but the last host.
    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=policy.id)
    ev = {}
    for s in systems:
        ev[s.id] = (
            db.query(CompliancePolicyEvidence)
            .filter(
                CompliancePolicyEvidence.policy_id == policy.id,
                CompliancePolicyEvidence.system_id == s.id,
                CompliancePolicyEvidence.verdict == "fail",
            )
            .first()
        )
        assert ev[s.id] is not None, "expected a failing evidence row"
    return policy, ev


def _mk_cmp_request(db, requester, evidence):
    return compliance_remediation_service.create_request(
        db, actor_user_id=requester.id, evidence_id=evidence.id
    )


def _mk_cmp_plan(db, approver, request):
    # ``approver`` must differ from the request's requester (separation of duties).
    compliance_remediation_service.approve_request(
        db, request.id, actor_user_id=approver.id
    )
    return compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=request.id, actor_user_id=approver.id
    )


def _mk_cmp_attempt(db, approver, plan):
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=approver.id
    )
    return compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=approver.id
    )


# --------------------------------------------------------------- evidence


def test_compliance_policy_evidence_list_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    policy, _ev = _mk_policy_evidence(db, admin_user, [a, b], "evlist")
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp-ev"))
    _login(client, maintainer_user)
    body = client.get(f"{_CMP}/policies/{policy.id}/evidence").json()
    sys_ids = {row["system_id"] for row in body["items"]}
    assert sys_ids == {a.id}
    assert body["total"] == 1
    assert b.hostname not in client.get(f"{_CMP}/policies/{policy.id}/evidence").text
    # Explicit out-of-scope system_id filter -> non-disclosing 404.
    assert (
        client.get(f"{_CMP}/policies/{policy.id}/evidence?system_id={b.id}").status_code
        == 404
    )
    assert (
        client.get(f"{_CMP}/policies/{policy.id}/evidence?system_id={a.id}").status_code
        == 200
    )


def test_compliance_policy_evidence_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    policy, _ev = _mk_policy_evidence(db, admin_user, [a, b], "evadm")
    _login(client, admin_user)
    body = client.get(f"{_CMP}/policies/{policy.id}/evidence").json()
    assert {a.id, b.id} <= {row["system_id"] for row in body["items"]}


def test_compliance_system_evidence_direct_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_policy_evidence(db, admin_user, [a, b], "sysev")
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp-sysev"))
    _login(client, maintainer_user)
    assert client.get(f"{_CMP}/systems/{a.id}/evidence").status_code == 200
    assert client.get(f"{_CMP}/systems/{b.id}/evidence").status_code == 404
    assert client.get(f"{_CMP}/systems/98765/evidence").status_code == 404


def test_compliance_policy_summary_and_fleet_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    policy, _ev = _mk_policy_evidence(db, admin_user, [a, b], "summ")
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp-summ"))
    _login(client, maintainer_user)
    summ = client.get(f"{_CMP}/policies/{policy.id}/summary").json()
    per_host_ids = {h["system_id"] for h in summ["per_host"]}
    assert per_host_ids == {a.id}  # only in-scope host in the rollup
    fleet = client.get(f"{_CMP}/fleet/summary").json()
    assert fleet["host_count"] == 1
    # Admin tenant-wide sees both hosts.
    _login(client, admin_user)
    assert client.get(f"{_CMP}/fleet/summary").json()["host_count"] >= 2


def test_compliance_evidence_export_scope(
    client, db, admin_user, maintainer_user, seed_roles, two_systems
):
    a, b = two_systems
    _mk_policy_evidence(db, admin_user, [a, b], "export")
    # A second maintainer with NO grants (empty scope) exercises the empty-scope
    # export path (the exports router is admin/maintainer-only, so an auditor
    # can't reach it — role gate 403).
    empty_maint = _mk_user(db, seed_roles, "pra281-empty-maint", ["maintainer"])
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp-exp"))
    _login(client, maintainer_user)
    # JSONL export streams only in-scope rows; no hidden hostname/system id.
    jsonl = client.get(f"{_CMP}/exports/evidence.jsonl")
    assert jsonl.status_code == 200
    sys_ids = {
        json.loads(line)["system_id"]
        for line in jsonl.text.splitlines()
        if line.strip()
    }
    assert sys_ids == {a.id}
    assert b.hostname not in jsonl.text
    # CSV export same scoping.
    csv_text = client.get(f"{_CMP}/exports/evidence.csv").text
    assert f",{b.id}," not in csv_text
    # Explicit out-of-scope system_id filter -> 404 before any byte.
    assert (
        client.get(f"{_CMP}/exports/evidence.jsonl?system_id={b.id}").status_code == 404
    )
    # Empty-scope maintainer exports no rows.
    _login(client, empty_maint)
    empty = client.get(f"{_CMP}/exports/evidence.jsonl")
    assert empty.status_code == 200
    assert [line for line in empty.text.splitlines() if line.strip()] == []


# --------------------------------------------------------------- remediation requests


def test_compliance_remediation_requests_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _policy, ev = _mk_policy_evidence(db, admin_user, [a, b], "req")
    req_a = _mk_cmp_request(db, maintainer_user, ev[a.id])
    req_b = _mk_cmp_request(db, maintainer_user, ev[b.id])
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp-req"))
    _login(client, maintainer_user)
    body = client.get(f"{_CMP}/remediation-requests").json()
    ids = {r["id"] for r in body["items"]}
    assert ids == {req_a.id}
    assert body["total"] == 1
    assert (
        client.get(f"{_CMP}/remediation-requests?system_id={b.id}").status_code == 404
    )
    # Direct detail: in-scope 200, out-of-scope + nonexistent 404.
    assert client.get(f"{_CMP}/remediation-requests/{req_a.id}").status_code == 200
    assert client.get(f"{_CMP}/remediation-requests/{req_b.id}").status_code == 404
    assert client.get(f"{_CMP}/remediation-requests/98765").status_code == 404
    # cancel (maintainer-reachable) on a hidden request -> 404 before any state
    # change; the request stays open.
    assert (
        client.post(
            f"{_CMP}/remediation-requests/{req_b.id}/cancel", json={}
        ).status_code
        == 404
    )
    db.expire_all()
    assert compliance_remediation_service.get_request(db, req_b.id).state == "requested"
    # build-plan (maintainer-reachable) on a hidden request -> 404, no plan built.
    assert (
        client.post(f"{_CMP}/remediation-requests/{req_b.id}/plan").status_code == 404
    )
    assert (
        compliance_remediation_plan_service.get_plan_for_request(db, req_b.id) is None
    )


def test_compliance_remediation_create_out_of_scope_evidence_404(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _policy, ev = _mk_policy_evidence(db, admin_user, [a, b], "reqcreate")
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp-reqc"))
    _login(client, maintainer_user)
    # Opening a request against out-of-scope evidence is a non-disclosing 404,
    # and no request row is written.
    before = client.get(f"{_CMP}/remediation-requests").json()["total"]
    res = client.post(f"{_CMP}/remediation-requests", json={"evidence_id": ev[b.id].id})
    assert res.status_code == 404
    assert str(b.id) not in res.text
    _login(client, admin_user)
    _, total = compliance_remediation_service.list_requests(db, system_id=b.id)
    assert total == 0
    # In-scope evidence still works for the maintainer.
    _login(client, maintainer_user)
    ok = client.post(f"{_CMP}/remediation-requests", json={"evidence_id": ev[a.id].id})
    assert ok.status_code == 201, ok.text


# --------------------------------------------------------------- plans + inventory


def test_compliance_remediation_plans_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _policy, ev = _mk_policy_evidence(db, admin_user, [a, b], "plan")
    plan_a = _mk_cmp_plan(
        db, admin_user, _mk_cmp_request(db, maintainer_user, ev[a.id])
    )
    plan_b = _mk_cmp_plan(
        db, admin_user, _mk_cmp_request(db, maintainer_user, ev[b.id])
    )
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp-plan"))
    _login(client, maintainer_user)
    body = client.get(f"{_CMP}/remediation-plans").json()
    ids = {p["id"] for p in body["items"]}
    assert ids == {plan_a.id}
    assert client.get(f"{_CMP}/remediation-plans?system_id={b.id}").status_code == 404
    assert client.get(f"{_CMP}/remediation-plans/{plan_a.id}").status_code == 200
    assert client.get(f"{_CMP}/remediation-plans/{plan_b.id}").status_code == 404
    # Fleet remediation summary counts only in-scope requests/plans.
    summary = client.get(f"{_CMP}/remediation/fleet-summary").json()
    assert summary["request_total"] == 1
    assert summary["current_plan_total"] == 1
    # Per-host remediation inventory: direct id scope.
    assert client.get(f"{_CMP}/systems/{a.id}/remediation").status_code == 200
    assert client.get(f"{_CMP}/systems/{b.id}/remediation").status_code == 404


def test_compliance_remediation_fleet_summary_admin(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _policy, ev = _mk_policy_evidence(db, admin_user, [a, b], "fltadm")
    _mk_cmp_plan(db, admin_user, _mk_cmp_request(db, maintainer_user, ev[a.id]))
    _mk_cmp_plan(db, admin_user, _mk_cmp_request(db, maintainer_user, ev[b.id]))
    _login(client, admin_user)
    summary = client.get(f"{_CMP}/remediation/fleet-summary").json()
    assert summary["request_total"] >= 2
    assert summary["current_plan_total"] >= 2


# --------------------------------------------------------------- executions


def test_compliance_remediation_executions_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _policy, ev = _mk_policy_evidence(db, admin_user, [a, b], "exec")
    req_a = _mk_cmp_request(db, maintainer_user, ev[a.id])
    req_b = _mk_cmp_request(db, maintainer_user, ev[b.id])
    att_a = _mk_cmp_attempt(db, admin_user, _mk_cmp_plan(db, admin_user, req_a))
    att_b = _mk_cmp_attempt(db, admin_user, _mk_cmp_plan(db, admin_user, req_b))
    _grant(db, maintainer_user, a, _mk_role(db, "r-cmp-exec"))
    _login(client, maintainer_user)
    body = client.get(f"{_CMP}/remediation-executions").json()
    ids = {r["id"] for r in body["items"]}
    assert ids == {att_a.id}
    assert (
        client.get(f"{_CMP}/remediation-executions?system_id={b.id}").status_code == 404
    )
    assert client.get(f"{_CMP}/remediation-executions/{att_a.id}").status_code == 200
    assert client.get(f"{_CMP}/remediation-executions/{att_b.id}").status_code == 404
    # Per-request execution rollup (auditor/maintainer-reachable): hidden request
    # -> non-disclosing 404 before the rollup (which echoes system_id + attempts).
    assert (
        client.get(f"{_CMP}/remediation-requests/{req_a.id}/executions").status_code
        == 200
    )
    assert (
        client.get(f"{_CMP}/remediation-requests/{req_b.id}/executions").status_code
        == 404
    )


def test_compliance_remediation_executions_admin_sees_all(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _policy, ev = _mk_policy_evidence(db, admin_user, [a, b], "execadm")
    att_a = _mk_cmp_attempt(
        db,
        admin_user,
        _mk_cmp_plan(db, admin_user, _mk_cmp_request(db, maintainer_user, ev[a.id])),
    )
    att_b = _mk_cmp_attempt(
        db,
        admin_user,
        _mk_cmp_plan(db, admin_user, _mk_cmp_request(db, maintainer_user, ev[b.id])),
    )
    _login(client, admin_user)
    ids = {
        r["id"] for r in client.get(f"{_CMP}/remediation-executions").json()["items"]
    }
    assert {att_a.id, att_b.id} <= ids


# --------------------------------------------------------------- empty scope


def test_compliance_empty_scope_sees_nothing(
    client, db, admin_user, maintainer_user, auditor_user, two_systems
):
    a, b = two_systems
    policy, ev = _mk_policy_evidence(db, admin_user, [a, b], "empty")
    _mk_cmp_plan(db, admin_user, _mk_cmp_request(db, maintainer_user, ev[a.id]))
    _login(client, auditor_user)  # no grants -> empty scope
    assert client.get(f"{_CMP}/policies/{policy.id}/evidence").json()["total"] == 0
    assert client.get(f"{_CMP}/fleet/summary").json()["host_count"] == 0
    assert client.get(f"{_CMP}/remediation-requests").json()["total"] == 0
    assert client.get(f"{_CMP}/remediation-plans").json()["total"] == 0
    rsum = client.get(f"{_CMP}/remediation/fleet-summary").json()
    assert rsum["request_total"] == 0 and rsum["current_plan_total"] == 0
    assert client.get(f"{_CMP}/systems/{a.id}/evidence").status_code == 404
    assert client.get(f"{_CMP}/systems/{a.id}/remediation").status_code == 404


# ================================================================= SLICE 14
# Airgap operations + residual fleet-access grant surfaces (PRA-281 Slice 14).
#
# Airgap bundle signing keys / export+import rows / trust pins / local paths /
# hashes / byte counts are instance-wide OPERATIONAL state with no system_id, so
# the whole surface is tenant-wide-admin-only for scoped callers (403 at a
# router-level dependency, before any service/GPG/row/background/audit work).
# AccessGrant.system_id and HostUserState.system_id ARE host-derived, so the
# grant list is scoped, the host-users route is a non-disclosing 404 out of
# scope, and grant-recompute is tenant-wide-admin-only.

_AIRGAP = "/airgap"
_FLEET = "/fleet"
_PGP_STUB = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nstub\n-----END PGP PUBLIC KEY BLOCK-----"
)


def _mk_host_user(db, system, login="alice", mode="per_user", state="ok"):
    row = HostUserState(system_id=system.id, login=login, mode=mode, state=state)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# --------------------------------------------------------------- airgap


def test_airgap_reads_forbidden_for_scoped(
    client, db, maintainer_user, auditor_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-ag-read"))
    for user in (maintainer_user, auditor_user):
        _login(client, user)
        assert client.get(f"{_AIRGAP}/signing-keys").status_code == 403
        assert client.get(f"{_AIRGAP}/import-trust").status_code == 403
        assert client.get(f"{_AIRGAP}/exports/nope").status_code == 403
        assert client.get(f"{_AIRGAP}/imports/nope").status_code == 403


def test_airgap_mutations_forbidden_for_scoped_no_side_effect(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-ag-mut"))
    _login(client, maintainer_user)
    # No-body + valid-body mutations all 403 at the router dependency, before any
    # signing-key/GPG/Vault/row/background-task/audit work.
    assert client.post(f"{_AIRGAP}/signing-key").status_code == 403
    assert client.post(f"{_AIRGAP}/signing-keys/rotate").status_code == 403
    assert client.post(f"{_AIRGAP}/signing-keys/1/retire").status_code == 403
    assert client.delete(f"{_AIRGAP}/import-trust/1").status_code == 403
    assert (
        client.post(
            f"{_AIRGAP}/import-trust", json={"armored_public_key": _PGP_STUB}
        ).status_code
        == 403
    )
    assert (
        client.post(f"{_AIRGAP}/exports", json={"profile_slugs": ["x"]}).status_code
        == 403
    )
    # No signing key was created by the scoped POST /signing-key (403 fired
    # before the service): an admin sees an empty key list.
    _login(client, admin_user)
    assert client.get(f"{_AIRGAP}/signing-keys").json() == []


def test_airgap_admin_not_gated(client, db, admin_user):
    # App-admin (tenant-wide) reaches the airgap surface unchanged — the
    # tenant-wide gate is a no-op for scope None.
    _login(client, admin_user)
    assert client.get(f"{_AIRGAP}/signing-keys").status_code == 200
    assert client.get(f"{_AIRGAP}/import-trust").status_code == 200


# --------------------------------------------------------------- fleet-access grants


def test_fleet_grants_list_scope(
    client, db, admin_user, maintainer_user, auditor_user, two_systems
):
    a, b = two_systems
    # maintainer granted on A (in scope); auditor granted on B (hidden).
    _grant(db, maintainer_user, a, _mk_role(db, "r-fg-a"))
    _grant(db, auditor_user, b, _mk_role(db, "r-fg-b"))
    _login(client, maintainer_user)
    grants = client.get(f"{_FLEET}/grants").json()["grants"]
    sys_ids = {g["system_id"] for g in grants}
    assert sys_ids == {a.id}  # only in-scope grants; B's grant hidden
    assert auditor_user.id not in {g["user_id"] for g in grants}
    # Explicit out-of-scope system_id filter -> non-disclosing 404.
    assert client.get(f"{_FLEET}/grants?system_id={b.id}").status_code == 404
    assert client.get(f"{_FLEET}/grants?system_id={a.id}").status_code == 200
    # A user_id filter still obeys system scope: auditor holds a grant only on B,
    # which is hidden, so the maintainer sees none of it.
    scoped = client.get(f"{_FLEET}/grants?user_id={auditor_user.id}").json()["grants"]
    assert scoped == []
    # Admin tenant-wide sees both systems' grants.
    _login(client, admin_user)
    admin_sys_ids = {
        g["system_id"] for g in client.get(f"{_FLEET}/grants").json()["grants"]
    }
    assert {a.id, b.id} <= admin_sys_ids


def test_fleet_grants_empty_scope_returns_none(client, db, seed_roles, two_systems):
    a, b = two_systems
    # Seed a grant so the table is non-empty, then query as a user with no grants.
    nogrant = _mk_user(db, seed_roles, "pra281-nogrant", ["auditor"])
    other = _mk_user(db, seed_roles, "pra281-other", ["maintainer"])
    _grant(db, other, a, _mk_role(db, "r-fg-seed"))
    _login(client, nogrant)
    assert client.get(f"{_FLEET}/grants").json()["grants"] == []


# --------------------------------------------------------------- host-users


def test_fleet_host_users_direct_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_host_user(db, a, login="alice")
    _mk_host_user(db, b, login="bob-secret")
    _grant(db, maintainer_user, a, _mk_role(db, "r-hu"))
    _login(client, maintainer_user)
    ok = client.get(f"{_FLEET}/systems/{a.id}/host-users")
    assert ok.status_code == 200
    # Out-of-scope + nonexistent both non-disclosing 404; no host-user login leaks.
    hidden = client.get(f"{_FLEET}/systems/{b.id}/host-users")
    assert hidden.status_code == 404
    assert "bob-secret" not in hidden.text
    assert client.get(f"{_FLEET}/systems/98765/host-users").status_code == 404
    # Admin tenant-wide reaches both.
    _login(client, admin_user)
    assert client.get(f"{_FLEET}/systems/{b.id}/host-users").status_code == 200


# --------------------------------------------------------------- recompute


def test_fleet_grants_recompute_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-recompute"))

    calls = {"n": 0}
    from app.services import access_binding_service

    real = access_binding_service.recompute_grants

    def _tracking(dbarg):
        calls["n"] += 1
        return real(dbarg)

    monkeypatch.setattr(access_binding_service, "recompute_grants", _tracking)

    _login(client, maintainer_user)
    # Scoped maintainer holds the role but is not tenant-wide -> 403, and
    # recompute is NOT called.
    assert client.post(f"{_FLEET}/grants/recompute").status_code == 403
    assert calls["n"] == 0
    # Admin (tenant-wide) may recompute.
    _login(client, admin_user)
    assert client.post(f"{_FLEET}/grants/recompute").status_code == 200
    assert calls["n"] == 1


# ================================================================= SLICE 15
# Bulk system mutation + import/template surfaces (PRA-281 Slice 15).
#
# bulk.py mutates/deletes systems by system_ids and creates systems on import.
# Batch mutations (status/group/delete) reject the WHOLE request with a
# non-disclosing 404 if any target is out of scope, BEFORE fleet-operation start,
# DB mutation/delete, audit, notification, or result rows — never partially
# applied. Credential-assign / import / import-template are tenant-wide-admin-only
# for scoped callers (credential secrecy / system creation / credential-name
# enumeration). Admin (scope None) is unchanged throughout.

_BULK = "/bulk"


def _track_bulk_side_effects(monkeypatch):
    """Stub the fleet-operation service + notification so a success path does not
    hit ``fleet_operation_service``'s own SessionLocal (which can't see the test's
    uncommitted user -> FK violation), while COUNTING the calls. A failed scope
    check must leave these at zero — that is the "no side effect" proof."""
    import app.api.routes.bulk as bulk_routes
    from app.services import fleet_operation_service

    calls = {"start_operation": 0, "notify": 0}

    def _start(**kw):
        calls["start_operation"] += 1
        return 1  # fake fleet_op_id

    def _noop(*a, **kw):
        return None

    def _notify(*a, **kw):
        calls["notify"] += 1
        return None

    monkeypatch.setattr(fleet_operation_service, "start_operation", _start)
    monkeypatch.setattr(fleet_operation_service, "record_result", _noop)
    monkeypatch.setattr(fleet_operation_service, "complete_operation", _noop)
    monkeypatch.setattr(bulk_routes, "create_notification", _notify)
    return calls


def test_bulk_status_mixed_batch_rejected_no_side_effect(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-bulk-st"))
    calls = _track_bulk_side_effects(monkeypatch)
    fleet_ops_before = db.query(FleetOperation).count()
    _login(client, maintainer_user)
    # Mixed in-scope + out-of-scope batch -> non-disclosing 404, no side effect.
    res = client.put(
        f"{_BULK}/status", json={"system_ids": [a.id, b.id], "status": "Maintenance"}
    )
    assert res.status_code == 404
    assert str(b.id) not in res.text and b.hostname not in res.text
    assert calls["start_operation"] == 0 and calls["notify"] == 0
    db.expire_all()
    assert db.query(FleetOperation).count() == fleet_ops_before  # no fleet-op row
    assert db.query(System).filter(System.id == a.id).first().status == "Active"
    # In-scope-only batch still works for the scoped maintainer.
    ok = client.put(
        f"{_BULK}/status", json={"system_ids": [a.id], "status": "Maintenance"}
    )
    assert ok.status_code == 200, ok.text
    assert calls["start_operation"] == 1
    db.expire_all()
    assert db.query(System).filter(System.id == a.id).first().status == "Maintenance"


def test_bulk_status_empty_scope_fails_closed(client, db, maintainer_user, two_systems):
    a, b = two_systems
    # maintainer with NO grants -> empty scope -> cannot mutate anything.
    _login(client, maintainer_user)
    res = client.put(
        f"{_BULK}/status", json={"system_ids": [a.id], "status": "Inactive"}
    )
    assert res.status_code == 404
    db.expire_all()
    assert db.query(System).filter(System.id == a.id).first().status == "Active"


def test_bulk_group_mixed_batch_rejected(
    client, db, admin_user, maintainer_user, grp, two_systems, monkeypatch
):
    a, b = two_systems
    other_group = Group(name="pra281-bulk-grp", description="x")
    db.add(other_group)
    db.commit()
    _grant(db, maintainer_user, a, _mk_role(db, "r-bulk-grp"))
    calls = _track_bulk_side_effects(monkeypatch)
    _login(client, maintainer_user)
    # Out-of-scope member -> 404 BEFORE the group lookup (no group-name probe) and
    # before any mutation.
    res = client.put(
        f"{_BULK}/group", json={"system_ids": [a.id, b.id], "group_id": other_group.id}
    )
    assert res.status_code == 404
    assert "pra281-bulk-grp" not in res.text
    assert calls["start_operation"] == 0
    db.expire_all()
    assert db.query(System).filter(System.id == a.id).first().group_id != other_group.id
    # In-scope-only batch works.
    ok = client.put(
        f"{_BULK}/group", json={"system_ids": [a.id], "group_id": other_group.id}
    )
    assert ok.status_code == 200, ok.text


def test_bulk_delete_mixed_batch_rejected_no_side_effect(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-bulk-del"))
    calls = _track_bulk_side_effects(monkeypatch)
    fleet_ops_before = db.query(FleetOperation).count()
    _login(client, maintainer_user)
    res = client.request(
        "DELETE", f"{_BULK}/systems", json={"system_ids": [a.id, b.id]}
    )
    assert res.status_code == 404
    assert calls["start_operation"] == 0 and calls["notify"] == 0
    db.expire_all()
    # Nothing deleted; no fleet-op row created.
    assert db.query(System).filter(System.id == a.id).first() is not None
    assert db.query(System).filter(System.id == b.id).first() is not None
    assert db.query(FleetOperation).count() == fleet_ops_before
    # In-scope-only delete works.
    ok = client.request("DELETE", f"{_BULK}/systems", json={"system_ids": [a.id]})
    assert ok.status_code == 200, ok.text
    db.expire_all()
    assert db.query(System).filter(System.id == a.id).first() is None


def test_bulk_credentials_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    cred2 = _mk_cred(db, "pra281-bulk-cred2")  # a fresh, distinct credential
    _grant(db, maintainer_user, a, _mk_role(db, "r-bulk-cred"))
    calls = _track_bulk_side_effects(monkeypatch)
    _login(client, maintainer_user)
    # Even an all-in-scope batch is refused before the credential lookup: no
    # credential id/name probing, no secret bound to hosts whose linkage is hidden.
    res = client.put(
        f"{_BULK}/credentials", json={"system_ids": [a.id], "credential_id": cred2.id}
    )
    assert res.status_code == 403
    assert cred2.name not in res.text
    assert calls["start_operation"] == 0
    db.expire_all()
    assert db.query(System).filter(System.id == a.id).first().credentials_id != cred2.id
    # Admin (tenant-wide) unchanged.
    _login(client, admin_user)
    ok = client.put(
        f"{_BULK}/credentials", json={"system_ids": [a.id], "credential_id": cred2.id}
    )
    assert ok.status_code == 200, ok.text
    db.expire_all()
    assert db.query(System).filter(System.id == a.id).first().credentials_id == cred2.id


def test_bulk_import_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-bulk-imp"))
    calls = _track_bulk_side_effects(monkeypatch)
    _login(client, maintainer_user)
    body = {
        "systems": [
            {"hostname": "new.example.com", "ip_address": "10.28.9.9", "distro": "x"}
        ]
    }
    res = client.post(f"{_BULK}/import", json=body)
    assert res.status_code == 403
    assert calls["start_operation"] == 0
    # No system was created.
    db.expire_all()
    assert db.query(System).filter(System.hostname == "new.example.com").first() is None
    # Admin (tenant-wide) reaches the import flow (dry-run validates only).
    _login(client, admin_user)
    dry = client.post(f"{_BULK}/import", json={**body, "dry_run": True})
    assert dry.status_code in (200, 201), dry.text


def test_bulk_import_template_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, cred, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-bulk-tpl"))
    _login(client, maintainer_user)
    res = client.get(f"{_BULK}/import/template")
    assert res.status_code == 403
    # No credential name leaks in the refusal.
    assert cred.name not in res.text
    # Admin sees the template (credentials included).
    _login(client, admin_user)
    ok = client.get(f"{_BULK}/import/template")
    assert ok.status_code == 200
    assert "credentials" in ok.json()["available_values"]


def test_bulk_status_admin_tenant_wide_unchanged(
    client, db, admin_user, two_systems, monkeypatch
):
    a, b = two_systems
    _track_bulk_side_effects(monkeypatch)
    _login(client, admin_user)
    res = client.put(
        f"{_BULK}/status", json={"system_ids": [a.id, b.id], "status": "Maintenance"}
    )
    assert res.status_code == 200, res.text
    assert res.json()["updated"] == 2
    db.expire_all()
    assert db.query(System).filter(System.id == b.id).first().status == "Maintenance"


# ================================================================= SLICE 16
# Legacy CSV/JSON export routes (PRA-281 Slice 16): export.py.
#
# /export/systems + /export/audits export only in-scope rows (maps resolved from
# exported rows only); /export/packages non-disclosing 404s a direct out-of-scope
# system_id before any package/body/filename; /export/jobs reuses the accepted
# Slice 4 job-visibility model. Admin (scope None) unchanged; empty scope → empty
# export. Both CSV and JSON serializers share the scoped row set.

_EXP = "/export"


def _mk_audit_ov(db, system, user, old, new, audit_type="status"):
    db.add(
        SystemAudit(
            system_id=system.id,
            audit_type=audit_type,
            changed_by=user.id,
            changed_at=datetime.utcnow(),
            operation="update",
            old_value=old,
            new_value=new,
        )
    )
    db.commit()


# --------------------------------------------------------------- /export/systems


def test_export_systems_scope_csv_and_json(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-exp-sys"))
    _login(client, maintainer_user)
    # JSON: only in-scope host; no hidden hostname/IP.
    j = client.get(f"{_EXP}/systems?format=json")
    assert j.status_code == 200
    hostnames = {row["hostname"] for row in j.json()}
    assert hostnames == {a.hostname}
    assert b.hostname not in j.text and str(b.ip_address) not in j.text
    # CSV: same scoping (both serializers share the scoped rows).
    c = client.get(f"{_EXP}/systems?format=csv")
    assert c.status_code == 200
    assert a.hostname in c.text and b.hostname not in c.text
    # Admin tenant-wide sees both.
    _login(client, admin_user)
    admin_hosts = {
        row["hostname"] for row in client.get(f"{_EXP}/systems?format=json").json()
    }
    assert {a.hostname, b.hostname} <= admin_hosts


def test_export_systems_empty_scope_empty(client, db, auditor_user, two_systems):
    a, b = two_systems
    _login(client, auditor_user)  # no grants -> empty scope
    j = client.get(f"{_EXP}/systems?format=json")
    assert j.status_code == 200 and j.json() == []


# --------------------------------------------------------------- /export/packages


def test_export_packages_direct_scope(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "pkg-a-exp")
    _mk_update(db, b, "pkg-b-secret")
    _grant(db, maintainer_user, a, _mk_role(db, "r-exp-pkg"))
    _login(client, maintainer_user)
    ok = client.get(f"{_EXP}/packages?system_id={a.id}&format=json")
    assert ok.status_code == 200
    assert "pkg-a-exp" in ok.text
    # Out-of-scope system_id -> 404 before any package/body/filename.
    hidden = client.get(f"{_EXP}/packages?system_id={b.id}&format=json")
    assert hidden.status_code == 404
    assert "pkg-b-secret" not in hidden.text
    assert "packages-system" not in hidden.text  # no filename leak
    # Nonexistent id (for a scoped caller) is the same 404.
    assert client.get(f"{_EXP}/packages?system_id=98765").status_code == 404
    # Admin tenant-wide reaches both.
    _login(client, admin_user)
    assert (
        client.get(f"{_EXP}/packages?system_id={b.id}&format=json").status_code == 200
    )


# --------------------------------------------------------------- /export/audits


def test_export_audits_scope(client, db, admin_user, auditor_user, two_systems):
    a, b = two_systems
    _mk_audit_ov(db, a, admin_user, old="a-old", new="a-new-visible")
    _mk_audit_ov(db, b, admin_user, old="b-old-secret", new="b-new-secret")
    _grant(db, auditor_user, a, _mk_role(db, "r-exp-aud"))
    _login(client, auditor_user)
    j = client.get(f"{_EXP}/audits?format=json")
    assert j.status_code == 200
    host_cells = {row["system_hostname"] for row in j.json()}
    assert host_cells == {a.hostname}  # only in-scope audit rows
    # No hidden hostname or old/new value leaks (neither JSON nor CSV).
    assert b.hostname not in j.text
    assert "b-old-secret" not in j.text and "b-new-secret" not in j.text
    assert "a-new-visible" in j.text
    csv_text = client.get(f"{_EXP}/audits?format=csv").text
    assert b.hostname not in csv_text and "b-new-secret" not in csv_text
    # Admin tenant-wide sees both hosts' audit rows.
    _login(client, admin_user)
    admin_hosts = {
        row["system_hostname"]
        for row in client.get(f"{_EXP}/audits?format=json").json()
    }
    assert {a.hostname, b.hostname} <= admin_hosts


def test_export_audits_empty_scope_empty(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    _mk_audit_ov(db, a, admin_user, old="x", new="y")
    _login(client, auditor_user)  # auditor role, no grants -> empty scope
    j = client.get(f"{_EXP}/audits?format=json")
    assert j.status_code == 200 and j.json() == []


# --------------------------------------------------------------- /export/jobs


def test_export_jobs_scope(client, db, admin_user, maintainer_user, two_systems):
    a, b = two_systems
    job_a = _mk_job(db, admin_user, "system", [a.id], name="jexp-a")
    job_b = _mk_job(db, admin_user, "system", [b.id], name="jexp-b")
    _mk_hist(db, job_a, status="completed", error="a-visible-err")
    _mk_hist(db, job_b, status="failed", error="b-secret-err")
    _grant(db, maintainer_user, a, _mk_role(db, "r-exp-job"))
    _login(client, maintainer_user)
    j = client.get(f"{_EXP}/jobs?format=json")
    assert j.status_code == 200
    job_ids = {row["job_id"] for row in j.json()}
    assert job_ids == {job_a.id}  # only in-scope job history
    assert str(job_b.id) not in {str(x) for x in job_ids}
    assert "b-secret-err" not in j.text
    assert "a-visible-err" in j.text
    # CSV path shares the scoped rows.
    csv_text = client.get(f"{_EXP}/jobs?format=csv").text
    assert "b-secret-err" not in csv_text and "a-visible-err" in csv_text
    # Admin tenant-wide sees both jobs' history.
    _login(client, admin_user)
    admin_job_ids = {
        row["job_id"] for row in client.get(f"{_EXP}/jobs?format=json").json()
    }
    assert {job_a.id, job_b.id} <= admin_job_ids


def test_export_jobs_empty_scope_empty(
    client, db, admin_user, auditor_user, two_systems
):
    a, b = two_systems
    job_a = _mk_job(db, admin_user, "system", [a.id], name="jexp-empty")
    _mk_hist(db, job_a, status="completed")
    _login(client, auditor_user)  # no grants -> empty scope
    j = client.get(f"{_EXP}/jobs?format=json")
    assert j.status_code == 200 and j.json() == []


# ================================================================= SLICE 17
# Per-system repository source routes (PRA-281 Slice 17): repos.py.
#
# Every /repos/{system_id} route (list/add/delete/sync) and
# /repos/templates/{system_id} scope-gates the direct system id with a
# non-disclosing 404 BEFORE the System lookup, any RepoService call, SSH,
# duplicate check, DB mutation, or serialization. /repos/templates/all is static
# distro taxonomy (no host/tenant/credential data) and stays global. Admin
# (scope None) unchanged; empty scope -> 404 for direct routes.

_REPOS = "/repos"


def _stub_repo_service(monkeypatch):
    """Stub every RepoService method the routes call, counting invocations. A
    failed scope check must leave all counts at zero — that is the "service not
    called" proof (the 404 fires before RepoService is even instantiated)."""
    from app.services.repo_service import RepoService

    calls = {
        "list_repos": 0,
        "add_repo": 0,
        "remove_repo": 0,
        "sync_repos": 0,
        "get_templates": 0,
    }

    def _list(self, system_id):
        calls["list_repos"] += 1
        return {"system_id": system_id, "repos": []}

    def _add(self, system_id, data):
        calls["add_repo"] += 1
        return {"status": "ok"}

    def _remove(self, system_id, repo_id):
        calls["remove_repo"] += 1
        return {"status": "removed"}

    def _sync(self, system_id):
        calls["sync_repos"] += 1
        return {"status": "synced"}

    def _templates(self, system_id=None):
        calls["get_templates"] += 1
        return {"templates": []}

    monkeypatch.setattr(RepoService, "list_repos", _list)
    monkeypatch.setattr(RepoService, "add_repo", _add)
    monkeypatch.setattr(RepoService, "remove_repo", _remove)
    monkeypatch.setattr(RepoService, "sync_repos", _sync)
    monkeypatch.setattr(RepoService, "get_templates", _templates)
    return calls


def test_repos_list_direct_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    calls = _stub_repo_service(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-repo-list"))
    _login(client, maintainer_user)
    assert client.get(f"{_REPOS}/{a.id}").status_code == 200
    assert calls["list_repos"] == 1
    # Out-of-scope + nonexistent -> non-disclosing 404 BEFORE RepoService.
    hidden = client.get(f"{_REPOS}/{b.id}")
    assert hidden.status_code == 404
    assert b.hostname not in hidden.text
    assert client.get(f"{_REPOS}/98765").status_code == 404
    assert calls["list_repos"] == 1  # not called for the hidden/nonexistent ids


def test_repos_mutations_direct_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    calls = _stub_repo_service(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-repo-mut"))
    _login(client, maintainer_user)
    body = {"name": "myrepo", "url": "http://example.com/repo"}
    # Hidden system -> 404 before add/remove/sync service calls, SSH, or DB write.
    assert client.post(f"{_REPOS}/{b.id}", json=body).status_code == 404
    assert client.request("DELETE", f"{_REPOS}/{b.id}/5").status_code == 404
    assert client.post(f"{_REPOS}/{b.id}/sync").status_code == 404
    assert (
        calls["add_repo"] == 0
        and calls["remove_repo"] == 0
        and calls["sync_repos"] == 0
    )
    # In-scope batch of writes works (service stubbed).
    assert client.post(f"{_REPOS}/{a.id}", json=body).status_code == 200
    assert client.request("DELETE", f"{_REPOS}/{a.id}/5").status_code == 200
    assert client.post(f"{_REPOS}/{a.id}/sync").status_code == 200
    assert (
        calls["add_repo"] == 1
        and calls["remove_repo"] == 1
        and calls["sync_repos"] == 1
    )


def test_repos_templates_system_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    calls = _stub_repo_service(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-repo-tpl"))
    _login(client, maintainer_user)
    assert client.get(f"{_REPOS}/templates/{a.id}").status_code == 200
    assert client.get(f"{_REPOS}/templates/{b.id}").status_code == 404
    assert client.get(f"{_REPOS}/templates/98765").status_code == 404
    # get_templates only ran for the in-scope system, never for hidden b.
    assert calls["get_templates"] == 1


def test_repos_templates_all_stays_global(
    client, db, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    _stub_repo_service(monkeypatch)
    # A scoped maintainer with no grants still reaches the static distro template
    # taxonomy (no host/tenant/credential/secret data).
    _login(client, maintainer_user)
    assert client.get(f"{_REPOS}/templates/all").status_code == 200


def test_repos_empty_scope_404(client, db, auditor_user, two_systems, monkeypatch):
    a, b = two_systems
    calls = _stub_repo_service(monkeypatch)
    _login(client, auditor_user)  # no grants -> empty scope
    assert client.get(f"{_REPOS}/{a.id}").status_code == 404
    assert client.get(f"{_REPOS}/templates/{a.id}").status_code == 404
    assert calls["list_repos"] == 0 and calls["get_templates"] == 0


def test_repos_write_role_denied_403(client, db, auditor_user, two_systems):
    a, b = two_systems
    _grant(db, auditor_user, a, _mk_role(db, "r-repo-role"))
    _login(client, auditor_user)
    # Auditor holds scope on A but lacks admin/maintainer for the write route ->
    # the role gate (403) fires before the scope gate.
    res = client.post(f"{_REPOS}/{a.id}", json={"name": "x", "url": "http://e.com/r"})
    assert res.status_code == 403


def test_repos_admin_tenant_wide(client, db, admin_user, two_systems, monkeypatch):
    a, b = two_systems
    _stub_repo_service(monkeypatch)
    _login(client, admin_user)
    # Admin (tenant-wide) reaches any system unchanged.
    assert client.get(f"{_REPOS}/{b.id}").status_code == 200
    assert client.get(f"{_REPOS}/templates/{b.id}").status_code == 200


# ================================================================= SLICE 18
# Content-profile subscriptions / host resolution / apply (PRA-281 Slice 18):
# content_profiles.py + content_profile_apply.py.
#
# Profile/channel/group/smart-group mutations + the mixed subscription list are
# tenant-wide-admin-only for scoped callers (they alter fleet-wide effective
# resolution + trigger recompute). Direct host subscription add/remove and the
# host effective/resolved/apply routes scope-gate the host/system id with a
# non-disclosing 404. /subscribers walks only in-scope hosts. Profile taxonomy
# reads (list/detail/resolved/manifest/diff) stay global. Admin unchanged.

_CP = "/content-profiles"


def _mk_profile(db, slug, family="deb"):
    from app.db.models import ContentProfile

    p = ContentProfile(slug=slug, display_name=slug, package_family=family)
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _sub_host(db, host, profile):
    from app.db.models import HostContentProfileSubscription

    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=profile.id))
    db.commit()


def _track_cp_side_effects(monkeypatch):
    """Count content-profile recompute + audit emit so a failed check can be
    proven side-effect-free (both must stay 0 after a 403/404)."""
    from app.services import audit_event_service, smart_group_service

    calls = {"recompute": 0, "emit": 0}

    def _recompute(db):
        calls["recompute"] += 1
        return 0

    def _emit(db, **kw):
        calls["emit"] += 1

    monkeypatch.setattr(smart_group_service, "recompute_profile_groups", _recompute)
    monkeypatch.setattr(audit_event_service, "emit", _emit)
    return calls


# --------------------------------------------------------------- profile/channel mutations


def test_cp_profile_mutations_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    p = _mk_profile(db, "pra281-mut")
    calls = _track_cp_side_effects(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-cp-mut"))
    _login(client, maintainer_user)
    assert (
        client.post(
            _CP,
            json={"slug": "x", "display_name": "X", "package_family": "deb"},
        ).status_code
        == 403
    )
    assert client.patch(f"{_CP}/{p.id}", json={"display_name": "Y"}).status_code == 403
    assert client.delete(f"{_CP}/{p.id}").status_code == 403
    assert (
        client.post(f"{_CP}/{p.id}/channels", json={"channel_id": 1}).status_code == 403
    )
    assert client.request("DELETE", f"{_CP}/{p.id}/channels/1").status_code == 403
    # No recompute or audit after any 403 (fired before lookup/mutation).
    assert calls["recompute"] == 0 and calls["emit"] == 0
    db.expire_all()
    from app.db.models import ContentProfile

    assert (
        db.query(ContentProfile).filter(ContentProfile.id == p.id).first().deleted_at
        is None
    )
    # Admin (tenant-wide) may mutate.
    _login(client, admin_user)
    assert client.patch(f"{_CP}/{p.id}", json={"display_name": "Z"}).status_code == 200


def test_cp_group_smartgroup_subs_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, grp, two_systems, monkeypatch
):
    a, b = two_systems
    p = _mk_profile(db, "pra281-gsg")
    sg = _mk_smart_group(db, admin_user, [a], "cpsg")
    calls = _track_cp_side_effects(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-cp-gsg"))
    _login(client, maintainer_user)
    assert (
        client.post(f"{_CP}/{p.id}/groups", json={"group_id": grp.id}).status_code
        == 403
    )
    assert client.request("DELETE", f"{_CP}/{p.id}/groups/{grp.id}").status_code == 403
    assert (
        client.post(
            f"{_CP}/{p.id}/smart-groups", json={"smart_group_id": sg.id}
        ).status_code
        == 403
    )
    assert (
        client.request("DELETE", f"{_CP}/{p.id}/smart-groups/{sg.id}").status_code
        == 403
    )
    assert calls["recompute"] == 0 and calls["emit"] == 0


def test_cp_subscriptions_list_admin_only_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    p = _mk_profile(db, "pra281-sublist")
    _sub_host(db, b, p)  # a hidden host subscribed
    _grant(db, maintainer_user, a, _mk_role(db, "r-cp-sublist"))
    _login(client, maintainer_user)
    res = client.get(f"{_CP}/{p.id}/subscriptions")
    assert res.status_code == 403
    assert b.hostname not in res.text
    # Admin sees the mixed list.
    _login(client, admin_user)
    assert client.get(f"{_CP}/{p.id}/subscriptions").status_code == 200


# --------------------------------------------------------------- host subscription


def test_cp_host_subscription_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    p = _mk_profile(db, "pra281-hostsub")
    calls = _track_cp_side_effects(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-cp-host"))
    _login(client, maintainer_user)
    # Out-of-scope host id -> 404 before profile/host lookup, insert, audit,
    # recompute, or hostname response.
    res = client.post(f"{_CP}/{p.id}/hosts", json={"host_id": b.id})
    assert res.status_code == 404
    assert b.hostname not in res.text
    assert client.request("DELETE", f"{_CP}/{p.id}/hosts/{b.id}").status_code == 404
    assert calls["recompute"] == 0 and calls["emit"] == 0
    from app.db.models import HostContentProfileSubscription

    assert (
        db.query(HostContentProfileSubscription)
        .filter(HostContentProfileSubscription.host_id == b.id)
        .first()
        is None
    )
    # In-scope host works.
    ok = client.post(f"{_CP}/{p.id}/hosts", json={"host_id": a.id})
    assert ok.status_code == 201, ok.text


# --------------------------------------------------------------- subscribers


def test_cp_subscribers_scope(
    client, db, admin_user, auditor_user, maintainer_user, two_systems
):
    a, b = two_systems
    p = _mk_profile(db, "pra281-subs")
    _sub_host(db, a, p)
    _sub_host(db, b, p)
    _grant(db, maintainer_user, a, _mk_role(db, "r-cp-subs"))
    _login(client, maintainer_user)
    res = client.get(f"{_CP}/{p.id}/subscribers")
    assert res.status_code == 200
    host_ids = {row["host_id"] for row in res.json()}
    assert host_ids == {a.id}  # only in-scope host
    assert b.hostname not in res.text
    # Admin sees both.
    _login(client, admin_user)
    admin_ids = {
        row["host_id"] for row in client.get(f"{_CP}/{p.id}/subscribers").json()
    }
    assert {a.id, b.id} <= admin_ids
    # Empty-scope auditor -> empty.
    _login(client, auditor_user)
    assert client.get(f"{_CP}/{p.id}/subscribers").json() == []


# --------------------------------------------------------------- host effective / resolved


def test_cp_host_effective_scope(client, db, admin_user, maintainer_user, two_systems):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-cp-eff"))
    _login(client, maintainer_user)
    assert client.get(f"/systems/{a.id}/content-profile").status_code == 200
    assert client.get(f"/systems/{b.id}/content-profile").status_code == 404
    assert client.get(f"/systems/98765/content-profile").status_code == 404
    assert client.get(f"/systems/{a.id}/content-profile/resolved").status_code == 200
    assert client.get(f"/systems/{b.id}/content-profile/resolved").status_code == 404


def test_cp_host_effective_empty_scope_404(client, db, auditor_user, two_systems):
    a, b = two_systems
    _login(client, auditor_user)  # no grants
    assert client.get(f"/systems/{a.id}/content-profile").status_code == 404
    assert client.get(f"/systems/{a.id}/content-profile/resolved").status_code == 404


# --------------------------------------------------------------- apply


def _stub_apply(monkeypatch):
    from unittest.mock import MagicMock

    from app.api.routes import content_profile_apply as route_module
    from app.services.content_profile_apply import ApplyOutcome

    calls = {"apply": 0, "transport": 0}

    async def _fake_apply(*_a, **_k):
        calls["apply"] += 1
        return ApplyOutcome(state="noop", profile_slug="p")

    async def _fake_transport(*_a, **_k):
        calls["transport"] += 1
        return object()

    class _FakeBroker:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(route_module, "apply_content_profile_to_host", _fake_apply)
    monkeypatch.setattr(route_module, "get_transport", _fake_transport)
    monkeypatch.setattr(route_module, "BrokerClient", lambda: _FakeBroker())
    monkeypatch.setattr(route_module, "SSHService", lambda db: MagicMock())
    return calls


def test_cp_apply_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    calls = _stub_apply(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-cp-apply"))
    _login(client, maintainer_user)
    # Hidden system -> 404 BEFORE transport setup / broker / orchestrator.
    assert client.post(f"/systems/{b.id}/content-profile/apply").status_code == 404
    assert calls["apply"] == 0 and calls["transport"] == 0
    # In-scope system reaches the (stubbed) orchestrator.
    ok = client.post(f"/systems/{a.id}/content-profile/apply")
    assert ok.status_code == 200, ok.text
    assert calls["apply"] == 1 and calls["transport"] == 1


def test_cp_apply_empty_scope_404(
    client, db, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    calls = _stub_apply(monkeypatch)
    _login(client, maintainer_user)  # no grants -> empty scope
    assert client.post(f"/systems/{a.id}/content-profile/apply").status_code == 404
    assert calls["apply"] == 0 and calls["transport"] == 0


# --------------------------------------------------------------- taxonomy reads global


def test_cp_taxonomy_reads_global_for_scoped(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    p1 = _mk_profile(db, "pra281-tax1")
    p2 = _mk_profile(db, "pra281-tax2")
    _grant(db, maintainer_user, a, _mk_role(db, "r-cp-tax"))
    _login(client, maintainer_user)
    # Profile/channel taxonomy reads carry no host-derived state -> stay global.
    assert client.get(_CP).status_code == 200
    assert client.get(f"{_CP}/{p1.id}").status_code == 200
    assert client.get(f"{_CP}/{p1.id}/resolved").status_code == 200
    assert client.get(f"{_CP}/{p1.id}/manifest").status_code == 200
    assert client.get(f"{_CP}/{p1.id}/diff?from_profile_id={p2.id}").status_code == 200


# ================================================================= SLICE 19
# Mirror-serve credential routes (PRA-281 Slice 19): mirror_serve_credentials.py.
#
# All three direct /systems/{system_id}/mirror-serve-credentials routes scope-gate
# the system id with a non-disclosing 404 BEFORE _system_or_404,
# MirrorServeCredentialService, the MirrorRepo lookup, plaintext token issue,
# list/history retrieval, revoke, or audit — so mirror_id is never a mirror-
# inventory probe, include_revoked never leaks hidden host history, and a
# credential id on a hidden system is never probeable. Admin unchanged.

_MSC = "mirror-serve-credentials"


def _mk_mirror(db, slug):
    from app.db.models import MirrorRepo

    m = MirrorRepo(
        slug=slug,
        display_name=slug,
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _track_msc(monkeypatch):
    """Count service methods (call-through so in-scope paths still work) + audit
    emit (no-op). All must stay 0 after a failed scope check."""
    from app.services import audit_event_service
    from app.services.mirror_serve_credential_service import (
        MirrorServeCredentialService,
    )

    calls = {"issue": 0, "list_for_host": 0, "get": 0, "revoke": 0, "emit": 0}
    real_issue = MirrorServeCredentialService.issue
    real_list = MirrorServeCredentialService.list_for_host
    real_get = MirrorServeCredentialService.get
    real_revoke = MirrorServeCredentialService.revoke

    def _issue(self, **kw):
        calls["issue"] += 1
        return real_issue(self, **kw)

    def _list(self, *a, **kw):
        calls["list_for_host"] += 1
        return real_list(self, *a, **kw)

    def _get(self, *a, **kw):
        calls["get"] += 1
        return real_get(self, *a, **kw)

    def _revoke(self, *a, **kw):
        calls["revoke"] += 1
        return real_revoke(self, *a, **kw)

    def _emit(db, **kw):
        calls["emit"] += 1

    monkeypatch.setattr(MirrorServeCredentialService, "issue", _issue)
    monkeypatch.setattr(MirrorServeCredentialService, "list_for_host", _list)
    monkeypatch.setattr(MirrorServeCredentialService, "get", _get)
    monkeypatch.setattr(MirrorServeCredentialService, "revoke", _revoke)
    monkeypatch.setattr(audit_event_service, "emit", _emit)
    return calls


def test_msc_issue_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    m = _mk_mirror(db, "pra281-msc-issue")
    calls = _track_msc(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-msc-issue"))
    _login(client, maintainer_user)
    # Hidden system -> 404 before service.issue / mirror lookup / plaintext / audit.
    res = client.post(f"/systems/{b.id}/{_MSC}", json={"mirror_id": m.id})
    assert res.status_code == 404
    assert b.hostname not in res.text and "plaintext" not in res.text
    assert calls["issue"] == 0 and calls["emit"] == 0
    # In-scope scoped maintainer still issues and receives the one-time plaintext.
    ok = client.post(f"/systems/{a.id}/{_MSC}", json={"mirror_id": m.id})
    assert ok.status_code == 201, ok.text
    assert ok.json()["plaintext"]
    assert calls["issue"] == 1


def test_msc_list_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    m = _mk_mirror(db, "pra281-msc-list")
    from app.services.mirror_serve_credential_service import (
        MirrorServeCredentialService,
    )

    MirrorServeCredentialService(db).issue(
        host_id=b.id, mirror_id=m.id
    )  # hidden host cred
    db.commit()
    calls = _track_msc(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-msc-list"))
    _login(client, maintainer_user)
    # Hidden system -> 404 before list_for_host / mirror slug lookup (incl. revoked).
    assert client.get(f"/systems/{b.id}/{_MSC}").status_code == 404
    assert client.get(f"/systems/{b.id}/{_MSC}?include_revoked=true").status_code == 404
    assert calls["list_for_host"] == 0
    # In-scope list works (never includes plaintext).
    ok = client.get(f"/systems/{a.id}/{_MSC}")
    assert ok.status_code == 200
    assert "plaintext" not in ok.text
    assert calls["list_for_host"] == 1


def test_msc_revoke_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    m = _mk_mirror(db, "pra281-msc-rev")
    from app.services.mirror_serve_credential_service import (
        MirrorServeCredentialService,
    )

    cred_a = MirrorServeCredentialService(db).issue(host_id=a.id, mirror_id=m.id)
    cred_b = MirrorServeCredentialService(db).issue(host_id=b.id, mirror_id=m.id)
    db.commit()
    calls = _track_msc(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-msc-rev"))
    _login(client, maintainer_user)
    # A credential id on a hidden system is not probeable -> 404 before get/revoke.
    assert (
        client.request(
            "DELETE", f"/systems/{b.id}/{_MSC}/{cred_b.credential_id}"
        ).status_code
        == 404
    )
    assert calls["get"] == 0 and calls["revoke"] == 0
    # In-scope revoke works.
    ok = client.request("DELETE", f"/systems/{a.id}/{_MSC}/{cred_a.credential_id}")
    assert ok.status_code == 204
    assert calls["revoke"] == 1


def test_msc_empty_scope_404(
    client, db, admin_user, auditor_user, two_systems, monkeypatch
):
    a, b = two_systems
    m = _mk_mirror(db, "pra281-msc-empty")
    calls = _track_msc(monkeypatch)
    _login(client, auditor_user)  # no grants -> empty scope
    # GET is any-authenticated; empty scope still 404s the direct id before service.
    assert client.get(f"/systems/{a.id}/{_MSC}").status_code == 404
    assert calls["list_for_host"] == 0


def test_msc_admin_tenant_wide(client, db, admin_user, two_systems):
    a, b = two_systems
    m = _mk_mirror(db, "pra281-msc-admin")
    _login(client, admin_user)
    # Admin reaches any host unchanged (issue + list).
    issued = client.post(f"/systems/{b.id}/{_MSC}", json={"mirror_id": m.id})
    assert issued.status_code == 201, issued.text
    assert client.get(f"/systems/{b.id}/{_MSC}").status_code == 200


# ================================================================= SLICE 20
# Patch policy + ring direct host bindings (PRA-281 Slice 20):
# patch_policies.py + patch_rings.py.
#
# The direct host-binding routes bind/unbind a patch policy/ring to a specific
# host — host-derived, and were missed by Slice 5 (which scoped the per-host
# effective-read routers). Each scope-gates the host id (body.host_id / {host_id})
# with a non-disclosing 404 BEFORE the service bind/unbind (which looks up the
# policy/ring + host, mutates the binding, and emits audit). Admin unchanged.


def _track_patch_bind(monkeypatch):
    """Count patch-policy/ring bind_host + unbind_host (call-through). All must
    stay 0 after a failed scope check — audit is emitted inside the service, so a
    0 count also proves no audit."""
    from app.services import patch_policy_service, patch_ring_service

    calls = {"pol_bind": 0, "pol_unbind": 0, "ring_bind": 0, "ring_unbind": 0}
    rpb, rpu = patch_policy_service.bind_host, patch_policy_service.unbind_host
    rrb, rru = patch_ring_service.bind_host, patch_ring_service.unbind_host

    def _pb(*a, **k):
        calls["pol_bind"] += 1
        return rpb(*a, **k)

    def _pu(*a, **k):
        calls["pol_unbind"] += 1
        return rpu(*a, **k)

    def _rb(*a, **k):
        calls["ring_bind"] += 1
        return rrb(*a, **k)

    def _ru(*a, **k):
        calls["ring_unbind"] += 1
        return rru(*a, **k)

    monkeypatch.setattr(patch_policy_service, "bind_host", _pb)
    monkeypatch.setattr(patch_policy_service, "unbind_host", _pu)
    monkeypatch.setattr(patch_ring_service, "bind_host", _rb)
    monkeypatch.setattr(patch_ring_service, "unbind_host", _ru)
    return calls


def _mk_patch_policy(client, admin_user, slug):
    _login(client, admin_user)
    res = client.post(
        "/patch/policies",
        json={"slug": slug, "name": slug, "scope_kind": "security_only"},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _mk_patch_ring(client, admin_user, slug, sort_order):
    _login(client, admin_user)
    res = client.post(
        "/patch/rings", json={"slug": slug, "name": slug, "sort_order": sort_order}
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def test_patch_policy_host_binding_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    pid = _mk_patch_policy(client, admin_user, "pra281-pol-bind")
    calls = _track_patch_bind(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-pp-bind"))
    _login(client, maintainer_user)
    # Hidden host -> 404 before bind_host / policy-host lookup / insert / audit.
    res = client.post(f"/patch/policies/{pid}/bindings/hosts", json={"host_id": b.id})
    assert res.status_code == 404
    assert b.hostname not in res.text
    assert (
        client.request(
            "DELETE", f"/patch/policies/{pid}/bindings/hosts/{b.id}"
        ).status_code
        == 404
    )
    assert calls["pol_bind"] == 0 and calls["pol_unbind"] == 0
    # In-scope bind + unbind still work for the scoped maintainer.
    ok = client.post(f"/patch/policies/{pid}/bindings/hosts", json={"host_id": a.id})
    assert ok.status_code == 201, ok.text
    assert (
        client.request(
            "DELETE", f"/patch/policies/{pid}/bindings/hosts/{a.id}"
        ).status_code
        == 204
    )
    assert calls["pol_bind"] == 1 and calls["pol_unbind"] == 1


def test_patch_ring_host_binding_scope(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    rid = _mk_patch_ring(client, admin_user, "pra281-ring-bind", 1)
    calls = _track_patch_bind(monkeypatch)
    _grant(db, maintainer_user, a, _mk_role(db, "r-pr-bind"))
    _login(client, maintainer_user)
    res = client.post(f"/patch/rings/{rid}/bindings/hosts", json={"host_id": b.id})
    assert res.status_code == 404
    assert b.hostname not in res.text
    assert (
        client.request(
            "DELETE", f"/patch/rings/{rid}/bindings/hosts/{b.id}"
        ).status_code
        == 404
    )
    assert calls["ring_bind"] == 0 and calls["ring_unbind"] == 0
    # In-scope bind + unbind still work.
    ok = client.post(f"/patch/rings/{rid}/bindings/hosts", json={"host_id": a.id})
    assert ok.status_code == 201, ok.text
    assert (
        client.request(
            "DELETE", f"/patch/rings/{rid}/bindings/hosts/{a.id}"
        ).status_code
        == 204
    )
    assert calls["ring_bind"] == 1 and calls["ring_unbind"] == 1


def test_patch_bind_empty_scope_404(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    pid = _mk_patch_policy(client, admin_user, "pra281-pol-empty")
    rid = _mk_patch_ring(client, admin_user, "pra281-ring-empty", 1)
    calls = _track_patch_bind(monkeypatch)
    _login(client, maintainer_user)  # no grants -> empty scope
    assert (
        client.post(
            f"/patch/policies/{pid}/bindings/hosts", json={"host_id": a.id}
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/patch/rings/{rid}/bindings/hosts", json={"host_id": a.id}
        ).status_code
        == 404
    )
    assert calls["pol_bind"] == 0 and calls["ring_bind"] == 0


def test_patch_bind_admin_tenant_wide(client, db, admin_user, two_systems):
    a, b = two_systems
    pid = _mk_patch_policy(client, admin_user, "pra281-pol-admin")
    rid = _mk_patch_ring(client, admin_user, "pra281-ring-admin", 1)
    _login(client, admin_user)
    # Admin binds any host (incl. one hidden to a scoped caller) unchanged.
    assert (
        client.post(
            f"/patch/policies/{pid}/bindings/hosts", json={"host_id": b.id}
        ).status_code
        == 201
    )
    assert (
        client.post(
            f"/patch/rings/{rid}/bindings/hosts", json={"host_id": b.id}
        ).status_code
        == 201
    )


# =====================================================================
# PRA-281 Slice 21: package reports, patch update plans, mirror trust
# =====================================================================

_S21_SEQ = {"n": 0}


def _mk_patch_policy_row(db, admin_user):
    _S21_SEQ["n"] += 1
    p = PatchPolicy(
        slug=f"pra281-pp-{_S21_SEQ['n']}",
        name=f"pra281-pp-{_S21_SEQ['n']}",
        scope_kind="full",
        reboot_policy="never",
        rollout_cadence="immediate",
        failure_policy="pause_fleet",
        created_by=admin_user.id,
    )
    db.add(p)
    db.flush()
    return p


def _mk_plan_row(db, admin_user, policy, systems, state="draft"):
    """Create a plan whose target host set is exactly ``systems``.

    ``systems`` may contain ``None`` to insert a deleted-system tombstone host
    (``system_id IS NULL``); those rows are excluded from the scope decision.
    """
    _S21_SEQ["n"] += 1
    plan = PatchUpdatePlan(
        policy_id=policy.id,
        name=f"pra281-plan-{_S21_SEQ['n']}",
        state=state,
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    for s in systems:
        db.add(
            PatchUpdatePlanHost(
                plan_id=plan.id,
                system_id=(s.id if s is not None else None),
                system_hostname_snapshot=(s.hostname if s is not None else "gone"),
                policy_resolution_kind="fleet_default",
                ring_resolution_status="resolved",
                wave_index=0,
                content_profile_state="no_profile",
                state="planned",
            )
        )
    db.commit()
    db.refresh(plan)
    return plan


# --------------------------------------------------------------- package reports


def test_package_reports_summary_defaults_to_caller_scope(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b1")
    _mk_update(db, b, "pkg-b2", sec=True)
    _grant(db, maintainer_user, a, _mk_role(db, "r-pr-sum"))
    _login(client, maintainer_user)

    # No smart_group_id: a scoped caller sees ONLY their fleet scope, not fleet-wide.
    summary = client.get("/package-reports/summary").json()
    assert summary["system_count"] == 1
    assert summary["updates_available_count"] == 1  # only a's update


def test_package_reports_summary_admin_is_fleet_wide(
    client, db, admin_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b")
    _login(client, admin_user)
    summary = client.get("/package-reports/summary").json()
    assert summary["system_count"] >= 2
    assert summary["updates_available_count"] >= 2


def test_package_reports_empty_scope_zeros(client, db, auditor_user, two_systems):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _login(client, auditor_user)  # no grants -> empty scope
    summary = client.get("/package-reports/summary").json()
    assert summary["system_count"] == 0
    assert summary["updates_available_count"] == 0
    compliance = client.get("/package-reports/compliance").json()
    assert compliance["systems"] == []


def test_package_reports_outdated_explicit_out_of_scope_404(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b")
    _grant(db, maintainer_user, a, _mk_role(db, "r-pr-out"))
    _login(client, maintainer_user)

    # In scope -> 200.
    assert client.get(f"/package-reports/outdated?system_id={a.id}").status_code == 200
    # Out-of-scope existing system -> non-disclosing 404 (before any row/hostname).
    res = client.get(f"/package-reports/outdated?system_id={b.id}")
    assert res.status_code == 404
    assert "pkg-b" not in res.text and b.hostname not in res.text
    # Nonexistent -> same 404.
    assert client.get("/package-reports/outdated?system_id=987654").status_code == 404


def test_package_reports_outdated_default_scoped(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b")
    _grant(db, maintainer_user, a, _mk_role(db, "r-pr-out2"))
    _login(client, maintainer_user)
    rows = client.get("/package-reports/outdated").json()
    assert {r["system_id"] for r in rows["items"]} == {a.id}


def test_package_reports_smart_group_intersects_caller_scope(
    client, db, maintainer_user, admin_user, two_systems
):
    a, b = two_systems
    _mk_update(db, a, "pkg-a")
    _mk_update(db, b, "pkg-b")
    sg_b = _mk_smart_group(db, admin_user, [b], "pr-b")
    sg_ab = _mk_smart_group(db, admin_user, [a, b], "pr-ab")
    _grant(db, maintainer_user, a, _mk_role(db, "r-pr-sg"))
    _login(client, maintainer_user)

    # smart group {b} INTERSECT caller scope {a} = empty -> zeros, NOT global,
    # and does not leak hidden membership of b.
    s_b = client.get(f"/package-reports/summary?smart_group_id={sg_b.id}").json()
    assert s_b["system_count"] == 0
    assert s_b["updates_available_count"] == 0

    # smart group {a,b} INTERSECT {a} = {a}.
    s_ab = client.get(f"/package-reports/summary?smart_group_id={sg_ab.id}").json()
    assert s_ab["system_count"] == 1
    assert s_ab["updates_available_count"] == 1


def test_package_reports_smart_group_admin_unchanged(
    client, db, admin_user, two_systems
):
    a, b = two_systems
    _mk_update(db, b, "pkg-b")
    sg_b = _mk_smart_group(db, admin_user, [b], "pr-adminb")
    _login(client, admin_user)
    s_b = client.get(f"/package-reports/summary?smart_group_id={sg_b.id}").json()
    assert s_b["system_count"] == 1
    assert s_b["updates_available_count"] == 1


# --------------------------------------------------------------- patch update plans


def test_patch_plan_detail_hidden_and_mixed_404(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    visible = _mk_plan_row(db, admin_user, pol, [a])
    hidden = _mk_plan_row(db, admin_user, pol, [b])
    mixed = _mk_plan_row(db, admin_user, pol, [a, b])
    empty = _mk_plan_row(db, admin_user, pol, [])
    tomb = _mk_plan_row(db, admin_user, pol, [None])  # only a deleted-system tombstone
    _grant(db, maintainer_user, a, _mk_role(db, "r-plan-detail"))
    _login(client, maintainer_user)

    assert client.get(f"/patch/update-plans/{visible.id}").status_code == 200
    for p in (hidden, mixed, empty, tomb):
        assert client.get(f"/patch/update-plans/{p.id}").status_code == 404
    assert client.get("/patch/update-plans/987654").status_code == 404


def test_patch_plan_subresources_hidden_404(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    hidden = _mk_plan_row(db, admin_user, pol, [b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-plan-sub"))
    _login(client, maintainer_user)

    pid = hidden.id
    # Every host-derived read hides behind the same non-disclosing 404, and the
    # hidden plan-host id is not probeable through the subroutes.
    for path in (
        f"/patch/update-plans/{pid}/hosts",
        f"/patch/update-plans/{pid}/hosts/1/selected-packages",
        f"/patch/update-plans/{pid}/selected-packages",
        f"/patch/update-plans/{pid}/hosts/1/preflight",
        f"/patch/update-plans/{pid}/preflight",
        f"/patch/update-plans/{pid}/export",
        f"/patch/update-plans/{pid}/reboots",
        f"/patch/update-plans/{pid}/rollback",
    ):
        assert client.get(path).status_code == 404, path


def test_patch_plan_visible_subresources_ok(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    visible = _mk_plan_row(db, admin_user, pol, [a])
    _grant(db, maintainer_user, a, _mk_role(db, "r-plan-vis"))
    _login(client, maintainer_user)
    assert client.get(f"/patch/update-plans/{visible.id}/hosts").status_code == 200
    assert client.get(f"/patch/update-plans/{visible.id}/preflight").status_code == 200


def test_patch_plan_list_hides_out_of_scope_and_mixed(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    visible = _mk_plan_row(db, admin_user, pol, [a])
    hidden = _mk_plan_row(db, admin_user, pol, [b])
    mixed = _mk_plan_row(db, admin_user, pol, [a, b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-plan-list"))
    _login(client, maintainer_user)
    ids = {p["id"] for p in client.get("/patch/update-plans").json()}
    assert visible.id in ids
    assert hidden.id not in ids
    assert mixed.id not in ids


def test_patch_plan_list_admin_sees_all(client, db, admin_user, two_systems):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    v = _mk_plan_row(db, admin_user, pol, [a])
    h = _mk_plan_row(db, admin_user, pol, [b])
    m = _mk_plan_row(db, admin_user, pol, [a, b])
    _login(client, admin_user)
    ids = {p["id"] for p in client.get("/patch/update-plans").json()}
    assert {v.id, h.id, m.id} <= ids


def test_patch_plan_export_excludes_hidden(
    client, db, admin_user, maintainer_user, two_systems
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    visible = _mk_plan_row(db, admin_user, pol, [a])
    hidden = _mk_plan_row(db, admin_user, pol, [b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-plan-exp"))
    _login(client, maintainer_user)
    res = client.get("/patch/update-plans/export?format=json")
    assert res.status_code == 200
    ids = {r["id"] for r in res.json()}
    assert visible.id in ids
    assert hidden.id not in ids


def test_patch_plan_mutations_reject_hidden_before_service(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    hidden = _mk_plan_row(db, admin_user, pol, [b])
    _grant(db, maintainer_user, a, _mk_role(db, "r-plan-mut"))
    _login(client, maintainer_user)

    def _boom(*args, **kwargs):
        raise AssertionError("service reached for a hidden plan")

    for fn in (
        "refresh_plan",
        "cancel_plan",
        "request_approval",
        "schedule_plan",
        "supersede_plan",
        "record_approval_vote",
        "approve_directly",
        "build_export_bundle",
    ):
        monkeypatch.setattr(patch_update_plan_service, fn, _boom)

    pid = hidden.id
    assert client.post(f"/patch/update-plans/{pid}/refresh").status_code == 404
    assert client.post(f"/patch/update-plans/{pid}/cancel").status_code == 404
    assert (
        client.post(f"/patch/update-plans/{pid}/approval/request", json={}).status_code
        == 404
    )
    assert (
        client.post(f"/patch/update-plans/{pid}/approval/reject", json={}).status_code
        == 404
    )
    assert (
        client.post(
            f"/patch/update-plans/{pid}/schedule",
            json={"scheduled_start_at": "2030-01-01T00:00:00Z"},
        ).status_code
        == 404
    )
    assert (
        client.post(f"/patch/update-plans/{pid}/supersede", json={}).status_code == 404
    )
    assert client.get(f"/patch/update-plans/{pid}/export").status_code == 404


def test_patch_plan_dry_run_rejects_out_of_scope_before_service(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    db.commit()
    _grant(db, maintainer_user, a, _mk_role(db, "r-plan-dry"))
    _login(client, maintainer_user)

    calls = {"n": 0}

    def _spy(*args, **kwargs):
        calls["n"] += 1
        raise patch_update_plan_service.PatchUpdatePlanError("stop after gate")

    monkeypatch.setattr(patch_update_plan_service, "create_plan", _spy)

    # Explicit batch containing an out-of-scope id -> non-disclosing 404, and the
    # service create is never reached.
    res = client.post(
        "/patch/update-plans/dry-run",
        json={
            "policy_id": pol.id,
            "name": "dry",
            "target_system_ids": [a.id, b.id],
        },
    )
    assert res.status_code == 404
    assert calls["n"] == 0

    # Auto-discovery (omitted targets) would build a fleet-wide plan -> forbidden
    # for a scoped caller; still no service call.
    res = client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "dry"},
    )
    assert res.status_code == 403
    assert calls["n"] == 0

    # Fully in-scope explicit batch passes the gate and reaches the service.
    res = client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "dry", "target_system_ids": [a.id]},
    )
    assert res.status_code == 422  # our sentinel PatchUpdatePlanError
    assert calls["n"] == 1


def test_patch_plan_dry_run_rejects_empty_explicit_targets(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    db.commit()
    _grant(db, maintainer_user, a, _mk_role(db, "r-plan-empty"))
    _login(client, maintainer_user)

    calls = {"n": 0}

    def _spy(*args, **kwargs):
        calls["n"] += 1
        raise patch_update_plan_service.PatchUpdatePlanError("stop after gate")

    monkeypatch.setattr(patch_update_plan_service, "create_plan", _spy)

    before = db.query(PatchUpdatePlan).count()
    # An explicit but EMPTY list must not reach the service — otherwise it would
    # persist a blocked zero-host plan the caller can then never see. It is
    # rejected at the PatchUpdatePlanCreate schema validator (422) before the route
    # body, so create_plan is never called and no plan row is persisted.
    res = client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "dry", "target_system_ids": []},
    )
    assert res.status_code == 422
    assert calls["n"] == 0
    db.expire_all()
    assert db.query(PatchUpdatePlan).count() == before


def test_patch_plan_dry_run_admin_auto_discovery_allowed(
    client, db, admin_user, two_systems, monkeypatch
):
    a, b = two_systems
    pol = _mk_patch_policy_row(db, admin_user)
    db.commit()
    _login(client, admin_user)

    calls = {"n": 0}

    def _spy(*args, **kwargs):
        calls["n"] += 1
        raise patch_update_plan_service.PatchUpdatePlanError("stop after gate")

    monkeypatch.setattr(patch_update_plan_service, "create_plan", _spy)
    res = client.post(
        "/patch/update-plans/dry-run",
        json={"policy_id": pol.id, "name": "dry"},
    )
    # Admin auto-discovery is not gated -> reaches the service.
    assert res.status_code == 422
    assert calls["n"] == 1


# --------------------------------------------------------------- mirror install-trust


def test_mirror_install_trust_rejects_out_of_scope_before_lookup(
    client, db, admin_user, maintainer_user, two_systems, monkeypatch
):
    a, b = two_systems
    _grant(db, maintainer_user, a, _mk_role(db, "r-mir-trust"))
    _login(client, maintainer_user)

    # A 418 sentinel proves control reached the mirror lookup; the install path
    # blows up if reached. A scope-blocked request hits NEITHER.
    def _sentinel(*args, **kwargs):
        raise HTTPException(status_code=418, detail="reached mirror lookup")

    def _no_install(*args, **kwargs):
        raise AssertionError("install reached for out-of-scope batch")

    monkeypatch.setattr(mirrors_routes, "_live_or_404", _sentinel)
    monkeypatch.setattr(mirrors_routes, "install_mirror_trust_on_host", _no_install)

    # Mixed batch -> non-disclosing 404 BEFORE mirror lookup (never the teapot).
    res = client.post("/mirrors/424242/install-trust", json={"host_ids": [a.id, b.id]})
    assert res.status_code == 404
    assert str(a.id) not in res.text and str(b.id) not in res.text

    # Empty host_ids stays a 400.
    assert (
        client.post("/mirrors/424242/install-trust", json={"host_ids": []}).status_code
        == 400
    )

    # Fully in-scope batch passes the gate and reaches the mirror lookup (418).
    res = client.post("/mirrors/424242/install-trust", json={"host_ids": [a.id]})
    assert res.status_code == 418


def test_mirror_install_trust_admin_not_gated(
    client, db, admin_user, two_systems, monkeypatch
):
    a, b = two_systems

    def _sentinel(*args, **kwargs):
        raise HTTPException(status_code=418, detail="reached mirror lookup")

    monkeypatch.setattr(mirrors_routes, "_live_or_404", _sentinel)
    _login(client, admin_user)
    # Admin batch spanning every host is not gated -> reaches the mirror lookup.
    res = client.post("/mirrors/424242/install-trust", json={"host_ids": [a.id, b.id]})
    assert res.status_code == 418


# --------------------------------------------------------------- activity feed
#
# Discovered by the Slice 21 mounted-route sweep (no ``{system_id}`` path param,
# so the Slice-20 path grep missed it). The ``package`` and ``audit`` sources
# surface host-attributed rows (system_id + hostname + package/version detail).


def test_activity_feed_package_source_scoped(client, db, maintainer_user, two_systems):
    a, b = two_systems
    _mk_pkg_history(db, a, maintainer_user, operation="install")
    _mk_pkg_history(db, b, maintainer_user, operation="install")
    _grant(db, maintainer_user, a, _mk_role(db, "r-feed-pkg"))
    _login(client, maintainer_user)
    items = client.get("/activity/feed?source=package").json()["items"]
    sys_ids = {i["system_id"] for i in items}
    assert sys_ids == {a.id}
    assert all(i["system_hostname"] != b.hostname for i in items)


def test_activity_feed_package_source_admin_sees_all(
    client, db, admin_user, two_systems
):
    a, b = two_systems
    _mk_pkg_history(db, a, admin_user, operation="install")
    _mk_pkg_history(db, b, admin_user, operation="install")
    _login(client, admin_user)
    items = client.get("/activity/feed?source=package").json()["items"]
    assert {a.id, b.id} <= {i["system_id"] for i in items}


def test_activity_feed_empty_scope_hides_host_rows(
    client, db, auditor_user, two_systems
):
    a, b = two_systems
    _mk_pkg_history(db, a, auditor_user, operation="install")
    _login(client, auditor_user)  # no grants -> empty scope
    items = client.get("/activity/feed?source=package").json()["items"]
    assert items == []


def test_activity_feed_explicit_out_of_scope_system_no_leak(
    client, db, maintainer_user, two_systems
):
    a, b = two_systems
    _mk_pkg_history(db, b, maintainer_user, operation="install")
    _grant(db, maintainer_user, a, _mk_role(db, "r-feed-noleak"))
    _login(client, maintainer_user)
    # Filtering the mixed feed by an out-of-scope system yields no host rows: the
    # fleet-scope filter intersects the explicit id to empty, so b never leaks.
    res = client.get(f"/activity/feed?source=package&system_id={b.id}")
    assert res.status_code == 200
    assert res.json()["items"] == []
    assert b.hostname not in res.text


def test_activity_feed_audit_source_admin_tenant_wide(
    client, db, admin_user, two_systems
):
    # The audit source is intentionally NOT fleet-scoped (PRA-221 audit posture);
    # the admin/auditor role gate is its access control. Admin sees every system.
    a, b = two_systems
    _mk_audit(db, a, admin_user)
    _mk_audit(db, b, admin_user)
    _login(client, admin_user)
    items = client.get("/activity/feed?source=audit").json()["items"]
    assert {a.id, b.id} <= {i["system_id"] for i in items}
