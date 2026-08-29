"""PRA-400: the fleet dashboard and scan routes carry security-scan provenance.

Route-level cover for the contract the dashboard renders:

* ``GET /fleet/dashboard`` reports a security state, never a bare zero, and
  keeps the existing patch-compliance counts intact;
* the state is derived inside the caller's fleet scope, so a scoped operator
  sees coverage for their hosts only;
* a single-host security scan records its own outcome, including the failure
  and partial cases, so a host that was asked the question can be told apart
  from one that never was;
* an ordinary package scan records no security-scan outcome at all.
"""

import json
from datetime import datetime

import pytest

from app.db.models import (
    AccessGrant,
    Credential,
    Distro,
    FleetOperation,
    FleetOperationResult,
    FleetRole,
    Group,
    Package,
    System,
)
from app.services import security_scan_status_service as provenance

# --------------------------------------------------------------- fixtures


@pytest.fixture
def cred(db):
    c = Credential(name="pra400-api-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def group(db):
    g = Group(name="pra400-api-group", description="x")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def rocky_distro(db):
    from datetime import date

    distro = db.query(Distro).filter_by(name="Rocky", version="9").first()
    if not distro:
        distro = Distro(
            name="Rocky",
            version="9",
            release_date=date(2022, 5, 16),
            end_of_life_date=date(2032, 5, 31),
        )
        db.add(distro)
        db.flush()
    return distro


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
    a = _mk_system(db, seed_distro, group, cred, "pra400-api-a", "10.41.0.1")
    b = _mk_system(db, seed_distro, group, cred, "pra400-api-b", "10.41.0.2")
    db.commit()
    return a, b


def _grant(db, user, system):
    role = FleetRole(
        name=f"pra400-role-{system.id}",
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


def _record_scan(db, user, system, status, error_message=None):
    op = FleetOperation(
        operation_type=provenance.SECURITY_SCAN_OPERATION_SINGLE,
        user_id=user.id,
        target_count=1,
        parameters=json.dumps({"system_ids": [system.id]}),
        status="completed",
        created_at=datetime.utcnow(),
    )
    db.add(op)
    db.flush()
    db.add(
        FleetOperationResult(
            fleet_operation_id=op.id,
            system_id=system.id,
            status=status,
            error_message=error_message,
            created_at=datetime.utcnow(),
        )
    )
    db.commit()


@pytest.fixture
def captured_ops(monkeypatch):
    """Capture operation recording instead of writing it.

    The real service opens its own ``SessionLocal``, which cannot see this
    test transaction's uncommitted rows, so the calls are captured here.
    """
    from app.services import fleet_operation_service as fos

    captured = {"start": [], "results": [], "completed": []}

    def _start(operation_type, user_id, target_count, parameters=None):
        captured["start"].append(
            {
                "operation_type": operation_type,
                "target_count": target_count,
                "parameters": parameters,
            }
        )
        return 4400 + len(captured["start"])

    def _record(op_id, system_id, status, error_message=None):
        captured["results"].append(
            {"system_id": system_id, "status": status, "message": error_message}
        )

    def _complete(op_id, success_count, failure_count, status=None):
        captured["completed"].append((success_count, failure_count, status))

    monkeypatch.setattr(fos, "start_operation", _start)
    monkeypatch.setattr(fos, "record_result", _record)
    monkeypatch.setattr(fos, "complete_operation", _complete)
    return captured


def _ssh_stub(monkeypatch, stdout, status="success", stderr=""):
    def fake_exec(self, system_id, command, timeout=60):
        return {"status": status, "stdout": stdout, "stderr": stderr}

    monkeypatch.setattr(
        "app.services.ssh_service.SSHService.execute_command", fake_exec
    )


# --------------------------------------------------------------- dashboard


def test_dashboard_reports_unscanned_instead_of_a_bare_zero(authed_client, hosts):
    res = authed_client.get("/fleet/dashboard")
    assert res.status_code == 200, res.text
    body = res.json()

    posture = body["security_posture"]
    assert posture["state"] == provenance.STATE_NOT_SCANNED
    assert posture["counts_trustworthy"] is False
    assert posture["systems_never_scanned"] == posture["systems_total"]
    assert posture["last_successful_scan_at"] is None
    # The pre-existing counts stay where API consumers already expect them.
    assert body["patch_compliance"]["with_security_updates"] == 0
    assert posture["pending_security_updates"] == 0


def test_dashboard_reports_a_trustworthy_zero_after_a_completed_scan(
    authed_client, db, admin_user, hosts
):
    a, b = hosts
    _record_scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _record_scan(db, admin_user, b, provenance.RESULT_SUCCESS)

    posture = authed_client.get("/fleet/dashboard").json()["security_posture"]
    assert posture["state"] == provenance.STATE_COMPLETE
    assert posture["counts_trustworthy"] is True
    assert posture["pending_security_updates"] == 0
    assert posture["last_successful_scan_at"] is not None


def test_dashboard_reports_findings_with_their_scan_provenance(
    authed_client, db, admin_user, hosts
):
    a, b = hosts
    pkg = Package(system_id=a.id, name="openssl", installed_version="1.0")
    db.add(pkg)
    db.flush()
    from app.db.models import PackageUpdate

    db.add(
        PackageUpdate(
            package_id=pkg.id,
            system_id=a.id,
            available_version="1.1",
            update_type="security",
            discovered_on=datetime.utcnow(),
        )
    )
    db.commit()
    _record_scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _record_scan(db, admin_user, b, provenance.RESULT_SUCCESS)

    posture = authed_client.get("/fleet/dashboard").json()["security_posture"]
    assert posture["state"] == provenance.STATE_COMPLETE
    assert posture["systems_with_security_updates"] == 1
    assert posture["pending_security_updates"] == 1


def test_dashboard_reports_failure_context_without_raw_control_characters(
    authed_client, db, admin_user, hosts
):
    a, b = hosts
    _record_scan(
        db,
        admin_user,
        a,
        provenance.RESULT_FAILURE,
        error_message="Failed to scan security updates:\n  no output\r\n",
    )
    _record_scan(
        db, admin_user, b, provenance.RESULT_FAILURE, error_message="no output"
    )

    posture = authed_client.get("/fleet/dashboard").json()["security_posture"]
    assert posture["state"] == provenance.STATE_FAILED
    assert posture["counts_trustworthy"] is False
    assert "\n" not in posture["last_failure_detail"]


def test_dashboard_never_serves_credential_material_in_failure_context(
    authed_client, db, admin_user, hosts
):
    """A secret in a stored scan failure must not reach a dashboard reader.

    `last_failure_detail` is read from a persisted result message, which for an
    SSH or package-manager failure can carry an exception string with a
    credential in it. The assertion is over the whole response body, not just
    the one field, so a secret cannot arrive through some other key either.
    """
    a, b = hosts
    sentinel = "SentinelApiSecret8f2c1d9a4b7e"
    _record_scan(
        db,
        admin_user,
        a,
        provenance.RESULT_FAILURE,
        error_message="Permission denied (publickey,password).",
    )
    # Recorded last, so this is the failure the dashboard surfaces.
    _record_scan(
        db,
        admin_user,
        b,
        provenance.RESULT_FAILURE,
        error_message=(
            f"dnf failed: cannot open https://mirroruser:{sentinel}@repo.internal/os"
        ),
    )

    body = authed_client.get("/fleet/dashboard").json()
    assert sentinel not in json.dumps(body)

    posture = body["security_posture"]
    assert posture["state"] == provenance.STATE_FAILED
    assert posture["counts_trustworthy"] is False
    assert "redacted" in posture["last_failure_detail"]
    # The diagnostic survives; only the credential is gone.
    assert "repo.internal" in posture["last_failure_detail"]


def test_dashboard_security_state_is_scoped_to_the_caller(
    client, db, admin_user, maintainer_user, hosts
):
    a, b = hosts
    _record_scan(db, admin_user, a, provenance.RESULT_SUCCESS)
    _record_scan(db, admin_user, b, provenance.RESULT_FAILURE, error_message="denied")
    _grant(db, maintainer_user, a)

    _login(client, maintainer_user)
    scoped = client.get("/fleet/dashboard").json()["security_posture"]
    assert scoped["systems_total"] == 1
    assert scoped["state"] == provenance.STATE_COMPLETE
    assert scoped["last_failure_detail"] is None

    _login(client, admin_user)
    tenant_wide = client.get("/fleet/dashboard").json()["security_posture"]
    assert tenant_wide["systems_total"] >= 2
    assert tenant_wide["state"] == provenance.STATE_PARTIAL


# --------------------------------------------------------------- scan routes


def test_single_host_scan_records_a_successful_security_scan(
    authed_client, db, group, cred, rocky_distro, captured_ops, monkeypatch
):
    host = _mk_system(db, rocky_distro, group, cred, "pra400-api-rpm", "10.41.1.1")
    db.add(Package(system_id=host.id, name="openssl", installed_version="1.0"))
    db.commit()
    _ssh_stub(
        monkeypatch,
        "RLSA-2024:7106 security Important openssl-1:3.0.7-27.el9.x86_64\n",
    )

    res = authed_client.post(f"/packages/{host.id}/scan-security")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["scan_state"] == provenance.STATE_COMPLETE
    assert body["fleet_operation_id"] is not None

    assert captured_ops["start"][0]["operation_type"] == (
        provenance.SECURITY_SCAN_OPERATION_SINGLE
    )
    assert captured_ops["start"][0]["parameters"]["system_ids"] == [host.id]
    assert captured_ops["results"] == [
        {"system_id": host.id, "status": provenance.RESULT_SUCCESS, "message": None}
    ]
    assert captured_ops["completed"] == [(1, 0, None)]


def test_single_host_scan_records_a_partial_security_scan(
    authed_client, db, group, cred, rocky_distro, captured_ops, monkeypatch
):
    host = _mk_system(db, rocky_distro, group, cred, "pra400-api-rpm2", "10.41.1.2")
    db.add(Package(system_id=host.id, name="openssl", installed_version="1.0"))
    db.commit()
    _ssh_stub(
        monkeypatch,
        "RLSA-2024:7106 security Important openssl-1:3.0.7-27.el9.x86_64\n"
        "RLSA-2024:7107 security Important garbled-advisory-row\n",
    )

    res = authed_client.post(f"/packages/{host.id}/scan-security")
    assert res.status_code == 200, res.text
    assert res.json()["scan_state"] == provenance.STATE_PARTIAL
    assert captured_ops["results"][0]["status"] == provenance.RESULT_PARTIAL
    assert "incomplete" in captured_ops["results"][0]["message"]


def test_single_host_scan_records_a_failed_security_scan(
    authed_client, db, group, cred, seed_distro, captured_ops, monkeypatch
):
    host = _mk_system(db, seed_distro, group, cred, "pra400-api-apt", "10.41.1.3")
    db.commit()
    _ssh_stub(monkeypatch, "", status="success", stderr="connection reset")

    res = authed_client.post(f"/packages/{host.id}/scan-security")
    assert res.status_code == 200, res.text
    assert res.json()["scan_state"] == provenance.STATE_FAILED
    assert captured_ops["results"][0]["status"] == provenance.RESULT_FAILURE
    assert captured_ops["completed"] == [(0, 1, None)]


def test_single_host_scan_records_a_transport_failure(
    authed_client, db, group, cred, seed_distro, captured_ops, monkeypatch
):
    host = _mk_system(db, seed_distro, group, cred, "pra400-api-apt2", "10.41.1.4")
    db.commit()

    from app.services.ssh_service import SSHConnectionError

    def fake_exec(self, system_id, command, timeout=60):
        raise SSHConnectionError("host unreachable")

    monkeypatch.setattr(
        "app.services.ssh_service.SSHService.execute_command", fake_exec
    )

    res = authed_client.post(f"/packages/{host.id}/scan-security")
    assert res.status_code == 400
    assert captured_ops["results"][0]["status"] == provenance.RESULT_FAILURE
    assert captured_ops["completed"] == [(0, 1, "failed")]


def test_single_host_scan_failure_never_persists_credential_material(
    authed_client, db, group, cred, seed_distro, captured_ops, monkeypatch
):
    """A transport exception string is redacted before the row is written.

    The display boundary redacts unconditionally, but a credential should not
    be persisted in the first place when the scan path is the one writing it.
    """
    host = _mk_system(db, seed_distro, group, cred, "pra400-api-secret", "10.41.2.1")
    db.commit()
    sentinel = "SentinelSshPw8f2c1d9a4b7e"

    from app.services.ssh_service import SSHConnectionError

    def fake_exec(self, system_id, command, timeout=60):
        raise SSHConnectionError(
            f"ssh handshake failed: password={sentinel} for user deploy"
        )

    monkeypatch.setattr(
        "app.services.ssh_service.SSHService.execute_command", fake_exec
    )

    res = authed_client.post(f"/packages/{host.id}/scan-security")
    assert res.status_code == 400

    recorded = captured_ops["results"][0]
    assert recorded["status"] == provenance.RESULT_FAILURE
    assert sentinel not in recorded["message"]
    assert "redacted" in recorded["message"]
    # The non-secret diagnostic survives, or the row is worthless.
    assert "handshake failed" in recorded["message"]


def test_single_host_partial_scan_message_is_redacted_before_recording(
    authed_client, db, group, cred, rocky_distro, captured_ops, monkeypatch
):
    """The partial-scan message is redacted on the same path as a failure."""
    host = _mk_system(db, rocky_distro, group, cred, "pra400-api-partial", "10.41.2.2")
    db.add(Package(system_id=host.id, name="openssl", installed_version="1.0"))
    db.commit()
    sentinel = "SentinelAdvisoryToken8f2c1d9a"

    monkeypatch.setattr(
        "app.services.package_service.PackageService.scan_security_updates",
        lambda self, system_id: {
            "system_id": system_id,
            "hostname": host.hostname,
            "status": "success",
            "scan_state": provenance.STATE_PARTIAL,
            "updates_available": 1,
            "message": (
                f"Security scan incomplete: advisory feed rejected token={sentinel}"
            ),
        },
    )

    res = authed_client.post(f"/packages/{host.id}/scan-security")
    assert res.status_code == 200, res.text

    recorded = captured_ops["results"][0]
    assert recorded["status"] == provenance.RESULT_PARTIAL
    assert sentinel not in recorded["message"]
    assert "redacted" in recorded["message"]
    assert "Security scan incomplete" in recorded["message"]


def test_cohort_security_scan_redacts_recorded_host_messages(
    authed_client, db, group, cred, seed_distro, captured_ops, monkeypatch
):
    """Cohort security scans redact per-host messages on the same boundary."""
    host = _mk_system(db, seed_distro, group, cred, "pra400-api-cohort", "10.41.2.3")
    db.commit()
    sentinel = "SentinelCohortPw8f2c1d9a"

    monkeypatch.setattr(
        "app.services.package_service.PackageService.scan_security_updates",
        lambda self, system_id: {
            "system_id": system_id,
            "hostname": host.hostname,
            "status": "error",
            "scan_state": provenance.STATE_FAILED,
            "message": f"Failed to scan security updates: password={sentinel}",
        },
    )

    res = authed_client.post(
        "/packages/scope/scan",
        json={"scope_type": "system", "scope_id": host.id, "security": True},
    )
    assert res.status_code == 200, res.text

    recorded = captured_ops["results"][0]
    assert recorded["status"] == provenance.RESULT_FAILURE
    assert sentinel not in recorded["message"]
    assert "redacted" in recorded["message"]


def test_ordinary_cohort_package_scan_recording_is_unchanged(
    authed_client, db, group, cred, seed_distro, captured_ops, monkeypatch
):
    """The non-security cohort path keeps recording exactly what it recorded.

    Redaction is added on the security-scan boundary this PRA owns; the shared
    package-scan recording is left alone.
    """
    host = _mk_system(db, seed_distro, group, cred, "pra400-api-cohort2", "10.41.2.4")
    db.commit()
    message = "Failed to scan packages: dpkg-query exited 2"

    monkeypatch.setattr(
        "app.services.package_service.PackageService.scan_packages",
        lambda self, system_id: {
            "system_id": system_id,
            "hostname": host.hostname,
            "status": "error",
            "message": message,
        },
    )

    res = authed_client.post(
        "/packages/scope/scan",
        json={"scope_type": "system", "scope_id": host.id, "security": False},
    )
    assert res.status_code == 200, res.text
    assert captured_ops["results"][0]["message"] == message


def test_ordinary_package_scan_records_no_security_outcome(
    authed_client, db, group, cred, seed_distro, captured_ops, monkeypatch
):
    host = _mk_system(db, seed_distro, group, cred, "pra400-api-apt3", "10.41.1.5")
    db.commit()
    _ssh_stub(monkeypatch, "bash\t5.1-6ubuntu1\tinstall ok installed\n")

    res = authed_client.post(f"/packages/{host.id}/scan")
    assert res.status_code == 200, res.text
    assert captured_ops["start"] == []
    assert captured_ops["results"] == []


def test_scan_security_is_refused_for_a_host_outside_the_callers_scope(
    client, db, maintainer_user, hosts, captured_ops
):
    _a, b = hosts
    _login(client, maintainer_user)
    res = client.post(f"/packages/{b.id}/scan-security")
    assert res.status_code == 404
    assert captured_ops["start"] == []
