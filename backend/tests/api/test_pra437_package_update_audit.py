"""PRA-437: ad-hoc package updates persist a truthful audit event.

``POST /packages/{system_id}/update`` and ``POST /packages/bulk/update`` mutate
hosts through ``PackageService.apply_updates``. They used to write package
history and nothing else, so the audit stream held no record of who updated
which host or what happened.

These tests drive the real routes, the real ``PackageService`` (held-package
filtering, history rows, post-update verification, response shaping) and the real
audit sink. Only the transport boundary is doubled: the SSH layer returns scripted
command results and the post-update rescan advances installed versions exactly as
a real rescan of a successful update would. The persisted ``AuditEvent`` rows are
the evidence, read directly and through the per-host audit query.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import pytest

import app.services.package_service as package_service_module
from app.db.access_models import AuditEvent
from app.db.models import (
    AccessGrant,
    Credential,
    FleetRole,
    Group,
    Package,
    PackageHistory,
    PackageUpdate,
    System,
)
from app.services import audit_event_service
from app.services.access_authorization_service import user_can_access_system
from app.services.package_service import PackageService
from app.services.ssh_service import SSHConnectionError

_CONTEXT_KEYS = {
    "hostname",
    "package_names",
    "package_count",
    "result",
    "packages_updated",
    "packages_skipped",
    "packages_failed",
    "packages_unrecorded",
}

_UPDATE_OK = {"status": "success", "exit_code": 0, "stdout": "done", "stderr": ""}
_PROBE = {
    "status": "success",
    "exit_code": 0,
    "stdout": "PRAXIS_REBOOT_PROBE=false",
    "stderr": "",
}


# --------------------------------------------------------------------- helpers


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


@pytest.fixture
def group(db) -> Group:
    g = Group(name="pra437-grp", description="x")
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def cred(db) -> Credential:
    c = Credential(name="pra437-cred", auth_method="ssh_key", username="root")
    db.add(c)
    db.commit()
    return c


def _host(db, seed_distro, group, cred, name: str, ip: str, pkgs: Dict[str, str]):
    """A host with one pending update per package, keyed name -> available version."""
    s = System(
        hostname=name,
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    for pkg_name, available in pkgs.items():
        pkg = Package(
            system_id=s.id,
            name=pkg_name,
            installed_version="1.0",
            package_type="apt",
        )
        db.add(pkg)
        db.commit()
        db.add(
            PackageUpdate(
                package_id=pkg.id,
                system_id=s.id,
                available_version=available,
                update_type="security",
                discovered_on=datetime.utcnow(),
            )
        )
        db.commit()
    return s


@pytest.fixture
def host(db, seed_distro, group, cred) -> System:
    return _host(
        db,
        seed_distro,
        group,
        cred,
        "pra437-a.example.com",
        "10.0.43.1",
        {"openssl": "1.1", "curl": "2.1"},
    )


@pytest.fixture
def host_b(db, seed_distro, group, cred) -> System:
    return _host(
        db,
        seed_distro,
        group,
        cred,
        "pra437-b.example.com",
        "10.0.43.2",
        {"openssl": "1.1"},
    )


class _Transport:
    """Scripted host plus SSH boundary shared by every host the test touches.

    The host's own installed versions are the truth. ``list_installed`` reads
    them, the update command moves them, and the rescan copies them into the
    inventory, so what the service observes is what the host holds and the
    stored inventory can be made stale or incomplete on purpose.
    """

    def __init__(self) -> None:
        self.update_result: Dict[str, Any] = dict(_UPDATE_OK)
        self.raise_on_update: Optional[Exception] = None
        self.advance: Optional[Set[str]] = None  # None = every package advances
        self.advance_by_system: Dict[int, Set[str]] = {}
        self.commands: List[str] = []
        # Packages whose installed version moves on the host without any pending
        # update row to verify them.
        self.untracked_moves: Set[str] = set()
        # Host state the stored inventory does not reflect yet: name -> version.
        self.host_versions: Dict[str, str] = {}
        self.rescan_status = "success"
        # The host listing is unreadable before / after the update command.
        self.listing_fails_before = False
        self.listing_fails_after = False
        # The listing exits nonzero but still prints a parseable package list.
        self.listing_nonzero_before = False
        self.listing_nonzero_after = False
        # Packages the rescan newly adds to the inventory (first-time sync).
        self.discovered: Set[str] = set()
        self._host: Dict[int, Dict[str, str]] = {}
        self._updated: Set[int] = set()

    def _state(self, db, system_id: int) -> Dict[str, str]:
        if system_id not in self._host:
            rows = db.query(Package).filter(Package.system_id == system_id).all()
            state = {p.name: p.installed_version for p in rows}
            state.update(self.host_versions)
            for name in self.discovered:
                state[name] = "3.0"
            self._host[system_id] = state
        return self._host[system_id]

    def _apply(self, db, system_id: int, command: str) -> None:
        state = self._state(db, system_id)
        moves = self.advance_by_system.get(system_id, self.advance)
        named = command.split()
        for upd in (
            db.query(PackageUpdate).filter(PackageUpdate.system_id == system_id).all()
        ):
            # A named upgrade touches only the packages it names.
            if "--only-upgrade" in named and upd.package.name not in named:
                continue
            if moves is None or upd.package.name in moves:
                state[upd.package.name] = upd.available_version
        for name in self.untracked_moves:
            if name in state and ("--only-upgrade" not in named or name in named):
                state[name] = "9.9"

    def install(self, monkeypatch, db) -> None:
        transport = self

        class _FakeSSH:
            def __init__(self, _db):
                pass

            def execute_privileged_command(
                self, system_id, command, timeout=None
            ):  # pylint: disable=unused-argument
                if "PRAXIS_REBOOT_PROBE" in command:
                    return dict(_PROBE)
                transport.commands.append(command)
                if transport.raise_on_update is not None:
                    raise transport.raise_on_update
                result = dict(transport.update_result)
                if result.get("exit_code") == 0:
                    transport._apply(db, system_id, command)
                    transport._updated.add(system_id)
                return result

            def execute_command(
                self, system_id, command, timeout=None
            ):  # pylint: disable=unused-argument
                after = system_id in transport._updated
                failing = (
                    transport.listing_fails_after
                    if after
                    else transport.listing_fails_before
                ) or (after and transport.rescan_status != "success")
                if failing:
                    return {
                        "status": "error",
                        "exit_code": 255,
                        "stdout": "",
                        "stderr": "listing unavailable",
                    }
                nonzero = (
                    transport.listing_nonzero_after
                    if after
                    else transport.listing_nonzero_before
                )
                lines = "".join(
                    f"{name}\t{version}\tinstall ok installed\n"
                    for name, version in transport._state(db, system_id).items()
                )
                return {
                    "status": "warning" if nonzero else "success",
                    "exit_code": 1 if nonzero else 0,
                    "outcome": "command_failed" if nonzero else "success",
                    "stdout": lines,
                    "stderr": "",
                }

            def close_all_connections(self):  # pragma: no cover
                pass

        monkeypatch.setattr(package_service_module, "SSHService", _FakeSSH)

        def _rescan(self, system_id, refresh=True):  # pylint: disable=unused-argument
            if transport.rescan_status == "success":
                state = transport._state(self.db, system_id)
                known = set()
                for pkg in (
                    self.db.query(Package).filter(Package.system_id == system_id).all()
                ):
                    known.add(pkg.name)
                    if pkg.name in state:
                        pkg.installed_version = state[pkg.name]
                for name in transport.discovered:
                    if name not in known:
                        self.db.add(
                            Package(
                                system_id=system_id,
                                name=name,
                                installed_version="3.0",
                                package_type="apt",
                            )
                        )
            self.db.flush()
            return {"status": transport.rescan_status}

        monkeypatch.setattr(PackageService, "scan_packages", _rescan)


@pytest.fixture
def transport(monkeypatch, db) -> _Transport:
    t = _Transport()
    t.install(monkeypatch, db)
    return t


@pytest.fixture
def fleet_ops(monkeypatch):
    """The bulk route's fleet-operation ledger commits on its own session, which
    cannot see the test transaction's users. It is orthogonal to the audit event,
    so it is stubbed rather than exercised."""
    from app.services import fleet_operation_service

    monkeypatch.setattr(fleet_operation_service, "start_operation", lambda **kw: 1)
    monkeypatch.setattr(fleet_operation_service, "record_result", lambda *a, **kw: None)
    monkeypatch.setattr(
        fleet_operation_service, "complete_operation", lambda *a, **kw: None
    )


def _grant(db, user, system) -> None:
    role = FleetRole(
        name=f"pra437-role-{user.username}",
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


def _events(db, system_id: Optional[int] = None) -> List[AuditEvent]:
    db.expire_all()
    q = db.query(AuditEvent).filter(
        AuditEvent.action == "package.update", AuditEvent.outcome != "denied"
    )
    if system_id is not None:
        q = q.filter(AuditEvent.target_system_id == system_id)
    return q.order_by(AuditEvent.id.asc()).all()


def _denials(db) -> List[AuditEvent]:
    db.expire_all()
    return (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "package.update", AuditEvent.outcome == "denied")
        .order_by(AuditEvent.id.asc())
        .all()
    )


def _untracked(db, system: System, name: str) -> None:
    """A package the inventory knows with no pending update row."""
    db.add(
        Package(
            system_id=system.id, name=name, installed_version="1.0", package_type="apt"
        )
    )
    db.commit()


def _context(row: AuditEvent) -> Dict[str, Any]:
    return json.loads(row.context_json or "{}")


def _history(db, system_id: int) -> List[PackageHistory]:
    db.expire_all()
    return (
        db.query(PackageHistory)
        .filter(PackageHistory.system_id == system_id)
        .order_by(PackageHistory.id.asc())
        .all()
    )


def _update(client, system_id: int, names: Optional[List[str]] = None):
    body = {"package_names": names} if names is not None else None
    return client.post(f"/packages/{system_id}/update", json=body)


# --------------------------------------------------------- the missing event


def test_successful_update_persists_one_event(
    db, authed_client, admin_user, host, transport
):
    """Reproduction: before the fix this route left no audit row at all."""
    res = _update(authed_client, host.id)
    assert res.status_code == 200, res.text
    assert res.json()["packages_updated"] == 2

    rows = _events(db)
    assert len(rows) == 1
    row = rows[0]
    assert row.outcome == "success"
    assert row.actor_user_id == admin_user.id
    assert row.actor_username == admin_user.username
    assert row.target_system_id == host.id
    assert row.target_kind == "system"
    assert row.target_id == str(host.id)
    assert row.schema_version == audit_event_service.SCHEMA_VERSION
    ctx = _context(row)
    assert set(ctx) == _CONTEXT_KEYS
    assert ctx["hostname"] == host.hostname
    assert ctx["result"] == "updated"
    assert ctx["packages_updated"] == 2
    assert ctx["packages_failed"] == 0
    assert ctx["packages_skipped"] == 0
    assert ctx["package_names"] is None  # nothing named: all pending updates


def test_package_history_is_unchanged_by_the_audit(
    db, authed_client, admin_user, host, transport
):
    res = _update(authed_client, host.id)
    assert res.status_code == 200, res.text

    rows = _history(db, host.id)
    assert {r.status for r in rows} == {"completed"}
    assert {r.performed_by for r in rows} == {admin_user.id}
    assert {r.operation for r in rows} == {"update"}
    hist = authed_client.get(f"/packages/history/{host.id}")
    if hist.status_code == 200:
        assert hist.json()["total"] == 2


def test_named_packages_are_recorded(db, authed_client, host, transport):
    res = _update(authed_client, host.id, ["openssl"])
    assert res.status_code == 200, res.text

    ctx = _context(_events(db)[0])
    assert ctx["package_names"] == ["openssl"]
    assert ctx["package_count"] == 1
    assert ctx["packages_updated"] == 1


def test_event_is_returned_by_the_per_host_audit_query(
    db, authed_client, host, host_b, transport
):
    assert _update(authed_client, host.id).status_code == 200
    assert _update(authed_client, host_b.id).status_code == 200

    res = authed_client.get(
        "/audit/events", params={"system_id": host.id, "action": "package.update"}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total"] == 1
    event = body["events"][0]
    assert event["target"]["system_id"] == host.id
    assert event["context"]["hostname"] == host.hostname


# ------------------------------------------------------------------- outcomes


def test_nonzero_exit_is_a_failure(db, authed_client, host, transport):
    transport.update_result = {
        "status": "failed",
        "exit_code": 100,
        "stdout": "",
        "stderr": "E: Unable to locate package curl",
    }
    res = _update(authed_client, host.id)
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "error"

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "failed"
    # Entries marked failed are measured; what the host did is not.
    assert ctx["packages_failed"] == 2
    assert ctx["packages_updated"] is None
    assert ctx["packages_unrecorded"] is None
    assert "Unable to locate package" in ctx["reason"]
    assert {h.status for h in _history(db, host.id)} == {"failed"}


def test_failure_reason_is_redacted_and_bounded(db, authed_client, host, transport):
    transport.update_result = {
        "status": "failed",
        "exit_code": 1,
        "stdout": "",
        "stderr": "auth failed password=hunter2-secret " + "x" * 5000,
    }
    assert _update(authed_client, host.id).status_code == 200

    reason = _context(_events(db)[0])["reason"]
    assert "hunter2-secret" not in reason
    assert len(reason) <= 512


def test_transport_failure_is_recorded_and_still_refused(
    db, authed_client, host, transport
):
    transport.raise_on_update = SSHConnectionError("host key mismatch for pra437")
    res = _update(authed_client, host.id)
    assert res.status_code == 400

    row = _events(db)[0]
    assert row.outcome == "failure"
    assert row.actor_username is not None
    assert row.target_system_id == host.id
    ctx = _context(row)
    assert ctx["result"] == "failed"
    # Nothing was measured, so no count is reported as zero.
    assert ctx["packages_updated"] is None
    assert ctx["packages_failed"] is None
    assert ctx["packages_skipped"] is None


def test_unexpected_error_is_recorded_without_the_exception_text(
    db, authed_client, host, transport
):
    transport.raise_on_update = RuntimeError("token=abc123-secret blew up")
    res = _update(authed_client, host.id)
    assert res.status_code == 500

    row = _events(db)[0]
    assert row.outcome == "failure"
    assert "abc123-secret" not in row.context_json


def test_partial_update_is_not_reported_as_success(db, authed_client, host, transport):
    transport.advance = {"openssl"}  # curl stays at the old version
    res = _update(authed_client, host.id)
    assert res.status_code == 200, res.text

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "partial"
    assert ctx["packages_updated"] == 1
    assert ctx["packages_failed"] == 1
    assert {h.status for h in _history(db, host.id)} == {"completed", "failed"}


def test_exit_zero_without_a_version_change_is_a_failure(
    db, authed_client, host, transport
):
    transport.advance = set()
    assert _update(authed_client, host.id).status_code == 200

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "failed"
    assert ctx["packages_updated"] == 0
    assert ctx["packages_failed"] == 2


def test_all_requested_packages_held_is_a_recorded_no_change(
    db, authed_client, host, transport
):
    db.query(Package).filter(
        Package.system_id == host.id, Package.name == "openssl"
    ).update({"is_held": True})
    db.commit()

    res = _update(authed_client, host.id, ["openssl"])
    assert res.status_code == 200, res.text
    assert transport.commands == []  # nothing was sent to the host

    row = _events(db)[0]
    assert row.outcome == "success"
    ctx = _context(row)
    assert ctx["result"] == "no_change"
    assert ctx["packages_updated"] == 0
    assert ctx["packages_skipped"] == 1


def test_nothing_pending_is_a_recorded_no_change(
    db, authed_client, group, cred, seed_distro, transport
):
    idle = _host(
        db, seed_distro, group, cred, "pra437-idle.example.com", "10.0.43.9", {}
    )
    _untracked(db, idle, "base-files")  # a real host always lists something
    assert _update(authed_client, idle.id).status_code == 200

    row = _events(db, idle.id)[0]
    assert row.outcome == "success"
    assert _context(row)["result"] == "no_change"


# ----------------------------------------- changes the history cannot account for


def test_named_untracked_package_that_moved_is_not_a_no_change(
    db, authed_client, host, transport
):
    _untracked(db, host, "zlib1g")
    transport.untracked_moves = {"zlib1g"}
    res = _update(authed_client, host.id, ["zlib1g"])
    assert res.status_code == 200, res.text
    assert res.json()["packages_unrecorded"] == 1

    row = _events(db)[0]
    assert row.outcome == "success"
    ctx = _context(row)
    assert ctx["result"] == "updated"
    assert ctx["packages_updated"] == 0
    assert ctx["packages_unrecorded"] == 1
    assert _history(db, host.id) == []


def test_mixed_tracked_and_untracked_packages_are_both_counted(
    db, authed_client, host, transport
):
    _untracked(db, host, "zlib1g")
    transport.untracked_moves = {"zlib1g"}
    res = _update(authed_client, host.id, ["openssl", "zlib1g"])
    assert res.status_code == 200, res.text

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "updated"
    assert ctx["packages_updated"] == 1
    assert ctx["packages_unrecorded"] == 1
    assert [h.status for h in _history(db, host.id)] == ["completed"]


def test_mixed_with_a_tracked_failure_is_partial(db, authed_client, host, transport):
    _untracked(db, host, "zlib1g")
    transport.untracked_moves = {"zlib1g"}
    transport.advance = set()  # the tracked package stays put
    assert _update(authed_client, host.id, ["openssl", "zlib1g"]).status_code == 200

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "partial"
    assert ctx["packages_updated"] == 0
    assert ctx["packages_failed"] == 1
    assert ctx["packages_unrecorded"] == 1


def test_upgrade_all_without_pending_rows_that_moved_a_package(
    db, authed_client, group, cred, seed_distro, transport
):
    idle = _host(
        db, seed_distro, group, cred, "pra437-all.example.com", "10.0.43.8", {}
    )
    _untracked(db, idle, "libc6")
    transport.untracked_moves = {"libc6"}
    assert _update(authed_client, idle.id).status_code == 200

    assert len(transport.commands) == 1 and "upgrade -y" in transport.commands[0]
    row = _events(db, idle.id)[0]
    assert row.outcome == "success"
    ctx = _context(row)
    assert ctx["result"] == "updated"
    assert ctx["packages_unrecorded"] == 1


def test_true_no_op_with_an_untracked_name_stays_no_change(
    db, authed_client, host, transport
):
    _untracked(db, host, "zlib1g")  # the command runs, nothing moves
    assert _update(authed_client, host.id, ["zlib1g"]).status_code == 200
    assert len(transport.commands) == 1

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "no_change"
    assert ctx["packages_unrecorded"] == 0


def test_inventory_first_seen_in_the_rescan_is_not_a_change(
    db, authed_client, host, transport
):
    _untracked(db, host, "zlib1g")
    transport.discovered = {"newly-listed-a", "newly-listed-b"}
    assert _update(authed_client, host.id, ["zlib1g"]).status_code == 200

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "no_change"
    assert ctx["packages_unrecorded"] == 0


def test_stale_inventory_does_not_credit_this_request(
    db, authed_client, host, transport
):
    """The host moved zlib1g after the last scan; this request changed nothing."""
    _untracked(db, host, "zlib1g")
    transport.host_versions = {"zlib1g": "9.9"}  # inventory still says 1.0
    res = _update(authed_client, host.id, ["zlib1g"])
    assert res.status_code == 200, res.text
    assert len(transport.commands) == 1

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "no_change"
    assert ctx["packages_unrecorded"] == 0


def test_stale_inventory_does_not_credit_an_unrelated_package(
    db, authed_client, host, transport
):
    """A named update must not take credit for a package it did not name."""
    _untracked(db, host, "zlib1g")
    transport.host_versions = {"zlib1g": "9.9"}
    transport.advance = {"openssl"}
    assert _update(authed_client, host.id, ["openssl"]).status_code == 200

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "updated"
    assert ctx["packages_updated"] == 1
    assert ctx["packages_unrecorded"] == 0


def test_stale_tracked_package_already_current_is_not_counted(
    db, authed_client, host, transport
):
    """The pending row is stale: the host already holds the offered version."""
    transport.host_versions = {"openssl": "1.1", "curl": "2.1"}
    assert _update(authed_client, host.id).status_code == 200

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "no_change"
    assert ctx["packages_updated"] == 0
    assert ctx["packages_failed"] == 0


def test_package_missing_from_the_inventory_that_upgrades_is_an_update(
    db, authed_client, host, transport
):
    """Absent from the stored baseline, present and upgraded on the host."""
    transport.host_versions = {"libssl3": "1.0"}  # the inventory has no such row
    transport.untracked_moves = {"libssl3"}
    res = _update(authed_client, host.id, ["libssl3"])
    assert res.status_code == 200, res.text
    assert res.json()["packages_unrecorded"] == 1

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "updated"
    assert ctx["packages_unrecorded"] == 1


def test_package_missing_from_the_inventory_that_does_not_move_is_no_change(
    db, authed_client, host, transport
):
    transport.host_versions = {"libssl3": "1.0"}
    assert _update(authed_client, host.id, ["libssl3"]).status_code == 200

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "no_change"
    assert ctx["packages_unrecorded"] == 0


def test_missing_baseline_reading_is_unverified_not_success(
    db, authed_client, host, transport
):
    _untracked(db, host, "zlib1g")
    transport.untracked_moves = {"zlib1g"}
    transport.listing_fails_before = True
    res = _update(authed_client, host.id, ["zlib1g"])
    assert res.status_code == 200, res.text
    assert res.json()["verification"] == "unavailable"
    assert res.json()["packages_unrecorded"] is None

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "unverified"
    assert ctx["packages_updated"] is None
    assert ctx["packages_unrecorded"] is None


def test_missing_baseline_does_not_assert_a_tracked_count(
    db, authed_client, host, transport
):
    transport.listing_fails_before = True
    res = _update(authed_client, host.id)
    assert res.status_code == 200
    assert res.json()["packages_updated"] == 0

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "unverified"
    assert ctx["packages_updated"] is None


def test_failed_rescan_with_pending_history_rows_is_unverified(
    db, authed_client, host, transport
):
    """The host did update, but nothing after the command could be read."""
    transport.rescan_status = "error"
    res = _update(authed_client, host.id)
    assert res.status_code == 200, res.text
    assert res.json()["verification"] == "unavailable"

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "unverified"
    assert ctx["packages_updated"] is None
    assert ctx["packages_failed"] is None
    assert ctx["packages_unrecorded"] is None
    # The history rows are not left pending or running, and say why.
    rows = _history(db, host.id)
    assert {h.status for h in rows} == {"failed"}
    assert all("could not be verified" in (h.error_message or "") for h in rows)


def test_failed_rescan_after_an_untracked_move_is_unverified(
    db, authed_client, host, transport
):
    _untracked(db, host, "zlib1g")
    transport.untracked_moves = {"zlib1g"}
    transport.rescan_status = "error"
    assert _update(authed_client, host.id, ["zlib1g"]).status_code == 200

    ctx = _context(_events(db)[0])
    assert ctx["result"] == "unverified"
    assert ctx["packages_unrecorded"] is None


_WIRE_FAILURE = {
    "status": "warning",
    "exit_code": 100,
    "outcome": "command_failed",
    "stdout": "",
    "stderr": "E: Unable to locate package curl",
}


def test_missing_baseline_with_target_already_present_counts_no_move(
    db, authed_client, host, transport
):
    """Without a reading before, the observed target stays in history but the
    API integer counts only attributable moves; the audit stays unverified."""
    transport.listing_fails_before = True
    transport.host_versions = {"openssl": "1.1", "curl": "2.1"}
    res = _update(authed_client, host.id)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["packages_updated"] == 0
    assert body["verification"] == "unavailable"
    assert {h.status for h in _history(db, host.id)} == {"completed"}

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "unverified"
    assert ctx["packages_updated"] is None
    assert ctx["packages_unrecorded"] is None


def test_wire_shaped_nonzero_update_is_a_failure(db, authed_client, host, transport):
    transport.update_result = dict(_WIRE_FAILURE)
    res = _update(authed_client, host.id)
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "error"

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "failed"
    assert ctx["packages_updated"] is None
    assert "Unable to locate package" in ctx["reason"]
    assert {h.status for h in _history(db, host.id)} == {"failed"}


def test_wire_shaped_nonzero_named_update_without_history_is_a_failure(
    db, authed_client, host, transport
):
    _untracked(db, host, "zlib1g")
    transport.update_result = dict(_WIRE_FAILURE)
    res = _update(authed_client, host.id, ["zlib1g"])
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "error"

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "failed"
    assert ctx["result"] not in ("no_change", "updated")
    assert _history(db, host.id) == []


def test_wire_shaped_nonzero_bulk_update_is_a_failure_per_host(
    db, authed_client, host, host_b, transport, fleet_ops
):
    transport.update_result = dict(_WIRE_FAILURE)
    res = authed_client.post(
        "/packages/bulk/update", json={"system_ids": [host.id, host_b.id]}
    )
    assert res.status_code == 200, res.text
    rows = _events(db)
    assert len(rows) == 2
    assert {r.outcome for r in rows} == {"failure"}
    assert {_context(r)["result"] for r in rows} == {"failed"}


def test_wire_shaped_nonzero_bulk_named_update_without_history_is_a_failure(
    db, authed_client, host, host_b, transport, fleet_ops
):
    _untracked(db, host, "zlib1g")
    _untracked(db, host_b, "zlib1g")
    transport.update_result = dict(_WIRE_FAILURE)
    res = authed_client.post(
        "/packages/bulk/update",
        json={"system_ids": [host.id, host_b.id], "package_names": ["zlib1g"]},
    )
    assert res.status_code == 200, res.text
    rows = _events(db)
    assert len(rows) == 2
    assert {r.outcome for r in rows} == {"failure"}
    assert {_context(r)["result"] for r in rows} == {"failed"}


@pytest.mark.parametrize("side", ["before", "after"])
def test_nonzero_listing_with_parseable_stdout_is_unavailable_evidence(
    db, authed_client, host, transport, side
):
    _untracked(db, host, "zlib1g")
    transport.untracked_moves = {"zlib1g"}
    setattr(transport, f"listing_nonzero_{side}", True)
    res = _update(authed_client, host.id, ["zlib1g"])
    assert res.status_code == 200, res.text
    assert res.json()["verification"] == "unavailable"

    row = _events(db)[0]
    assert row.outcome == "failure"
    ctx = _context(row)
    assert ctx["result"] == "unverified"
    assert ctx["packages_unrecorded"] is None


# --------------------------------------------------- refusals and duplicates


def test_role_refusal_is_persisted_and_unchanged(
    db, client, auditor_user, host, transport
):
    # In fleet scope, so the refusal is the global role gate rather than scope.
    _grant(db, auditor_user, host)
    assert user_can_access_system(db, auditor_user, host.id)
    _login(client, auditor_user)
    res = _update(client, host.id)
    assert res.status_code == 403
    assert res.json() == {"detail": "Requires one of: admin, maintainer"}
    assert transport.commands == []
    assert _events(db) == []
    assert _history(db, host.id) == []

    [row] = _denials(db)
    assert row.outcome == "denied"
    assert row.actor_user_id == auditor_user.id
    assert row.actor_username == auditor_user.username
    assert row.target_system_id == host.id
    ctx = _context(row)
    assert ctx["reason_code"] == "role_not_permitted"
    assert "hostname" not in ctx


def test_out_of_scope_refusal_is_persisted_and_indistinguishable(
    db, client, maintainer_user, host, transport
):
    assert not user_can_access_system(db, maintainer_user, host.id)
    _login(client, maintainer_user)
    existing = _update(client, host.id)
    unknown = _update(client, 987654)
    assert existing.status_code == unknown.status_code == 404
    assert existing.json() == unknown.json() == {"detail": "System not found"}
    assert transport.commands == []
    assert _events(db) == []
    assert _history(db, host.id) == []

    real, missing = _denials(db)
    assert real.actor_user_id == maintainer_user.id
    assert real.target_system_id == host.id
    assert missing.target_system_id is None
    assert missing.target_id == "987654"
    for row in (real, missing):
        assert row.outcome == "denied"
        assert _context(row)["reason_code"] == "system_not_in_scope"
        assert set(_context(row)) == {"reason_code", "reason"}


def test_denied_events_are_read_by_auditors_not_by_the_denied_caller(
    db, client, admin_user, maintainer_user, host, transport
):
    _login(client, maintainer_user)
    assert _update(client, host.id).status_code == 404

    # The denied caller cannot read the audit stream, so the refusal reveals
    # nothing about the host through it.
    assert client.get("/audit/events").status_code == 403
    _login(client, admin_user)

    res = client.get(
        "/audit/events",
        params={"system_id": host.id, "action": "package.update", "outcome": "denied"},
    )
    assert res.status_code == 200, res.text
    [event] = res.json()["events"]
    assert event["outcome"] == "denied"
    assert event["actor"]["username"] == maintainer_user.username
    assert event["target"]["system_id"] == host.id


def test_unauthenticated_request_persists_nothing(db, client, host, transport):
    res = _update(client, host.id)
    assert res.status_code == 401
    assert _denials(db) == []
    assert _events(db) == []


def test_unknown_system_for_an_admin_persists_no_executed_event(
    db, authed_client, transport
):
    res = _update(authed_client, 987654)
    assert res.status_code == 404
    assert _events(db) == []
    assert transport.commands == []


def test_concurrent_request_does_not_duplicate_the_event(
    db, authed_client, host, transport
):
    """A request that loses the per-host single-flight did no work and owns no
    event; the in-flight request records the one outcome."""
    lock = package_service_module._host_worklock(host.id)
    held = threading.Event()
    release = threading.Event()

    def _hold():
        with lock:
            held.set()
            release.wait(5)

    t = threading.Thread(target=_hold)
    t.start()
    assert held.wait(5)
    try:
        res = _update(authed_client, host.id)
    finally:
        release.set()
        t.join()
    assert res.status_code == 200
    assert res.json()["status"] == "already_running"
    assert _events(db) == []
    assert transport.commands == []


def test_service_callers_do_not_emit_on_their_own(db, host, transport):
    """The route owns the event. Scheduled jobs and plan execution reach the
    service directly with their own ledgers and must never double-record."""
    result = PackageService(db).apply_updates(host.id, user_id=None)
    assert result["status"] == "success"
    assert _events(db) == []


def test_each_request_records_exactly_one_event(db, authed_client, host, transport):
    assert _update(authed_client, host.id, ["openssl"]).status_code == 200
    assert _update(authed_client, host.id, ["curl"]).status_code == 200
    rows = _events(db, host.id)
    assert len(rows) == 2
    assert len({r.event_uuid for r in rows}) == 2


def test_audit_failure_does_not_undo_or_misreport_the_update(
    db, authed_client, host, transport, monkeypatch
):
    def _boom(*_a, **_kw):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(audit_event_service, "emit", _boom)
    res = _update(authed_client, host.id)
    assert res.status_code == 200, res.text
    assert res.json()["packages_updated"] == 2
    assert {h.status for h in _history(db, host.id)} == {"completed"}
    assert _events(db) == []


# ----------------------------------------------------------------- bulk route


def test_bulk_update_records_one_event_per_host_with_its_own_outcome(
    db, authed_client, admin_user, host, host_b, transport, fleet_ops
):
    # The package manager exits zero on both hosts, but host_b's rescan finds no
    # version moved, so only host succeeds.
    transport.advance_by_system[host_b.id] = set()
    res = authed_client.post(
        "/packages/bulk/update", json={"system_ids": [host.id, host_b.id]}
    )
    assert res.status_code == 200, res.text

    ok = _events(db, host.id)
    bad = _events(db, host_b.id)
    assert len(ok) == 1 and len(bad) == 1
    assert ok[0].outcome == "success"
    assert bad[0].outcome == "failure"
    assert ok[0].actor_user_id == bad[0].actor_user_id == admin_user.id
    assert _context(ok[0])["hostname"] == host.hostname
    assert _context(bad[0])["hostname"] == host_b.hostname
    assert len(_events(db)) == 2


def test_bulk_out_of_scope_is_persisted_once_with_every_denied_host(
    db, client, admin_user, maintainer_user, host, host_b, transport, fleet_ops
):
    _grant(db, maintainer_user, host)  # host_b stays out of scope
    _login(client, maintainer_user)
    res = client.post(
        "/packages/bulk/update", json={"system_ids": [host.id, host_b.id]}
    )
    assert res.status_code == 404
    assert res.json() == {"detail": "System not found"}
    assert transport.commands == []
    assert _events(db) == []

    [row] = _denials(db)
    ctx = _context(row)
    assert ctx["reason_code"] == "system_not_in_scope"
    assert ctx["system_ids"] == [host_b.id]
    assert row.actor_user_id == maintainer_user.id
    assert row.target_system_id is None

    _login(client, admin_user)
    found = client.get(
        "/audit/events", params={"system_id": host_b.id, "outcome": "denied"}
    ).json()
    assert found["total"] == 1
    assert (
        client.get(
            "/audit/events", params={"system_id": host.id, "outcome": "denied"}
        ).json()["total"]
        == 0
    )


def test_bulk_role_refusal_is_persisted_and_unchanged(
    db, client, auditor_user, host, transport, fleet_ops
):
    _login(client, auditor_user)
    res = client.post("/packages/bulk/update", json={"system_ids": [host.id]})
    assert res.status_code == 403
    assert res.json() == {"detail": "Requires one of: admin, maintainer"}
    assert transport.commands == []
    [row] = _denials(db)
    assert _context(row)["reason_code"] == "role_not_permitted"
    assert row.actor_user_id == auditor_user.id


def test_bulk_unexpected_error_reason_is_a_bounded_safe_string(
    db, authed_client, host, host_b, transport, fleet_ops
):
    marker = "opaque-marker-QX7ZP"
    transport.raise_on_update = RuntimeError(f"connection detail {marker}")
    res = authed_client.post(
        "/packages/bulk/update", json={"system_ids": [host.id, host_b.id]}
    )
    assert res.status_code == 200, res.text
    assert marker not in res.text

    rows = _events(db)
    assert len(rows) == 2
    for row in rows:
        assert row.outcome == "failure"
        assert marker not in row.context_json
        ctx = _context(row)
        assert ctx["reason"] == "Update failed: RuntimeError"
        assert ctx["packages_updated"] is None
        assert ctx["packages_failed"] is None


def test_bulk_nonzero_exit_reports_measured_failed_counts(
    db, authed_client, host, host_b, transport, fleet_ops
):
    transport.update_result = {
        "status": "failed",
        "exit_code": 100,
        "stdout": "",
        "stderr": "E: broken",
    }
    res = authed_client.post(
        "/packages/bulk/update", json={"system_ids": [host.id, host_b.id]}
    )
    assert res.status_code == 200, res.text
    by_host = {r.target_system_id: _context(r) for r in _events(db)}
    assert by_host[host.id]["packages_failed"] == 2
    assert by_host[host_b.id]["packages_failed"] == 1
    assert by_host[host.id]["packages_updated"] is None


def test_audit_schema_lists_the_action(authed_client):
    res = authed_client.get("/audit/schema")
    assert res.status_code == 200, res.text
    assert "package.update" in res.json()["actions"]
