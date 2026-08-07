"""PRA-313: per-host transport circuit breaker (failing-host isolation).

Proves one bad/half-open SSH host cannot make unrelated work wait on that host's
SSH timeout:

- repeated banner/connect failures enter a bounded per-host cooldown;
- a cooling-down host fast-fails WITHOUT opening a new SSH socket (SSH path and
  the SFTP/file-transfer path share the one breaker);
- an explicit force/bypass retries and clears the cooldown on success;
- auth failures (host reachable, fast) do NOT trip the breaker;
- ``check-all`` skips cooling-down hosts by default and retries them under force;
- the privilege-reconcile drain stays bounded (skips cooling-down hosts, caps the
  number processed) and never marks skipped cleanup complete (fail-closed).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.db.access_models import HostUserState
from app.db.models import Credential, Group, System, SystemMetadata
from app.services import fleet_reconciliation_service as frs
from app.services import ssh_service
from app.services.ssh_service import (
    HostCoolingDownError,
    SSHService,
    is_host_cooling_down,
    raise_if_cooling_down,
    record_transport_failure,
    record_transport_reachable,
    record_transport_success,
)

# --------------------------------------------------------------------- fixtures


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra313-grp").first()
    if not g:
        g = Group(name="pra313-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra313-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname, *, status="Active"):
    s = System(
        hostname=hostname,
        ip_address="10.113.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status=status,
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _with_metadata(db, system) -> SystemMetadata:
    md = SystemMetadata(system_id=system.id)
    db.add(md)
    system.system_metadata = md
    db.flush()
    return md


def _cool_down(db, system, *, seconds=60) -> SystemMetadata:
    md = system.system_metadata or _with_metadata(db, system)
    md.transport_cooldown_until = datetime.utcnow() + timedelta(seconds=seconds)
    md.transport_failures = 3
    md.last_transport_error = "Error reading SSH protocol banner"
    db.flush()
    return md


# ------------------------------------------------------------- breaker mechanics


def test_repeated_failures_enter_cooldown_then_success_clears(
    db, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "pra313-breaker")

    # Threshold defaults to 3. First two failures do not open a cooldown.
    record_transport_failure(db, system, "banner timeout")
    record_transport_failure(db, system, "banner timeout")
    assert system.system_metadata.transport_failures == 2
    assert is_host_cooling_down(db, system) is None

    # Third consecutive failure opens the cooldown.
    record_transport_failure(db, system, "connection refused")
    remaining = is_host_cooling_down(db, system)
    assert remaining is not None and remaining > 0
    assert system.system_metadata.last_transport_error == "connection refused"

    # A success fully clears the breaker.
    record_transport_success(db, system)
    assert is_host_cooling_down(db, system) is None
    assert system.system_metadata.transport_failures == 0
    assert system.system_metadata.transport_cooldown_until is None
    assert system.system_metadata.last_transport_error is None


def test_expired_cooldown_reads_as_not_cooling(db, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "pra313-expired")
    md = _with_metadata(db, system)
    md.transport_cooldown_until = datetime.utcnow() - timedelta(seconds=1)
    db.flush()
    assert is_host_cooling_down(db, system) is None


def test_raise_if_cooling_down_respects_bypass(db, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "pra313-raise")
    _cool_down(db, system)

    with pytest.raises(HostCoolingDownError):
        raise_if_cooling_down(db, system)

    # Explicit operator recheck bypasses the gate.
    raise_if_cooling_down(db, system, bypass=True)


def test_auth_failure_does_not_trip_breaker(db, seed_distro, group, cred):
    """record_transport_reachable (used on auth failure / host-key mismatch) resets
    the counter — a reachable, fast-failing host must never enter the slowness
    breaker."""
    system = _system(db, seed_distro, group, cred, "pra313-auth")
    record_transport_failure(db, system, "banner timeout")
    record_transport_failure(db, system, "banner timeout")
    record_transport_reachable(db, system)  # auth failed but host answered
    assert system.system_metadata.transport_failures == 0
    assert is_host_cooling_down(db, system) is None


# ------------------------------------------------ SSH connection path fast-fail


def test_get_connection_fast_fails_without_opening_socket(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra313-getconn")
    _cool_down(db, system)

    created = MagicMock(name="_create_connection")
    monkeypatch.setattr(SSHService, "_create_connection", created)

    svc = SSHService(db)
    with pytest.raises(HostCoolingDownError):
        svc.get_connection(system.id)
    # The whole point: no new SSH socket was opened.
    created.assert_not_called()


def test_get_connection_bypass_attempts_and_success_clears_cooldown(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra313-bypass")
    _cool_down(db, system)

    def _fake_create(self, sys_obj, force_password_auth=False):
        # Simulate what _on_connected does on a real successful connect.
        record_transport_success(self.db, sys_obj)
        return MagicMock(name="client")

    monkeypatch.setattr(SSHService, "_create_connection", _fake_create)

    svc = SSHService(db)
    client, is_new = svc.get_connection(system.id, bypass_cooldown=True)
    assert client is not None and is_new is True
    # Force retry cleared the cooldown on success.
    assert is_host_cooling_down(db, system) is None
    assert system.system_metadata.transport_failures == 0


# ----------------------------------------------- file-transfer path fast-fail


def test_file_transfer_listdir_fast_fails_during_cooldown(
    db, seed_distro, group, cred, monkeypatch
):
    from app.services import file_transfer_service as fts

    system = _system(db, seed_distro, group, cred, "pra313-sftp")
    _cool_down(db, system)

    user = MagicMock(id=1, username="alice")
    monkeypatch.setattr(fts, "_gate", lambda db_, u, sid: (system, "ops"))
    # If the breaker works, we fast-fail BEFORE minting a cert / hitting Vault.
    mint = MagicMock(name="_mint_cert_for")
    monkeypatch.setattr(fts, "_mint_cert_for", mint)

    with pytest.raises(fts.FileTransferError) as ei:
        fts.listdir(db, user, system.id, "/tmp")
    assert "host_cooling_down" in str(ei.value)
    mint.assert_not_called()


# ------------------------------------------------------- check-all boundedness


def test_check_all_skips_cooling_down_by_default_force_retries(
    db, seed_distro, group, cred, monkeypatch
):
    from app.services.health_service import HealthService

    healthy = _system(db, seed_distro, group, cred, "pra313-ok")
    _with_metadata(db, healthy)
    cooling = _system(db, seed_distro, group, cred, "pra313-cool")
    _cool_down(db, cooling)
    db.flush()

    svc = HealthService(db)
    calls = []

    def _fake_check(system_id, *, bypass_cooldown=False):
        calls.append((system_id, bypass_cooldown))
        return {"system_id": system_id, "status": "success"}

    monkeypatch.setattr(svc, "check_system", _fake_check)

    # Default: cooling-down host is skipped, not hammered.
    res = svc.check_all_systems()
    checked = {sid for sid, _ in calls}
    assert healthy.id in checked
    assert cooling.id not in checked
    assert res["skipped_cooldown"] == 1

    # Force: every host retried, bypassing the breaker.
    calls.clear()
    res_forced = svc.check_all_systems(force=True)
    forced = {sid: bypass for sid, bypass in calls}
    assert cooling.id in forced and forced[cooling.id] is True
    assert healthy.id in forced


# ------------------------------------------ privilege-reconcile drain bounded


def _pending_account(db, system, login="ops"):
    row = HostUserState(
        system_id=system.id,
        login=login,
        mode="per_user",
        state="provisioned",
        privilege_reconcile_pending=True,
    )
    db.add(row)
    db.flush()
    return row


def test_privilege_reconcile_skips_cooldown_and_caps_processed(
    db, seed_distro, group, cred, monkeypatch
):
    # Four hosts flagged pending; one is cooling down.
    systems = [
        _system(db, seed_distro, group, cred, f"pra313-priv-{i}") for i in range(4)
    ]
    for s in systems:
        _with_metadata(db, s)
        _pending_account(db, s)
    _cool_down(db, systems[0])
    db.flush()

    processed = []
    monkeypatch.setattr(
        frs,
        "reconcile_system",
        lambda db_, sid: (
            processed.append(sid)
            or {"provisioned": 0, "removed": 0, "errors": 0, "skipped": 0}
        ),
    )

    # Three eligible hosts, capped at 2 per call.
    totals = frs.reconcile_pending_privilege(db, limit=2)

    assert systems[0].id not in processed  # cooling-down host never touched
    assert totals["skipped_cooldown"] == 1
    assert totals["hosts"] == 2
    assert len(processed) == 2
    assert totals["truncated"] == 1
    # Fail-closed: skipped/untouched hosts stay flagged pending — cleanup is never
    # marked complete for a host we did not actually reconcile.
    assert totals["still_pending"] == 4


def test_privilege_reconcile_bounded_all_hosts_timing_out(
    db, seed_distro, group, cred, monkeypatch
):
    """With every pending host cooling down, the drain does no host work at all
    (bounded) and leaves them visibly pending."""
    systems = [
        _system(db, seed_distro, group, cred, f"pra313-down-{i}") for i in range(3)
    ]
    for s in systems:
        _with_metadata(db, s)
        _pending_account(db, s)
        _cool_down(db, s)
    db.flush()

    called = MagicMock()
    monkeypatch.setattr(frs, "reconcile_system", called)

    totals = frs.reconcile_pending_privilege(db)
    called.assert_not_called()
    assert totals["hosts"] == 0
    assert totals["skipped_cooldown"] == 3
    assert totals["still_pending"] == 3
