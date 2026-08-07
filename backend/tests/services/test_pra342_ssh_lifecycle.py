"""PRA-342: SSH client/session lifecycle — no orphaned Paramiko clients.

Before: a failed connect/auth (and every ephemeral reconcile/provisioning
SSHService) left a live Paramiko client/transport, which showed up as long-lived
`sshd: praxis@notty` sessions accumulating on managed hosts under repeated
background failures.

After: failed connects discard the client deterministically, and ephemeral
SSHService instances close their pool (context manager + close_all_connections in
the provisioning finally).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import paramiko
import pytest

from app.db.access_models import FleetRole
from app.db.models import Credential, Group, System, SystemMetadata
from app.services import host_user_provisioning_service as hups
from app.services import ssh_service
from app.services.ssh_service import SSHConnectionError, SSHService


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra342-grp").first()
    if not g:
        g = Group(name="pra342-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = Credential(
        name="pra342-cred",
        auth_method="password",
        username="root",
        vault_path="v/pra342",
    )
    db.add(c)
    db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.34.2.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    md = SystemMetadata(system_id=s.id)
    db.add(md)
    s.system_metadata = md
    db.flush()
    return s


def _isolate(monkeypatch, fake_client):
    """Reach client.connect() without real crypto/DB side effects."""
    monkeypatch.setattr(ssh_service.paramiko, "SSHClient", lambda: fake_client)
    monkeypatch.setattr(ssh_service, "configure_host_key_policy", lambda *a, **k: None)
    monkeypatch.setattr(
        ssh_service.VaultService,
        "read_secret",
        lambda self, p: {"password": "pw", "username": "root"},
    )
    monkeypatch.setattr(SSHService, "_log_security_event", lambda *a, **k: None)
    monkeypatch.setattr(ssh_service, "record_transport_reachable", lambda *a, **k: None)
    monkeypatch.setattr(ssh_service, "record_transport_failure", lambda *a, **k: None)


def test_create_connection_closes_client_on_auth_failure(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra342-auth")
    fake = MagicMock()
    fake.connect.side_effect = paramiko.AuthenticationException("bad creds")
    _isolate(monkeypatch, fake)

    svc = SSHService(db)
    with pytest.raises(SSHConnectionError):
        svc._create_connection(system)

    fake.close.assert_called()  # PRA-342: no orphan client on failed auth


def test_create_connection_closes_client_on_ssh_error(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra342-sshx")
    fake = MagicMock()
    fake.connect.side_effect = paramiko.SSHException("banner exchange failed")
    _isolate(monkeypatch, fake)

    svc = SSHService(db)
    with pytest.raises(SSHConnectionError):
        svc._create_connection(system)

    fake.close.assert_called()


def test_context_manager_closes_pool_on_exit(db, monkeypatch):
    svc = SSHService(db)
    closed = {"n": 0}
    monkeypatch.setattr(
        svc,
        "close_all_connections",
        lambda scope_system_ids=None: closed.__setitem__("n", closed["n"] + 1),
    )
    with svc as s:
        assert s is svc
    assert closed["n"] == 1


def test_ensure_user_closes_ephemeral_pool_on_command_failure(
    db, seed_distro, group, cred, monkeypatch
):
    """A failed (privileged) provisioning command must still close the ephemeral
    SSHService pool — otherwise the ownership-refusal path orphans an sshd
    session every drain tick (the core PRA-342 leak)."""
    system = _system(db, seed_distro, group, cred, "pra342-own")
    role = FleetRole(
        name="pra342-role",
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()

    closed = {"n": 0}

    class _FakeSSH:
        def __init__(self, _db):
            pass

        def execute_privileged_command(self, sid, cmd, timeout=None):
            return {
                "exit_code": 3,
                "stderr": (
                    "PRAXIS_OWNERSHIP_ERROR: account cfreeman exists but is not "
                    "Praxis-managed (no valid ownership marker); refusing to modify"
                ),
                "stdout": "",
            }

        def close_all_connections(self, scope_system_ids=None):
            closed["n"] += 1
            return 0

    monkeypatch.setattr(hups, "SSHService", _FakeSSH)

    state = hups.ensure_user(db, system, "cfreeman", role)

    assert state.state == "error"
    assert "PRAXIS_OWNERSHIP_ERROR" in (state.last_error or "")
    assert closed["n"] == 1  # PRA-342: ephemeral pool closed even on failure
