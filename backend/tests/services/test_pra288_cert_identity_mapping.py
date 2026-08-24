"""PRA-288: role-account SSH certificate identity mapping.

The certificate PRINCIPAL for managed user access is the immutable Praxis user
principal (``praxis-user-<id>``); the SSH connection USERNAME stays the target
Linux login. Both the session and file-transfer paths use the same mapping, and
the host principals file lists the immutable principals of the users currently
authorized to land as that login. This proves:

  * the mapping is bound to the immutable user id, so a username rename cannot
    break cert auth and a recreated username cannot inherit stale authority;
  * ``_principals_for`` emits immutable principals (one per active user) for both
    per-user and shared role-account logins, and drops them on revocation;
  * session + file-transfer sign with the immutable principal while connecting as
    the Linux login;
  * the mapping composes with the PRA-287 shared-login model.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import paramiko
import pytest

from app.db.access_models import AccessGrant, FleetRole, HostUserState
from app.db.models import Credential, Group, System, User
from app.services import access_authorization_service as authz
from app.services import file_transfer_service as fts
from app.services import host_user_provisioning_service as prov
from app.services import session_service as ss
from app.services.access_authorization_service import cert_principal_for_user

# --------------------------------------------------------------------- helpers


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra288-grp").first()
    if not g:
        g = Group(name="pra288-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra288-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.88.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _user(db, username):
    from app.core.auth import get_password_hash

    u = User(
        username=username,
        email=f"{username}@praxis.example.com",
        hashed_password=get_password_hash("x"),
        is_active=True,
    )
    db.add(u)
    db.flush()
    return u


def _role(db, name, *, login_mode="role_account", role_account_name="svc"):
    r = FleetRole(
        name=name,
        login_mode=login_mode,
        role_account_name=role_account_name,
        allowed_actions_json=json.dumps(["session_open", "command_exec"]),
        os_groups_json="[]",
    )
    db.add(r)
    db.flush()
    return r


def _grant(db, user, system, role, login):
    g = AccessGrant(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=role.id,
        login=login,
    )
    db.add(g)
    db.flush()
    return g


class _SpyClient:
    """paramiko.SSHClient stand-in that records the connect username."""

    def __init__(self, connect_raises=None):
        self.policy = None
        self.connect_username = None
        self.connect_raises = connect_raises
        self._host_keys = MagicMock()

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def get_host_keys(self):
        return self._host_keys

    def connect(self, **kw):
        self.connect_username = kw.get("username")
        if self.connect_raises:
            raise self.connect_raises

    def open_sftp(self):
        return MagicMock()

    def get_transport(self):
        return MagicMock(is_active=lambda: True)

    def close(self):
        pass


# ------------------------------------------------------- cert principal helper


def test_cert_principal_is_stable_namespaced_and_id_based(db):
    u = _user(db, "pra288-alice")
    p = cert_principal_for_user(u)
    assert p == f"praxis-user-{u.id}"
    # Stable, id-based, and does NOT embed the mutable username.
    assert cert_principal_for_user(u.id) == p
    assert "pra288-alice" not in p
    # Passes the host-side principal validation (no expansion of the charset).
    prov._validate_principal(p)


def test_rename_does_not_change_cert_principal(db):
    u = _user(db, "pra288-before")
    before = cert_principal_for_user(u)
    u.username = "pra288-after"
    db.flush()
    assert cert_principal_for_user(u) == before  # bound to id, not username


def test_username_reuse_new_id_yields_different_principal(db):
    u1 = _user(db, "pra288-reuse")
    p1 = cert_principal_for_user(u1)
    db.delete(u1)
    db.flush()
    u2 = _user(db, "pra288-reuse")  # same username, new row/id
    assert u2.id != u1.id
    assert cert_principal_for_user(u2) != p1  # cannot inherit stale authority


# ----------------------------------------------------------- host principals


def test_principals_for_per_user_emits_immutable_principal(
    db, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p288-peruser")
    u = _user(db, "pra288-solo")
    role = _role(db, "p288-pu", login_mode="per_user", role_account_name=None)
    _grant(db, u, s, role, u.username)

    principals = prov._principals_for(db, s.id, u.username)
    assert principals == [cert_principal_for_user(u)]
    assert u.username not in principals  # never the mutable username


def test_principals_for_role_account_emits_one_immutable_principal_per_user(
    db, seed_distro, group, cred
):
    s = _system(db, seed_distro, group, cred, "p288-shared")
    alice = _user(db, "pra288-a")
    bob = _user(db, "pra288-b")
    role = _role(db, "p288-ra")
    _grant(db, alice, s, role, "svc")
    _grant(db, bob, s, role, "svc")

    principals = prov._principals_for(db, s.id, "svc")
    assert principals == sorted(
        [cert_principal_for_user(alice), cert_principal_for_user(bob)]
    )
    # The shared Linux login itself is never a principal.
    assert "svc" not in principals


def test_principals_for_drops_revoked_user(db, seed_distro, group, cred):
    from app.services import access_binding_service as abs_svc

    s = _system(db, seed_distro, group, cred, "p288-revoke")
    u = _user(db, "pra288-rev")
    # role_account role -> grants land on login "svc" at recompute.
    role = _role(db, "p288-rev-role")
    b = abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=u.id,
        scope_group_id=group.id,
    )
    assert cert_principal_for_user(u) in prov._principals_for(db, s.id, "svc")

    abs_svc.delete_binding(db, b.id)
    assert prov._principals_for(db, s.id, "svc") == []


# ----------------------------------------------------- session path mapping


def test_session_signs_immutable_principal_connects_as_login(
    db, seed_distro, group, cred, admin_user, monkeypatch
):
    """The session cert is signed with the immutable Praxis principal while the SSH
    connection uses the shared Linux login as the username."""
    s = _system(db, seed_distro, group, cred, "p288-sess")
    login = "svc"  # shared role-account Linux login
    db.add(
        HostUserState(
            system_id=s.id, login=login, mode="role_account", state="provisioned"
        )
    )
    db.flush()

    from types import SimpleNamespace

    fake_result = SimpleNamespace(
        fleet_role=SimpleNamespace(id=1, max_session_s=3600),
        login=login,
        requires_approval=False,
        requires_totp=False,
        max_session_s=3600,
        recording_retention_days=90,
    )
    monkeypatch.setattr(ss, "authorize_action", lambda *a, **k: fake_result)

    recorded = {}

    class _FakeVault:
        def sign_ssh_user_cert(self, *, public_key, principal, ttl_seconds, key_id):
            recorded["principal"] = principal
            return "signed-cert"

    monkeypatch.setattr(ss, "VaultService", lambda db: _FakeVault())
    monkeypatch.setattr(paramiko.RSAKey, "load_certificate", lambda self, cert: None)
    import app.services.audit_event_service as aes

    monkeypatch.setattr(aes, "emit_user_cert_sign", lambda *a, **k: None)

    spy = _SpyClient(connect_raises=paramiko.SSHException("stop-after-connect"))
    monkeypatch.setattr(ss, "CertificateSSHClient", lambda: spy)

    with pytest.raises(ss.SessionError):
        ss.open_session(db, admin_user, s.id, login=login)

    # Signed with the immutable user principal, connected as the Linux login.
    assert recorded["principal"] == cert_principal_for_user(admin_user)
    assert recorded["principal"] != login
    assert spy.connect_username == login


# ------------------------------------------------- file-transfer path mapping


def test_file_transfer_mint_signs_immutable_principal(
    db, seed_distro, group, cred, admin_user, monkeypatch
):
    recorded = {}

    class _FakeVault:
        def sign_ssh_user_cert(self, *, public_key, principal, ttl_seconds, key_id):
            recorded["principal"] = principal
            return "signed-cert"

    monkeypatch.setattr(fts, "VaultService", lambda db: _FakeVault())
    monkeypatch.setattr(paramiko.RSAKey, "load_certificate", lambda self, cert: None)
    import app.services.audit_event_service as aes

    monkeypatch.setattr(aes, "emit_user_cert_sign", lambda *a, **k: None)

    fts._mint_cert_for(admin_user, "svc")
    # Signed with the immutable user principal, NOT the shared Linux login.
    assert recorded["principal"] == cert_principal_for_user(admin_user)
    assert recorded["principal"] != "svc"


def test_file_transfer_connects_as_linux_login(
    db, seed_distro, group, cred, admin_user, monkeypatch
):
    s = _system(db, seed_distro, group, cred, "p288-xfer")
    spy = _SpyClient()
    monkeypatch.setattr(fts, "_mint_cert_for", lambda user, login, ttl=300: MagicMock())
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: spy)

    with fts._open_sftp(db, admin_user, s, "svc") as sftp:
        assert sftp is not None
    assert spy.connect_username == "svc"  # SFTP connects as the Linux login


# ------------------------------------------------- composition with PRA-287


def test_mapping_composes_with_pra287_shared_login(db, seed_distro, group, cred):
    """Two users sharing a compatible role-account login each get their own
    immutable principal, and the login is not a PRA-287 conflict."""
    s = _system(db, seed_distro, group, cred, "p288-compose")
    alice = _user(db, "pra288-c1")
    bob = _user(db, "pra288-c2")
    # Same account shape -> compatible under PRA-287.
    role = _role(db, "p288-compose-role")
    _grant(db, alice, s, role, "svc")
    _grant(db, bob, s, role, "svc")

    assert not authz.resolve_login_resolution(db, s.id, "svc").is_conflict
    principals = prov._principals_for(db, s.id, "svc")
    assert set(principals) == {
        cert_principal_for_user(alice),
        cert_principal_for_user(bob),
    }
