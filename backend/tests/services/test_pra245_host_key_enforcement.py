"""PRA-245: SSH host-key verification is enforced for browser sessions and SFTP
file transfers, not just normal SSH connections.

Covers the shared ``configure_host_key_policy`` helper plus the session and
file-transfer client-setup paths — proving none of them silently install
``AutoAddPolicy`` when a system requires host-key verification.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import paramiko
import pytest

from app.db.access_models import HostUserState
from app.db.models import Credential, Group, System
from app.db.ssh_security_models import SSHHostKey, SSHSecurityPolicy
from app.services import file_transfer_service as fts
from app.services import session_service as ss
from app.services.ssh_service import (
    HostKeyPromptPolicy,
    SSHConnectionError,
    configure_host_key_policy,
)

# --------------------------------------------------------------- helpers


def _rsa_pub_b64() -> str:
    return paramiko.RSAKey.generate(2048).get_base64()


def _mk_system(
    db, seed_distro, admin_user, *, require: bool | None, ip="10.9.0.1"
) -> System:
    """Build a system for host-key tests.

    ``require=None`` creates the system with **no** SSH security policy at all
    (PRA-370: absent configuration, which must fail closed) rather than a policy
    that opts out.
    """
    tag = uuid.uuid4().hex[:8]
    grp = Group(name=f"pra245-{tag}")
    cred = Credential(
        name=f"pra245-cred-{tag}", auth_method="password", username="root"
    )
    db.add_all([grp, cred])
    db.flush()
    policy_id = None
    if require is not None:
        policy = SSHSecurityPolicy(
            name=f"pra245-pol-{tag}",
            require_host_key_verification=require,
            created_by=admin_user.id,
        )
        db.add(policy)
        db.flush()
        policy_id = policy.id
    system = System(
        hostname=f"pra245-{tag}.example.com",
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
        ssh_security_policy_id=policy_id,
    )
    db.add(system)
    db.flush()
    return system


def _store_key(db, system, *, key_type="ssh-rsa", verified=True) -> SSHHostKey:
    hk = SSHHostKey(
        system_id=system.id,
        hostname=system.hostname,
        key_type=key_type,
        public_key=_rsa_pub_b64(),
        fingerprint=f"fp-{uuid.uuid4().hex}",
        verified=verified,
    )
    db.add(hk)
    db.flush()
    return hk


def _mock_client() -> MagicMock:
    client = MagicMock()
    client.get_host_keys.return_value = MagicMock()
    return client


class _SpyClient:
    """A stand-in paramiko.SSHClient that records the host-key policy and can
    simulate a rejected (mismatch/unknown) host key at connect time."""

    def __init__(self, connect_raises: Exception | None = None):
        self.policy = None
        self.connect_raises = connect_raises
        self._host_keys = MagicMock()

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def get_host_keys(self):
        return self._host_keys

    def connect(self, **_kw):
        if self.connect_raises:
            raise self.connect_raises

    def open_sftp(self):
        return MagicMock()

    def close(self):
        pass


# --------------------------------------------- configure_host_key_policy


def test_verification_disabled_uses_autoadd(db, seed_distro, admin_user):
    """PRA-370: the permissive path survives, but ONLY as an explicit,
    persisted administrator opt-out."""
    system = _mk_system(db, seed_distro, admin_user, require=False)
    assert system.ssh_security_policy is not None
    assert system.ssh_security_policy.require_host_key_verification is False
    client = _mock_client()
    configure_host_key_policy(client, db, system)
    policy = client.set_missing_host_key_policy.call_args[0][0]
    assert isinstance(policy, paramiko.AutoAddPolicy)


def test_required_without_stored_key_uses_tofu_prompt(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, require=True)
    client = _mock_client()
    configure_host_key_policy(client, db, system)
    policy = client.set_missing_host_key_policy.call_args[0][0]
    assert isinstance(policy, HostKeyPromptPolicy)
    assert not isinstance(policy, paramiko.AutoAddPolicy)


def test_required_with_verified_key_uses_reject_and_loads_both_names(
    db, seed_distro, admin_user
):
    system = _mk_system(db, seed_distro, admin_user, require=True)
    _store_key(db, system, key_type="ssh-rsa")
    client = _mock_client()
    configure_host_key_policy(client, db, system)
    policy = client.set_missing_host_key_policy.call_args[0][0]
    assert isinstance(policy, paramiko.RejectPolicy)
    # The verified key is preloaded for BOTH hostname and IP (paramiko then
    # rejects any mismatch/unknown key).
    names = [c.args[0] for c in client.get_host_keys.return_value.add.call_args_list]
    assert system.hostname in names
    assert system.ip_address in names


def test_unsupported_stored_key_type_fails_closed(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, require=True)
    _store_key(db, system, key_type="ecdsa-sha2-nistp256")
    client = _mock_client()
    with pytest.raises(SSHConnectionError):
        configure_host_key_policy(client, db, system)


# ------------------------------- PRA-370: a MISSING policy must fail closed
#
# A system with no ``ssh_security_policy`` is absent security configuration, not
# an administrator opt-out. It must take the same verifying path as a policy that
# requires verification, and must never reach ``AutoAddPolicy``.


def test_missing_policy_uses_tofu_prompt_never_autoadd(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, require=None)
    assert system.ssh_security_policy is None
    client = _mock_client()
    configure_host_key_policy(client, db, system)
    assert client.set_missing_host_key_policy.call_count == 1
    policy = client.set_missing_host_key_policy.call_args[0][0]
    assert isinstance(policy, HostKeyPromptPolicy)
    assert not isinstance(policy, paramiko.AutoAddPolicy)
    # No AutoAddPolicy was installed at any point in the call.
    assert not any(
        isinstance(c.args[0], paramiko.AutoAddPolicy)
        for c in client.set_missing_host_key_policy.call_args_list
    )


def test_missing_policy_with_verified_key_uses_reject(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, require=None)
    _store_key(db, system, key_type="ssh-rsa")
    client = _mock_client()
    configure_host_key_policy(client, db, system)
    policy = client.set_missing_host_key_policy.call_args[0][0]
    assert isinstance(policy, paramiko.RejectPolicy)
    assert not isinstance(policy, paramiko.AutoAddPolicy)


def test_missing_policy_unsupported_stored_key_fails_closed(
    db, seed_distro, admin_user
):
    system = _mk_system(db, seed_distro, admin_user, require=None)
    _store_key(db, system, key_type="ecdsa-sha2-nistp256")
    client = _mock_client()
    with pytest.raises(SSHConnectionError):
        configure_host_key_policy(client, db, system)
    # The fail-closed policy was installed before the parse failure, so the
    # client is never left permissive.
    assert isinstance(
        client.set_missing_host_key_policy.call_args[0][0], paramiko.RejectPolicy
    )


def test_missing_policy_unverified_stored_key_uses_tofu_prompt(
    db, seed_distro, admin_user
):
    system = _mk_system(db, seed_distro, admin_user, require=None)
    _store_key(db, system, key_type="ssh-rsa", verified=False)
    client = _mock_client()
    configure_host_key_policy(client, db, system)
    policy = client.set_missing_host_key_policy.call_args[0][0]
    assert isinstance(policy, HostKeyPromptPolicy)
    assert not isinstance(policy, paramiko.AutoAddPolicy)


# ------------------------------------------------- command path (SSHService)


def test_ssh_service_missing_policy_installs_verifying_policy(
    db, seed_distro, admin_user, monkeypatch
):
    """The command path shares the helper, so a policy-less system gets the
    first-use capture policy there too, not AutoAddPolicy."""
    from app.services import ssh_service as sshs

    system = _mk_system(db, seed_distro, admin_user, require=None)
    spy = _SpyClient()
    # The SSH connection path builds a CertificateSSHClient (a paramiko.SSHClient
    # subclass that only changes certificate algorithm negotiation).
    monkeypatch.setattr(sshs, "CertificateSSHClient", lambda: spy)

    svc = sshs.SSHService(db)
    # The credential has no Vault path, so the connect attempt fails right after
    # the host-key policy is installed. That is all this test needs.
    with pytest.raises(SSHConnectionError):
        svc._create_connection(system)

    assert isinstance(spy.policy, HostKeyPromptPolicy)
    assert not isinstance(spy.policy, paramiko.AutoAddPolicy)


# ------------------------------------------------- file-transfer / SFTP


def test_file_transfer_uses_reject_policy_when_required(
    db, seed_distro, admin_user, monkeypatch
):
    system = _mk_system(db, seed_distro, admin_user, require=True)
    _store_key(db, system, key_type="ssh-rsa")
    spy = _SpyClient()
    monkeypatch.setattr(fts, "_mint_cert_for", lambda user, login, ttl=300: MagicMock())
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: spy)
    with fts._open_sftp(db, admin_user, system, "root") as sftp:
        assert sftp is not None
    assert isinstance(spy.policy, paramiko.RejectPolicy)
    assert not isinstance(spy.policy, paramiko.AutoAddPolicy)


def test_file_transfer_rejects_changed_or_unknown_key(
    db, seed_distro, admin_user, monkeypatch
):
    # A rejected host key at connect surfaces as ssh_connect_failed for every
    # SFTP op (upload/download/list/stat all go through _open_sftp).
    system = _mk_system(db, seed_distro, admin_user, require=True)
    _store_key(db, system, key_type="ssh-rsa")
    spy = _SpyClient(connect_raises=paramiko.SSHException("host key mismatch/unknown"))
    monkeypatch.setattr(fts, "_mint_cert_for", lambda *a, **k: MagicMock())
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: spy)
    with pytest.raises(fts.FileTransferError, match="ssh_connect_failed"):
        with fts._open_sftp(db, admin_user, system, "root"):
            pass


def test_file_transfer_missing_policy_never_uses_autoadd(
    db, seed_distro, admin_user, monkeypatch
):
    # PRA-370: SFTP inherits the shared helper, so a policy-less system captures
    # on first use instead of blindly trusting whatever key the server offers.
    system = _mk_system(db, seed_distro, admin_user, require=None)
    spy = _SpyClient()
    monkeypatch.setattr(fts, "_mint_cert_for", lambda user, login, ttl=300: MagicMock())
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: spy)
    with fts._open_sftp(db, admin_user, system, "root") as sftp:
        assert sftp is not None
    assert isinstance(spy.policy, HostKeyPromptPolicy)
    assert not isinstance(spy.policy, paramiko.AutoAddPolicy)


def test_file_transfer_unsupported_key_fails_closed(
    db, seed_distro, admin_user, monkeypatch
):
    system = _mk_system(db, seed_distro, admin_user, require=True)
    _store_key(db, system, key_type="ecdsa-sha2-nistp256")
    spy = _SpyClient()
    monkeypatch.setattr(fts, "_mint_cert_for", lambda *a, **k: MagicMock())
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: spy)
    with pytest.raises(fts.FileTransferError, match="ssh_host_key_error"):
        with fts._open_sftp(db, admin_user, system, "root"):
            pass


# ----------------------------------------------------- browser session


def _open_session_with_spy(db, admin_user, system, monkeypatch, login="root"):
    """Drive ``session_service.open_session`` far enough to install the host-key
    policy, then abort at connect. Returns the spy client."""
    db.add(
        HostUserState(
            system_id=system.id, login=login, mode="per_user", state="provisioned"
        )
    )
    db.flush()

    # Permissive authorization (no approval / no TOTP) so we reach the client setup.
    fake_result = SimpleNamespace(
        fleet_role=SimpleNamespace(id=1, max_session_s=3600),
        login=login,
        requires_approval=False,
        requires_totp=False,
        # PRA-287: session_service now takes the conservative session ceiling and
        # recording retention from the AuthorizationResult, not the representative
        # role.
        max_session_s=3600,
        recording_retention_days=90,
    )
    monkeypatch.setattr(ss, "authorize_action", lambda *a, **k: fake_result)
    # Fake the Vault cert mint + audit so no external calls are made.
    fake_vault = MagicMock()
    fake_vault.sign_ssh_user_cert.return_value = "signed-cert"
    monkeypatch.setattr(ss, "VaultService", lambda db: fake_vault)
    monkeypatch.setattr(paramiko.RSAKey, "load_certificate", lambda self, cert: None)
    import app.services.audit_event_service as aes

    monkeypatch.setattr(aes, "emit_user_cert_sign", lambda *a, **k: None)

    # A rejected host key at connect (as RejectPolicy would produce).
    spy = _SpyClient(connect_raises=paramiko.SSHException("host key mismatch/unknown"))
    monkeypatch.setattr(ss, "CertificateSSHClient", lambda: spy)

    with pytest.raises(ss.SessionError):
        ss.open_session(db, admin_user, system.id, login=login)

    return spy


def test_session_uses_reject_policy_and_rejects_changed_key(
    db, seed_distro, admin_user, monkeypatch
):
    system = _mk_system(db, seed_distro, admin_user, require=True)
    _store_key(db, system, key_type="ssh-rsa")

    spy = _open_session_with_spy(db, admin_user, system, monkeypatch)

    # The session path installed the verification policy — never AutoAddPolicy.
    assert isinstance(spy.policy, paramiko.RejectPolicy)
    assert not isinstance(spy.policy, paramiko.AutoAddPolicy)


def test_session_missing_policy_never_uses_autoadd(
    db, seed_distro, admin_user, monkeypatch
):
    # PRA-370: browser sessions inherit the shared helper, so a policy-less
    # system captures on first use rather than auto-adding.
    system = _mk_system(db, seed_distro, admin_user, require=None)

    spy = _open_session_with_spy(db, admin_user, system, monkeypatch)

    assert isinstance(spy.policy, HostKeyPromptPolicy)
    assert not isinstance(spy.policy, paramiko.AutoAddPolicy)
