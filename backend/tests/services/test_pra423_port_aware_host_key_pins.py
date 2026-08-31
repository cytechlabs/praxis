"""PRA-423: a pinned SSH host key is preloaded under the endpoint name paramiko
actually looks it up by, so a host reached on a non-default port verifies.

Paramiko names an endpoint ``host`` on port 22 and ``[host]:port`` on any other
port, and ``RejectPolicy`` refuses anything it cannot find under that exact
name. Before this change the verified key was preloaded under the bare hostname
and IP only, so an enrolled host answering on 2222 was rejected as unknown even
though its key had been approved.

These tests cover the naming helper, the shared
``configure_host_key_policy`` path used by command execution, browser sessions
and SFTP, and a real paramiko handshake on a non-default port proving an
approved key connects under ``RejectPolicy`` while a rotated one does not.
"""

from __future__ import annotations

import io
import socket
import threading
import uuid
from typing import List, Optional

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.db.models import (
    Credential,
    GlobalConnectionSettings,
    Group,
    System,
    SystemMetadata,
)
from app.db.ssh_security_models import SSHHostKey, SSHSecurityPolicy
from app.services import file_transfer_service as fts
from app.services import session_service as ss
from app.services import ssh_service as sshs
from app.services.ssh_service import (
    HostKeyPromptPolicy,
    SSHConnectionError,
    configure_host_key_policy,
    known_host_identity,
    resolve_ssh_port,
)

# --------------------------------------------------------------- helpers


def _ed25519_key() -> paramiko.PKey:
    """An Ed25519 host key. Paramiko cannot generate one, so build it here."""
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))


def _mk_system(
    db,
    seed_distro,
    admin_user,
    *,
    hostname: Optional[str] = None,
    ip: str = "10.23.0.1",
    ssh_port: Optional[int] = None,
    with_metadata: bool = True,
) -> System:
    """A verification-required system, optionally carrying a persisted port."""
    tag = uuid.uuid4().hex[:8]
    grp = Group(name=f"pra423-{tag}")
    cred = Credential(
        name=f"pra423-cred-{tag}", auth_method="password", username="root"
    )
    policy = SSHSecurityPolicy(
        name=f"pra423-pol-{tag}",
        require_host_key_verification=True,
        created_by=admin_user.id,
    )
    db.add_all([grp, cred, policy])
    db.flush()
    system = System(
        hostname=hostname or f"pra423-{tag}.example.com",
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="9.4",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
        ssh_security_policy_id=policy.id,
    )
    db.add(system)
    db.flush()
    if with_metadata:
        db.add(SystemMetadata(system_id=system.id, ssh_port=ssh_port))
        db.flush()
        db.refresh(system)
    return system


def _store_key(db, system, key: paramiko.PKey, *, verified: bool = True) -> SSHHostKey:
    hk = SSHHostKey(
        system_id=system.id,
        hostname=system.hostname,
        key_type=key.get_name(),
        public_key=key.get_base64(),
        fingerprint=sshs.host_key_fingerprint(key),
        verified=verified,
    )
    db.add(hk)
    db.flush()
    return hk


def _preloaded_names(client: paramiko.SSHClient) -> List[str]:
    """Every name the verified key was preloaded under."""
    names: List[str] = []
    for entry in client.get_host_keys()._entries:  # pylint: disable=protected-access
        names.extend(entry.hostnames)
    return names


def _set_default_ssh_port(db, port: int) -> None:
    settings = db.query(GlobalConnectionSettings).first()
    if settings is None:
        settings = GlobalConnectionSettings()
        db.add(settings)
    settings.default_ssh_port = port
    db.flush()


# ------------------------------------------------------ the naming helper


@pytest.mark.parametrize(
    "host,port,expected",
    [
        ("host.example.com", 22, "host.example.com"),
        ("10.23.0.1", 22, "10.23.0.1"),
        ("fd00::23", 22, "fd00::23"),
        ("host.example.com", 2222, "[host.example.com]:2222"),
        ("10.23.0.1", 2222, "[10.23.0.1]:2222"),
        ("fd00::23", 2222, "[fd00::23]:2222"),
        ("10.23.0.1", 65535, "[10.23.0.1]:65535"),
        ("10.23.0.1", 1, "[10.23.0.1]:1"),
    ],
)
def test_known_host_identity_matches_paramiko_naming(host, port, expected):
    assert known_host_identity(host, port) == expected


def test_known_host_identity_does_not_double_bracket_ipv6():
    """A literal that already carries brackets keeps exactly one pair."""
    assert known_host_identity("[fd00::23]", 2222) == "[fd00::23]:2222"
    assert "[[" not in known_host_identity("[fd00::23]", 2222)


def test_known_host_identity_agrees_with_paramiko_client():
    """The helper must produce the same string paramiko's client builds, or the
    lookup silently misses."""
    from paramiko.client import SSH_PORT

    assert SSH_PORT == 22
    for host in ("host.example.com", "10.23.0.1", "fd00::23"):
        assert known_host_identity(host, SSH_PORT) == host
        assert known_host_identity(host, 2222) == "[{}]:{}".format(host, 2222)


# ------------------------------------------------------- port resolution


def test_resolve_ssh_port_prefers_persisted_metadata(db, seed_distro, admin_user):
    _set_default_ssh_port(db, 2200)
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    assert resolve_ssh_port(db, system) == 2222


def test_resolve_ssh_port_falls_back_to_configured_default(db, seed_distro, admin_user):
    _set_default_ssh_port(db, 2200)
    system = _mk_system(db, seed_distro, admin_user, with_metadata=False)
    assert resolve_ssh_port(db, system) == 2200


def test_resolve_ssh_port_falls_back_to_22_without_settings(
    db, seed_distro, admin_user
):
    """An installation with neither a persisted port nor connection settings
    still names the endpoint paramiko will ask for."""
    system = _mk_system(db, seed_distro, admin_user, with_metadata=False)
    for settings in db.query(GlobalConnectionSettings).all():
        db.delete(settings)
    db.flush()
    assert db.query(GlobalConnectionSettings).first() is None
    assert resolve_ssh_port(db, system) == 22


def test_resolve_ssh_port_ignores_an_unconnectable_stored_port(
    db, seed_distro, admin_user
):
    """A port outside the valid range names an endpoint nothing can reach."""
    system = _mk_system(db, seed_distro, admin_user, ssh_port=70000)
    assert resolve_ssh_port(db, system) == 22


# ------------------------------------ preload names on the shared helper


def test_default_port_preloads_bare_hostname_and_ip(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, ssh_port=22)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    names = _preloaded_names(client)
    assert system.hostname in names
    assert system.ip_address in names


def test_non_default_port_preloads_bracketed_names_only(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    names = _preloaded_names(client)
    assert f"[{system.hostname}]:2222" in names
    assert f"[{system.ip_address}]:2222" in names
    # The bare names are what paramiko would never ask for on this endpoint,
    # so the pin must not depend on them being present.
    assert system.hostname not in names
    assert system.ip_address not in names
    assert client.get_host_keys().lookup(f"[{system.ip_address}]:2222") is not None
    assert client.get_host_keys().lookup(system.ip_address) is None


def test_non_default_port_still_uses_reject_policy(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    policy = client._policy  # pylint: disable=protected-access
    assert isinstance(policy, paramiko.RejectPolicy)
    assert not isinstance(policy, paramiko.AutoAddPolicy)


def test_absent_metadata_follows_the_configured_default_port(
    db, seed_distro, admin_user
):
    _set_default_ssh_port(db, 2200)
    system = _mk_system(db, seed_distro, admin_user, with_metadata=False)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    names = _preloaded_names(client)
    assert f"[{system.hostname}]:2200" in names
    assert f"[{system.ip_address}]:2200" in names


def test_explicit_port_argument_wins_over_persisted_metadata(
    db, seed_distro, admin_user
):
    """The connecting caller resolves the port it is about to dial and passes
    it, so the preloaded name and the dialled endpoint cannot disagree."""
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system, ssh_port=2022)
    names = _preloaded_names(client)
    assert f"[{system.ip_address}]:2022" in names
    assert f"[{system.ip_address}]:2222" not in names


def test_ipv6_system_preloads_a_single_bracket_pair(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, ip="fd00::23", ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    names = _preloaded_names(client)
    assert "[fd00::23]:2222" in names
    assert not any(n.startswith("[[") for n in names)


def test_ipv6_system_on_default_port_stays_bare(db, seed_distro, admin_user):
    system = _mk_system(db, seed_distro, admin_user, ip="fd00::23", ssh_port=22)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    assert "fd00::23" in _preloaded_names(client)


@pytest.mark.parametrize(
    "key_factory",
    [
        lambda: paramiko.RSAKey.generate(2048),
        lambda: paramiko.ECDSAKey.generate(bits=256),
        _ed25519_key,
    ],
    ids=["rsa", "ecdsa", "ed25519"],
)
def test_every_pinnable_key_type_preloads_on_a_non_default_port(
    db, seed_distro, admin_user, key_factory
):
    key = key_factory()
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, key)
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    loaded = client.get_host_keys().lookup(f"[{system.ip_address}]:2222")
    assert loaded is not None
    assert loaded[key.get_name()] == key


def test_unsupported_stored_key_type_still_fails_closed_on_a_non_default_port(
    db, seed_distro, admin_user
):
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    hk = SSHHostKey(
        system_id=system.id,
        hostname=system.hostname,
        key_type="ssh-dss",
        public_key=paramiko.RSAKey.generate(2048).get_base64(),
        fingerprint="fp-" + uuid.uuid4().hex,
        verified=True,
    )
    db.add(hk)
    db.flush()
    client = paramiko.SSHClient()
    with pytest.raises(SSHConnectionError):
        configure_host_key_policy(client, db, system)
    assert _preloaded_names(client) == []


def test_unverified_key_on_a_non_default_port_still_captures_on_first_use(
    db, seed_distro, admin_user
):
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048), verified=False)
    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    policy = client._policy  # pylint: disable=protected-access
    assert isinstance(policy, HostKeyPromptPolicy)
    assert not isinstance(policy, paramiko.AutoAddPolicy)


def test_changing_the_persisted_port_changes_the_identity(db, seed_distro, admin_user):
    """A port change must move the pin to the new endpoint without becoming a
    second approved key or an opportunity to accept a new one."""
    system = _mk_system(db, seed_distro, admin_user, ssh_port=22)
    key = paramiko.RSAKey.generate(2048)
    _store_key(db, system, key)

    before = paramiko.SSHClient()
    configure_host_key_policy(before, db, system)
    assert system.ip_address in _preloaded_names(before)

    system.system_metadata.ssh_port = 2222
    db.flush()
    db.refresh(system)

    after = paramiko.SSHClient()
    configure_host_key_policy(after, db, system)
    names = _preloaded_names(after)
    assert f"[{system.ip_address}]:2222" in names
    assert system.ip_address not in names
    # Still exactly one approved key, and still the rejecting policy.
    assert db.query(SSHHostKey).filter(SSHHostKey.system_id == system.id).count() == 1
    assert isinstance(
        after._policy, paramiko.RejectPolicy  # pylint: disable=protected-access
    )


# ------------------------------------------- the callers share the naming


class _SpyClient:
    """Records the host-key policy, the preloaded names and the dialled port.

    ``connect_raises`` makes the dial fail the way a refused host key would,
    which is how a caller is stopped after the endpoint has been recorded.
    """

    def __init__(self, connect_raises: Optional[Exception] = None):
        self.policy = None
        self.host_keys = paramiko.HostKeys()
        self.connect_calls: List[dict] = []
        self.connect_raises = connect_raises
        self.closed = 0

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def get_host_keys(self):
        return self.host_keys

    def connect(self, **kw):
        self.connect_calls.append(kw)
        if self.connect_raises is not None:
            raise self.connect_raises
        return None

    @property
    def dialled_port(self) -> Optional[int]:
        return self.connect_calls[-1]["port"] if self.connect_calls else None

    def open_sftp(self):
        from unittest.mock import MagicMock

        return MagicMock()

    def get_transport(self):
        return None

    def close(self):
        self.closed += 1


_REFUSED = paramiko.SSHException("host key mismatch/unknown")


def _spy_names(spy: _SpyClient) -> List[str]:
    names: List[str] = []
    for entry in spy.host_keys._entries:  # pylint: disable=protected-access
        names.extend(entry.hostnames)
    return names


def test_command_path_preloads_the_endpoint_identity(
    db, seed_distro, admin_user, monkeypatch
):
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    spy = _SpyClient()
    monkeypatch.setattr(sshs, "CertificateSSHClient", lambda: spy)
    svc = sshs.SSHService(db)
    # The credential has no Vault path, so the attempt fails right after the
    # host-key policy is installed. That is all this assertion needs.
    with pytest.raises(SSHConnectionError):
        svc._create_connection(system)  # pylint: disable=protected-access
    assert isinstance(spy.policy, paramiko.RejectPolicy)
    assert f"[{system.ip_address}]:2222" in _spy_names(spy)


def test_file_transfer_path_preloads_the_endpoint_identity(
    db, seed_distro, admin_user, monkeypatch
):
    from unittest.mock import MagicMock

    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    spy = _SpyClient()
    monkeypatch.setattr(fts, "_mint_cert_for", lambda user, login, ttl=300: MagicMock())
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: spy)
    # pylint: disable-next=protected-access
    with fts._open_sftp(db, admin_user, system, "root"):
        pass
    assert isinstance(spy.policy, paramiko.RejectPolicy)
    assert f"[{system.hostname}]:2222" in _spy_names(spy)
    assert f"[{system.ip_address}]:2222" in _spy_names(spy)


def test_session_path_preloads_the_endpoint_identity(
    db, seed_distro, admin_user, monkeypatch
):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import app.services.audit_event_service as aes
    from app.db.access_models import HostUserState

    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048))
    db.add(
        HostUserState(
            system_id=system.id, login="root", mode="per_user", state="provisioned"
        )
    )
    db.flush()

    fake_result = SimpleNamespace(
        fleet_role=SimpleNamespace(id=1, max_session_s=3600),
        login="root",
        requires_approval=False,
        requires_totp=False,
        max_session_s=3600,
        recording_retention_days=90,
    )
    monkeypatch.setattr(ss, "authorize_action", lambda *a, **k: fake_result)
    fake_vault = MagicMock()
    fake_vault.sign_ssh_user_cert.return_value = "signed-cert"
    monkeypatch.setattr(ss, "VaultService", lambda db: fake_vault)
    monkeypatch.setattr(paramiko.RSAKey, "load_certificate", lambda self, cert: None)
    monkeypatch.setattr(aes, "emit_user_cert_sign", lambda *a, **k: None)

    # The session aborts at the dial, right after the client is set up.
    spy = _SpyClient(connect_raises=_REFUSED)
    monkeypatch.setattr(ss, "CertificateSSHClient", lambda: spy)

    with pytest.raises(ss.SessionError):
        ss.open_session(db, admin_user, system.id, login="root")

    assert isinstance(spy.policy, paramiko.RejectPolicy)
    assert f"[{system.hostname}]:2222" in _spy_names(spy)
    assert f"[{system.ip_address}]:2222" in _spy_names(spy)


# ------------------------- the dialled port is the port the pin is filed under
#
# Browser sessions and SFTP resolve their own port and must hand that exact
# value to the shared helper. If the helper resolved its own, a system with no
# persisted port on an installation whose global default is not 22 would be
# pinned under one endpoint and dialled at another, and the approved key would
# read as unknown.


def _session_spy(db, admin_user, system, monkeypatch) -> _SpyClient:
    """Drive ``open_session`` to the dial and return the client it used."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import app.services.audit_event_service as aes
    from app.db.access_models import HostUserState

    db.add(
        HostUserState(
            system_id=system.id, login="root", mode="per_user", state="provisioned"
        )
    )
    db.flush()
    fake_result = SimpleNamespace(
        fleet_role=SimpleNamespace(id=1, max_session_s=3600),
        login="root",
        requires_approval=False,
        requires_totp=False,
        max_session_s=3600,
        recording_retention_days=90,
    )
    monkeypatch.setattr(ss, "authorize_action", lambda *a, **k: fake_result)
    fake_vault = MagicMock()
    fake_vault.sign_ssh_user_cert.return_value = "signed-cert"
    monkeypatch.setattr(ss, "VaultService", lambda db: fake_vault)
    monkeypatch.setattr(paramiko.RSAKey, "load_certificate", lambda self, cert: None)
    monkeypatch.setattr(aes, "emit_user_cert_sign", lambda *a, **k: None)

    spy = _SpyClient(connect_raises=_REFUSED)
    monkeypatch.setattr(ss, "CertificateSSHClient", lambda: spy)
    with pytest.raises(ss.SessionError):
        ss.open_session(db, admin_user, system.id, login="root")
    return spy


def _sftp_spy(db, admin_user, system, monkeypatch) -> _SpyClient:
    """Drive ``_open_sftp`` to the dial and return the client it used."""
    from unittest.mock import MagicMock

    monkeypatch.setattr(fts, "_mint_cert_for", lambda user, login, ttl=300: MagicMock())
    spy = _SpyClient(connect_raises=_REFUSED)
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: spy)
    with pytest.raises(fts.FileTransferError):
        # pylint: disable-next=protected-access
        with fts._open_sftp(db, admin_user, system, "root"):
            pass
    return spy


@pytest.mark.parametrize("drive", [_session_spy, _sftp_spy], ids=["session", "sftp"])
def test_persisted_port_is_used_for_both_preload_and_dial(
    db, seed_distro, admin_user, monkeypatch, drive
):
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    _store_key(db, system, paramiko.RSAKey.generate(2048))

    spy = drive(db, admin_user, system, monkeypatch)

    assert spy.dialled_port == 2222
    names = _spy_names(spy)
    assert f"[{system.hostname}]:2222" in names
    assert f"[{system.ip_address}]:2222" in names
    assert isinstance(spy.policy, paramiko.RejectPolicy)


@pytest.mark.parametrize("drive", [_session_spy, _sftp_spy], ids=["session", "sftp"])
def test_absent_metadata_dials_22_and_pins_22_whatever_the_global_default_says(
    db, seed_distro, admin_user, monkeypatch, drive
):
    """These two services dial 22 for a system with no persisted port. The pin
    has to follow the dial, not the global default they do not consult."""
    _set_default_ssh_port(db, 2222)
    system = _mk_system(db, seed_distro, admin_user, with_metadata=False)
    _store_key(db, system, paramiko.RSAKey.generate(2048))

    spy = drive(db, admin_user, system, monkeypatch)

    assert spy.dialled_port == 22
    names = _spy_names(spy)
    assert system.hostname in names
    assert system.ip_address in names
    assert f"[{system.hostname}]:2222" not in names


@pytest.mark.parametrize("drive", [_session_spy, _sftp_spy], ids=["session", "sftp"])
def test_an_approved_key_is_still_required_on_both_callers(
    db, seed_distro, admin_user, monkeypatch, drive
):
    """Neither caller reaches a dial with a stored key it cannot pin, and
    neither becomes permissive when no key is stored yet."""
    unpinnable = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    db.add(
        SSHHostKey(
            system_id=unpinnable.id,
            hostname=unpinnable.hostname,
            key_type="ssh-dss",
            public_key=paramiko.RSAKey.generate(2048).get_base64(),
            fingerprint="fp-" + uuid.uuid4().hex,
            verified=True,
        )
    )
    db.flush()
    spy = drive(db, admin_user, unpinnable, monkeypatch)
    assert spy.connect_calls == []

    first_use = _mk_system(db, seed_distro, admin_user, ip="10.23.0.2", ssh_port=2222)
    spy = drive(db, admin_user, first_use, monkeypatch)
    assert isinstance(spy.policy, HostKeyPromptPolicy)
    assert not isinstance(spy.policy, paramiko.AutoAddPolicy)


# ------------------------------- a changed key during certificate auth


def test_ca_path_host_key_mismatch_is_sanitized_and_does_not_fall_back(
    db, seed_distro, admin_user, monkeypatch, caplog
):
    """A host that answers certificate auth with a different key is refused
    outright. Offering the stored credential to it next would be offering it to
    whatever answered, and paramiko's own text quotes both key bodies."""
    import logging

    from app.db.ssh_security_models import SSHSecurityLog

    approved = paramiko.RSAKey.generate(2048)
    presented = paramiko.RSAKey.generate(2048)
    # The key bodies are the sentinels: they are exactly what must not escape.
    approved_body = approved.get_base64()
    presented_body = presented.get_base64()

    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    system.ca_trust_deployed = True
    system.credentials.vault_path = "praxis/pra423-ca"
    _store_key(db, system, approved)
    db.flush()

    spy = _SpyClient(
        connect_raises=paramiko.BadHostKeyException(
            system.ip_address, presented, approved
        )
    )
    monkeypatch.setattr(sshs, "CertificateSSHClient", lambda: spy)

    class _Vault:
        """Signs the throwaway cert and would hand back the stored secret."""

        reads: List[str] = []

        def __init__(self, _db):
            pass

        def sign_ssh_user_cert(self, **_kw):
            return "signed-cert"

        def read_secret(self, path):
            type(self).reads.append(path)
            return {"password": "unused"}

    _Vault.reads = []
    monkeypatch.setattr(sshs, "VaultService", _Vault)
    monkeypatch.setattr(paramiko.RSAKey, "load_certificate", lambda self, cert: None)

    svc = sshs.SSHService(db)
    with caplog.at_level(logging.DEBUG, logger="app.services.ssh_service"):
        with pytest.raises(SSHConnectionError) as exc:
            svc._create_connection(system)  # pylint: disable=protected-access

    message = str(exc.value)
    assert "Host key MISMATCH" in message
    assert "SSH Security > Host Keys" in message

    # No fallback: one dial, and the stored credential was never fetched.
    assert len(spy.connect_calls) == 1
    assert _Vault.reads == []
    assert spy.closed >= 1

    # Neither sentinel reaches the operator error, the logs, or the persisted
    # security context.
    logged = "\n".join(record.getMessage() for record in caplog.records)
    security = (
        db.query(SSHSecurityLog)
        .filter(SSHSecurityLog.system_id == system.id)
        .order_by(SSHSecurityLog.id.desc())
        .first()
    )
    assert security is not None
    context = security.event_details or ""
    for sentinel in (approved_body, presented_body):
        assert sentinel not in message
        assert sentinel not in logged
        assert sentinel not in context
    assert "does not match: got" not in logged
    assert "Host key MISMATCH" in context

    # The approved row is untouched by the refusal.
    db.expire_all()
    stored = db.query(SSHHostKey).filter(SSHHostKey.system_id == system.id).one()
    assert stored.public_key == approved_body
    assert stored.verified is True


# -------------------------------------------- a real non-default-port handshake


class _AcceptAnyServer(paramiko.ServerInterface):
    """Minimal sshd stand-in: the handshake is what is under test."""

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


class _LocalSSHServer:
    """A paramiko server on an ephemeral (therefore non-default) local port.

    It negotiates under the same retired-algorithm floor the production client
    applies, so a handshake here fails for host-key reasons and nothing else.
    """

    def __init__(self, host_key: paramiko.PKey):
        self.host_key = host_key
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._transports: List[paramiko.Transport] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            transport = paramiko.Transport(
                conn, disabled_algorithms=sshs.harden_disabled_algorithms()
            )
            transport.add_server_key(self.host_key)
            self._transports.append(transport)
            try:
                transport.start_server(server=_AcceptAnyServer())
            except Exception:  # pylint: disable=broad-except
                pass

    def close(self) -> None:
        self._stop.set()
        for transport in self._transports:
            try:
                transport.close()
            except Exception:  # pylint: disable=broad-except
                pass
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


@pytest.fixture
def local_ssh_server():
    """Yields a factory so a test can start a server, then restart it on the
    same port with a rotated key."""
    servers: List[_LocalSSHServer] = []

    def _start(host_key: paramiko.PKey) -> _LocalSSHServer:
        server = _LocalSSHServer(host_key)
        servers.append(server)
        return server

    yield _start
    for server in servers:
        server.close()


def _connect(client: paramiko.SSHClient, address: str, port: int) -> None:
    client.connect(
        hostname=address,
        port=port,
        username="operator",
        password="not-checked",
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
    )


def _system_for(db, seed_distro, admin_user, port: int) -> System:
    """A system whose hostname and IP both reach the loopback server."""
    return _mk_system(
        db,
        seed_distro,
        admin_user,
        hostname="localhost",
        ip="127.0.0.1",
        ssh_port=port,
    )


@pytest.mark.parametrize("address", ["127.0.0.1", "localhost"], ids=["ip", "hostname"])
def test_approved_key_connects_on_a_non_default_port(
    db, seed_distro, admin_user, local_ssh_server, address
):
    """The whole point: RejectPolicy plus a real handshake on a port that is not
    22, reached by direct IP and by hostname."""
    host_key = paramiko.RSAKey.generate(2048)
    server = local_ssh_server(host_key)
    assert server.port != 22
    system = _system_for(db, seed_distro, admin_user, server.port)
    _store_key(db, system, host_key)

    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    assert isinstance(
        client._policy, paramiko.RejectPolicy  # pylint: disable=protected-access
    )
    try:
        _connect(client, address, server.port)
        assert client.get_transport() is not None
        assert client.get_transport().is_active()
    finally:
        client.close()


def test_rotated_key_is_rejected_on_a_non_default_port(
    db, seed_distro, admin_user, local_ssh_server
):
    """A host that comes back with a different key fails closed rather than
    being re-trusted."""
    approved = paramiko.RSAKey.generate(2048)
    rotated = paramiko.RSAKey.generate(2048)
    assert approved.get_base64() != rotated.get_base64()
    server = local_ssh_server(rotated)
    system = _system_for(db, seed_distro, admin_user, server.port)
    _store_key(db, system, approved)

    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    try:
        with pytest.raises(paramiko.BadHostKeyException):
            _connect(client, "127.0.0.1", server.port)
    finally:
        client.close()
    # The approved row is untouched by the refusal.
    stored = db.query(SSHHostKey).filter(SSHHostKey.system_id == system.id).one()
    assert stored.public_key == approved.get_base64()
    assert stored.verified is True


def test_ed25519_host_key_verifies_on_a_non_default_port(
    db, seed_distro, admin_user, local_ssh_server
):
    host_key = _ed25519_key()
    server = local_ssh_server(host_key)
    system = _system_for(db, seed_distro, admin_user, server.port)
    _store_key(db, system, host_key)

    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    try:
        _connect(client, "127.0.0.1", server.port)
        assert client.get_transport().is_active()
    finally:
        client.close()


def test_bare_name_pin_is_not_enough_on_a_non_default_port(
    db, seed_distro, admin_user, local_ssh_server
):
    """The pre-change behavior, asserted directly: a key preloaded only under
    the bare names is invisible to paramiko on a non-default port, and
    RejectPolicy refuses the connection."""
    host_key = paramiko.RSAKey.generate(2048)
    server = local_ssh_server(host_key)
    system = _system_for(db, seed_distro, admin_user, server.port)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.get_host_keys().add(system.hostname, host_key.get_name(), host_key)
    client.get_host_keys().add(system.ip_address, host_key.get_name(), host_key)
    try:
        with pytest.raises(paramiko.SSHException):
            _connect(client, "127.0.0.1", server.port)
    finally:
        client.close()


def test_port_change_does_not_let_a_new_key_in(
    db, seed_distro, admin_user, local_ssh_server
):
    """Moving a host to another port re-pins the endpoint, it does not reopen
    trust-on-first-use."""
    approved = paramiko.RSAKey.generate(2048)
    other = paramiko.RSAKey.generate(2048)
    server = local_ssh_server(other)
    system = _system_for(db, seed_distro, admin_user, 22)
    _store_key(db, system, approved)

    system.system_metadata.ssh_port = server.port
    db.flush()
    db.refresh(system)

    client = paramiko.SSHClient()
    configure_host_key_policy(client, db, system)
    try:
        with pytest.raises(paramiko.BadHostKeyException):
            _connect(client, "127.0.0.1", server.port)
    finally:
        client.close()


def test_rotated_key_refusal_is_sanitized_and_actionable(
    db, seed_distro, admin_user, local_ssh_server, monkeypatch
):
    """The managed-host path reports a changed key in fingerprints and names
    the one action that resolves it, not paramiko's raw key bodies."""
    approved = paramiko.RSAKey.generate(2048)
    rotated = paramiko.RSAKey.generate(2048)
    server = local_ssh_server(rotated)
    system = _system_for(db, seed_distro, admin_user, server.port)
    _store_key(db, system, approved)
    # A paramiko server cannot offer group-exchange key exchange without a
    # moduli file, so this system's policy constrains nothing beyond the
    # retired-algorithm floor. Algorithm allow-lists are covered elsewhere;
    # what is under test here is the host-key refusal.
    policy = system.ssh_security_policy
    policy.allowed_ciphers = None
    policy.allowed_macs = None
    policy.allowed_kex = None
    db.flush()

    real_client = paramiko.SSHClient()
    monkeypatch.setattr(sshs, "CertificateSSHClient", lambda: real_client)

    class _Vault:
        def __init__(self, _db):
            pass

        def read_secret(self, _path):
            return {"password": "not-checked"}

    monkeypatch.setattr(sshs, "VaultService", _Vault)
    system.credentials.vault_path = "praxis/pra423"
    db.flush()

    svc = sshs.SSHService(db)
    with pytest.raises(SSHConnectionError) as exc:
        svc._create_connection(system)  # pylint: disable=protected-access
    message = str(exc.value)
    assert "Host key MISMATCH" in message
    assert "SSH Security > Host Keys" in message
    assert approved.get_base64() not in message
    assert rotated.get_base64() not in message
    assert "not-checked" not in message
    real_client.close()


def test_connection_error_carries_no_key_material(db, seed_distro, admin_user):
    """Refusals stay sanitized: no key body, only what to do about it."""
    system = _mk_system(db, seed_distro, admin_user, ssh_port=2222)
    public_key = paramiko.RSAKey.generate(2048).get_base64()
    db.add(
        SSHHostKey(
            system_id=system.id,
            hostname=system.hostname,
            key_type="ssh-dss",
            public_key=public_key,
            fingerprint="fp-" + uuid.uuid4().hex,
            verified=True,
        )
    )
    db.flush()
    client = paramiko.SSHClient()
    with pytest.raises(SSHConnectionError) as exc:
        configure_host_key_policy(client, db, system)
    message = str(exc.value)
    assert public_key not in message
    assert "SSH Security" in message
