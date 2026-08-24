"""PRA-415: browser sessions and SFTP use the RSA-SHA2 certificate client.

Both governed host paths authenticate only with a Vault-signed user
certificate, so both must build the shared certificate client rather than a
plain ``paramiko.SSHClient``. Paramiko's legacy-server heuristic misreads an
``OpenSSH_10`` banner as OpenSSH 1.x and forces the SHA-1
``ssh-rsa-cert-v01@openssh.com`` algorithm, which modern servers dropped from
``PubkeyAcceptedAlgorithms``; the certificate is then never evaluated and the
session or transfer fails with a generic authentication error.

These tests drive paramiko's own algorithm negotiation, so they prove the
agreed algorithm rather than restating the workaround:

- both services construct the one shared ``CertificateSSHClient``;
- against an OpenSSH 10 banner the agreed algorithm is
  ``rsa-sha2-512-cert-v01@openssh.com``, and a plain client would still agree
  on the SHA-1 certificate algorithm;
- host-key policy, fleet authorization, the configured port, the configured
  timeout, and the connect arguments are unchanged; and
- a failed connect or a recording that cannot start still fails closed, closes
  what it opened, and leaks no certificate or secret material.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import paramiko
import pytest
from paramiko.auth_handler import AuthHandler

from app.db.access_models import HostUserState
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, System
from app.services import file_transfer_service as fts
from app.services import recording_service as rec_svc
from app.services import session_runtime as runtime_registry
from app.services import session_service as ss
from app.services.ssh_service import CertificateSSHClient

# A current Ubuntu server. Paramiko's legacy test is ``-OpenSSH_(?:[1-6]|7\\.[0-7])``
# and the leading "1" of "10" matches ``[1-6]``, which is the whole defect.
OPENSSH_10_BANNER = "SSH-2.0-OpenSSH_10.0p2 Ubuntu-3ubuntu1"

# What a modern OpenSSH advertises in ``server-sig-algs``. The SHA-1 "ssh-rsa"
# signature algorithm is deliberately absent, exactly as on the real host.
SERVER_SIG_ALGS = b"ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"

RSA_CERT_KEY_TYPE = "ssh-rsa-cert-v01@openssh.com"
SHA1_CERT_ALGORITHM = "ssh-rsa-cert-v01@openssh.com"
RSA_SHA2_CERT_ALGORITHM = "rsa-sha2-512-cert-v01@openssh.com"

CERT_BODY = "ssh-rsa-cert-v01@openssh.com AAAAsecretcertificatebody praxis"

# Stands in for teardown detail that must never reach the caller or the logs.
TEARDOWN_SENTINEL = "socket teardown detail /data/praxis/private"

SERVICE_LOGGERS = (
    "app.services.session_service",
    "app.services.file_transfer_service",
    "app.services.recording_service",
)


# --------------------------------------------------------------- negotiation


class _NegotiatingTransport:
    """Enough of a paramiko transport to run its real algorithm choice."""

    def __init__(self, remote_version: str):
        self.remote_version = remote_version
        self.preferred_pubkeys = paramiko.Transport._preferred_pubkeys
        self.server_extensions = {"server-sig-algs": SERVER_SIG_ALGS}
        self._agreed_pubkey_algorithm = None
        self.closed = 0

    def is_active(self):
        return self.closed == 0

    def close(self):
        self.closed += 1


def _install_real_negotiation(monkeypatch):
    """Let paramiko decide the algorithm instead of the test asserting it.

    Replaces only the base-class ``_auth`` -- the certificate client keeps its
    own override, so the banner it presents is the one paramiko negotiates
    against.
    """

    def _auth(self, username, password, pkey, *args, **kwargs):  # noqa: ARG001
        handler = AuthHandler(self._transport)
        handler._log = lambda *a, **k: None
        return handler._finalize_pubkey_algorithm(RSA_CERT_KEY_TYPE)

    monkeypatch.setattr(paramiko.SSHClient, "_auth", _auth)


class _LoopbackClient(paramiko.SSHClient):
    """A client with the socket and handshake removed, nothing else.

    Subclassed by the certificate client under test and by a plain paramiko
    client, so the only difference between the two runs is the class the
    service builds.
    """

    def __init__(
        self, connect_raises=None, close_raises=None, banner=OPENSSH_10_BANNER
    ):
        super().__init__()
        self.connect_kwargs = None
        self.policy = None
        self.closed = 0
        self.negotiated = None
        self.channel = MagicMock()
        self.sftp = MagicMock()
        self._connect_raises = connect_raises
        self._close_raises = close_raises
        self._banner = banner

    def set_missing_host_key_policy(self, policy):
        self.policy = policy
        super().set_missing_host_key_policy(policy)

    def connect(self, **kwargs):  # pylint: disable=arguments-differ
        self.connect_kwargs = kwargs
        if self._connect_raises is not None:
            raise self._connect_raises
        transport = _NegotiatingTransport(self._banner)
        self._transport = transport
        self._auth(kwargs.get("username"), None, kwargs.get("pkey"))
        self.negotiated = transport._agreed_pubkey_algorithm

    def get_transport(self):
        return self._transport

    def invoke_shell(self, **kwargs):  # pylint: disable=arguments-differ
        return self.channel

    def open_sftp(self):
        return self.sftp

    def close(self):
        # Counted before raising, so a test can prove the close was attempted
        # even when teardown itself fails.
        self.closed += 1
        if self._close_raises is not None:
            raise self._close_raises
        if self._transport is not None:
            self._transport.close()
            self._transport = None


class _LoopbackCertificateClient(_LoopbackClient, CertificateSSHClient):
    """The real certificate client, minus the socket."""


class _LoopbackPlainClient(_LoopbackClient):
    """What these paths built before: paramiko's client, unmodified."""


# ------------------------------------------------------------------ fixtures


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra415-grp").first()
    if not g:
        g = Group(name="pra415-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).filter_by(name="pra415-cred").first()
    if c is None:
        c = Credential(name="pra415-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname, *, ssh_port=None):
    s = System(
        hostname=hostname,
        ip_address="10.41.5.1",
        distro_id=seed_distro.id,
        os_version="26.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    if ssh_port is not None:
        from app.db.models import SystemMetadata

        db.add(SystemMetadata(system_id=s.id, ssh_port=ssh_port))
        db.flush()
    return s


def _certificate_key(monkeypatch):
    """A real RSA key that carries a certificate once Vault has signed it."""
    key = paramiko.RSAKey.generate(2048)

    def _load_certificate(self, value):  # noqa: ARG001
        self.public_blob = SimpleNamespace(key_type=RSA_CERT_KEY_TYPE)

    monkeypatch.setattr(paramiko.RSAKey, "load_certificate", _load_certificate)
    monkeypatch.setattr(paramiko.RSAKey, "generate", staticmethod(lambda bits: key))
    return key


def _fake_vault(recorder=None):
    def _sign(**kwargs):
        if recorder is not None:
            recorder.update(kwargs)
        return CERT_BODY

    return SimpleNamespace(sign_ssh_user_cert=_sign)


def _arrange_session(db, monkeypatch, user, system, login, *, max_session_s=3600):
    """Stub authorization, Vault, and cert material for ``open_session``."""
    db.add(
        HostUserState(
            system_id=system.id, login=login, mode="per_user", state="provisioned"
        )
    )
    db.flush()
    monkeypatch.setattr(
        ss,
        "authorize_action",
        lambda *a, **k: SimpleNamespace(
            fleet_role=SimpleNamespace(
                id=None, name="pra415-role", max_session_s=max_session_s
            ),
            login=login,
            requires_approval=False,
            requires_totp=False,
            max_session_s=max_session_s,
            recording_retention_days=90,
        ),
    )
    _certificate_key(monkeypatch)
    monkeypatch.setattr(ss, "VaultService", lambda db_: _fake_vault())
    import app.services.audit_event_service as aes

    monkeypatch.setattr(aes, "emit_user_cert_sign", lambda *a, **k: None)


def _arrange_transfer(monkeypatch):
    """Stub cert minting for ``_open_sftp``.

    ``_open_sftp`` is the connection primitive; the fleet-authorization gate
    runs in the upload/download callers, so nothing here stands in for it.
    """
    _certificate_key(monkeypatch)

    def _mint(user_, login_, ttl=300):  # noqa: ARG001
        key = paramiko.RSAKey.generate(2048)
        key.load_certificate(CERT_BODY)
        return key

    monkeypatch.setattr(fts, "_mint_cert_for", _mint)


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def blob(self) -> str:
        fmt = logging.Formatter()
        return "\n".join(fmt.format(r) for r in self.records)


class _capture_service_logs:  # pylint: disable=invalid-name
    """Collect service log records, establishing its own logging state.

    An earlier test may have left a global ``logging.disable`` or a raised
    level in place, which would make the capture silently empty and the
    redaction assertions vacuous.
    """

    def __enter__(self) -> _CaptureHandler:
        self._handler = _CaptureHandler()
        self._prev_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self._saved = []
        for name in SERVICE_LOGGERS:
            lg = logging.getLogger(name)
            self._saved.append((lg, lg.level, lg.disabled))
            lg.disabled = False
            lg.setLevel(logging.DEBUG)
            lg.addHandler(self._handler)
        return self._handler

    def __exit__(self, *exc):
        for lg, level, disabled in self._saved:
            lg.removeHandler(self._handler)
            lg.setLevel(level)
            lg.disabled = disabled
        logging.disable(self._prev_disable)
        return False


# ------------------------------------------------ the shared client is used


def test_the_two_paths_share_one_certificate_client():
    """Neither service may fork or re-implement the workaround locally."""
    assert ss.CertificateSSHClient is CertificateSSHClient
    assert fts.CertificateSSHClient is CertificateSSHClient
    assert issubclass(CertificateSSHClient, paramiko.SSHClient)


def test_session_builds_the_certificate_client_and_negotiates_rsa_sha2(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra415-session-ok", ssh_port=2222)
    _arrange_session(db, monkeypatch, admin_user, system, admin_user.username)
    _install_real_negotiation(monkeypatch)

    built = []

    def _factory():
        client = _LoopbackCertificateClient()
        built.append(client)
        return client

    monkeypatch.setattr(ss, "CertificateSSHClient", _factory)

    row, runtime = ss.open_session(db, admin_user, system.id)
    try:
        assert row.status == "active"
        assert len(built) == 1
        client = built[0]
        # The service built the shared certificate client, not paramiko's.
        assert isinstance(client, CertificateSSHClient)
        # And paramiko agreed on an RSA-SHA2 certificate algorithm, which is
        # the only reason the OpenSSH 10 host accepts the certificate.
        assert client.negotiated == RSA_SHA2_CERT_ALGORITHM
        assert client.negotiated != SHA1_CERT_ALGORITHM
    finally:
        ss.close_session(db, row.id, reason="test")
        runtime_registry.drop(row.id)


def test_file_transfer_builds_the_certificate_client_and_negotiates_rsa_sha2(
    db, admin_user, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra415-xfer-ok", ssh_port=2222)
    _arrange_transfer(monkeypatch)
    _install_real_negotiation(monkeypatch)

    built = []

    def _factory():
        client = _LoopbackCertificateClient()
        built.append(client)
        return client

    monkeypatch.setattr(fts, "CertificateSSHClient", _factory)

    with fts._open_sftp(db, admin_user, system, "svc") as sftp:
        assert sftp is not None

    assert len(built) == 1
    client = built[0]
    assert isinstance(client, CertificateSSHClient)
    assert client.negotiated == RSA_SHA2_CERT_ALGORITHM
    assert client.negotiated != SHA1_CERT_ALGORITHM


@pytest.mark.parametrize(
    "client_cls, expected",
    [
        (_LoopbackPlainClient, SHA1_CERT_ALGORITHM),
        (_LoopbackCertificateClient, RSA_SHA2_CERT_ALGORITHM),
    ],
)
def test_only_the_certificate_client_survives_the_openssh_10_banner(
    client_cls, expected, monkeypatch
):
    """States the regression directly: paramiko's own client still fails."""
    _install_real_negotiation(monkeypatch)
    client = client_cls()
    key = paramiko.RSAKey.generate(2048)
    key.public_blob = SimpleNamespace(key_type=RSA_CERT_KEY_TYPE)

    client.connect(username="svc", pkey=key)

    assert client.negotiated == expected


def test_genuinely_old_servers_still_get_the_sha1_certificate_algorithm(monkeypatch):
    """The workaround must not change how a real OpenSSH 7.4 is handled."""
    _install_real_negotiation(monkeypatch)
    client = _LoopbackCertificateClient(banner="SSH-2.0-OpenSSH_7.4")
    key = paramiko.RSAKey.generate(2048)
    key.public_blob = SimpleNamespace(key_type=RSA_CERT_KEY_TYPE)

    client.connect(username="svc", pkey=key)

    assert client.negotiated == SHA1_CERT_ALGORITHM


# --------------------------------------------- surrounding contracts unchanged


def test_session_connect_arguments_and_host_key_policy_are_unchanged(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra415-session-args", ssh_port=2022)
    _arrange_session(db, monkeypatch, admin_user, system, admin_user.username)
    _install_real_negotiation(monkeypatch)
    client = _LoopbackCertificateClient()
    monkeypatch.setattr(ss, "CertificateSSHClient", lambda: client)

    row, runtime = ss.open_session(db, admin_user, system.id)
    try:
        kwargs = client.connect_kwargs
        assert kwargs["hostname"] == str(system.ip_address)
        assert kwargs["port"] == 2022
        assert kwargs["username"] == admin_user.username
        assert kwargs["timeout"] == 10
        assert kwargs["allow_agent"] is False
        assert kwargs["look_for_keys"] is False
        assert kwargs["pkey"] is not None
        # No stored key yet, so the shared helper installs first-use capture and
        # never AutoAddPolicy.
        assert client.policy is not None
        assert not isinstance(client.policy, paramiko.AutoAddPolicy)
    finally:
        ss.close_session(db, row.id, reason="test")
        runtime_registry.drop(row.id)


def test_file_transfer_connect_arguments_and_host_key_policy_are_unchanged(
    db, admin_user, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra415-xfer-args", ssh_port=2022)
    _arrange_transfer(monkeypatch)
    _install_real_negotiation(monkeypatch)
    client = _LoopbackCertificateClient()
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: client)

    with fts._open_sftp(db, admin_user, system, "svc"):
        pass

    kwargs = client.connect_kwargs
    assert kwargs["hostname"] == str(system.ip_address)
    assert kwargs["port"] == 2022
    # SFTP connects as the Linux login; the certificate carries the principal.
    assert kwargs["username"] == "svc"
    assert kwargs["timeout"] == fts.connection_timeout_for(db)
    assert kwargs["allow_agent"] is False
    assert kwargs["look_for_keys"] is False
    assert client.policy is not None
    assert not isinstance(client.policy, paramiko.AutoAddPolicy)


def test_file_transfer_still_fails_closed_on_a_host_key_error(
    db, admin_user, seed_distro, group, cred, monkeypatch
):
    """Host-key verification runs before the connect and still fails closed."""
    system = _system(db, seed_distro, group, cred, "pra415-xfer-hostkey")
    _arrange_transfer(monkeypatch)
    client = _LoopbackCertificateClient()
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: client)
    monkeypatch.setattr(
        fts,
        "configure_host_key_policy",
        MagicMock(side_effect=fts.SSHConnectionError("Unsupported host key type")),
    )

    with pytest.raises(fts.FileTransferError, match="ssh_host_key_error"):
        with fts._open_sftp(db, admin_user, system, "svc"):
            pass

    assert client.connect_kwargs is None
    assert client.closed >= 1


# ------------------------------------------------------- failure closes down


def test_file_transfer_rejected_certificate_fails_closed_and_closes_the_client(
    db, admin_user, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra415-xfer-authfail")
    _arrange_transfer(monkeypatch)
    client = _LoopbackCertificateClient(
        connect_raises=paramiko.AuthenticationException("Authentication failed.")
    )
    monkeypatch.setattr(fts, "CertificateSSHClient", lambda: client)

    with _capture_service_logs() as logs:
        with pytest.raises(fts.FileTransferError) as excinfo:
            with fts._open_sftp(db, admin_user, system, "svc"):
                pass

    assert "ssh_auth_failed" in str(excinfo.value)
    # No second credential is tried inside the governed operation.
    assert client.connect_kwargs["pkey"] is not None
    assert client.closed >= 1
    assert CERT_BODY not in str(excinfo.value)
    assert CERT_BODY not in logs.blob()


def test_session_rejected_certificate_fails_closed_without_a_runtime(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra415-session-authfail")
    _arrange_session(db, monkeypatch, admin_user, system, admin_user.username)
    monkeypatch.setattr(ss, "_diagnose_allowlist_denial", lambda *a, **k: None)
    client = _LoopbackCertificateClient(
        connect_raises=paramiko.AuthenticationException("Authentication failed.")
    )
    monkeypatch.setattr(ss, "CertificateSSHClient", lambda: client)

    with _capture_service_logs() as logs:
        with pytest.raises(ss.SessionError) as excinfo:
            ss.open_session(db, admin_user, system.id)

    row = (
        db.query(SessionRow)
        .filter(SessionRow.system_id == system.id)
        .order_by(SessionRow.id.desc())
        .first()
    )
    assert row.status == "errored"
    assert runtime_registry.get(row.id) is None
    # Paramiko keeps the transport and socket after an authentication failure,
    # so a refused session has to release the client rather than rely on the
    # ledger row alone.
    assert client.closed >= 1
    # No fallback credential is attempted inside the session open.
    assert client.connect_kwargs["pkey"] is not None
    assert CERT_BODY not in str(excinfo.value)
    assert CERT_BODY not in (row.close_reason or "")
    assert CERT_BODY not in logs.blob()


def test_session_close_failure_cannot_replace_the_connect_error(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    """Teardown is best effort: it may not reshape what the caller is told."""
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra415-session-closefail")
    _arrange_session(db, monkeypatch, admin_user, system, admin_user.username)
    monkeypatch.setattr(ss, "_diagnose_allowlist_denial", lambda *a, **k: None)
    client = _LoopbackCertificateClient(
        connect_raises=paramiko.AuthenticationException("Authentication failed."),
        close_raises=OSError(TEARDOWN_SENTINEL),
    )
    monkeypatch.setattr(ss, "CertificateSSHClient", lambda: client)

    with _capture_service_logs() as logs:
        with pytest.raises(ss.SessionError) as excinfo:
            ss.open_session(db, admin_user, system.id)

    # The connect failure still reaches the caller, unchanged, and the teardown
    # error neither surfaces nor becomes the raised exception.
    assert isinstance(excinfo.value, ss.SessionError)
    assert "ssh_connect_failed" in str(excinfo.value)
    assert "Authentication failed" in str(excinfo.value)
    assert TEARDOWN_SENTINEL not in str(excinfo.value)
    assert not isinstance(excinfo.value.__cause__, OSError)
    assert client.closed >= 1

    row = (
        db.query(SessionRow)
        .filter(SessionRow.system_id == system.id)
        .order_by(SessionRow.id.desc())
        .first()
    )
    # The ledger update after the failed teardown still happened.
    assert row.status == "errored"
    assert row.close_reason.startswith("ssh_connect:")
    assert TEARDOWN_SENTINEL not in (row.close_reason or "")
    assert runtime_registry.get(row.id) is None
    # The teardown failure is recorded by category only, never by message.
    blob = logs.blob()
    assert "teardown" in blob
    assert "OSError" in blob
    assert TEARDOWN_SENTINEL not in blob
    assert CERT_BODY not in blob


def test_session_recording_failure_still_refuses_and_closes_the_certificate_client(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    """Mandatory recording is preserved on the new client."""
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra415-session-norec")
    _arrange_session(db, monkeypatch, admin_user, system, admin_user.username)
    _install_real_negotiation(monkeypatch)
    client = _LoopbackCertificateClient()
    monkeypatch.setattr(ss, "CertificateSSHClient", lambda: client)
    monkeypatch.setattr(
        rec_svc,
        "start_recording",
        MagicMock(side_effect=OSError("Permission denied")),
    )

    with _capture_service_logs() as logs:
        with pytest.raises(ss.SessionError) as excinfo:
            ss.open_session(db, admin_user, system.id)

    assert ss.UNRECORDED_ABORT_REASON in str(excinfo.value)
    row = (
        db.query(SessionRow)
        .filter(SessionRow.system_id == system.id)
        .order_by(SessionRow.id.desc())
        .first()
    )
    assert row.status == "errored"
    assert row.close_reason == ss.UNRECORDED_ABORT_REASON
    assert runtime_registry.get(row.id) is None
    assert client.closed >= 1
    assert CERT_BODY not in logs.blob()
