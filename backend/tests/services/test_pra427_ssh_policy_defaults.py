"""PRA-427: new SSH security policies default to a negotiable key exchange.

The seeded Default, a policy created through the API with the algorithm
fields omitted, and a policy created from the form all used to pin key
exchange to ``diffie-hellman-group-exchange-sha256`` alone. Current OpenSSH
servers no longer offer finite-field Diffie-Hellman by default, so a fresh
installation could not reach a stock Ubuntu 26.04 or Debian 13 host at all.
A new policy now leaves key exchange unconstrained beyond the
retired-algorithm floor, while ciphers and MACs keep their modern subsets.

These prove the default at model insertion, schema construction and a fresh
seed; prove it at the wire against a server that offers only modern key
exchange, with the legacy value as the control; and prove that existing rows,
explicit restrictions, deletion markers and the floor are all untouched.
"""

from __future__ import annotations

import importlib.util
import io
import socket
import sys
import threading
import uuid
from pathlib import Path
from typing import List, Tuple

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.api.schemas.ssh_security import (
    SSHSecurityPolicyCreate,
    SSHSecurityPolicyUpdate,
)
from app.core.auth import get_password_hash
from app.db import ssh_security_models as policy_models
from app.db.models import AppSettings, User
from app.db.ssh_security_models import SSHSecurityPolicy
from app.services import onboarding_preflight_service as preflight
from app.services import ssh_service as sshs

LEGACY_KEX = "diffie-hellman-group-exchange-sha256"

# The contract every creation path has to meet, pinned here as literals so a
# regression is reported as the wrong value and never as a missing name.
EXPECTED_KEX = ""
EXPECTED_CIPHERS = "aes256-ctr,aes192-ctr,aes128-ctr"
EXPECTED_MACS = "hmac-sha2-512,hmac-sha2-256"

# What a stock OpenSSH 10 server proposes, restricted to the names the client
# library also implements. Finite-field Diffie-Hellman is deliberately absent.
MODERN_KEX = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
)

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = _BACKEND_ROOT / "scripts" / "seed_ssh_security_policy.py"


# --------------------------------------------------------------- helpers


def _policy(db, admin_user, **overrides) -> SSHSecurityPolicy:
    """A policy row inserted the way every creation path inserts one."""
    policy = SSHSecurityPolicy(
        name=f"pra427-{uuid.uuid4().hex[:8]}", created_by=admin_user.id, **overrides
    )
    db.add(policy)
    db.flush()
    db.refresh(policy)
    return policy


def _ed25519_key() -> paramiko.PKey:
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))


class _AcceptAnyServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"


class _ModernKexServer:
    """A loopback sshd stand-in that proposes only modern key exchange.

    This is the proposal a current OpenSSH release makes out of the box, so a
    client that pins finite-field Diffie-Hellman has nothing in common with
    it. Everything past key exchange is irrelevant to these tests.
    """

    def __init__(self, kex: Tuple[str, ...]):
        self.kex = kex
        self.host_key = _ed25519_key()
        self.errors: List[BaseException] = []
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
            transport = paramiko.Transport(conn)
            transport.get_security_options().kex = self.kex
            transport.add_server_key(self.host_key)
            self._transports.append(transport)
            try:
                transport.start_server(server=_AcceptAnyServer())
            except Exception as exc:  # pylint: disable=broad-except
                self.errors.append(exc)

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
def modern_kex_server():
    offered = tuple(
        name for name in MODERN_KEX if name in sshs.supported_algorithms()["kex"]
    )
    assert offered, "the client library offers none of the modern key exchanges"
    server = _ModernKexServer(offered)
    yield server
    server.close()


def _handshake(policy: SSHSecurityPolicy, port: int) -> paramiko.SSHClient:
    """Connect the production client under ``policy``'s algorithm translation.

    The translation is the same one a managed host and onboarding preflight
    apply, so what fails or succeeds here is the policy, not the test rig.
    """
    client = sshs.CertificateSSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname="127.0.0.1",
        port=port,
        username="operator",
        password="not-checked",
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
        disabled_algorithms=preflight.build_disabled_algorithms(policy),
    )
    return client


class _KeepOpenSession:
    def __init__(self, session):
        self._session = session

    def __getattr__(self, name):
        return getattr(self._session, name)

    @staticmethod
    def close():
        return None


@pytest.fixture
def seeder(db, monkeypatch):
    """The seeder loaded as a module, with its session factory bound to ``db``."""
    spec = importlib.util.spec_from_file_location(
        "seed_ssh_security_policy_defaults", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["seed_ssh_security_policy_defaults"] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SessionLocal", lambda: _KeepOpenSession(db))
    yield module
    sys.modules.pop("seed_ssh_security_policy_defaults", None)


def _make_admin(db, seed_roles) -> User:
    tag = uuid.uuid4().hex[:8]
    admin = User(
        username=f"pra427-admin-{tag}",
        email=f"pra427-admin-{tag}@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
        roles=[seed_roles["admin"]],
    )
    db.add(admin)
    db.flush()
    return admin


# ------------------------------------------------ the default, at every path


def test_the_model_publishes_the_defaults_it_applies():
    """The schema and the form mirror these; one definition is the reference."""
    assert policy_models.DEFAULT_ALLOWED_KEX == EXPECTED_KEX
    assert policy_models.DEFAULT_ALLOWED_CIPHERS == EXPECTED_CIPHERS
    assert policy_models.DEFAULT_ALLOWED_MACS == EXPECTED_MACS


def test_model_insertion_applies_the_default(db, admin_user):
    policy = _policy(db, admin_user)

    assert policy.allowed_kex == EXPECTED_KEX
    assert policy.allowed_ciphers == EXPECTED_CIPHERS
    assert policy.allowed_macs == EXPECTED_MACS
    assert policy.require_host_key_verification is True


def test_the_create_schema_defaults_match_the_model():
    """An API create that omits the algorithm fields inserts the model default."""
    created = SSHSecurityPolicyCreate(name="pra427-schema")

    assert created.allowed_kex == EXPECTED_KEX
    assert created.allowed_ciphers == EXPECTED_CIPHERS
    assert created.allowed_macs == EXPECTED_MACS


def test_the_update_schema_still_omits_what_the_caller_did_not_send():
    """The default is for creation only; an update never implies a value."""
    update = SSHSecurityPolicyUpdate(description="touched")

    assert "allowed_kex" not in update.dict(exclude_unset=True)
    assert update.allowed_kex is None


def test_a_fresh_seed_carries_the_default(db, seed_roles, seeder):
    _make_admin(db, seed_roles)

    policy = seeder.ensure_default_policy(db)

    assert policy is not None
    assert policy.name == seeder.POLICY_NAME
    assert policy.allowed_kex == EXPECTED_KEX
    assert policy.allowed_ciphers == EXPECTED_CIPHERS
    assert policy.allowed_macs == EXPECTED_MACS
    assert policy.require_host_key_verification is True
    assert seeder.read_seed_marker(db) is not None


# ------------------------------------------------ the default, on the wire


def test_a_new_policy_negotiates_with_a_modern_only_server(
    db, admin_user, modern_kex_server
):
    """The whole point: a fresh policy reaches a current OpenSSH server."""
    policy = _policy(db, admin_user)

    client = _handshake(policy, modern_kex_server.port)
    try:
        transport = client.get_transport()
        assert transport is not None
        assert transport.is_active()
        assert transport.is_authenticated()
    finally:
        client.close()
    assert modern_kex_server.errors == []


def test_the_legacy_default_is_refused_by_that_same_server(
    db, admin_user, modern_kex_server
):
    """The control: the old pinned value has no key exchange in common."""
    policy = _policy(db, admin_user, allowed_kex=LEGACY_KEX)

    with pytest.raises(paramiko.SSHException) as excinfo:
        _handshake(policy, modern_kex_server.port)

    assert "kex" in str(excinfo.value).lower()


def test_the_default_translation_keeps_the_floor_and_the_other_lists(db, admin_user):
    policy = _policy(db, admin_user)
    supported = sshs.supported_algorithms()

    disabled = preflight.build_disabled_algorithms(policy)

    # Key exchange: nothing beyond the floor is taken away.
    for name in MODERN_KEX:
        assert name not in disabled.get("kex", [])
    assert LEGACY_KEX not in disabled.get("kex", [])
    for name in sshs._RETIRED_ALGORITHMS["kex"]:  # pylint: disable=protected-access
        assert name in disabled["kex"]
    assert "ssh-rsa" in disabled["pubkeys"]
    assert "ssh-dss" in disabled["keys"]
    # Ciphers and MACs are as narrow as before.
    assert set(supported["ciphers"]) - set(disabled["ciphers"]) == set(
        EXPECTED_CIPHERS.split(",")
    )
    assert set(supported["macs"]) - set(disabled["macs"]) == set(
        EXPECTED_MACS.split(",")
    )


# ------------------------------------------------ explicit restrictions stand


def test_an_explicit_restriction_is_still_honored(db, admin_user):
    policy = _policy(db, admin_user, allowed_kex=LEGACY_KEX)

    disabled = preflight.build_disabled_algorithms(policy)

    assert LEGACY_KEX not in disabled["kex"]
    for name in sshs.supported_algorithms()["kex"]:
        if name != LEGACY_KEX:
            assert name in disabled["kex"]


def test_a_restriction_naming_only_retired_algorithms_is_reported(db, admin_user):
    policy = _policy(db, admin_user, allowed_kex="diffie-hellman-group14-sha1")

    with pytest.raises(sshs.SSHConnectionError) as excinfo:
        preflight.build_disabled_algorithms(policy)

    assert "allows no supported key exchange algorithms" in str(excinfo.value)


def test_a_retired_algorithm_on_an_allow_list_stays_retired(db, admin_user):
    policy = _policy(
        db,
        admin_user,
        allowed_kex="diffie-hellman-group14-sha1,curve25519-sha256@libssh.org",
    )

    disabled = preflight.build_disabled_algorithms(policy)

    assert "diffie-hellman-group14-sha1" in disabled["kex"]
    assert "curve25519-sha256@libssh.org" not in disabled["kex"]


# ------------------------------------------------ existing rows are untouched


def test_a_legacy_default_policy_survives_adoption_and_restarts(db, seed_roles, seeder):
    """A row that predates the change keeps its stored lists, every start."""
    admin = _make_admin(db, seed_roles)
    legacy = SSHSecurityPolicy(
        name=seeder.POLICY_NAME,
        description="operator-tuned",
        allowed_kex=LEGACY_KEX,
        allowed_ciphers="aes256-ctr",
        created_by=admin.id,
    )
    db.add(legacy)
    db.flush()
    assert seeder.read_seed_marker(db) is None

    for _ in range(3):
        settled = seeder.ensure_default_policy(db)
        assert settled is not None
        assert settled.id == legacy.id
        db.refresh(legacy)
        assert legacy.allowed_kex == LEGACY_KEX
        assert legacy.allowed_ciphers == "aes256-ctr"
        assert legacy.description == "operator-tuned"
        assert seeder.read_seed_marker(db) is not None

    assert (
        db.query(SSHSecurityPolicy)
        .filter(SSHSecurityPolicy.name == seeder.POLICY_NAME)
        .count()
        == 1
    )


def test_a_deleted_default_is_not_resurrected_with_the_new_value(
    db, seed_roles, seeder
):
    _make_admin(db, seed_roles)
    db.add(
        AppSettings(
            setting_key=seeder.SEED_MARKER_KEY, setting_value=seeder.SEED_MARKER_VALUE
        )
    )
    db.flush()

    for _ in range(2):
        assert seeder.ensure_default_policy(db) is None
        assert seeder.read_default_policy(db) is None


def test_an_explicit_policy_row_is_never_rewritten_to_the_default(
    db, admin_user, seeder
):
    """The seeder settles only the Default; other rows are not its business."""
    other = _policy(db, admin_user, allowed_kex=LEGACY_KEX)

    seeder.ensure_default_policy(db)
    db.refresh(other)

    assert other.allowed_kex == LEGACY_KEX


def test_a_legacy_policy_recovers_through_an_ordinary_update(db, admin_user):
    """The supported recovery: set the one field, keep everything else."""
    legacy = _policy(
        db, admin_user, allowed_kex=LEGACY_KEX, allowed_ciphers="aes256-ctr"
    )

    update = SSHSecurityPolicyUpdate(allowed_kex=EXPECTED_KEX)
    for field, value in update.dict(exclude_unset=True).items():
        setattr(legacy, field, value)
    db.flush()
    db.refresh(legacy)

    assert legacy.allowed_kex == EXPECTED_KEX
    assert legacy.allowed_ciphers == "aes256-ctr"
    disabled = preflight.build_disabled_algorithms(legacy)
    for name in MODERN_KEX:
        assert name not in disabled.get("kex", [])
    assert "aes128-ctr" in disabled["ciphers"]
