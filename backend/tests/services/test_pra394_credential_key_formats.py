"""PRA-394: stored SSH credential private keys are loaded by one shared,
type-aware loader.

Covers ``load_credential_private_key`` directly (RSA regression, Ed25519 and
ECDSA support, algorithm-appropriate strength rules, and the sanitized failures
for malformed, unsupported and encrypted keys) plus the connection path that
every SSH consumer reaches through ``SSHService._create_connection``.
"""

from __future__ import annotations

import binascii
import hashlib
import io
import logging
import os
import textwrap
import uuid
from base64 import b64encode
from unittest.mock import MagicMock

import paramiko
import pytest
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.db.models import Credential, Group, System
from app.db.ssh_security_models import SSHSecurityPolicy
from app.services import ssh_service
from app.services.ssh_service import (
    SSHConnectionError,
    SSHKeyError,
    SSHService,
    load_credential_private_key,
)

PASSPHRASE = "correct-horse-battery-staple"

# --------------------------------------------------------------- key material


def _serialize(private_key, fmt, passphrase: str | None = None) -> str:
    """Serialize a freshly generated key. Nothing here is a stored secret."""
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=fmt,
        encryption_algorithm=encryption,
    ).decode()


def _openssh(private_key, passphrase: str | None = None) -> str:
    return _serialize(private_key, serialization.PrivateFormat.OpenSSH, passphrase)


def _pkcs8(private_key) -> str:
    return _serialize(private_key, serialization.PrivateFormat.PKCS8)


def _encrypted_traditional_pem(private_key, passphrase: str, tag: str = "RSA") -> str:
    """A traditional PEM encrypted the way ``openssl rsa -aes256`` writes one.

    Written by hand rather than through ``BestAvailableEncryption`` because the
    cipher that picks varies by cryptography release, and the behavior under
    test is how the loader handles this envelope, not which cipher today's
    installed version happens to prefer. The key derivation is OpenSSL's
    EVP_BytesToKey with MD5, seeded from the first eight bytes of the IV, which
    is what the ``DEK-Info`` header describes.
    """
    der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    iv = os.urandom(16)
    secret = passphrase.encode()
    derived = b""
    block = b""
    while len(derived) < 32:
        block = hashlib.md5(block + secret + iv[:8]).digest()
        derived += block
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    encryptor = Cipher(algorithms.AES(derived[:32]), modes.CBC(iv)).encryptor()
    body = encryptor.update(padder.update(der) + padder.finalize())
    body += encryptor.finalize()
    return (
        f"-----BEGIN {tag} PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        f"DEK-Info: AES-256-CBC,{binascii.hexlify(iv).decode().upper()}\n"
        "\n"
        + textwrap.fill(b64encode(body).decode(), 64)
        + f"\n-----END {tag} PRIVATE KEY-----\n"
    )


@pytest.fixture(scope="module")
def ed25519_key() -> str:
    return _openssh(ed25519.Ed25519PrivateKey.generate())


@pytest.fixture(scope="module")
def ecdsa_key() -> str:
    return _openssh(ec.generate_private_key(ec.SECP256R1()))


@pytest.fixture(scope="module")
def rsa_key() -> str:
    return _openssh(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="module")
def rsa_key_object():
    """A key object, for tests that serialize the envelope themselves."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa_key_pem() -> str:
    """The classic ``BEGIN RSA PRIVATE KEY`` envelope Praxis accepted before."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _serialize(key, serialization.PrivateFormat.TraditionalOpenSSL)


# --------------------------------------------------------------- format support


def test_rsa_openssh_container_still_loads(rsa_key):
    key = load_credential_private_key(rsa_key)
    assert key.get_name() == "ssh-rsa"


def test_rsa_traditional_pem_still_loads(rsa_key_pem):
    key = load_credential_private_key(rsa_key_pem)
    assert key.get_name() == "ssh-rsa"


def test_ed25519_key_loads(ed25519_key):
    key = load_credential_private_key(ed25519_key)
    assert key.get_name() == "ssh-ed25519"


def test_ecdsa_key_loads(ecdsa_key):
    key = load_credential_private_key(ecdsa_key)
    assert key.get_name() == "ecdsa-sha2-nistp256"


@pytest.mark.parametrize(
    "curve,expected",
    [
        (ec.SECP384R1(), "ecdsa-sha2-nistp384"),
        (ec.SECP521R1(), "ecdsa-sha2-nistp521"),
    ],
)
def test_larger_ecdsa_curves_load(curve, expected):
    key = load_credential_private_key(_openssh(ec.generate_private_key(curve)))
    assert key.get_name() == expected


def test_carriage_returns_do_not_break_loading(rsa_key):
    """Keys pasted through a browser can arrive with CRLF line endings."""
    key = load_credential_private_key(rsa_key.replace("\n", "\r\n"))
    assert key.get_name() == "ssh-rsa"


# --------------------------------------------------------------- rejected formats


def test_dsa_key_is_reported_as_unsupported():
    key_text = _openssh(dsa.generate_private_key(key_size=1024))
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text)
    assert "DSA format" in str(excinfo.value)
    assert "Ed25519" in str(excinfo.value)


def test_pkcs8_container_is_reported_as_unsupported():
    key_text = _pkcs8(ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text)
    assert "PKCS#8 format" in str(excinfo.value)


def test_putty_key_is_reported_as_unsupported():
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(
            "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: k\n"
        )
    assert "PuTTY PPK format" in str(excinfo.value)


@pytest.mark.parametrize("key_text", [None, "", "   \n\t "])
def test_missing_key_is_reported_as_missing(key_text):
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text)
    assert "No SSH private key" in str(excinfo.value)


def test_malformed_key_is_reported_as_unreadable():
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key("-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n")
    assert "could not be read" in str(excinfo.value)


def test_truncated_key_body_is_reported_as_unreadable(ed25519_key):
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(ed25519_key[:120])
    assert "could not be read" in str(excinfo.value)


# --------------------------------------------------------------- encrypted keys


def test_encrypted_key_without_passphrase_names_the_secret_field():
    key_text = _openssh(ed25519.Ed25519PrivateKey.generate(), PASSPHRASE)
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text)
    message = str(excinfo.value)
    assert "encrypted" in message
    assert "ssh_passphrase" in message


def test_encrypted_key_loads_with_the_stored_passphrase():
    key_text = _openssh(ed25519.Ed25519PrivateKey.generate(), PASSPHRASE)
    key = load_credential_private_key(key_text, passphrase=PASSPHRASE)
    assert key.get_name() == "ssh-ed25519"


def test_encrypted_pem_key_loads_with_the_stored_passphrase():
    """Whatever cipher the installed cryptography picks for this envelope."""
    key_text = _serialize(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        serialization.PrivateFormat.TraditionalOpenSSL,
        PASSPHRASE,
    )
    key = load_credential_private_key(key_text, passphrase=PASSPHRASE)
    assert key.get_name() == "ssh-rsa"


def test_encrypted_traditional_rsa_pem_loads(rsa_key_object):
    """The envelope that fails on a strict DER parser, at the AES-256 default.

    Paramiko decrypts a ``Proc-Type: 4,ENCRYPTED`` body but leaves its block
    padding attached, so whether it can read this key at all depends on how
    strict the installed DER parser is. The loader must produce the key either
    way.
    """
    key_text = _encrypted_traditional_pem(rsa_key_object, PASSPHRASE)
    key = load_credential_private_key(key_text, passphrase=PASSPHRASE)
    assert key.get_name() == "ssh-rsa"


def _reject_encrypted_pem(monkeypatch):
    """Make Paramiko fail on an encrypted PEM the way a strict DER parser does.

    Paramiko decrypts a ``Proc-Type: 4,ENCRYPTED`` body and hands the result on
    with its block padding still attached. A lenient DER parser ignores those
    trailing bytes and a strict one rejects them, so whether the shipped
    Paramiko can read this envelope at all depends on the installed
    cryptography. Forcing the rejection pins the loader's behavior on the side
    of that line the release runs on, from any development environment.
    Unencrypted reads are left alone, which is what the fallback re-reads.
    """
    original = paramiko.pkey.PKey._read_private_key_pem

    def _reject(self, lines, end, password):
        if password is not None:
            raise paramiko.SSHException("Could not deserialize key data")
        return original(self, lines, end, password)

    monkeypatch.setattr(paramiko.pkey.PKey, "_read_private_key_pem", _reject)


def test_compatibility_path_loads_what_paramiko_rejects(monkeypatch, rsa_key_object):
    """Proof the fallback carries the load, on any dependency set."""
    key_text = _encrypted_traditional_pem(rsa_key_object, PASSPHRASE)
    _reject_encrypted_pem(monkeypatch)

    with pytest.raises(paramiko.SSHException):
        paramiko.RSAKey.from_private_key(io.StringIO(key_text), password=PASSPHRASE)

    key = load_credential_private_key(key_text, passphrase=PASSPHRASE)
    assert key.get_name() == "ssh-rsa"


def test_unwrapped_pem_carries_no_encryption_envelope(rsa_key_object):
    """The text handed back to Paramiko is the same key without the envelope."""
    key_text = _encrypted_traditional_pem(rsa_key_object, PASSPHRASE)
    unwrapped = ssh_service._unwrap_traditional_pem(key_text, PASSPHRASE)

    assert unwrapped is not None
    assert "Proc-Type" not in unwrapped
    assert "DEK-Info" not in unwrapped
    expected = rsa_key_object.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    assert unwrapped == expected


def test_unwrapping_returns_nothing_for_a_wrong_passphrase(rsa_key_object):
    key_text = _encrypted_traditional_pem(rsa_key_object, PASSPHRASE)
    assert ssh_service._unwrap_traditional_pem(key_text, "wrong-passphrase") is None


def test_encrypted_traditional_ec_pem_loads_through_the_compatibility_path(monkeypatch):
    _reject_encrypted_pem(monkeypatch)
    key_text = _encrypted_traditional_pem(
        ec.generate_private_key(ec.SECP256R1()), PASSPHRASE, tag="EC"
    )
    key = load_credential_private_key(key_text, passphrase=PASSPHRASE)
    assert key.get_name() == "ecdsa-sha2-nistp256"


def test_compatibility_path_still_enforces_the_rsa_floor(monkeypatch):
    """Unwrapping the envelope must not bypass the strength rule."""
    _reject_encrypted_pem(monkeypatch)
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(
            _encrypted_traditional_pem(weak, PASSPHRASE), passphrase=PASSPHRASE
        )
    assert "1024 bits" in str(excinfo.value)


def test_compatibility_path_rejects_a_wrong_passphrase(monkeypatch, rsa_key_object):
    _reject_encrypted_pem(monkeypatch)
    key_text = _encrypted_traditional_pem(rsa_key_object, PASSPHRASE)
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text, passphrase="wrong-passphrase")
    message = str(excinfo.value)
    assert "could not be decrypted" in message
    assert PASSPHRASE not in message
    assert "wrong-passphrase" not in message


def test_compatibility_path_does_not_admit_an_encrypted_pkcs8_key(monkeypatch):
    """PKCS#8 stays rejected by name; the unwrap path must not smuggle it in."""
    _reject_encrypted_pem(monkeypatch)
    key_text = _serialize(
        ed25519.Ed25519PrivateKey.generate(),
        serialization.PrivateFormat.PKCS8,
        PASSPHRASE,
    )
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text, passphrase=PASSPHRASE)
    assert "PKCS#8 format" in str(excinfo.value)


def test_compatibility_path_does_not_admit_an_encrypted_dsa_key(monkeypatch):
    """DSA stays rejected by name even with a usable passphrase."""
    _reject_encrypted_pem(monkeypatch)
    key_text = _encrypted_traditional_pem(
        dsa.generate_private_key(key_size=1024), PASSPHRASE, tag="DSA"
    )
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text, passphrase=PASSPHRASE)
    assert "DSA format" in str(excinfo.value)


def test_wrong_passphrase_is_reported_as_a_decryption_failure():
    """A wrong passphrase must not be flattened into "unreadable key"."""
    key_text = _openssh(ed25519.Ed25519PrivateKey.generate(), PASSPHRASE)
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text, passphrase="wrong-passphrase")
    assert "could not be decrypted" in str(excinfo.value)


# --------------------------------------------------------------- strength rules


def test_rsa_below_the_builtin_floor_is_rejected():
    key_text = _openssh(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text)
    assert "1024 bits" in str(excinfo.value)
    assert "2048" in str(excinfo.value)


def test_configured_minimum_raises_the_rsa_floor(rsa_key):
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(rsa_key, minimum_rsa_bits=4096)
    assert "4096" in str(excinfo.value)


def test_configured_minimum_below_the_builtin_floor_is_not_an_opt_out():
    key_text = _openssh(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text, minimum_rsa_bits=512)
    assert "2048 bits" in str(excinfo.value)


@pytest.mark.parametrize("fixture_name", ["ed25519_key", "ecdsa_key"])
def test_rsa_bit_rule_does_not_apply_to_modern_algorithms(request, fixture_name):
    """A 256-bit Ed25519/ECDSA key is strong; the RSA modulus rule is not it."""
    key_text = request.getfixturevalue(fixture_name)
    key = load_credential_private_key(key_text, minimum_rsa_bits=4096)
    assert key.get_bits() == 256


# --------------------------------------------------------------- redaction


@pytest.mark.parametrize(
    "key_text,marker",
    [
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nc2VjcmV0LWJvZHk=\n", "c2VjcmV0LWJvZHk="),
        ("PuTTY-User-Key-File-2: ssh-rsa\n", "PuTTY-User-Key-File"),
    ],
)
def test_failures_do_not_echo_the_supplied_material(key_text, marker):
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text)
    assert marker not in str(excinfo.value)


def test_encrypted_key_failure_does_not_echo_key_or_passphrase():
    key_text = _openssh(ed25519.Ed25519PrivateKey.generate(), PASSPHRASE)
    body = [line for line in key_text.splitlines() if not line.startswith("-----")]
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(key_text, passphrase="wrong-passphrase")
    message = str(excinfo.value)
    assert PASSPHRASE not in message
    assert "wrong-passphrase" not in message
    for line in body:
        assert line not in message


class _capture_ssh_logs:  # pylint: disable=invalid-name
    """Collect the SSH service log records emitted in the block.

    Establishes its own logging preconditions, because an earlier test may have
    left a global ``logging.disable``, a disabled logger, or a raised level in
    place, any of which would make this capture silently empty and the
    assertions vacuous. The handler is attached to the service logger directly
    so capture does not depend on propagation.
    """

    def __enter__(self) -> list:
        self.records: list = []
        self._handler = logging.Handler()
        self._handler.emit = self.records.append
        self._logger = ssh_service.logger
        self._prev_disable = logging.root.manager.disable
        self._saved = (self._logger.level, self._logger.disabled)
        logging.disable(logging.NOTSET)
        self._logger.disabled = False
        self._logger.setLevel(logging.DEBUG)
        self._logger.addHandler(self._handler)
        return self.records

    def __exit__(self, *exc):
        self._logger.removeHandler(self._handler)
        self._logger.setLevel(self._saved[0])
        self._logger.disabled = self._saved[1]
        logging.disable(self._prev_disable)
        return False


def test_rejected_key_is_not_logged_verbatim():
    """``validate_ssh_key`` logs the sanitized reason, never the key body."""
    key_text = _openssh(ed25519.Ed25519PrivateKey.generate(), PASSPHRASE)
    body = [line for line in key_text.splitlines() if not line.startswith("-----")]
    db = MagicMock()
    db.query.return_value.first.return_value = None

    with _capture_ssh_logs() as records:
        assert SSHService(db).validate_ssh_key(key_text) is False

    logged = "\n".join(logging.Formatter().format(record) for record in records)
    assert "ssh_passphrase" in logged
    for line in body:
        assert line not in logged


# --------------------------------------------------------------- validate_ssh_key


@pytest.mark.parametrize("fixture_name", ["rsa_key", "ed25519_key", "ecdsa_key"])
def test_validate_ssh_key_accepts_every_supported_algorithm(request, fixture_name):
    db = MagicMock()
    db.query.return_value.first.return_value = None
    assert SSHService(db).validate_ssh_key(request.getfixturevalue(fixture_name))


def test_validate_ssh_key_rejects_a_weak_rsa_key():
    db = MagicMock()
    db.query.return_value.first.return_value = None
    key_text = _openssh(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    assert SSHService(db).validate_ssh_key(key_text) is False


def test_validate_ssh_key_accepts_an_encrypted_key_with_its_passphrase():
    db = MagicMock()
    db.query.return_value.first.return_value = None
    key_text = _openssh(ed25519.Ed25519PrivateKey.generate(), PASSPHRASE)
    service = SSHService(db)
    assert service.validate_ssh_key(key_text) is False
    assert service.validate_ssh_key(key_text, passphrase=PASSPHRASE) is True


# --------------------------------------------------------------- connection path


def _mk_system(db, seed_distro, admin_user, *, minimum_key_size=None) -> System:
    tag = uuid.uuid4().hex[:8]
    group = Group(name=f"pra394-{tag}")
    credential = Credential(
        name=f"pra394-cred-{tag}",
        auth_method="ssh_key",
        username="praxis",
        vault_path=f"praxis/credentials/pra394-{tag}",
    )
    db.add_all([group, credential])
    db.flush()
    policy_id = None
    if minimum_key_size is not None:
        policy = SSHSecurityPolicy(
            name=f"pra394-pol-{tag}",
            require_host_key_verification=False,
            minimum_key_size=minimum_key_size,
            created_by=admin_user.id,
        )
        db.add(policy)
        db.flush()
        policy_id = policy.id
    system = System(
        hostname=f"pra394-{tag}.example.com",
        ip_address="10.94.0.1",
        distro_id=seed_distro.id,
        os_version="24.04",
        status="Active",
        group_id=group.id,
        credentials_id=credential.id,
        ssh_security_policy_id=policy_id,
    )
    db.add(system)
    db.flush()
    return system


@pytest.fixture
def connect_probe(monkeypatch):
    """Capture the ``connect`` kwargs without opening a socket."""
    client = MagicMock(spec=paramiko.SSHClient)
    monkeypatch.setattr(ssh_service.paramiko, "SSHClient", lambda: client)
    monkeypatch.setattr(
        ssh_service.SSHService, "_on_connected", lambda self, *a, **k: None
    )
    return client


def _patch_vault(monkeypatch, secret):
    vault = MagicMock()
    vault.read_secret.return_value = secret
    monkeypatch.setattr(ssh_service, "VaultService", lambda db: vault)


@pytest.mark.parametrize(
    "fixture_name,expected",
    [
        ("rsa_key", "ssh-rsa"),
        ("ed25519_key", "ssh-ed25519"),
        ("ecdsa_key", "ecdsa-sha2-nistp256"),
    ],
)
def test_connection_authenticates_with_every_supported_algorithm(
    request,
    db,
    seed_distro,
    admin_user,
    monkeypatch,
    connect_probe,
    fixture_name,
    expected,
):
    system = _mk_system(db, seed_distro, admin_user)
    _patch_vault(
        monkeypatch,
        {"username": "praxis", "ssh_key": request.getfixturevalue(fixture_name)},
    )

    assert SSHService(db)._create_connection(system) is connect_probe

    pkey = connect_probe.connect.call_args.kwargs["pkey"]
    assert pkey.get_name() == expected


def test_connection_uses_the_stored_passphrase_for_an_encrypted_key(
    db, seed_distro, admin_user, monkeypatch, connect_probe
):
    system = _mk_system(db, seed_distro, admin_user)
    _patch_vault(
        monkeypatch,
        {
            "username": "praxis",
            "ssh_key": _openssh(ed25519.Ed25519PrivateKey.generate(), PASSPHRASE),
            "ssh_passphrase": PASSPHRASE,
        },
    )

    SSHService(db)._create_connection(system)

    assert connect_probe.connect.call_args.kwargs["pkey"].get_name() == "ssh-ed25519"


def test_connection_reports_an_encrypted_key_without_its_passphrase(
    db, seed_distro, admin_user, monkeypatch, connect_probe
):
    system = _mk_system(db, seed_distro, admin_user)
    key_text = _openssh(ed25519.Ed25519PrivateKey.generate(), PASSPHRASE)
    _patch_vault(monkeypatch, {"username": "praxis", "ssh_key": key_text})

    with pytest.raises(SSHConnectionError) as excinfo:
        SSHService(db)._create_connection(system)

    message = str(excinfo.value)
    assert "ssh_passphrase" in message
    assert PASSPHRASE not in message
    connect_probe.connect.assert_not_called()


def test_connection_applies_the_configured_minimum_key_size(
    db, seed_distro, admin_user, monkeypatch, connect_probe, rsa_key
):
    system = _mk_system(db, seed_distro, admin_user, minimum_key_size=4096)
    _patch_vault(monkeypatch, {"username": "praxis", "ssh_key": rsa_key})

    with pytest.raises(SSHConnectionError) as excinfo:
        SSHService(db)._create_connection(system)

    assert "4096" in str(excinfo.value)
    connect_probe.connect.assert_not_called()


def test_connection_does_not_apply_the_rsa_rule_to_ed25519(
    db, seed_distro, admin_user, monkeypatch, connect_probe, ed25519_key
):
    """A policy raising the RSA floor must not lock out a modern key."""
    system = _mk_system(db, seed_distro, admin_user, minimum_key_size=4096)
    _patch_vault(monkeypatch, {"username": "praxis", "ssh_key": ed25519_key})

    SSHService(db)._create_connection(system)

    assert connect_probe.connect.call_args.kwargs["pkey"].get_name() == "ssh-ed25519"
