"""PRA-266 follow-up: official builds ship a built-in license verification PUBLIC
key so a purchased license applies with no env setup. PRAXIS_LICENSE_PUBLIC_KEY
still overrides. The private signing key is never embedded.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.core.entitlements import LICENSE_STATE_INVALID
from app.services import license_service

ENV = license_service.LICENSE_PUBLIC_KEY_ENV


def test_builtin_public_key_used_when_env_unset(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    assert (
        license_service._public_key_pem() == license_service.DEFAULT_LICENSE_PUBLIC_KEY
    )
    assert license_service._public_key_pem()  # never None -> no "no key" error path


def test_env_public_key_overrides_builtin(monkeypatch):
    monkeypatch.setenv(
        ENV, "-----BEGIN PUBLIC KEY-----\ncustom\n-----END PUBLIC KEY-----"
    )
    assert "custom" in license_service._public_key_pem()
    assert (
        license_service._public_key_pem() != license_service.DEFAULT_LICENSE_PUBLIC_KEY
    )


def test_builtin_key_is_a_valid_ed25519_public_key():
    # Catches a paste/format error in the embedded key.
    key = serialization.load_pem_public_key(
        license_service.DEFAULT_LICENSE_PUBLIC_KEY.encode()
    )
    assert isinstance(key, Ed25519PublicKey)


def test_no_verification_key_error_emitted_with_builtin(db, monkeypatch):
    """With the env unset, applying a license verifies against the built-in key —
    a wrong-key token fails on SIGNATURE, not with a 'no verification key' error."""
    monkeypatch.delenv(ENV, raising=False)
    priv = Ed25519PrivateKey.generate()  # NOT the built-in key
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    iid = license_service.get_or_create_instance_id(db)
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "tier": "pro",
            "host_cap": 50,
            "instance_id": iid,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=1)).timestamp()),
            "entitlements": [],
        },
        priv_pem,
        algorithm="EdDSA",
    )
    with pytest.raises(license_service.LicenseError) as ei:
        license_service.apply_license(db, token)
    assert ei.value.state == LICENSE_STATE_INVALID
    # The built-in key was used to verify -> signature failure, NOT "no key".
    assert "verification key" not in ei.value.message
    assert ei.value.message == "invalid license signature"
