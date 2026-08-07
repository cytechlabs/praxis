"""PRA-134: public-side integration contract for the bundled praxis_ee package.

The real praxis_ee lives in a separate private repo; here we exercise the
CONTRACT it must satisfy with a faithful fake whose register_ee installs the
license public key exactly as the real one does. Proves:

  - no praxis_ee              -> free
  - bundled praxis_ee, no key -> free
  - bundled praxis_ee, valid license -> paid entitlements from the license
"""

import os
import sys
import types
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.entitlements import (
    ACCESS_SESSION_LOCKS,
    COMMANDS_METRICS,
    TIER_PRO,
    registry,
)
from app.ee.loader import load_ee
from app.services import license_service

PUB_ENV = license_service.LICENSE_PUBLIC_KEY_ENV


def _keypair():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return priv_pem, pub_pem


def _fake_ee(pub_pem):
    """A praxis_ee stand-in whose register_ee installs the verification key and
    grants nothing (matching the real thin hook)."""
    mod = types.ModuleType("praxis_ee")

    def register_ee(*, registry, app=None, db_session_factory=None, config=None):
        if not os.getenv(PUB_ENV, "").strip():
            os.environ[PUB_ENV] = pub_pem

    mod.register_ee = register_ee
    return mod


def _mint(priv_pem, *, instance_id, entitlements):
    now = datetime.now(timezone.utc)
    payload = {
        "tier": TIER_PRO,
        "host_cap": 50,
        "issued_to": "ACME Corp",
        "instance_id": instance_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=365)).timestamp()),
        "entitlements": entitlements,
        "license_id": "lic-1",
    }
    return jwt.encode(payload, priv_pem, algorithm="EdDSA")


def test_no_praxis_ee_is_free(monkeypatch):
    monkeypatch.delitem(sys.modules, "praxis_ee", raising=False)
    monkeypatch.delenv(PUB_ENV, raising=False)
    registry.reset()
    assert load_ee(registry=registry) is False
    assert registry.edition == "free"


def test_bundled_ee_no_license_is_free(monkeypatch, db):
    priv, pub = _keypair()
    monkeypatch.delenv(PUB_ENV, raising=False)
    monkeypatch.setitem(sys.modules, "praxis_ee", _fake_ee(pub))
    registry.reset()
    assert load_ee(registry=registry) is True  # EE registered (key installed)
    # No stored license -> hydrate is a no-op -> still free.
    license_service.hydrate_registry(db)
    assert registry.edition == "free"
    assert registry.is_active(ACCESS_SESSION_LOCKS) is False


def test_bundled_ee_valid_license_unlocks_paid(monkeypatch, db):
    priv, pub = _keypair()
    monkeypatch.delenv(PUB_ENV, raising=False)
    monkeypatch.setitem(sys.modules, "praxis_ee", _fake_ee(pub))
    registry.reset()
    load_ee(registry=registry)  # installs the verification key
    assert os.getenv(PUB_ENV, "").strip()  # key is now available to the spine

    iid = license_service.get_or_create_instance_id(db)
    token = _mint(
        priv, instance_id=iid, entitlements=[ACCESS_SESSION_LOCKS, COMMANDS_METRICS]
    )
    license_service.apply_license(db, token)

    assert registry.tier == TIER_PRO
    assert registry.host_cap == 50
    assert registry.is_active(ACCESS_SESSION_LOCKS) is True
    assert registry.is_active(COMMANDS_METRICS) is True


def test_bundled_ee_grants_only_licensed_entitlements(monkeypatch, db):
    priv, pub = _keypair()
    monkeypatch.delenv(PUB_ENV, raising=False)
    monkeypatch.setitem(sys.modules, "praxis_ee", _fake_ee(pub))
    registry.reset()
    load_ee(registry=registry)
    iid = license_service.get_or_create_instance_id(db)
    # Only one entitlement granted -> the others stay locked.
    token = _mint(priv, instance_id=iid, entitlements=[COMMANDS_METRICS])
    license_service.apply_license(db, token)
    assert registry.is_active(COMMANDS_METRICS) is True
    assert registry.is_active(ACCESS_SESSION_LOCKS) is False
