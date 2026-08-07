"""PRA-160 slice #1: AirgapBundleSigningKeyService tests.

GPG subprocess is monkeypatched (same shape as PRA-158's
``test_pra158_mirror_signing_key_service.py``). DB is per-test
``db`` fixture; Vault is the in-memory ``mock_vault``.
"""

from __future__ import annotations

import pytest

from app.db.models import AirgapBundleSigningKey
from app.services.airgap import signing_key_service as svc_module
from app.services.airgap.signing_key_service import (
    AirgapBundleSigningKeyService,
    vault_path_for,
)

# Predictable test fingerprints.
_FPR_A = "AA00000000000000000000000000000000000001"
_FPR_B = "BB00000000000000000000000000000000000002"


@pytest.fixture
def patch_gpg(monkeypatch):
    """Replace mirror_gpg primitives with deterministic fakes."""
    counter = {"n": 0}

    def fake_generate(home, slug):
        counter["n"] += 1
        return _FPR_A if counter["n"] == 1 else _FPR_B

    def fake_export_secret(home, fpr):
        return (
            f"-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE-PRIV-{fpr}\n-----END-----\n"
        )

    def fake_export_public(home, fpr):
        return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUB-{fpr}\n-----END-----\n"

    monkeypatch.setattr(svc_module.mirror_gpg, "generate_keypair", fake_generate)
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_secret_armored", fake_export_secret
    )
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_public_armored", fake_export_public
    )


def test_ensure_active_lazy_creates_first_call(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    key = service.ensure_active()
    assert key.id is not None
    assert key.status == "active"
    assert key.gpg_fingerprint == _FPR_A
    assert key.key_uid == f"Praxis Airgap Bundle Signing {_FPR_A}"
    assert key.vault_path == vault_path_for(_FPR_A)
    assert key.armored_public_key and "FAKE-PUB-" in key.armored_public_key
    secret = mock_vault.secrets[key.vault_path]
    assert "FAKE-PUB-" in secret["public_armored"]
    assert "FAKE-PRIV-" in secret["private_armored"]


def test_ensure_active_is_idempotent(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    first = service.ensure_active()
    second = service.ensure_active()
    assert first.id == second.id
    rows = db.query(AirgapBundleSigningKey).all()
    assert len(rows) == 1


def test_get_active_returns_none_when_absent(db):
    service = AirgapBundleSigningKeyService(db)
    assert service.get_active() is None


def test_get_public_armored_uses_db_column(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    key = service.ensure_active()
    # Wipe Vault so a column-backed read is the only option.
    mock_vault.secrets.clear()
    armored = service.get_public_armored(key)
    assert "FAKE-PUB-" in armored


def test_get_public_armored_falls_back_to_vault(db, mock_vault, patch_gpg):
    """If the DB column is empty (eg. legacy row), service backfills
    from Vault and persists."""
    service = AirgapBundleSigningKeyService(db)
    key = service.ensure_active()
    key.armored_public_key = None
    db.add(key)
    db.commit()

    armored = service.get_public_armored(key)
    assert "FAKE-PUB-" in armored
    db.refresh(key)
    assert key.armored_public_key == armored


def test_active_partial_unique_index_enforced(
    db, mock_vault, patch_gpg
):  # pylint: disable=unused-argument
    """Two manually-inserted ``active`` rows collide via the partial
    unique index (DB belt). The service path goes through
    ``ensure_active``'s race recovery so it never produces this state,
    but the constraint is the suspenders."""
    service = AirgapBundleSigningKeyService(db)
    service.ensure_active()
    rogue = AirgapBundleSigningKey(
        status="active",
        gpg_fingerprint="ZZ00000000000000000000000000000000000099",
        key_uid="rogue",
        vault_path="praxis/bundle-signing-key/rogue",
    )
    db.add(rogue)
    with pytest.raises(Exception):
        db.commit()
    db.rollback()
