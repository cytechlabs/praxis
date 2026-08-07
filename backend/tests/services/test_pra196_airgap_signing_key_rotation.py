"""PRA-196: airgap bundle signing-key rotation/retire/list service tests.

GPG is monkeypatched (same shape as the PRA-160 service tests); Vault is the
in-memory ``mock_vault``. ``fake_generate`` returns _FPR_A on the first call
and _FPR_B on the second, so bootstrap → rotate produces A (rotating_out) + B
(active).
"""

from __future__ import annotations

import pytest

from app.db.models import AirgapBundleSigningKey
from app.services.airgap import signing_key_service as svc_module
from app.services.airgap.signing_key_service import (
    AirgapBundleSigningKeyService,
    NoActiveKeyToRotate,
    RetireActiveKeyRefused,
    SigningKeyNotFound,
)

_FPR_A = "AA00000000000000000000000000000000000001"
_FPR_B = "BB00000000000000000000000000000000000002"


@pytest.fixture
def patch_gpg(monkeypatch):
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


def test_rotate_demotes_active_and_creates_new(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    first = service.ensure_active()
    assert first.gpg_fingerprint == _FPR_A

    old, new = service.rotate()
    assert old.id == first.id
    assert old.gpg_fingerprint == _FPR_A
    assert old.status == "rotating_out"
    assert new.gpg_fingerprint == _FPR_B
    assert new.status == "active"

    # Exactly one active key, and it's the new one.
    actives = (
        db.query(AirgapBundleSigningKey)
        .filter(AirgapBundleSigningKey.status == "active")
        .all()
    )
    assert len(actives) == 1
    assert actives[0].id == new.id

    # Old key material is retained (still needed to verify already-exported
    # bundles); new material is written too.
    assert first.vault_path in mock_vault.secrets
    assert new.vault_path in mock_vault.secrets


def test_rotate_without_active_raises(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    with pytest.raises(NoActiveKeyToRotate):
        service.rotate()


def test_list_keys_returns_active_and_rotating_out(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    service.ensure_active()
    service.rotate()
    keys = service.list_keys()
    assert len(keys) == 2
    by_fpr = {k.gpg_fingerprint: k.status for k in keys}
    assert by_fpr == {_FPR_A: "rotating_out", _FPR_B: "active"}


def test_retire_rotating_out_key(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    service.ensure_active()
    old, _new = service.rotate()
    retired = service.retire(old.id)
    assert retired.id == old.id
    assert retired.status == "retired"


def test_retire_active_refused(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    key = service.ensure_active()
    with pytest.raises(RetireActiveKeyRefused):
        service.retire(key.id)
    db.refresh(key)
    assert key.status == "active"


def test_retire_is_idempotent_on_retired(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    service.ensure_active()
    old, _new = service.rotate()
    service.retire(old.id)
    again = service.retire(old.id)
    assert again.status == "retired"


def test_retire_missing_raises(db, mock_vault, patch_gpg):
    service = AirgapBundleSigningKeyService(db)
    with pytest.raises(SigningKeyNotFound):
        service.retire(999_999)
