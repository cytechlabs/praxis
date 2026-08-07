"""PRA-160 slice #3: ImportTrustKeyService unit tests.

GPG primitives are monkeypatched so tests run without a real gpg
binary. Real-gpg integration coverage rides on PRA-158's
``test_pra158_mirror_gpg.py`` — the import trust service reuses
those primitives.
"""

from __future__ import annotations

import pytest

from app.db.models import AirgapImportTrustKey
from app.services.airgap import import_trust_service as svc_module
from app.services.airgap.import_trust_service import (
    ImportTrustKeyExists,
    ImportTrustKeyService,
)

_ARMOR = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n"
_FPR_A = "EE00000000000000000000000000000000000001"
_FPR_B = "EE00000000000000000000000000000000000002"


@pytest.fixture
def patch_gpg(monkeypatch):
    """Stub the GPG primitives the trust service uses."""
    counter = {"n": 0}

    def fake_extract(home, armored):
        counter["n"] += 1
        return _FPR_A if counter["n"] == 1 else _FPR_B

    monkeypatch.setattr(
        svc_module.mirror_gpg,
        "import_public_and_extract_fingerprint",
        fake_extract,
    )

    def fake_run_gpg(home, args, **_):
        # Return a colon-format uid line so _extract_uid_or_fallback
        # produces a non-fallback string.
        class Result:
            stdout = (
                b"pub:::::::::\n"
                b"fpr:::::::::%s:\n"
                b"uid:::::::::Fake Operator <ops@example.com>:\n" % _FPR_A.encode()
            )

        return Result()

    monkeypatch.setattr(svc_module.mirror_gpg, "_run_gpg", fake_run_gpg)


def test_add_armored_public_key_persists_row(db, patch_gpg):
    service = ImportTrustKeyService(db)
    row = service.add_armored_public_key(_ARMOR)
    assert row.id is not None
    assert row.gpg_fingerprint == _FPR_A
    assert row.armored_public_key == _ARMOR
    assert row.deleted_at is None


def test_add_armored_public_key_duplicate_active_refuses(db, patch_gpg):
    service = ImportTrustKeyService(db)
    service.add_armored_public_key(_ARMOR)
    # Second call with the same fake-extract-fingerprint returns
    # _FPR_B (counter), so collision wouldn't fire on fingerprint.
    # Re-pin the same one explicitly: pre-seed an active row, then
    # try again with another armor that maps to the same fingerprint.
    # Simpler: poke the counter back so fake_extract returns _FPR_A
    # again.
    from app.services.airgap import import_trust_service as svc

    def fake_extract(home, armored):
        return _FPR_A

    import unittest.mock

    with unittest.mock.patch.object(
        svc.mirror_gpg, "import_public_and_extract_fingerprint", fake_extract
    ):
        with pytest.raises(ImportTrustKeyExists):
            service.add_armored_public_key(_ARMOR)


def test_list_active_excludes_soft_deleted(db, patch_gpg):
    service = ImportTrustKeyService(db)
    row1 = service.add_armored_public_key(_ARMOR)
    row2 = service.add_armored_public_key(_ARMOR)  # _FPR_B
    service.soft_delete(row1.id)

    active = service.list_active()
    assert {r.id for r in active} == {row2.id}
    all_rows = service.list_all()
    assert {r.id for r in all_rows} == {row1.id, row2.id}


def test_soft_delete_idempotent(db, patch_gpg):
    service = ImportTrustKeyService(db)
    row = service.add_armored_public_key(_ARMOR)
    first = service.soft_delete(row.id)
    second = service.soft_delete(row.id)
    assert first.deleted_at == second.deleted_at  # no churn on second call


def test_soft_delete_unknown_raises(db, patch_gpg):
    service = ImportTrustKeyService(db)
    with pytest.raises(RuntimeError, match="not found"):
        service.soft_delete(9_999_999)


def test_re_pin_after_delete_creates_fresh_row(db, patch_gpg):
    service = ImportTrustKeyService(db)
    row1 = service.add_armored_public_key(_ARMOR)
    service.soft_delete(row1.id)

    # Make fake_extract return _FPR_A again for re-pin.
    import unittest.mock

    with unittest.mock.patch.object(
        svc_module.mirror_gpg,
        "import_public_and_extract_fingerprint",
        lambda home, armored: _FPR_A,
    ):
        row2 = service.add_armored_public_key(_ARMOR)
    assert row2.id != row1.id
    assert row2.gpg_fingerprint == _FPR_A
    assert row2.deleted_at is None
    # Two rows total: deleted + active.
    rows = db.query(AirgapImportTrustKey).filter_by(gpg_fingerprint=_FPR_A).all()
    assert len(rows) == 2
