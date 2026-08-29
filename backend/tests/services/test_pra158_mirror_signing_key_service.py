"""PRA-158 slice #1: MirrorSigningKeyService tests.

GPG subprocess is monkeypatched so unit tests run instantly without
needing the gpg binary. Real-gpg integration lives in
``test_pra158_mirror_gpg.py``.

DB is the per-test ``db`` fixture (savepoint rollback). Vault is the
in-memory ``mock_vault`` from conftest, exposed at
``app.services.mirror_signing_key_service.VaultService``.
"""

from __future__ import annotations

import pytest

from app.db.models import MirrorRepo, MirrorSigningKey
from app.services import mirror_signing_key_service as svc_module
from app.services.mirror_signing_key_service import (
    MirrorSigningKeyService,
    vault_path_for,
)
from tests.helpers.armor import pgp_private_block

# A predictable 40-char hex "fingerprint" for tests; differs from any
# real GPG output so cross-talk between tests is obvious.
_TEST_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
_TEST_FPR_2 = "1111111111111111111111111111111111111111"


@pytest.fixture
def patch_gpg(monkeypatch):
    """Replace gpg subprocess calls with deterministic fakes.

    ``generate_keypair`` returns a slug-keyed fingerprint so multiple
    mirrors get distinct rows; the armored material is a marker string
    so tests can verify Vault round-trip without parsing real PGP.
    """
    fpr_by_slug: dict[str, str] = {}

    def fake_generate(home, slug):
        fpr = fpr_by_slug.setdefault(
            slug, _TEST_FPR if not fpr_by_slug else _TEST_FPR_2
        )
        return fpr

    def fake_export_secret(home, fpr):
        return pgp_private_block(f"FAKE-SECRET-{fpr}")

    def fake_export_public(home, fpr):
        return (
            f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUBLIC-{fpr}\n-----END-----\n"
        )

    monkeypatch.setattr(svc_module.mirror_gpg, "generate_keypair", fake_generate)
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_secret_armored", fake_export_secret
    )
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_public_armored", fake_export_public
    )


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="test-mirror",
        display_name="Test Mirror",
        package_family="deb",
        upstream_url="http://example.com/ubuntu",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


# ---------------------------------------------------------------------------
# ensure_active — generation + idempotency
# ---------------------------------------------------------------------------


def test_ensure_active_lazy_creates_first_call(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    key = service.ensure_active(mirror)
    assert key.id is not None
    assert key.mirror_repo_id == mirror.id
    assert key.status == "active"
    assert key.gpg_fingerprint == _TEST_FPR
    assert key.key_uid == f"Praxis Mirror Signing test-mirror {_TEST_FPR}"
    assert key.vault_path == vault_path_for("test-mirror", _TEST_FPR)
    # Vault round-trip: both halves stored.
    secret = mock_vault.secrets[key.vault_path]
    assert "FAKE-PUBLIC-" in secret["public_armored"]
    assert "FAKE-SECRET-" in secret["private_armored"]


def test_ensure_active_is_idempotent(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    first = service.ensure_active(mirror)
    second = service.ensure_active(mirror)
    assert first.id == second.id
    # And no duplicate rows landed in DB.
    rows = db.query(MirrorSigningKey).filter_by(mirror_repo_id=mirror.id).all()
    assert len(rows) == 1


def test_get_active_returns_none_when_absent(db, mirror):
    service = MirrorSigningKeyService(db)
    assert service.get_active(mirror.id) is None


def test_get_public_armored_reads_from_db_column_for_new_keys(
    db, mock_vault, patch_gpg, mirror
):
    """PRA-158 #3a: new keys cache armored_public_key on the row at
    generation. get_public_armored returns it without touching Vault.
    """
    service = MirrorSigningKeyService(db)
    key = service.ensure_active(mirror)
    assert key.armored_public_key is not None
    assert "BEGIN PGP PUBLIC KEY BLOCK" in key.armored_public_key

    # Drop the Vault entry — DB-backed read should still work.
    mock_vault.secrets.pop(key.vault_path)
    armored = service.get_public_armored(key)
    assert "FAKE-PUBLIC-" in armored
    assert "BEGIN PGP PUBLIC KEY BLOCK" in armored


def test_get_public_armored_lazy_backfills_pre_pra158_3a_rows(
    db, mock_vault, patch_gpg, mirror
):
    """Slice #1 rows have armored_public_key NULL (column added in
    #3a). First read backfills from Vault and persists to the DB.
    """
    service = MirrorSigningKeyService(db)
    key = service.ensure_active(mirror)
    # Simulate a slice #1 row by clearing the column AFTER generation.
    key.armored_public_key = None
    db.commit()
    db.refresh(key)
    assert key.armored_public_key is None

    armored = service.get_public_armored(key)
    assert "FAKE-PUBLIC-" in armored
    db.refresh(key)
    assert key.armored_public_key == armored  # backfill persisted

    # Subsequent reads: DB-only, even if Vault disappears.
    mock_vault.secrets.pop(key.vault_path)
    armored2 = service.get_public_armored(key)
    assert armored2 == armored


def test_get_public_armored_raises_when_db_and_vault_both_missing(
    db, mock_vault, patch_gpg, mirror
):
    service = MirrorSigningKeyService(db)
    key = service.ensure_active(mirror)
    # Clear both DB cache and Vault entry.
    key.armored_public_key = None
    db.commit()
    mock_vault.secrets.pop(key.vault_path)
    with pytest.raises(RuntimeError, match="no public material in DB or vault"):
        service.get_public_armored(key)


# ---------------------------------------------------------------------------
# bundle_public_keys — locked invariant: NEVER includes retired
# ---------------------------------------------------------------------------


def test_bundle_excludes_retired(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    active = service.ensure_active(mirror)

    # Hand-insert sibling rows representing rotation states.
    pending = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="pending_cutover",
        gpg_fingerprint="2" * 40,
        key_uid="pending uid",
        vault_path=vault_path_for("test-mirror", "2" * 40),
    )
    rotating = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="rotating_out",
        gpg_fingerprint="3" * 40,
        key_uid="rotating uid",
        vault_path=vault_path_for("test-mirror", "3" * 40),
    )
    retired = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="retired",
        gpg_fingerprint="4" * 40,
        key_uid="retired uid",
        vault_path=vault_path_for("test-mirror", "4" * 40),
    )
    db.add_all([pending, rotating, retired])
    db.commit()

    bundle = service.bundle_public_keys(mirror.id)
    statuses = [k.status for k in bundle]
    assert "retired" not in statuses
    # Order locked: active first, then pending_cutover, then rotating_out.
    assert statuses == ["active", "pending_cutover", "rotating_out"]
    assert {k.id for k in bundle} == {active.id, pending.id, rotating.id}


def test_list_for_mirror_excludes_retired_by_default(db, mock_vault, patch_gpg, mirror):
    service = MirrorSigningKeyService(db)
    active = service.ensure_active(mirror)
    retired = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="retired",
        gpg_fingerprint="5" * 40,
        key_uid="retired uid",
        vault_path=vault_path_for("test-mirror", "5" * 40),
    )
    db.add(retired)
    db.commit()

    default = service.list_for_mirror(mirror.id)
    assert {k.id for k in default} == {active.id}
    full = service.list_for_mirror(mirror.id, include_retired=True)
    assert {k.id for k in full} == {active.id, retired.id}


# ---------------------------------------------------------------------------
# vault_path composition
# ---------------------------------------------------------------------------


def test_vault_path_for_format():
    path = vault_path_for("ubuntu-jammy", "A" * 40)
    assert path == f"praxis/mirror-signing-keys/ubuntu-jammy/{'A' * 40}"


# ---------------------------------------------------------------------------
# Slice #1-a: partial unique index + bootstrap race recovery
# ---------------------------------------------------------------------------


def test_partial_unique_index_blocks_second_active(db, mock_vault, patch_gpg, mirror):
    """The DB-enforced ``uq_mirror_signing_keys_one_active_per_mirror``
    partial unique index must reject a second ``active`` row for the
    same mirror — proves this isn't a documented-and-accepted
    race anymore.
    """
    from sqlalchemy.exc import IntegrityError

    service = MirrorSigningKeyService(db)
    service.ensure_active(mirror)

    second = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="active",
        gpg_fingerprint="9" * 40,
        key_uid="bootstrap-race uid",
        vault_path=vault_path_for(mirror.slug, "9" * 40),
    )
    db.add(second)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_partial_unique_index_blocks_second_pending(db, mock_vault, patch_gpg, mirror):
    """Same DB protection for ``pending_cutover`` — slice #5's rotate-prepare
    flow can rely on the index instead of carrying its own race logic.
    """
    from sqlalchemy.exc import IntegrityError

    first_pending = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="pending_cutover",
        gpg_fingerprint="A" * 40,
        key_uid="pending-1",
        vault_path=vault_path_for(mirror.slug, "A" * 40),
    )
    db.add(first_pending)
    db.commit()

    second_pending = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="pending_cutover",
        gpg_fingerprint="B" * 40,
        key_uid="pending-2",
        vault_path=vault_path_for(mirror.slug, "B" * 40),
    )
    db.add(second_pending)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_partial_unique_index_allows_many_retired(db, mock_vault, patch_gpg, mirror):
    """A mirror accumulates retired keys across rotations — the partial
    indexes intentionally don't cover ``rotating_out`` or ``retired``.
    """
    for i, fp_char in enumerate(("3", "4", "5")):
        retired = MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="retired",
            gpg_fingerprint=fp_char * 40,
            key_uid=f"retired-{i}",
            vault_path=vault_path_for(mirror.slug, fp_char * 40),
        )
        db.add(retired)
    db.commit()
    rows = (
        db.query(MirrorSigningKey)
        .filter_by(mirror_repo_id=mirror.id, status="retired")
        .all()
    )
    assert len(rows) == 3


def test_ensure_active_recovers_from_bootstrap_race(db, mock_vault, patch_gpg, mirror):
    """Simulate a lost race: a winner has already inserted an active
    row before our ``ensure_active`` commits. The IntegrityError path
    should clean up our orphan Vault entry, re-fetch, and return the
    winner — never raise.
    """
    # Pre-seed a winner row directly (bypassing the service).
    winner_fpr = "C" * 40
    winner = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="active",
        gpg_fingerprint=winner_fpr,
        key_uid="winner uid",
        vault_path=vault_path_for(mirror.slug, winner_fpr),
    )
    db.add(winner)
    db.commit()

    # Force ``get_active`` to return None on the first call inside
    # ``ensure_active`` so it proceeds to gen+insert (and races us).
    service = MirrorSigningKeyService(db)
    original_get_active = service.get_active
    call_count = {"n": 0}

    def fake_get_active(mirror_id):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return None  # masks the winner so we attempt insert
        return original_get_active(mirror_id)

    service.get_active = fake_get_active
    result = service.ensure_active(mirror)
    assert result.id == winner.id
    assert result.gpg_fingerprint == winner_fpr
    # Loser's Vault entry was cleaned up.
    loser_fpr = _TEST_FPR
    loser_path = vault_path_for(mirror.slug, loser_fpr)
    assert loser_path not in mock_vault.secrets
