"""PRA-158 #4a: MirrorUpstreamKeyService tests.

Real-gpg integration tests do the import+fingerprint roundtrip;
non-gpg unit tests cover the validation surface (empty name,
malformed armored body, multi-key bodies).
"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from app.db.models import MirrorUpstreamKey
from app.services.mirror_gpg import (
    ephemeral_gnupg_home,
    export_public_armored,
    generate_keypair,
    gpg_available,
)
from app.services.mirror_upstream_key_service import (
    MirrorUpstreamKeyError,
    MirrorUpstreamKeyService,
)

skip_without_gpg = pytest.mark.skipif(
    not gpg_available(),
    reason="needs gpg on PATH (present in backend image; absent on hosted CI)",
)


def _make_real_armored(slug: str = "upstream-test") -> tuple[str, str]:
    """Generate a real keypair, return (fingerprint, armored_public)."""
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, slug)
        return fpr, export_public_armored(home, fpr)


# ---------------------------------------------------------------------------
# Validation (no gpg needed)
# ---------------------------------------------------------------------------


def test_create_rejects_empty_name(db):
    service = MirrorUpstreamKeyService(db)
    with pytest.raises(MirrorUpstreamKeyError, match="name is required"):
        service.create_from_armored(name="", armored_public_key="x")


def test_create_rejects_whitespace_name(db):
    service = MirrorUpstreamKeyService(db)
    with pytest.raises(MirrorUpstreamKeyError, match="name is required"):
        service.create_from_armored(name="   ", armored_public_key="x")


def test_create_rejects_empty_armored(db):
    service = MirrorUpstreamKeyService(db)
    with pytest.raises(MirrorUpstreamKeyError, match="armored_public_key"):
        service.create_from_armored(name="test", armored_public_key="")


def test_create_rejects_non_armored_body(db):
    """Plain text without the BEGIN PGP PUBLIC KEY BLOCK marker is
    rejected before any gpg subprocess runs.
    """
    service = MirrorUpstreamKeyService(db)
    with pytest.raises(MirrorUpstreamKeyError, match="failed to import"):
        service.create_from_armored(
            name="bogus", armored_public_key="this is not a key"
        )


# ---------------------------------------------------------------------------
# Real gpg roundtrip
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_create_imports_real_armored_key_and_extracts_fingerprint(db):
    fpr, armored = _make_real_armored("ubuntu-archive")
    service = MirrorUpstreamKeyService(db)

    row = service.create_from_armored(
        name="Ubuntu Archive Test", armored_public_key=armored
    )
    assert row.id is not None
    assert row.gpg_fingerprint == fpr
    assert row.name == "Ubuntu Archive Test"
    assert row.armored_public_key == armored
    assert row.notes is None

    fetched = service.get_by_fingerprint(fpr)
    assert fetched is not None and fetched.id == row.id


@skip_without_gpg
def test_create_normalizes_name_whitespace(db):
    _, armored = _make_real_armored("normalize-test")
    service = MirrorUpstreamKeyService(db)
    row = service.create_from_armored(
        name="  Padded Name  ", armored_public_key=armored
    )
    assert row.name == "Padded Name"


@skip_without_gpg
def test_create_persists_notes(db):
    _, armored = _make_real_armored("notes-test")
    service = MirrorUpstreamKeyService(db)
    row = service.create_from_armored(
        name="Test", armored_public_key=armored, notes="rotated 2024-08"
    )
    assert row.notes == "rotated 2024-08"


@skip_without_gpg
def test_create_rejects_duplicate_fingerprint(db):
    _, armored = _make_real_armored("dup-test")
    service = MirrorUpstreamKeyService(db)
    service.create_from_armored(name="First", armored_public_key=armored)
    # Same body → same fingerprint → DB unique violation surfaces as
    # IntegrityError (route layer maps to 409).
    with pytest.raises(IntegrityError):
        service.create_from_armored(name="Second", armored_public_key=armored)


@skip_without_gpg
def test_create_rejects_multi_armor_block_body(db):
    """An armored body containing two PGP PUBLIC KEY BLOCKs (two armor
    headers) is rejected before import — operators should add keys
    one at a time.
    """
    _, armored_a = _make_real_armored("multi-a")
    _, armored_b = _make_real_armored("multi-b")
    multi = armored_a + "\n" + armored_b
    service = MirrorUpstreamKeyService(db)
    with pytest.raises(MirrorUpstreamKeyError, match="exactly one"):
        service.create_from_armored(name="Multi", armored_public_key=multi)


@skip_without_gpg
def test_create_rejects_multi_primary_key_in_single_armor_block(db):
    """A single PGP PUBLIC KEY BLOCK can pack multiple
    primary keys. Counting armor headers (one block) is not the same
    as counting primary keys. After import, the gate must count
    ``pub:`` lines — multi-primary bodies are rejected so the operator
    can't land hidden trust for keys not visible in the DB row.

    Synthesis: generate each real key in its own GNUPGHOME (the
    helper enforces single-key per home for secret keys), import the
    two armored public bodies into a third bundling home, then a
    single ``--armor --export`` call there packs both primaries into
    one BEGIN PGP PUBLIC KEY BLOCK.
    """
    from app.services.mirror_gpg import _run_gpg, import_armored_public

    fpr_a, armored_a = _make_real_armored("multi-primary-a")
    fpr_b, armored_b = _make_real_armored("multi-primary-b")

    with ephemeral_gnupg_home() as bundle_home:
        import_armored_public(bundle_home, armored_a)
        import_armored_public(bundle_home, armored_b)
        # Default ``--armor --export`` (no fingerprint args) exports
        # ALL public keys in the home into one armored block.
        result = _run_gpg(bundle_home, ["--armor", "--export"])
        bundle = result.stdout.decode("utf-8")

    # Sanity: one armor header but two primary keys.
    assert bundle.count("BEGIN PGP PUBLIC KEY BLOCK") == 1
    assert fpr_a != fpr_b

    service = MirrorUpstreamKeyService(db)
    with pytest.raises(MirrorUpstreamKeyError, match="primary keys"):
        service.create_from_armored(name="Smuggled", armored_public_key=bundle)
    # Nothing landed in the DB.
    assert service.get_by_fingerprint(fpr_a) is None
    assert service.get_by_fingerprint(fpr_b) is None


@skip_without_gpg
def test_list_keys_returns_alpha_by_name(db):
    _, armored_a = _make_real_armored("list-a")
    _, armored_b = _make_real_armored("list-b")
    service = MirrorUpstreamKeyService(db)
    service.create_from_armored(name="Zulu", armored_public_key=armored_a)
    service.create_from_armored(name="Alpha", armored_public_key=armored_b)

    names = [k.name for k in service.list_keys()]
    assert names == sorted(names)
    assert "Alpha" in names and "Zulu" in names


@skip_without_gpg
def test_delete_returns_true_when_row_exists_and_false_otherwise(db):
    _, armored = _make_real_armored("delete-test")
    service = MirrorUpstreamKeyService(db)
    row = service.create_from_armored(name="Delete Me", armored_public_key=armored)
    assert service.delete(row.id) is True
    assert service.get_by_id(row.id) is None
    # Second delete is a no-op returning False.
    assert service.delete(row.id) is False


@skip_without_gpg
def test_get_by_fingerprint_normalizes_case(db):
    fpr, armored = _make_real_armored("normalize-fpr")
    service = MirrorUpstreamKeyService(db)
    service.create_from_armored(name="Test", armored_public_key=armored)
    # gpg returns uppercase fingerprints; lookup with lowercase / mixed
    # should still hit thanks to ``.upper().strip()`` in the query.
    assert service.get_by_fingerprint(fpr.lower()) is not None
    assert service.get_by_fingerprint(f"  {fpr}  ") is not None


# ---------------------------------------------------------------------------
# Belt: unit-level fingerprint extraction (separate from the service)
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_import_public_and_extract_fingerprint_returns_uppercase_hex():
    from app.services.mirror_gpg import import_public_and_extract_fingerprint

    _, armored = _make_real_armored("fpr-extract")
    with ephemeral_gnupg_home() as home:
        fpr = import_public_and_extract_fingerprint(home, armored)
    assert len(fpr) == 40
    assert all(c in "0123456789ABCDEF" for c in fpr)


def test_import_public_and_extract_fingerprint_rejects_non_armored():
    from app.services.mirror_gpg import (
        MirrorGPGError,
        import_public_and_extract_fingerprint,
    )

    with ephemeral_gnupg_home() as home:
        with pytest.raises(MirrorGPGError, match="PGP PUBLIC KEY BLOCK"):
            import_public_and_extract_fingerprint(home, "garbage")
