"""PRA-158 #4c: seed-upstream-keys script tests.

Drives the script's ``import_seed`` function against the per-test ``db``
fixture so test isolation works. Real-gpg integration verifies the
fingerprint extraction path.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from app.db.models import MirrorUpstreamKey
from app.services.mirror_gpg import (
    ephemeral_gnupg_home,
    export_public_armored,
    generate_keypair,
    gpg_available,
)

skip_without_gpg = pytest.mark.skipif(
    not gpg_available(),
    reason="needs gpg on PATH (present in backend image; absent on hosted CI)",
)

# Resolve the script + shipped seed relative to the repo so tests
# work both inside the backend container (``/app/...``) and on the
# hosted CI runner (which executes pytest against the checkout, not
# inside docker). ``parents[2]`` from this test file's location is
# ``backend/``. The script's runtime default
# ``DEFAULT_SEED_PATH`` stays ``/app/...`` because the runtime is
# container-only; only the test discovery needs the repo-relative
# resolution.
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = _BACKEND_ROOT / "scripts" / "seed-upstream-keys.py"
SHIPPED_SEED_PATH = _BACKEND_ROOT / "app" / "db" / "seed_data" / "upstream_keys.json"


def _load_script_module():
    """The script is named ``seed-upstream-keys.py`` (hyphenated, not
    importable as a normal module). Load it via SourceFileLoader so
    tests can call its ``import_seed`` function directly.
    """
    spec = importlib.util.spec_from_file_location("seed_upstream_keys", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["seed_upstream_keys"] = module
    spec.loader.exec_module(module)
    return module


def _real_armored(slug: str) -> tuple[str, str]:
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, slug)
        return fpr, export_public_armored(home, fpr)


def _write_seed(tmp_path: Path, entries: list) -> Path:
    seed = tmp_path / "upstream_keys.json"
    seed.write_text(json.dumps({"_meta": {}, "entries": entries}))
    return seed


# ---------------------------------------------------------------------------
# Empty seed + missing-file edges (no gpg needed)
# ---------------------------------------------------------------------------


def test_import_seed_empty_entries_is_clean_noop(db, tmp_path):
    script = _load_script_module()
    seed = _write_seed(tmp_path, [])
    summary = script.import_seed(seed, db)
    assert summary.imported == 0
    assert summary.skipped_duplicate == 0
    assert summary.failed == []
    assert db.query(MirrorUpstreamKey).count() == 0


def test_import_seed_missing_file_raises(db, tmp_path):
    script = _load_script_module()
    bogus = tmp_path / "no-such-file.json"
    with pytest.raises(FileNotFoundError):
        script.import_seed(bogus, db)


def test_import_seed_rejects_entries_with_missing_fields(db, tmp_path):
    script = _load_script_module()
    seed = _write_seed(
        tmp_path,
        [
            {"name": "OK"},  # missing armored_public_key
            {"armored_public_key": "x"},  # missing name
        ],
    )
    summary = script.import_seed(seed, db)
    assert summary.imported == 0
    assert len(summary.failed) == 2
    assert all("missing required field" in f for f in summary.failed)


# ---------------------------------------------------------------------------
# Real-gpg roundtrip
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_import_seed_imports_each_entry(db, tmp_path):
    script = _load_script_module()
    fpr_a, armored_a = _real_armored("seed-a")
    fpr_b, armored_b = _real_armored("seed-b")
    seed = _write_seed(
        tmp_path,
        [
            {
                "name": "Anchor A",
                "armored_public_key": armored_a,
                "notes": "first",
            },
            {
                "name": "Anchor B",
                "armored_public_key": armored_b,
            },
        ],
    )

    summary = script.import_seed(seed, db)
    assert summary.imported == 2
    assert summary.skipped_duplicate == 0
    assert summary.failed == []

    rows = db.query(MirrorUpstreamKey).order_by(MirrorUpstreamKey.name).all()
    assert [r.name for r in rows] == ["Anchor A", "Anchor B"]
    assert {r.gpg_fingerprint for r in rows} == {fpr_a, fpr_b}
    notes_by_name = {r.name: r.notes for r in rows}
    assert notes_by_name["Anchor A"] == "first"
    assert notes_by_name["Anchor B"] is None


@skip_without_gpg
def test_import_seed_is_idempotent_skip_on_duplicate(db, tmp_path):
    """Re-running with the same seed (or with an entry whose fingerprint
    is already present) skips, doesn't fail.
    """
    script = _load_script_module()
    fpr, armored = _real_armored("seed-dup")
    seed = _write_seed(tmp_path, [{"name": "Anchor", "armored_public_key": armored}])

    first = script.import_seed(seed, db)
    assert first.imported == 1 and first.skipped_duplicate == 0

    second = script.import_seed(seed, db)
    assert second.imported == 0
    assert second.skipped_duplicate == 1
    assert second.failed == []

    # Still exactly one row in the table.
    assert db.query(MirrorUpstreamKey).filter_by(gpg_fingerprint=fpr).count() == 1


@skip_without_gpg
def test_import_seed_continues_past_a_bad_entry(db, tmp_path):
    """A malformed entry shouldn't abort the whole import — the rest
    of the seed still lands.
    """
    script = _load_script_module()
    fpr, armored = _real_armored("seed-mixed")
    seed = _write_seed(
        tmp_path,
        [
            {"name": "Bad", "armored_public_key": "not a real key"},
            {"name": "Good", "armored_public_key": armored},
        ],
    )

    summary = script.import_seed(seed, db)
    assert summary.imported == 1
    assert len(summary.failed) == 1
    assert "Bad" in summary.failed[0]
    assert db.query(MirrorUpstreamKey).filter_by(gpg_fingerprint=fpr).count() == 1


# ---------------------------------------------------------------------------
# Shipped seed file: must parse and have an empty entries array
# ---------------------------------------------------------------------------


def test_shipped_seed_file_is_valid_json_with_empty_entries():
    """The seed JSON in app/db/seed_data/upstream_keys.json ships as a
    parseable file with entries=[]. Operators populate locally; we
    don't bake known distro keys (rotation risk).
    """
    assert SHIPPED_SEED_PATH.is_file()
    payload = json.loads(SHIPPED_SEED_PATH.read_text())
    assert payload["entries"] == []
    assert "_meta" in payload
