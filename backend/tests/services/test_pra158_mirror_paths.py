"""PRA-158 #2a: path helpers for staging + signature sidecar.

Pure-function tests that prove the layout invariants the slice #2c
orchestrator depends on:

  * ``snapshots-staging/`` is a SIBLING of ``snapshots/``, not inside.
  * Per-run staged dirs sit under ``snapshots-staging/<run_id>/``.
  * The manifest signature lives in ``snapshots/`` next to the manifest.
"""

from __future__ import annotations

from app.services.mirror_paths import (
    mirror_repo_root,
    snapshot_manifest_path,
    snapshot_manifest_signature_path,
    snapshots_dir,
    snapshots_staging_dir,
    staged_manifest_dir,
    staged_manifest_path,
    staged_manifest_signature_path,
)


def test_snapshot_manifest_signature_path_is_sibling_of_manifest():
    slug = "ubuntu-jammy"
    run_id = 42
    manifest = snapshot_manifest_path(slug, run_id)
    sig = snapshot_manifest_signature_path(slug, run_id)
    assert sig.parent == manifest.parent
    assert sig.name == f"{manifest.name}.sig"


def test_snapshots_staging_dir_is_sibling_of_snapshots():
    """Staging MUST NOT live under snapshots/ — readers serve snapshots/
    and would observe partially-written staging files.
    """
    slug = "ubuntu-jammy"
    snapshots = snapshots_dir(slug)
    staging = snapshots_staging_dir(slug)
    assert staging.parent == snapshots.parent == mirror_repo_root(slug)
    assert staging != snapshots
    assert "snapshots-staging" in staging.name
    assert staging.name != snapshots.name


def test_staged_manifest_dir_is_per_run_subdir():
    slug = "ubuntu-jammy"
    run_id = 7
    sub = staged_manifest_dir(slug, run_id)
    assert sub.parent == snapshots_staging_dir(slug)
    assert sub.name == "7"


def test_staged_manifest_paths_match_promoted_filenames():
    """The mv from staging→snapshots is straight rename; filenames
    must match between the two areas.
    """
    slug = "ubuntu-jammy"
    run_id = 99
    assert (
        staged_manifest_path(slug, run_id).name
        == snapshot_manifest_path(slug, run_id).name
    )
    assert (
        staged_manifest_signature_path(slug, run_id).name
        == snapshot_manifest_signature_path(slug, run_id).name
    )


def test_staged_paths_share_per_run_parent():
    slug = "ubuntu-jammy"
    run_id = 99
    manifest = staged_manifest_path(slug, run_id)
    sig = staged_manifest_signature_path(slug, run_id)
    assert manifest.parent == sig.parent == staged_manifest_dir(slug, run_id)
