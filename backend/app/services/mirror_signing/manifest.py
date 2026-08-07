"""Manifest signing: stage in snapshots-staging/, promote into snapshots/
(PRA-158 #2b).

Two-step shape so the slice #2c orchestrator can sign the manifest in
``work/`` BEFORE the rsync promotion, keep the signature in a staging
area, and only ``mv`` it into the read-served ``snapshots/`` once
``rsync work/ → live/`` succeeds. On failure between sign and rsync,
the orchestrator ``rmtree``s the staging dir and ``snapshots/`` is
never touched.

Locks (project_pra158_design_locks.md "Fence ordering"):

  * Manifest is built from ``work/`` (the already-signed tree), so
    its ``files`` list reflects the InRelease/Release.gpg/repomd.xml.asc
    files the native signing engine just wrote. ``manifest_sha256``
    naturally captures them.
  * Manifest signature does NOT feed back into ``manifest_sha256`` —
    it's a detached sidecar over the manifest JSON bytes.
  * Failure between sign and rsync MUST clean staging and leave
    ``snapshots/`` untouched.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Tuple

from .. import mirror_gpg
from ..mirror_manifest import serialize_manifest
from ..mirror_paths import (
    snapshot_manifest_path,
    snapshot_manifest_signature_path,
    snapshots_dir,
    staged_manifest_dir,
    staged_manifest_path,
    staged_manifest_signature_path,
)

logger = logging.getLogger(__name__)


def stage_signed_manifest(
    *,
    slug: str,
    run_id: int,
    manifest: dict,
    key_fingerprint: str,
    gnupg_home: Path,
) -> Tuple[Path, Path]:
    """Serialize+sign the manifest, write both to ``snapshots-staging/<run_id>/``.

    Returns ``(staged_manifest_path, staged_signature_path)``. The
    caller (orchestrator) is responsible for promoting these into
    ``snapshots/`` after a successful rsync, or ``rmtree``-ing the
    parent dir on failure (see ``cleanup_staged`` below).

    Manifest serialization uses the existing canonical-bytes helper
    so the sig covers exactly what an operator will see in the
    on-disk JSON (with run_id / generated_at / mirror_slug).
    """
    body = serialize_manifest(manifest)
    sig = mirror_gpg.detached_sign(gnupg_home, key_fingerprint, body)

    staged_dir = staged_manifest_dir(slug, run_id)
    staged_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = staged_manifest_path(slug, run_id)
    sig_path = staged_manifest_signature_path(slug, run_id)
    manifest_path.write_bytes(body)
    sig_path.write_bytes(sig)

    return manifest_path, sig_path


def promote_staged_manifest(slug: str, run_id: int) -> Tuple[Path, Path]:
    """Move staged manifest+signature into ``snapshots/`` (PRA-158 #2c).

    Returns ``(final_manifest_path, final_signature_path)``. If the
    staged dir is missing, raises ``FileNotFoundError``. If a final
    file already exists at the destination (idempotent re-promote),
    overwrites — ``Path.replace`` is atomic per file.

    Cleans up the now-empty per-run staging dir on success. Best
    effort — a stale empty dir under ``snapshots-staging/`` is benign
    and gets cleaned up by the next run for that run_id (slice #2c
    cleanup pass on orchestrator startup is also free to sweep).
    """
    staged_dir = staged_manifest_dir(slug, run_id)
    src_manifest = staged_manifest_path(slug, run_id)
    src_sig = staged_manifest_signature_path(slug, run_id)
    if not src_manifest.is_file() or not src_sig.is_file():
        raise FileNotFoundError(
            f"staged manifest or signature missing for slug={slug} run_id={run_id}"
        )

    snapshots_dir(slug).mkdir(parents=True, exist_ok=True)
    dst_manifest = snapshot_manifest_path(slug, run_id)
    dst_sig = snapshot_manifest_signature_path(slug, run_id)

    # All-or-nothing pair: if the manifest
    # mv succeeds but the signature mv then fails, rollback the
    # manifest mv before raising. Without this, callers would see a
    # published manifest with no signature alongside a 'failed' run
    # row — violating the slice's paired-artifact contract and
    # confusing future export/import tooling.
    src_manifest.replace(dst_manifest)
    try:
        src_sig.replace(dst_sig)
    except OSError:
        # Roll the manifest back into staging so cleanup_staged on
        # the orchestrator's failure path can drop the whole pair.
        # If the rollback itself fails, drop dst_manifest entirely
        # so we never leave an unsigned manifest behind.
        try:
            dst_manifest.replace(src_manifest)
        except OSError:
            try:
                dst_manifest.unlink(missing_ok=True)
            except OSError as unlink_err:  # pragma: no cover - belt
                logger.warning(
                    "couldn't unlink dst_manifest %s during promote rollback: %s",
                    dst_manifest,
                    unlink_err,
                )
        raise

    try:
        # Rmtree-not-rmdir because future slices may stage extra
        # sidecar files in this dir (e.g. detached upstream-verification
        # artifacts). Empty after both replaces today, but tolerant.
        if staged_dir.is_dir():
            shutil.rmtree(staged_dir, ignore_errors=True)
    except OSError as exc:  # pragma: no cover - belt
        logger.warning(
            "couldn't remove staged dir %s after promotion: %s",
            staged_dir,
            exc,
        )

    return dst_manifest, dst_sig


def cleanup_staged(slug: str, run_id: int) -> None:
    """Remove the per-run staging dir on a failure path (PRA-158 #2c).

    Idempotent: missing dir is a no-op. Failure to clean is logged
    but never re-raised — the orchestrator's run-finalization path
    must not be derailed by a cleanup hiccup.
    """
    staged_dir = staged_manifest_dir(slug, run_id)
    if not staged_dir.exists():
        return
    try:
        shutil.rmtree(staged_dir, ignore_errors=False)
    except OSError as exc:
        logger.warning(
            "couldn't clean staged dir %s after signing failure: %s",
            staged_dir,
            exc,
        )
