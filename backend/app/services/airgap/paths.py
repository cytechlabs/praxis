"""Filesystem paths for airgap export/import (PRA-160 slice #1).

Two roots:

  * **Staging** lives under the mirror volume so it shares the same
    free-space gating as mirror sync work — and so a future operator
    looking at ``/data/praxis/mirrors/`` sees airgap activity in one
    place. Slice #1 only writes the descriptor here. Dot-prefixed
    so future mirror-list scans in the volume root don't accidentally
    pick it up.

      ``<PRAXIS_MIRROR_ROOT>/.airgap-staging/<bundle_id>/``

  * **Bundle output** lives at a dedicated root so airgap bundles
    don't get pulled into mirror retention sweeps or otherwise
    mistaken for mirror state.

      ``PRAXIS_AIRGAP_BUNDLE_ROOT`` (env var, default
      ``/data/praxis/airgap-bundles``)

  * **Import staging** (slice #3) lives at
    ``PRAXIS_AIRGAP_IMPORT_STAGING`` env var, default
    ``/data/praxis/airgap-import-staging``. Forward-declared here so
    slice #3 doesn't have to plumb a new module.

Locks (PRA-160 design conversation):
  * Locked staging dir prefix: ``.airgap-staging`` under mirror root
    (matches PRA-159's ``praxis-profile-*`` discipline of giving
    Praxis-managed dirs an obvious prefix).
  * Bundle-output root MAY be on a separate volume from the mirror
    root in production (a USB drive at ``/mnt/airgap``, an NFS
    share, etc.). The env var lets ops point it wherever.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..mirror_paths import mirror_root  # services.mirror_paths is one level up

DEFAULT_AIRGAP_BUNDLE_ROOT = "/data/praxis/airgap-bundles"
DEFAULT_AIRGAP_IMPORT_STAGING = "/data/praxis/airgap-import-staging"

STAGING_DIR_NAME = ".airgap-staging"

DESCRIPTOR_FILENAME = "bundle.json"
DESCRIPTOR_SIGNATURE_FILENAME = "bundle.json.sig"


def airgap_bundle_root() -> Path:
    """Return the configured bundle output root."""
    return Path(os.getenv("PRAXIS_AIRGAP_BUNDLE_ROOT", DEFAULT_AIRGAP_BUNDLE_ROOT))


def airgap_import_staging_root() -> Path:
    """Return the configured import staging root (slice #3 uses this)."""
    return Path(
        os.getenv("PRAXIS_AIRGAP_IMPORT_STAGING", DEFAULT_AIRGAP_IMPORT_STAGING)
    )


def staging_dir(bundle_id: str) -> Path:
    """Return ``<mirror_root>/.airgap-staging/<bundle_id>/``."""
    return mirror_root() / STAGING_DIR_NAME / bundle_id


def descriptor_path(bundle_id: str) -> Path:
    """Path to ``bundle.json`` inside the staging dir."""
    return staging_dir(bundle_id) / DESCRIPTOR_FILENAME


def descriptor_signature_path(bundle_id: str) -> Path:
    """Path to ``bundle.json.sig`` inside the staging dir."""
    return staging_dir(bundle_id) / DESCRIPTOR_SIGNATURE_FILENAME


# ---------------------------------------------------------------------------
# Slice #2: final tar bundle path + tmp variant for atomic promotion.
# ---------------------------------------------------------------------------


def bundle_file_path(bundle_id: str) -> Path:
    """Return the final tar path: ``<airgap_bundle_root>/<bundle_id>.tar``.

    Lock (PRA-160 design conversation): bundle file naming is
    ``<bundle_id>.tar`` only — no compression suffix. Operator can
    gzip on transport if needed; double-compressing apt/dnf
    metadata is wasteful.
    """
    return airgap_bundle_root() / f"{bundle_id}.tar"


def bundle_file_tmp_path(bundle_id: str) -> Path:
    """Return the in-progress tar path used during assembly.

    Atomic promotion contract: the assembler writes here, then
    ``os.rename(tmp, final)`` once the tar is closed and
    ``payload_sha256`` is known. A crashed build leaves a ``.tmp``
    sibling that the next attempt cleans up.
    """
    return airgap_bundle_root() / f"{bundle_id}.tar.tmp"
