"""Filesystem path helpers for the mirror engine (PRA-157).

Centralizes layout decisions so that any future S3/MinIO storage
backend can swap these helpers without touching call sites. v1 is
local filesystem only.

Layout invariant::

    <PRAXIS_MIRROR_ROOT>/
        praxis-mirror.json          # self-describing layout descriptor
        <mirror-slug>/
            work/                   # debmirror/reposync working dir
            live/                   # last coherent published tree
            snapshots/
                <run_id>.manifest.json
            sync.lock               # filesystem belt; advisory lock is the belt
            .last-error

PRA-160's airgap importer keys off ``praxis-mirror.json``; bumping
``LAYOUT_VERSION`` is the explicit signal that an importer must
adapt.

Configuration env vars (read directly via ``os.getenv`` to match the
established PRAXIS_* pattern at activation_tokens / agent_bootstrap;
the ``app/core/config.py:Settings`` class is unused dead code from a
pre-PRA-141 era and not the right home for new fields):

  * ``PRAXIS_MIRROR_ROOT`` — volume root, default ``/data/praxis/mirrors``
  * ``PRAXIS_MIRROR_MIN_FREE_BYTES`` — global free-space floor (bytes)
  * ``PRAXIS_MIRROR_MIN_FREE_PERCENT`` — global free-space floor (%)
  * ``PRAXIS_MIRROR_MAX_CONCURRENT_SYNCS`` — sweep concurrency cap

The pre-sync gate uses ``max(bytes_floor, percent * volume_capacity / 100)``
so a tiny dev volume and a multi-TB prod volume both reserve sensibly.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Bump when the on-disk layout changes in a way PRA-160's importer
# must care about. Layout-only — the descriptor JSON schema can grow
# fields freely without a bump as long as readers tolerate unknown
# keys.
LAYOUT_VERSION = "v1"

DESCRIPTOR_FILENAME = "praxis-mirror.json"

DEFAULT_MIRROR_ROOT = "/data/praxis/mirrors"
DEFAULT_MIN_FREE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GiB
DEFAULT_MIN_FREE_PERCENT = 5
DEFAULT_MAX_CONCURRENT_SYNCS = 2


def mirror_root() -> Path:
    return Path(os.getenv("PRAXIS_MIRROR_ROOT", DEFAULT_MIRROR_ROOT))


def min_free_bytes() -> int:
    raw = os.getenv("PRAXIS_MIRROR_MIN_FREE_BYTES")
    if raw is None or raw.strip() == "":
        return DEFAULT_MIN_FREE_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_MIN_FREE_BYTES


def min_free_percent() -> int:
    raw = os.getenv("PRAXIS_MIRROR_MIN_FREE_PERCENT")
    if raw is None or raw.strip() == "":
        return DEFAULT_MIN_FREE_PERCENT
    try:
        return max(0, min(100, int(raw)))
    except ValueError:
        return DEFAULT_MIN_FREE_PERCENT


def max_concurrent_syncs() -> int:
    raw = os.getenv("PRAXIS_MIRROR_MAX_CONCURRENT_SYNCS")
    if raw is None or raw.strip() == "":
        return DEFAULT_MAX_CONCURRENT_SYNCS
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_MAX_CONCURRENT_SYNCS


def mirror_repo_root(slug: str) -> Path:
    return mirror_root() / slug


def work_dir(slug: str) -> Path:
    return mirror_repo_root(slug) / "work"


def live_dir(slug: str) -> Path:
    return mirror_repo_root(slug) / "live"


def snapshots_dir(slug: str) -> Path:
    return mirror_repo_root(slug) / "snapshots"


def snapshot_manifest_path(slug: str, run_id: int) -> Path:
    return snapshots_dir(slug) / f"{run_id}.manifest.json"


def snapshot_manifest_signature_path(slug: str, run_id: int) -> Path:
    """Detached signature sidecar for ``snapshot_manifest_path`` (PRA-158 #2a).

    Layout: ``<slug>/snapshots/<run_id>.manifest.json.sig``. Sibling
    of the manifest JSON in the same directory so a single
    ``snapshots/`` dir listing shows manifest + signature side by side.
    """
    return snapshots_dir(slug) / f"{run_id}.manifest.json.sig"


def snapshots_staging_dir(slug: str) -> Path:
    """Staging area for manifest+sig pairs that aren't yet promoted
    (PRA-158 #2a).

    Layout: ``<slug>/snapshots-staging/``. Sibling of ``snapshots/``,
    NOT inside it — the snapshots/ dir is what the read endpoints
    serve, so a partially-written staging file under snapshots/
    could be observed by a concurrent reader.

    Promotion (slice #2c) is ``mv staging/<run_id>/* snapshots/`` on
    success; failure paths ``rmtree staging/<run_id>/`` and leave
    ``snapshots/`` untouched. Cleanup of stale staging dirs across
    crashes is the orchestrator's responsibility — this helper just
    names the path.
    """
    return mirror_repo_root(slug) / "snapshots-staging"


def staged_manifest_dir(slug: str, run_id: int) -> Path:
    """Per-run subdirectory under ``snapshots_staging_dir`` (PRA-158 #2a).

    One dir per run so the orchestrator's failure-cleanup is a clean
    ``shutil.rmtree`` of the whole subdir, not file-by-file unlink
    work that has to know which sidecars were written.
    """
    return snapshots_staging_dir(slug) / str(run_id)


def staged_manifest_path(slug: str, run_id: int) -> Path:
    return staged_manifest_dir(slug, run_id) / f"{run_id}.manifest.json"


def staged_manifest_signature_path(slug: str, run_id: int) -> Path:
    return staged_manifest_dir(slug, run_id) / f"{run_id}.manifest.json.sig"


def sync_lock_path(slug: str) -> Path:
    return mirror_repo_root(slug) / "sync.lock"


def dnf_state_dir(slug: str) -> Path:
    """Documented path for the rpm engine's transient state dir
    (PRA-157 #6-a). The engine itself derives the dir from
    ``work_dir.parent / "dnf-state"`` (#6-c) so it stays pure with
    respect to its parameters and doesn't read
    ``PRAXIS_MIRROR_ROOT`` mid-test, but the helper is kept as the
    canonical name external callers (cleanup scripts, retention
    sweeps, future tooling) can use to find the same path.

    dnf creates ``.rpmdb/`` and other transient state under
    ``$HOME`` on first invocation. The praxis user's HOME is
    ``/app`` in production, so without a mirror-owned scratch dir
    that state would land under the application root and distinct
    RPM mirrors running concurrently under the global cap would
    contend on shared state. The rpm engine pins BOTH ``cwd`` and
    ``HOME`` to this directory; cwd is belt against a future tool
    that DOES use cwd. ``mirror_repo_root(slug) / "dnf-state"`` is
    sibling to ``work/`` — the rsync ``work/ → live/`` promotion
    doesn't traverse siblings, so the side-effect state stays out
    of ``live/`` without any rsync filter.
    """
    return mirror_repo_root(slug) / "dnf-state"


def last_error_path(slug: str) -> Path:
    return mirror_repo_root(slug) / ".last-error"


def descriptor_path() -> Path:
    return mirror_root() / DESCRIPTOR_FILENAME


def ensure_descriptor() -> None:
    """Idempotently write the layout descriptor to the mirror root.

    First writer wins — if a descriptor already exists, it is left
    alone. PRA-160 owns the layout migration story; slice #1 only
    ensures the descriptor is present on a fresh install.

    If an existing descriptor records a different
    ``praxis_mirror_layout`` than this code knows about, log a
    warning so the mismatch shows up at scheduler startup. Silent
    "first writer wins" with a stale descriptor on disk would make
    a future PRA-160 importer harder to debug.
    """
    root = mirror_root()
    root.mkdir(parents=True, exist_ok=True)

    path = descriptor_path()
    if path.exists():
        try:
            existing = json.loads(path.read_text())
            existing_layout = existing.get("praxis_mirror_layout")
            if existing_layout != LAYOUT_VERSION:
                logger.warning(
                    "praxis-mirror.json layout mismatch at %s: on-disk "
                    "praxis_mirror_layout=%r, code expects %r. Leaving "
                    "the existing descriptor in place; PRA-160's layout "
                    "migration path will need to handle this.",
                    path,
                    existing_layout,
                    LAYOUT_VERSION,
                )
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "praxis-mirror.json at %s exists but could not be parsed: "
                "%s. Leaving existing file in place.",
                path,
                exc,
            )
        return

    body = {
        "praxis_mirror_layout": LAYOUT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "description": (
            "Praxis mirror data root. PRA-157 mirror engine and PRA-160 "
            "airgap export/import key off this file. Do not delete."
        ),
    }
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
