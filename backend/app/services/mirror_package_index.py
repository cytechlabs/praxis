"""Mirror sync per-package index (PRA-164 slice 3 / option B).

A *derived* index over ``MirrorSyncRun`` rows: one
``MirrorSyncRunPackage`` row per ``(mirror_sync_run_id, package_name,
version, arch)`` tuple parsed from the on-disk manifest produced by
:func:`mirror_manifest.build_manifest`. The manifest file remains the
source of truth; this index exists so PRA-164 preflight can answer
"does mirror X publish package P at version V?" via a SQL query
rather than reading the manifest JSON each time.

Two write paths:

* :func:`populate_from_run` — invoked from inside the existing
  PRA-157/158 mirror-sync-completion flow right after
  ``stage_signed_manifest`` succeeds and the run row is finalized
  ``ok``. Reads the on-disk manifest file once and replaces any
  existing index rows for the run.
* :func:`backfill_run_if_missing` — invoked from the PRA-164
  preflight resolver when a successful sync run has no index rows
  yet (i.e. it predates Slice 3 or was missed). Reads the same
  manifest file and writes the rows. Idempotent: if the rows
  already exist, returns without touching the DB.

Read access at preflight time is DB-only — :func:`mirror_publishes`
queries the index without touching the filesystem. The slice spec
allows manifest reads only inside this module's write paths.

Manifest entries with ``package=None`` (index/metadata files like
``Release``, ``Packages.xz``, ``repodata/repomd.xml``) are skipped:
they are not packages, and the strict version-level availability
check has nothing to compare them against.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from sqlalchemy.orm import Session

from ..db.models import MirrorRepo, MirrorSyncRun, MirrorSyncRunPackage

logger = logging.getLogger(__name__)


class MirrorPackageIndexError(Exception):
    """Raised when a manifest read or index write fails in a way
    that the caller needs to surface (missing file, malformed JSON,
    etc.). Sync-completion callers swallow these into a warning so
    a transient index failure never breaks the parent sync; the
    backfill helper retries on next preflight."""


# ---------------------------------------------------------------------------
# Read path — DB only
# ---------------------------------------------------------------------------


def mirror_publishes(
    db: Session,
    *,
    mirror_sync_run_id: int,
    package_name: str,
    version: str,
) -> bool:
    """Return True iff the **specific** indexed sync run
    ``mirror_sync_run_id`` publishes ``package_name`` at ``version``.

    Slice 3a fix: the lookup is scoped to the run the
    caller selected (latest-ok for unpinned mirror entries, or
    ``ContentChannelRepo.pinned_run_id`` for pinned entries) — NOT
    any retained run for the mirror. An older retained sync that
    happens to publish the version cannot satisfy availability when
    the selected current/pinned run does not, because applying the
    plan will read from the selected run's bytes, not the historical
    one.

    Uses the ``(mirror_sync_run_id)`` index for a B-tree lookup
    plus equality filters on the unique-key columns. Returns False
    when the run has no row matching ``(name, version)``.

    Caller is responsible for ensuring the index has been
    populated/backfilled for the run — see
    :func:`backfill_run_if_missing`.
    """
    return (
        db.query(MirrorSyncRunPackage.id)
        .filter(
            MirrorSyncRunPackage.mirror_sync_run_id == mirror_sync_run_id,
            MirrorSyncRunPackage.package_name == package_name,
            MirrorSyncRunPackage.version == version,
        )
        .first()
        is not None
    )


def latest_ok_run_id(db: Session, mirror_repo_id: int) -> Optional[int]:
    """Return the id of the most recent ``status='ok'`` sync run for
    a mirror, or None when no successful run exists."""
    row = (
        db.query(MirrorSyncRun.id)
        .filter(
            MirrorSyncRun.mirror_repo_id == mirror_repo_id,
            MirrorSyncRun.status == "ok",
        )
        .order_by(MirrorSyncRun.started_at.desc(), MirrorSyncRun.id.desc())
        .first()
    )
    return row[0] if row is not None else None


# ---------------------------------------------------------------------------
# Write paths — manifest read allowed only here
# ---------------------------------------------------------------------------


def populate_from_run(db: Session, run: MirrorSyncRun) -> int:
    """Populate the per-package index for a completed sync run.

    Reads the manifest file at ``run.manifest_path`` once and writes
    one ``MirrorSyncRunPackage`` row per parsed package entry.
    Replaces any existing index rows for the run (idempotent
    re-run). Returns the count of rows written.

    Skips silently when the run is not ``ok`` or the manifest path
    is unset — callers may invoke this defensively.

    Raises :class:`MirrorPackageIndexError` if the manifest file
    exists but is unreadable or malformed; the caller decides
    whether to swallow (sync-completion path) or propagate
    (backfill path) the failure.
    """
    if run.status != "ok" or not run.manifest_path:
        return 0

    parsed_files = _read_manifest_files(Path(run.manifest_path))

    # Replace-all per run keeps the path idempotent. Use
    # synchronize_session=False so SQLAlchemy doesn't try to
    # auto-flush pending session state mid-replace.
    db.query(MirrorSyncRunPackage).filter(
        MirrorSyncRunPackage.mirror_sync_run_id == run.id
    ).delete(synchronize_session=False)
    db.flush()

    rows_written = 0
    for entry in parsed_files:
        # Skip non-package entries (Release, Packages.xz, repomd, ...).
        if not entry.get("package") or not entry.get("version"):
            continue
        db.add(
            MirrorSyncRunPackage(
                mirror_sync_run_id=run.id,
                mirror_repo_id=run.mirror_repo_id,
                package_name=entry["package"],
                version=entry["version"],
                arch=entry.get("arch"),
                filename=entry.get("filename") or "",
                sha256=entry.get("sha256") or "",
                size=int(entry.get("size") or 0),
            )
        )
        rows_written += 1

    # PRA-170: production SessionLocal is autoflush=False, so the
    # rows just added are not visible to subsequent queries on the
    # same session (e.g. ``backfill_run_if_missing``'s existence
    # check, ``mirror_publishes``'s index lookup) until we flush.
    # Flush here so the index is consistent the moment this returns.
    if rows_written:
        db.flush()

    return rows_written


def backfill_run_if_missing(db: Session, run: MirrorSyncRun) -> int:
    """Idempotent backfill: populate the index for ``run`` only if
    it has no rows yet AND the run is ``ok`` AND its manifest file
    is reachable. Returns the count of rows written (0 when
    skipped).

    Used by the PRA-164 preflight resolver to lazily fill in the
    index for sync runs that pre-date Slice 3 or were missed by the
    sync-completion hook (e.g. an upgrade window where the hook
    code wasn't deployed yet).

    Manifest read errors are swallowed and logged here — a missing
    manifest file means we cannot answer the strict-availability
    question for this run, but the resolver will report
    ``unavailable`` rather than crashing.
    """
    if run.status != "ok" or not run.manifest_path:
        return 0
    existing = (
        db.query(MirrorSyncRunPackage.id)
        .filter(MirrorSyncRunPackage.mirror_sync_run_id == run.id)
        .first()
    )
    if existing is not None:
        return 0
    try:
        return populate_from_run(db, run)
    except MirrorPackageIndexError as exc:
        logger.warning(
            "mirror_package_index backfill skipped for run %s: %s",
            run.id,
            exc,
        )
        return 0


def populate_from_run_safe(db: Session, run: MirrorSyncRun) -> int:
    """Sync-completion-safe wrapper: catches manifest read errors
    so an index failure never breaks the parent sync transaction.
    Returns the row count or 0 on failure (logged)."""
    try:
        return populate_from_run(db, run)
    except MirrorPackageIndexError as exc:
        logger.warning(
            "mirror_package_index population failed for run %s "
            "(parent sync stays ok; preflight will backfill): %s",
            run.id,
            exc,
        )
        return 0


# ---------------------------------------------------------------------------
# Manifest file IO — confined to this module
# ---------------------------------------------------------------------------


def _read_manifest_files(path: Path) -> List[dict]:
    if not path.exists():
        raise MirrorPackageIndexError(f"manifest file does not exist: {path}")
    try:
        with path.open("r", encoding="utf-8") as fp:
            doc = json.load(fp)
    except (OSError, json.JSONDecodeError) as exc:
        raise MirrorPackageIndexError(
            f"manifest file unreadable at {path}: {exc}"
        ) from exc
    files = doc.get("files")
    if not isinstance(files, list):
        raise MirrorPackageIndexError(
            f"manifest at {path} has no 'files' list (got {type(files).__name__})"
        )
    return files


# ---------------------------------------------------------------------------
# Convenience for callers that want to bulk-backfill a set of runs
# ---------------------------------------------------------------------------


def backfill_runs_if_missing(db: Session, runs: Iterable[MirrorSyncRun]) -> int:
    """Backfill a set of runs in one call. Returns the total rows
    written across all runs. Used by the preflight resolver when
    expanding multiple mirror candidates per host."""
    total = 0
    for run in runs:
        total += backfill_run_if_missing(db, run)
    return total
