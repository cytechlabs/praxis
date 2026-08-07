"""Retention policy for mirror_sync_runs (PRA-157 #4).

Per the locked design: retention drops ``mirror_sync_runs`` rows
and their on-disk manifest JSON files. Bytes under ``work/`` and
``live/`` stay put — PRA-159 will own byte-level immutability /
hardlinked snapshots; PRA-160's exporter expects current ``live/``
content. Manifest-only retention keeps the table from growing
unbounded without changing how clients pull from the mirror.

Policy keeps a row if EITHER:
  * it is among the most recent ``retention_keep_count`` ok runs
    (keep_count is "at least N most recent"); OR
  * it finished within the last ``retention_keep_within_days`` days.

Plus an absolute floor: the most recent ok run is ALWAYS kept,
even if both retention numbers are zero. Without this guard, a
mirror with ``retention_keep_count=0`` could drop the run that
operators just synced, leaving manifest readers (PRA-158 signing,
PRA-160 export) without a current row.

Failed and running rows are excluded from retention math. Failed
rows stay for forensics until an operator clears them; running
rows are stale-recovered by the claim path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from ..db.models import MirrorRepo, MirrorSyncRun

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RetentionResult:
    dropped_run_ids: List[int]
    manifest_files_unlinked: int
    # PRA-158 #2-c: track signature-sidecar unlinks alongside manifest
    # unlinks so retention metrics distinguish "manifest gone, sig
    # gone" (signed run dropped clean) from "manifest gone, sig
    # missing" (legacy unsigned PRA-157 run dropped) at log-line
    # granularity.
    signature_files_unlinked: int = 0


def apply_retention_for_mirror(
    db, mirror: MirrorRepo, *, now: Optional[datetime] = None
) -> RetentionResult:
    """Drop ok rows for ``mirror`` outside the retention window.

    Caller is responsible for committing. The orchestrator calls
    this from inside ``perform_sync_for_mirror``'s ok path, after
    finalization, so the just-finalized run is already in the
    set when retention math runs and is guaranteed to land in the
    keep set (it's the newest ok row).

    ``now`` defaults to a fresh ``datetime.utcnow()`` when None —
    Retention's policy semantics ("within the last
    N days") are best served by real-clock time, not by the
    orchestrator's start-time ``now`` (which can be hours stale
    after a long sync).

    Production ``SessionLocal`` is autoflush=False (db/session.py).
    Without an explicit flush, the just-finalized ``ok`` run row
    sits in pending state and the ``status='ok'`` query below
    issues a fresh SELECT that doesn't see it. With keep_count=1
    that scenario keeps the *previous* ok row and lets the caller
    commit two ok rows. The flush inside this function makes the
    helper safe regardless of caller.
    """
    if now is None:
        now = datetime.utcnow()

    keep_count = max(int(mirror.retention_keep_count or 0), 0)
    keep_within_days = max(int(mirror.retention_keep_within_days or 0), 0)

    db.flush()

    ok_runs = (
        db.query(MirrorSyncRun)
        .filter(
            MirrorSyncRun.mirror_repo_id == mirror.id,
            MirrorSyncRun.status == "ok",
        )
        .order_by(MirrorSyncRun.id.desc())
        .all()
    )

    if not ok_runs:
        return RetentionResult(dropped_run_ids=[], manifest_files_unlinked=0)

    cutoff = now - timedelta(days=keep_within_days) if keep_within_days else None

    keep_ids = set()

    # Always keep the most recent ok row regardless of policy. Without
    # this floor, a mirror with retention_keep_count=0 +
    # retention_keep_within_days=0 (legal per the schema check) would
    # drop the row we just finalized, breaking PRA-158 / PRA-160
    # contracts that need a current manifest.
    keep_ids.add(ok_runs[0].id)

    # Keep most recent N (where N = keep_count).
    for run in ok_runs[:keep_count]:
        keep_ids.add(run.id)

    # Keep anything within the time window.
    if cutoff is not None:
        for run in ok_runs:
            anchor = run.finished_at or run.started_at
            if anchor is not None and anchor >= cutoff:
                keep_ids.add(run.id)

    drops = [run for run in ok_runs if run.id not in keep_ids]
    if not drops:
        return RetentionResult(
            dropped_run_ids=[],
            manifest_files_unlinked=0,
            signature_files_unlinked=0,
        )

    unlinked = 0
    sig_unlinked = 0
    for run in drops:
        if run.manifest_path:
            try:
                Path(run.manifest_path).unlink(missing_ok=True)
                unlinked += 1
            except OSError as exc:
                # Best-effort. The row is still going to be dropped;
                # an orphaned file gets surfaced to the operator via
                # logs and can be cleaned by hand. Don't roll back
                # the retention transaction over a stale path.
                logger.warning(
                    "mirror retention: couldn't unlink manifest file %s "
                    "for run %d (%s): %s",
                    run.manifest_path,
                    run.id,
                    mirror.slug,
                    exc,
                )
        # PRA-158 #2-c: also drop the detached signature sidecar
        # (snapshots/<run_id>.manifest.json.sig) so signed runs
        # don't leave .sig orphans accumulating in snapshots/ after
        # the manifest + DB row are gone. NULL on pre-PRA-158 runs;
        # missing-file is benign (best-effort, mirrors the manifest
        # unlink discipline above).
        if run.manifest_signature_path:
            try:
                Path(run.manifest_signature_path).unlink(missing_ok=True)
                sig_unlinked += 1
            except OSError as exc:
                logger.warning(
                    "mirror retention: couldn't unlink signature file %s "
                    "for run %d (%s): %s",
                    run.manifest_signature_path,
                    run.id,
                    mirror.slug,
                    exc,
                )
        db.delete(run)

    # PRA-170: production SessionLocal is autoflush=False, so a caller
    # that runs another query in the same session after this helper
    # would not see the pending deletes. Flush here so downstream
    # queries are consistent with the retention decision.
    db.flush()

    logger.info(
        "mirror retention: %s dropped %d ok run(s) outside policy "
        "(keep_count=%d, keep_within_days=%d); %d manifest file(s) "
        "and %d signature sidecar(s) unlinked",
        mirror.slug,
        len(drops),
        keep_count,
        keep_within_days,
        unlinked,
        sig_unlinked,
    )
    return RetentionResult(
        dropped_run_ids=[r.id for r in drops],
        manifest_files_unlinked=unlinked,
        signature_files_unlinked=sig_unlinked,
    )
