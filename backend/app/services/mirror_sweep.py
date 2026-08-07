"""Sweep + claim orchestration for the mirror engine
(PRA-157 #2b, refactored in #2b-a).

Owns:
  * ``sweep_eligible_mirrors_query(db)`` — canonical filter for
    "mirrors the *sweep* should consider": not soft-deleted,
    enabled, ``source_mode='upstream_sync'``. Routes that surface
    mirror lists or accept on-demand actions should NOT use this
    blindly — disabled and imported_offline mirrors still appear in
    list/detail surfaces for operators to manage. The narrower
    sweep-eligibility name avoids that misuse.
  * ``_stale_recover_running_runs_for_mirror`` — flips orphaned
    ``running`` rows for a mirror to ``failed`` after our claim wins.
  * ``_persist_claim_for_mirror`` — under both per-mirror advisory
    lock AND global concurrency gate, do stale recovery, count
    running rows globally, **re-check mirror eligibility**, INSERT
    a new running run row, and update mirror state. Returns a
    ``ClaimResult`` distinguishing slot-taken / cap-reached /
    ineligible.
  * ``_belt_finalize_failed`` — defensive run-row finalizer used on
    unexpected exception in the orchestrator path.
  * ``claim_and_sync_one_mirror`` — the per-mirror end-to-end claim
    + sync flow. Sweep and on-demand POST both call into this so
    they share one safety surface.

The alert dispatch path runs on a **fresh** session decoupled from
the sync state's session. ``alert_service.send_alert`` commits
``AlertHistory`` rows; isolating it prevents alert configs from
prematurely committing sync finalization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ..db.models import MirrorRepo, MirrorSyncRun
from ..db.session import SessionLocal
from . import mirror_alerts
from .mirror_lock import claim_mirror_for_sync, global_claim_gate
from .mirror_paths import max_concurrent_syncs

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sweep-eligibility filter
# ---------------------------------------------------------------------------


def sweep_eligible_mirrors_query(db):
    """Mirrors the periodic sweep should consider for due-checking.

    Excludes soft-deleted, disabled, and ``imported_offline`` rows.
    Routes that need a wider view (e.g. PATCH a disabled mirror to
    re-enable it, or detail-view of an imported mirror) should query
    ``MirrorRepo`` directly with the soft-delete filter only.
    """
    return db.query(MirrorRepo).filter(
        MirrorRepo.deleted_at.is_(None),
        MirrorRepo.enabled.is_(True),
        MirrorRepo.source_mode == "upstream_sync",
    )


# ---------------------------------------------------------------------------
# Stale recovery + claim persistence
# ---------------------------------------------------------------------------


def _stale_recover_running_runs_for_mirror(db, mirror_id: int, now: datetime) -> int:
    """Flip any pre-existing ``running`` rows for ``mirror_id`` to
    ``failed``. Caller commits.

    Called by the claim path AFTER acquiring the per-mirror advisory
    lock — by definition any rows still in 'running' are orphans
    from a prior process death (we hold the only valid claim now,
    so they cannot be live).
    """
    stale = (
        db.query(MirrorSyncRun)
        .filter(
            MirrorSyncRun.mirror_repo_id == mirror_id,
            MirrorSyncRun.status == "running",
        )
        .all()
    )
    for run in stale:
        run.status = "failed"
        run.finished_at = now
        run.error_text = "stale: scheduler restarted before completion"
    return len(stale)


@dataclass(frozen=True)
class ClaimResult:
    """Result of ``_persist_claim_for_mirror``.

    ``outcome`` is one of:
      * ``"slot_taken"`` — run row inserted, mirror state advanced
        to running. ``run_id`` is the new row's id; ``prior_status``
        is the mirror's last_sync_status BEFORE this claim mutated
        it (used by the orchestrator's recovery-alert transition
        gate).
      * ``"cap_reached"`` — global concurrency cap is full this
        tick. ``run_id`` and ``prior_status`` are None.
      * ``"ineligible"`` — mirror was deleted, disabled, or flipped
        to ``imported_offline`` between the caller's enumeration /
        preflight and this claim attempt. The caller's eligibility
        guarantee (sweep filter, on-demand 409 preflight) is not
        sufficient on its own — by the time we hold the lock, the
        operator may have changed state. Re-checking under the
        gate is the only correct moment.
    """

    outcome: str
    run_id: Optional[int] = None
    prior_status: Optional[str] = None


def _persist_claim_for_mirror(
    db, mirror_id: int, now: datetime, cap: int
) -> ClaimResult:
    _stale_recover_running_runs_for_mirror(db, mirror_id, now)

    # Production SessionLocal is autoflush=False (db/session.py).
    # Without an explicit flush, the stale-recovery UPDATEs sit in
    # ORM-pending state and the count() below issues a fresh SELECT
    # that still sees those rows as 'running'. Flush so the cap
    # math reflects the cleanup we just did in this same transaction.
    db.flush()

    running_count = (
        db.query(MirrorSyncRun).filter(MirrorSyncRun.status == "running").count()
    )
    if running_count >= cap:
        return ClaimResult(outcome="cap_reached")

    mirror_obj = db.query(MirrorRepo).filter(MirrorRepo.id == mirror_id).first()
    if mirror_obj is None:
        return ClaimResult(outcome="ineligible")

    # PRA-157 #2b-a: re-check eligibility AFTER the lock. The sweep's
    # ``sweep_eligible_mirrors_query`` and the on-demand route's 409
    # preflight both filter on (deleted_at IS NULL, enabled,
    # source_mode='upstream_sync'), but those checks happen BEFORE
    # the lock + global gate are acquired. An operator can disable /
    # soft-delete / flip the mode between enumeration and our claim;
    # we'd insert a running run row for an ineligible mirror.
    if (
        mirror_obj.deleted_at is not None
        or not mirror_obj.enabled
        or mirror_obj.source_mode != "upstream_sync"
    ):
        return ClaimResult(outcome="ineligible")

    # Capture BEFORE the mutation below — the orchestrator uses this
    # to gate the failed→ok recovery alert. Without capturing here,
    # the orchestrator would see ``last_sync_status == 'running'``
    # (set by the next two lines) and never fire recovery.
    prior_status = mirror_obj.last_sync_status

    new_run = MirrorSyncRun(
        mirror_repo_id=mirror_id,
        started_at=now,
        status="running",
    )
    db.add(new_run)
    mirror_obj.last_sync_started_at = now
    mirror_obj.last_sync_status = "running"

    # Flush so the auto-generated id is populated for the caller.
    db.flush()
    return ClaimResult(
        outcome="slot_taken", run_id=new_run.id, prior_status=prior_status
    )


def _belt_finalize_failed(db, mirror_id: int, run_id: int, error_text: str) -> None:
    """Defensive finalizer for the orchestrator's unexpected-exception
    path. Runs on a fresh session because the orchestrator's session
    is rolled back / unusable when this is reached.
    """
    now = datetime.utcnow()
    run = db.query(MirrorSyncRun).filter(MirrorSyncRun.id == run_id).first()
    if run is not None and run.status == "running":
        run.status = "failed"
        run.finished_at = now
        run.error_text = ("scheduler crash during sync; belt-finalized: " + error_text)[
            :8192
        ]
    mirror = db.query(MirrorRepo).filter(MirrorRepo.id == mirror_id).first()
    if mirror is not None:
        mirror.last_sync_finished_at = now
        mirror.last_sync_status = "failed"
        mirror.last_sync_error = error_text[:8192]


# ---------------------------------------------------------------------------
# End-to-end claim + sync entry point
# ---------------------------------------------------------------------------


def claim_and_sync_one_mirror(
    mirror_id: int,
    slug: str,
    *,
    now: Optional[datetime] = None,
) -> str:
    """Run the full claim → persist → sync → alert flow for one mirror.

    Returns one of:
      * ``"locked"`` — another worker is already syncing this mirror.
      * ``"capped"`` — global concurrency cap reached this tick.
      * ``"ineligible"`` — mirror was disabled / soft-deleted / flipped
        to ``imported_offline`` after enumeration but before our
        claim. Distinct from "vanished" so callers can log meaningfully.
      * ``"vanished"`` — mirror or run row went missing between claim
        and sync (rare; most state changes flow through ``ineligible``).
      * ``"ok"`` — sync ran and finalized as ``status='ok'``.
      * ``"failed"`` — sync ran and finalized as ``status='failed'``.

    Does NOT raise on operational failures — the orchestrator
    finalizes its own row, the belt path handles unexpected
    exceptions, and the alert dispatch is best-effort on a separate
    session.
    """
    from .mirror_sync.service import perform_sync_for_mirror

    now = now or datetime.utcnow()
    cap = max_concurrent_syncs()

    with claim_mirror_for_sync(mirror_id) as mirror_acquired:
        if not mirror_acquired:
            return "locked"

        claim: Optional[ClaimResult] = None
        with global_claim_gate():
            short_db = SessionLocal()
            try:
                claim = _persist_claim_for_mirror(short_db, mirror_id, now, cap)
                short_db.commit()
            except Exception as exc:  # pylint: disable=broad-except
                short_db.rollback()
                logger.error("mirror claim persistence failed for %s: %s", slug, exc)
                claim = None
            finally:
                short_db.close()

        if claim is None or claim.outcome != "slot_taken":
            if claim is not None and claim.outcome == "cap_reached":
                return "capped"
            if claim is not None and claim.outcome == "ineligible":
                return "ineligible"
            return "vanished"

        run_id = claim.run_id
        prior_status = claim.prior_status

        # Sync orchestration on its own session. Alert events are
        # collected here and dispatched on a fresh session below
        # (PRA-157 #2b-a: alert/sync transaction decoupling).
        events: list = []
        outcome = "failed"
        mirror_for_alerts: Optional[MirrorRepo] = None

        sync_db = SessionLocal()
        try:
            mirror = (
                sync_db.query(MirrorRepo).filter(MirrorRepo.id == mirror_id).first()
            )
            run = (
                sync_db.query(MirrorSyncRun).filter(MirrorSyncRun.id == run_id).first()
            )
            if mirror is None or run is None:
                logger.warning(
                    "mirror sync: mirror=%s run=%s vanished before sync started",
                    mirror_id,
                    run_id,
                )
                return "vanished"

            try:
                ok, events = perform_sync_for_mirror(
                    sync_db, mirror, run, prior_status=prior_status
                )
                sync_db.commit()
                outcome = "ok" if ok else "failed"
            except Exception as exc:  # pylint: disable=broad-except
                sync_db.rollback()
                logger.exception("mirror sync: unexpected error for %s: %s", slug, exc)
                cleanup_db = SessionLocal()
                try:
                    _belt_finalize_failed(cleanup_db, mirror_id, run_id, str(exc))
                    cleanup_db.commit()
                finally:
                    cleanup_db.close()
                outcome = "failed"
                events = []

            # Detach a snapshot of the mirror's id/slug/family/distribution
            # for the alert path — the sync_db will close before alerts
            # dispatch. ``expire_on_commit=False`` keeps scalar attributes
            # readable but we don't want to rely on lazy-load.
            if mirror is not None:
                mirror_for_alerts = mirror
        finally:
            sync_db.close()

        if events and mirror_for_alerts is not None:
            alert_db = SessionLocal()
            try:
                # Re-fetch the mirror on the alert session so the
                # ORM-managed object is local to this transaction.
                # ``expire_on_commit=False`` lets us read sync_db's
                # mirror, but the dedup-row INSERT/UPDATE needs a
                # live session, and alert_service.send_alert commits
                # AlertHistory on this session — keep all of it
                # local.
                mirror_alert_obj = (
                    alert_db.query(MirrorRepo)
                    .filter(MirrorRepo.id == mirror_id)
                    .first()
                )
                if mirror_alert_obj is not None:
                    mirror_alerts.dispatch_alert_events(
                        alert_db, mirror_alert_obj, events, now=now
                    )
                    alert_db.commit()
                else:
                    logger.warning(
                        "mirror alerts: mirror=%s vanished before dispatch",
                        mirror_id,
                    )
            except Exception as exc:  # pylint: disable=broad-except
                alert_db.rollback()
                logger.exception("mirror alerts: dispatch failed for %s: %s", slug, exc)
            finally:
                alert_db.close()

        return outcome
