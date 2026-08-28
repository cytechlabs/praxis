"""
Background scheduler service for running cron-based jobs.
Uses APScheduler with BackgroundScheduler for sync SQLAlchemy sessions.
"""

import logging
from datetime import datetime, timezone
from functools import wraps
from typing import TYPE_CHECKING, Callable

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from ..db.models import Job, JobHistory
from ..db.session import SessionLocal
from .scheduler_lock import (
    SCHEDULER_JOB_KEYS,
    claim_recurring_tick,
    claim_user_job_tick,
)

if TYPE_CHECKING:  # pragma: no cover
    from ..db.models import MirrorRepo

logger = logging.getLogger(__name__)


def _guarded(job_id: str) -> Callable:
    """PRA-169: wrap a recurring scheduler callback in the rolling-
    window cross-worker claim. Lock losers skip the body and return
    promptly so the body executes at most once per ``period_seconds``
    cadence cycle across all uvicorn workers — both for overlapping
    firings (advisory lock) AND for staggered firings that arrive
    after the winner has already exited but inside the cadence
    cooldown (durable ``scheduler_job_locks`` row anchored to
    ``last_fired_at``, the rolling-window fix from the Slice 1
    review).

    The ``job_id`` matches the APScheduler ``id=`` passed to
    ``add_job`` AND the key in ``SCHEDULER_JOB_KEYS``. The dict
    lookup is at decoration time so a stale id (rebase drift,
    typo) fails the import rather than silently slipping through
    until the first tick at 02:15 UTC.
    """

    # Trigger the KeyError at decoration time, not first call.
    _ = SCHEDULER_JOB_KEYS[job_id]

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            with claim_recurring_tick(job_id) as acquired:
                if not acquired:
                    logger.debug(
                        "scheduler job %s: another worker already claimed "
                        "this tick — skipping",
                        job_id,
                    )
                    return None
                return func(self, *args, **kwargs)

        return wrapper

    return decorator


def _mirror_due(mirror: "MirrorRepo", now: datetime) -> bool:
    """Return True if ``mirror``'s cron schedule says it is due to
    sync since its last attempt.

    Anchors off ``last_sync_started_at`` (covers the case where a
    sync started but didn't yet finish — the cron's next-fire-after
    that anchor is still the right comparison). For brand-new
    mirrors (no last_sync_started_at), anchors off the unix epoch
    so the very first sweep tick fires the first sync.

    Returns False on cron parse error so a malformed schedule
    doesn't crash the whole sweep — slice #2b's API validates cron
    on write, but defensive parsing here keeps the runtime
    forgiving.
    """
    try:
        trigger = CronTrigger.from_crontab(mirror.sync_schedule_cron, timezone="UTC")
    except Exception:  # pylint: disable=broad-except
        logger.warning(
            "mirror %s: invalid cron %r; skipping",
            mirror.slug,
            mirror.sync_schedule_cron,
        )
        return False

    anchor = mirror.last_sync_started_at or datetime(1970, 1, 1)
    # APScheduler's CronTrigger expects timezone-aware datetimes for
    # comparison. The DB stores naive UTC; tag both with UTC so the
    # arithmetic is unambiguous.
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    now_aware = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)

    next_fire = trigger.get_next_fire_time(anchor, now_aware)
    return next_fire is not None and next_fire <= now_aware


class SchedulerService:
    """Background scheduler that runs recurring jobs based on cron expressions."""

    def __init__(self):
        self.scheduler = BackgroundScheduler(
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": 300,
            }
        )

    def start(self):
        """Load all recurring jobs from DB and start the scheduler."""
        db = SessionLocal()
        try:
            jobs = (
                db.query(Job)
                .filter(
                    Job.is_recurring.is_(True),
                    Job.schedule.isnot(None),
                    Job.status.in_(["scheduled", "completed"]),
                )
                .all()
            )

            for job in jobs:
                self.schedule_job(job)

            # PRA-112: Recurring fleet connectivity health check (every 30 min).
            # Wrapped through ``self._run_fleet_health_check`` so it picks up
            # the PRA-169 cross-worker advisory-lock guard.
            self.scheduler.add_job(
                self._run_fleet_health_check,
                trigger=IntervalTrigger(minutes=30),
                id="fleet_health_check",
                name="Fleet connectivity health check",
                replace_existing=True,
            )

            # PRA-125: Webhook delivery retry sweeper (every 30s)
            self.scheduler.add_job(
                self._run_webhook_retry_sweep,
                trigger=IntervalTrigger(seconds=30),
                id="webhook_retry_sweep",
                name="Webhook delivery retry sweeper",
                replace_existing=True,
            )

            # PRA-126: Smart group membership recompute (every 5 min safety net)
            self.scheduler.add_job(
                self._run_smart_group_recompute,
                trigger=IntervalTrigger(minutes=5),
                id="smart_group_recompute",
                name="Smart group membership recompute",
                replace_existing=True,
            )

            # PRA-127: Drift detection — run due baselines every 15 min
            self.scheduler.add_job(
                self._run_drift_sweep,
                trigger=IntervalTrigger(minutes=15),
                id="drift_sweep",
                name="Drift detection baseline runner",
                replace_existing=True,
            )

            # PRA-127: 90-day retention sweep for baseline_checks — once/day at 03:00 UTC
            self.scheduler.add_job(
                self._run_drift_retention,
                trigger=CronTrigger(hour=3, minute=0, timezone="UTC"),
                id="drift_retention",
                name="Baseline check retention sweep",
                replace_existing=True,
            )

            # PRA-165 Slice 2: Compliance evaluation — run due policies
            # every 15 min. The sweep skips policies whose
            # ``last_run_at`` is younger than ``schedule_interval_hours``,
            # so per-policy cadence is honored even though the sweeper
            # itself runs more often. Mirrors the drift_sweep cadence so
            # operators only have one "wait for the next sweep tick"
            # mental model.
            self.scheduler.add_job(
                self._run_compliance_evaluation_sweep,
                trigger=IntervalTrigger(minutes=15),
                id="compliance_evaluation_sweep",
                name="Compliance evaluation runner",
                replace_existing=True,
            )

            # PRA-165 Slice 2: per-policy evidence retention sweep — once/day at 03:15 UTC.
            # 15 minutes after the drift retention so they don't both
            # contend on the audit fan-out queue at the same minute.
            self.scheduler.add_job(
                self._run_compliance_retention,
                trigger=CronTrigger(hour=3, minute=15, timezone="UTC"),
                id="compliance_retention",
                name="Compliance evidence retention sweep",
                replace_existing=True,
            )

            # PRA-129: Command approval expiration sweeper (every 5 min)
            self.scheduler.add_job(
                self._run_approval_expiration,
                trigger=IntervalTrigger(minutes=5),
                id="approval_expiration",
                name="Command approval expiration sweeper",
                replace_existing=True,
            )

            # PRA-155 #2b-b: facts refresh sweeper (every 30 min). The
            # sweeper itself runs frequently so a host that just
            # missed its window gets picked up promptly; the per-host
            # skip-if-fresh check inside the sweep enforces the real
            # 6h refresh cadence. APScheduler's default
            # ``max_instances=1`` keeps two sweepers from racing.
            self.scheduler.add_job(
                self._run_facts_refresh_sweep,
                trigger=IntervalTrigger(minutes=30),
                id="facts_refresh_sweep",
                name="Host facts periodic refresh",
                replace_existing=True,
            )

            # PRA-140: interactive session sweepers (every 60s)
            self.scheduler.add_job(
                self._run_session_sweeps,
                trigger=IntervalTrigger(seconds=60),
                id="session_sweeps",
                name="Interactive session idle + max-duration sweeps",
                replace_existing=True,
            )

            # PRA-149: access review overdue sweep (every 60 min)
            self.scheduler.add_job(
                self._run_access_review_overdue,
                trigger=IntervalTrigger(minutes=60),
                id="access_review_overdue",
                name="Access review overdue sweeper",
                replace_existing=True,
            )

            # PRA-149: scheduled cadence-based review creation (daily 04:00 UTC)
            self.scheduler.add_job(
                self._run_access_review_creation,
                trigger=CronTrigger(hour=4, minute=0, timezone="UTC"),
                id="access_review_creation",
                name="Access review cadence runner",
                replace_existing=True,
            )

            # Guided onboarding drafts: expire, release stale finalization
            # leases, and prune old rows so the table stays bounded.
            self.scheduler.add_job(
                self._run_onboarding_draft_sweep,
                trigger=IntervalTrigger(minutes=5),
                id="onboarding_draft_sweep",
                name="Onboarding draft sweeper",
                replace_existing=True,
            )

            # PRA-147: session approval expiration sweeper (every 60s)
            self.scheduler.add_job(
                self._run_session_approval_expiration,
                trigger=IntervalTrigger(seconds=60),
                id="session_approval_expiration",
                name="Session approval expiration sweeper",
                replace_existing=True,
            )

            # PRA-141: recording retention sweep (once/day at 03:30 UTC)
            self.scheduler.add_job(
                self._run_recording_retention,
                trigger=CronTrigger(hour=3, minute=30, timezone="UTC"),
                id="recording_retention",
                name="Session recording retention sweep",
                replace_existing=True,
            )

            # PRA-143: audit event sink delivery sweep (every 30s)
            self.scheduler.add_job(
                self._run_audit_delivery,
                trigger=IntervalTrigger(seconds=30),
                id="audit_delivery",
                name="Audit event sink delivery sweep",
                replace_existing=True,
            )

            # PRA-285: access-revocation drain (every 30s). Reconciles hosts for
            # narrowed access, closes DB-only/cross-worker sessions, realizes JIT
            # expiry, retries offline hosts. Guarded (one worker per tick).
            self.scheduler.add_job(
                self._run_revocation_drain,
                trigger=IntervalTrigger(seconds=30),
                id="revocation_drain",
                name="Access revocation drain (PRA-285)",
                replace_existing=True,
            )

            # PRA-156 #3c: daily lifecycle recompute. ``today`` advances
            # once per day with no facts upsert; a host that was
            # ``approaching-eol`` yesterday can be ``unsupported`` today
            # without any per-host event the ingest hook would catch.
            # Scheduled at 02:15 UTC — early enough that ``today`` is
            # firmly the new day in every TZ, late enough to not
            # collide with the 03:00 drift retention or 03:30 recording
            # retention sweeps. The pass itself filters to
            # lifecycle-using groups so the cost on installs without
            # any lifecycle predicate is one cheap query.
            self.scheduler.add_job(
                self._run_lifecycle_recompute,
                trigger=CronTrigger(hour=2, minute=15, timezone="UTC"),
                id="lifecycle_recompute",
                name="Daily lifecycle smart-group recompute",
                replace_existing=True,
            )

            # PRA-156 #3e-c: daily lifecycle notification emitter.
            # Runs 15 minutes after the recompute pass so any group
            # membership shifts triggered by the new day's verdicts
            # are settled before the emitter walks the lifecycle
            # index. Each (system, threshold, eol_date) combination
            # notifies exactly once via the
            # lifecycle_notification_state dedup table.
            self.scheduler.add_job(
                self._run_lifecycle_emitter,
                trigger=CronTrigger(hour=2, minute=30, timezone="UTC"),
                id="lifecycle_emitter",
                name="Daily lifecycle notification emitter",
                replace_existing=True,
            )

            # PRA-178 Slice 5: scheduled report runs. Walks every
            # enabled report_schedule whose ``next_run_at`` is in the
            # past, fires the underlying export through the Slice 1/4
            # service, persists a ``report_runs`` row with
            # ``triggered_by='system_scheduled'``, and advances
            # ``next_run_at``. Idempotent — a re-fire inside the same
            # tick sees ``next_run_at`` already in the future and
            # skips. Runs every 5 minutes so a schedule that was due
            # earlier gets picked up promptly without flooding under
            # an empty fleet.
            self.scheduler.add_job(
                self._run_report_schedules_due,
                trigger=IntervalTrigger(minutes=5),
                id="report_schedules_due",
                name="Scheduled report runs (PRA-178 Slice 5)",
                replace_existing=True,
            )

            # PRA-157 slice #1: mirror sync due-sweep. Every minute,
            # walk enabled non-imported non-deleted mirrors and
            # attempt to claim each whose cron schedule is due since
            # its last sync. Claim uses pg_try_advisory_lock — losers
            # skip without blocking, so this sweep stays cheap even
            # under prod's 4 uvicorn workers. Slice #1 NOOPs the
            # subprocess body after exercising stale-running recovery;
            # slice #2a wires the deb sync engine into this same path.
            self.scheduler.add_job(
                self._run_mirror_sync_due,
                trigger=IntervalTrigger(minutes=1),
                id="mirror_sync_due",
                name="Mirror sync due sweep (PRA-157)",
                replace_existing=True,
            )

            # PRA-157 slice #1: write the layout descriptor at the
            # mirror data root on first scheduler init. PRA-160's
            # airgap importer keys off this file. Idempotent — first
            # writer wins.
            try:
                from .mirror_paths import ensure_descriptor

                ensure_descriptor()
            except Exception as e:  # pylint: disable=broad-except
                # Don't block scheduler startup on descriptor write
                # failure (e.g. read-only volume); the mirror sweep
                # itself logs the underlying issue when it fails to
                # touch the volume. Tests assert the write succeeds
                # under the normal mounted-volume happy path.
                logger.warning("Failed to write praxis-mirror.json descriptor: %s", e)

            self.scheduler.start()
            logger.info(
                "Scheduler started with %d recurring jobs + health + webhook + smart-group + drift sweepers",
                len(jobs),
            )
        except Exception as e:
            logger.error("Failed to start scheduler: %s", str(e))
            raise
        finally:
            db.close()

    def stop(self):
        """Shutdown the scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")

    def schedule_job(self, job: Job):
        """Add or update a job's cron trigger in the scheduler."""
        job_scheduler_id = f"job_{job.id}"

        # Remove existing schedule if present
        existing = self.scheduler.get_job(job_scheduler_id)
        if existing:
            self.scheduler.remove_job(job_scheduler_id)

        if not job.schedule:
            logger.warning("Job %d has no schedule, skipping", job.id)
            return

        try:
            trigger = CronTrigger.from_crontab(job.schedule, timezone="UTC")
            self.scheduler.add_job(
                self._execute_job,
                trigger=trigger,
                id=job_scheduler_id,
                args=[job.id],
                name=f"Job: {job.name}",
                replace_existing=True,
            )
            logger.info(
                "Scheduled job %d (%s) with cron: %s",
                job.id,
                job.name,
                job.schedule,
            )
        except Exception as e:
            logger.error("Failed to schedule job %d: %s", job.id, str(e))

    def unschedule_job(self, job_id: int):
        """Remove a job from the scheduler."""
        job_scheduler_id = f"job_{job_id}"
        existing = self.scheduler.get_job(job_scheduler_id)
        if existing:
            self.scheduler.remove_job(job_scheduler_id)
            logger.info("Unscheduled job %d", job_id)

    @_guarded("fleet_health_check")
    def _run_fleet_health_check(self):
        """PRA-112: Recurring fleet connectivity health check.

        PRA-169: thin wrapper around ``run_scheduled_health_check``
        so the cross-worker advisory-lock guard applies. Without
        this guard the 30-min interval triggers 4x per tick in prod
        and probes every host from each uvicorn worker."""
        from .health_service import run_scheduled_health_check

        try:
            run_scheduled_health_check()
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Fleet health check failed: %s", e)

    @_guarded("approval_expiration")
    def _run_approval_expiration(self):
        """PRA-129: Expire pending command approvals past their expires_at."""
        from .command_approval_service import expire_stale

        db = SessionLocal()
        try:
            n = expire_stale(db)
            if n:
                logger.info("Expired %d stale command approvals", n)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Approval expiration sweep failed: %s", e)
        finally:
            db.close()

    @_guarded("session_sweeps")
    def _run_session_sweeps(self):
        """PRA-140: close idle and past-max-duration interactive sessions."""
        from .session_service import sweep_idle, sweep_max_duration

        try:
            idle = sweep_idle(idle_seconds=900)
            maxed = sweep_max_duration()
            if idle or maxed:
                logger.info(
                    "session sweep: %d idle-closed, %d max-duration-closed",
                    idle,
                    maxed,
                )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Session sweep failed: %s", e)

    @_guarded("access_review_overdue")
    def _run_access_review_overdue(self):
        """PRA-149: mark past-due pending reviews as expired."""
        from .access_review_service import sweep_overdue

        try:
            n = sweep_overdue()
            if n:
                logger.info("access review overdue: %d expired", n)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Access review overdue sweep failed: %s", e)

    @_guarded("access_review_creation")
    def _run_access_review_creation(self):
        """PRA-149: create a new all-scope review if the cadence has elapsed."""
        from .access_review_service import maybe_create_scheduled_review

        try:
            new_id = maybe_create_scheduled_review()
            if new_id is not None:
                logger.info("access review %d auto-created by cadence runner", new_id)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Access review cadence runner failed: %s", e)

    @_guarded("session_approval_expiration")
    def _run_session_approval_expiration(self):
        """PRA-147: mark granted-but-unused approvals past expires_at."""
        from .session_approval_service import sweep_expired

        try:
            n = sweep_expired()
            if n:
                logger.info("session approval expiration: %d expired", n)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Session approval expiration sweep failed: %s", e)

    @_guarded("onboarding_draft_sweep")
    def _run_onboarding_draft_sweep(self):
        """Expire, release and prune guided onboarding drafts."""
        from .onboarding_draft_service import sweep_drafts

        db = SessionLocal()
        try:
            counts = sweep_drafts(db)
            if any(counts.values()):
                logger.info(
                    "onboarding draft sweep: released=%d expired=%d pruned=%d",
                    counts["released"],
                    counts["expired"],
                    counts["pruned"],
                )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Onboarding draft sweep failed: %s", e)
        finally:
            db.close()

    @_guarded("recording_retention")
    def _run_recording_retention(self):
        """PRA-141: delete recordings past their retention_expires_at."""
        from .recording_service import sweep_expired

        try:
            n = sweep_expired()
            if n:
                logger.info("recording retention: pruned %d", n)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Recording retention sweep failed: %s", e)

    @_guarded("audit_delivery")
    def _run_audit_delivery(self):
        """PRA-143: drain pending audit sink deliveries."""
        from .audit_event_service import run_delivery_sweep

        try:
            counts = run_delivery_sweep()
            if any(counts.values()):
                logger.info("audit delivery sweep: %s", counts)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Audit delivery sweep failed: %s", e)

    @_guarded("revocation_drain")
    def _run_revocation_drain(self):
        """PRA-285: drain the access-revocation work outbox (host reconcile +
        DB-only session close + JIT expiry), guarded to one worker per tick."""
        from .revocation_service import drain

        db = SessionLocal()
        try:
            n = drain(db)
            if n:
                logger.info("revocation drain processed %d work item(s)", n)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Revocation drain failed: %s", e)
        finally:
            db.close()

    @_guarded("facts_refresh_sweep")
    def _run_facts_refresh_sweep(self):
        """PRA-155 #2b-b: refresh facts for any host whose existing
        ``host_facts`` row is older than the configured interval (or
        has no row yet).

        Picks the SSH path for every host. The agent path is always
        available via the on-demand refresh endpoint (#2b-b) but the
        scheduler intentionally does NOT use it: an agent that's
        actively running ops shouldn't be interrupted on a 30-min
        cadence for inventory, and agent-collected facts already
        flow through ``/agent/enroll`` and the broker's facts op
        when an operator triggers them. The SSH sweep covers the
        non-agent fleet plus agent hosts whose tunnel is down.
        """
        from .facts_refresh_sweep import run_facts_refresh_sweep

        db = SessionLocal()
        try:
            stats = run_facts_refresh_sweep(db)
            if stats:
                logger.info("Facts refresh sweep: %s", stats)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Facts refresh sweep failed: %s", e)
        finally:
            db.close()

    @_guarded("drift_sweep")
    def _run_drift_sweep(self):
        """PRA-127: Run every enabled baseline whose schedule is due."""
        from .drift_service import run_all_due

        db = SessionLocal()
        try:
            stats = run_all_due(db)
            if stats:
                logger.info("Drift sweep ran %d baselines: %s", len(stats), stats)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Drift sweep failed: %s", e)
        finally:
            db.close()

    @_guarded("drift_retention")
    def _run_drift_retention(self):
        """PRA-127: Delete BaselineCheck rows older than 90 days."""
        from .drift_service import purge_old_checks

        db = SessionLocal()
        try:
            removed = purge_old_checks(db, days=90)
            if removed:
                logger.info("Drift retention purged %d old check rows", removed)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Drift retention sweep failed: %s", e)
        finally:
            db.close()

    @_guarded("compliance_evaluation_sweep")
    def _run_compliance_evaluation_sweep(self):
        """PRA-165 Slice 2: evaluate every enabled, due compliance policy
        against the fleet using existing facts + package inventory.
        """
        from .compliance_evaluation_service import evaluate_due_policies

        db = SessionLocal()
        try:
            summaries = evaluate_due_policies(db)
            if summaries:
                logger.info(
                    "Compliance evaluation sweep ran %d policies",
                    len(summaries),
                )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Compliance evaluation sweep failed: %s", e)
        finally:
            db.close()

    @_guarded("compliance_retention")
    def _run_compliance_retention(self):
        """PRA-165 Slice 2: prune compliance evidence past each policy's
        ``evidence_retention_days``.
        """
        from .compliance_evaluation_service import retain_evidence

        db = SessionLocal()
        try:
            pruned = retain_evidence(db)
            if pruned:
                logger.info(
                    "Compliance evidence retention pruned %d policies (%d rows total)",
                    len(pruned),
                    sum(pruned.values()),
                )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Compliance retention sweep failed: %s", e)
        finally:
            db.close()

    @_guarded("smart_group_recompute")
    def _run_smart_group_recompute(self):
        """PRA-126: Safety-net recompute of smart group membership."""
        from .smart_group_service import recompute_all

        db = SessionLocal()
        try:
            stats = recompute_all(db)
            if stats:
                logger.info("Smart group recompute touched %d groups", len(stats))
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Smart group recompute failed: %s", e)
        finally:
            db.close()

    @_guarded("lifecycle_recompute")
    def _run_lifecycle_recompute(self):
        """PRA-156 #3c: Daily lifecycle smart-group recompute.

        Re-evaluates membership for groups whose rules reference
        ``lifecycle.*`` so the time-driven status transitions (today
        moving past eol_date, into the 90-day approaching window)
        land in cached membership without a facts upsert.
        """
        from .smart_group_service import recompute_lifecycle_groups

        db = SessionLocal()
        try:
            touched = recompute_lifecycle_groups(db)
            logger.info("Lifecycle recompute touched %d groups", touched)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Lifecycle recompute failed: %s", e)
        finally:
            db.close()

    @_guarded("lifecycle_emitter")
    def _run_lifecycle_emitter(self):
        """PRA-156 #3e-c: Daily lifecycle notification emitter.

        Walks the lifecycle index and fires host_eol_approaching /
        host_eol_reached for hosts that crossed a threshold since
        the last run. Dedup state lives in
        lifecycle_notification_state so each
        (system, event_type, threshold, effective_eol_date)
        combination notifies exactly once.
        """
        from .lifecycle_emitter_service import emit_for_all_systems

        db = SessionLocal()
        try:
            fired = emit_for_all_systems(db)
            logger.info("Lifecycle emitter fired %d new event(s)", len(fired))
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Lifecycle emitter failed: %s", e)
        finally:
            db.close()

    @_guarded("webhook_retry_sweep")
    def _run_webhook_retry_sweep(self):
        """PRA-125: Pick up failed webhook deliveries whose retry time is due."""
        from .alert_service import retry_pending_deliveries

        db = SessionLocal()
        try:
            processed = retry_pending_deliveries(db)
            if processed:
                logger.info("Webhook retry sweep processed %d deliveries", processed)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Webhook retry sweep failed: %s", e)
        finally:
            db.close()

    @_guarded("report_schedules_due")
    def _run_report_schedules_due(self):
        """PRA-178 Slice 5: fire every due report schedule. Each
        successful firing persists a ``report_runs`` row with
        ``triggered_by='system_scheduled'`` and advances the
        schedule's ``next_run_at``. Idempotent — a re-fire inside
        the same tick is a no-op.

        PRA-169: the scheduler-job-level advisory lock above is the
        first line of defense (one body execution per tick across
        all uvicorn workers). The per-schedule conditional UPDATE
        inside ``fire_due_schedules`` is preserved as
        defense-in-depth — it remains the correctness guarantee
        for races with on-demand fires or operators advancing
        ``next_run_at`` manually."""
        from .report_schedule_service import fire_due_schedules

        db = SessionLocal()
        try:
            counters = fire_due_schedules(db)
            if any(v for v in counters.values() if v):
                logger.info(
                    "Report schedule sweep: %s",
                    counters,
                )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Report schedule sweep failed: %s", e)
        finally:
            db.close()

    def _run_mirror_sync_due(self):
        """PRA-157: walk enabled mirrors and claim those whose cron
        schedule is due since the last sync.

        The per-mirror flow (advisory lock → global cap gate → persist
        running row → run sync orchestrator) lives in
        ``mirror_sweep.claim_and_sync_one_mirror`` so the on-demand
        ``POST /mirrors/{id}/sync`` route shares the same claim path.

        PRA-169 audit decision: this sweep is intentionally NOT
        wrapped in the scheduler-job-level advisory lock. The
        PRA-157 per-mirror ``claim_mirror_for_sync`` lock and the
        global concurrency gate already give the correct
        per-resource serialization, and the sweep is designed to
        run concurrently from multiple workers — each worker
        attempts each due mirror and the per-mirror lock arbitrates
        which one wins. Adding a job-level guard would force all 4
        uvicorn workers' ticks to serialize through one body,
        partially defeating the parallel claim attempts the
        per-mirror lock supports for installs with multiple due
        mirrors at the same tick.
        """
        from datetime import datetime

        from .mirror_sweep import (
            claim_and_sync_one_mirror,
            sweep_eligible_mirrors_query,
        )

        db = SessionLocal()
        try:
            mirrors = sweep_eligible_mirrors_query(db).all()
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Mirror sweep failed to enumerate mirrors: %s", e)
            db.close()
            return
        finally:
            db.close()

        now = datetime.utcnow()
        for mirror in mirrors:
            if not _mirror_due(mirror, now):
                continue

            outcome = claim_and_sync_one_mirror(mirror.id, mirror.slug, now=now)
            if outcome == "capped":
                logger.info(
                    "mirror sweep: %s skipped — global concurrency cap "
                    "reached this tick (will retry next tick)",
                    mirror.slug,
                )
            elif outcome == "ineligible":
                logger.info(
                    "mirror sweep: %s skipped — became ineligible "
                    "(disabled / soft-deleted / imported_offline) between "
                    "enumeration and claim",
                    mirror.slug,
                )
            elif outcome == "vanished":
                logger.warning("mirror sweep: %s vanished during claim", mirror.slug)

    def _execute_job(self, job_id: int):
        """Callback that runs when a cron trigger fires.

        PRA-169: a DB-defined ``Job`` row's cron is registered in
        every uvicorn worker's APScheduler, so without a
        cross-worker claim each cron fire triggers the body 4x.
        The downstream status='running' guard inside the body
        races between workers (read-modify-write across separate
        ORM sessions), so the safe path is to claim before any
        DB read.

        Uses the rolling-window durable claim
        (``scheduler_job_locks`` keyed on ``f"user:{job_id}"`` with
        a 1-minute cadence cooldown anchored to ``last_fired_at``)
        so staggered firings inside the same minute can't
        re-execute after the winner exits. The advisory-lock layer
        underneath uses ``SCHEDULER_USER_JOB_NAMESPACE`` + the
        row's id, structurally non-colliding with recurring-sweep
        keys.
        """
        with claim_user_job_tick(job_id) as acquired:
            if not acquired:
                logger.info(
                    "Cron trigger for user job %d: another worker already "
                    "claimed this tick — skipping",
                    job_id,
                )
                return
            self._execute_job_body(job_id)

    def _execute_job_body(self, job_id: int):
        """Inner body of ``_execute_job`` — runs only after the
        cross-worker claim has been acquired."""
        from .job_service import JobService

        logger.info("Cron trigger fired for job %d", job_id)

        db = SessionLocal()
        try:
            job = db.query(Job).filter(Job.id == job_id).first()
            if not job:
                logger.error("Job %d not found, unscheduling", job_id)
                self.unschedule_job(job_id)
                return

            if job.status == "paused":
                logger.info("Job %d is paused, skipping execution", job_id)
                return

            if job.status == "running":
                logger.warning("Job %d is already running, skipping", job_id)
                return

            # PRA-81: Check if this job has unmet dependency
            if job.depends_on_job_id:
                dep_history = (
                    db.query(JobHistory)
                    .filter(JobHistory.job_id == job.depends_on_job_id)
                    .order_by(JobHistory.id.desc())
                    .first()
                )
                condition = job.chain_condition or "on_success"
                if not dep_history:
                    logger.info(
                        "Job %d skipped: dependency job %d hasn't run yet",
                        job_id,
                        job.depends_on_job_id,
                    )
                    return
                dep_status = dep_history.status
                should_run = (
                    condition == "on_complete"
                    or (condition == "on_success" and dep_status == "completed")
                    or (condition == "on_failure" and dep_status == "failed")
                )
                if not should_run:
                    logger.info(
                        "Job %d skipped: chain condition '%s' not met (dep status=%s)",
                        job_id,
                        condition,
                        dep_status,
                    )
                    return

            service = JobService(db)
            result = service.run_job(job_id, job.created_by)
            logger.info(
                "Cron execution of job %d completed: %s",
                job_id,
                result.get("message", ""),
            )
        except Exception as e:
            logger.error(
                "Cron execution of job %d failed: %s",
                job_id,
                str(e),
            )
        finally:
            db.close()


# Singleton instance
scheduler_service = SchedulerService()
