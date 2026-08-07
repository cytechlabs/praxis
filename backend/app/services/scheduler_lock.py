"""Multi-worker-safe rolling-window claim primitive for scheduler job
bodies (PRA-169).

Background
----------
Production can be configured with multiple Uvicorn workers, and each
worker spawns its own APScheduler ``BackgroundScheduler``. Recurring
callbacks registered in
:mod:`backend.app.services.scheduler_service` therefore fire once
per worker per cron tick. APScheduler's ``max_instances=1`` only
gates re-entrance *within a single process* — it cannot serialize
across workers — so without an explicit cross-worker claim the same
body runs once per worker per tick (the PRA-156 lifecycle recompute /
emitter pattern called out in Linear PRA-169). This primitive stays
correct for any worker count, including the 1.0 single-worker default.

Why a body-duration advisory lock is not enough
-----------------------------------------------
A PRA-157-style
``pg_try_advisory_lock`` mutually-excludes only while the body is
*actively running*. A second worker firing milliseconds after the
winner releases the lock can re-acquire and execute the same cron
tick again. Fast/no-op sweeps finish well inside the cron tick
window.

Why epoch-anchored buckets were not enough either
-------------------------------------------------
Slice 1a layered a durable ``(job_id, tick_bucket)`` claim row on
top of the advisory lock. Two workers in the same epoch bucket
race for the same row and the loser skips. But the boundary case for
interval triggers remained: with a 30s job,
worker A can fire at :59 (epoch bucket [:30, :60)) and worker B
can fire at :61 (epoch bucket [:60, :90)), and the per-(epoch-
bucket) UNIQUE key lets both run — both bodies execute inside one
effective 30-second multi-worker cadence cycle. Interval triggers
in APScheduler are anchored to each worker's scheduler start time
(no shared ``start_date``), so the bucket boundary almost never
matches the actual cadence.

Slice 1b — rolling cadence window
---------------------------------
The fix is to enforce "no two body executions within
``period_seconds`` of each other across all workers" — a true
rolling window, anchored to the most recent successful claim
rather than to wall-clock epoch bins.

Storage: one row per ``job_id`` in ``scheduler_job_locks``
(``UNIQUE(job_id)``) carrying ``last_fired_at``. The claim path is::

    INSERT INTO scheduler_job_locks (job_id, last_fired_at, ...)
    VALUES (:job_id, :now, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT ON CONSTRAINT scheduler_job_locks_job_id_uniq
    DO UPDATE
       SET last_fired_at = EXCLUDED.last_fired_at,
           updated_at    = CURRENT_TIMESTAMP
     WHERE scheduler_job_locks.last_fired_at
           + (:period_seconds * INTERVAL '1 second')
           <= EXCLUDED.last_fired_at
    RETURNING id

Atomicity comes from the UNIQUE constraint: two concurrent INSERTs
serialize on the row, and the loser's ``ON CONFLICT DO UPDATE``
fires the WHERE clause which compares the existing row's
``last_fired_at`` to the proposed ``now``. If the cadence cooldown
has not elapsed, no UPDATE happens and ``RETURNING`` yields zero
rows. The worker that gets zero rows back is a loser and skips
its body.

This is the correct rolling-window semantic: a worker firing at
the boundary of one epoch bucket and another firing slightly into
the next epoch bucket both compare against the SAME
``last_fired_at`` anchor; only the one that advances the anchor
by at least the cadence wins.

Two-level guard
---------------
The PRA-157 advisory lock still wraps the claim path as a cheap
in-process gate to prevent thundering UPSERTs at the cron tick.
Correctness lives in the rolling-window SQL above; the advisory
lock is just an optimization.

Pool-correctness
----------------
The advisory lock is taken on a dedicated AUTOCOMMIT connection
that is invalidated + closed on context exit (the PRA-157
``mirror_lock`` pattern). The UPSERT runs on the same dedicated
connection so a forgotten transaction can't pin the claim row's
visibility for other workers.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Generator, Optional

from sqlalchemy import text

from ..db.session import engine

logger = logging.getLogger(__name__)


# 16-bit namespace for recurring sweep job bodies. 0x5343 = "SC" =
# Scheduler. Distinct from the PRA-157 mirror namespace (0x4D52,
# "MR") so the two advisory-lock pools never collide.
SCHEDULER_LOCK_NAMESPACE = 0x5343

# 16-bit namespace for DB-defined Job rows scheduled through
# ``SchedulerService._execute_job``. 0x5355 = "SU" =
# Scheduler-User. Keys are the row's id, so collisions with the
# recurring-sweep namespace are structurally impossible.
SCHEDULER_USER_JOB_NAMESPACE = 0x5355


# Cron's minimum granularity. A DB-defined ``Job`` row firing twice
# within the same rolling 60-second window collapses to one body
# execution. Operators wanting sub-minute user-job cadence are out
# of scope for cron-based scheduling anyway.
USER_JOB_TICK_PERIOD_SECONDS = 60


@dataclass(frozen=True)
class SchedulerJobSpec:
    """Lock key + cron cadence for one recurring scheduler job.

    ``key`` is the advisory-lock id under
    :data:`SCHEDULER_LOCK_NAMESPACE`. ``period_seconds`` drives the
    rolling-window claim: two body executions for the same
    ``job_id`` must be at least ``period_seconds`` apart anywhere
    in the fleet.

    Keys are kept unique by :func:`_assert_keys_unique` at import
    time. Periods are documented per-job so a future cadence change
    is a single grep-able edit here.
    """

    key: int
    period_seconds: int


# Stable, deterministic int32 keys + cron period for each recurring
# sweeper. Adding a new scheduler job means adding a new entry here
# AND wiring the guard at the callback site in
# ``backend/app/services/scheduler_service.py``. Removing one is a
# coordinated change with the scheduler registration. The string id
# matches the APScheduler ``id=`` passed to ``add_job`` so an
# operator can map a log line back to the lock key without grepping
# two files.
SCHEDULER_JOB_KEYS: Dict[str, SchedulerJobSpec] = {
    "fleet_health_check": SchedulerJobSpec(key=1, period_seconds=30 * 60),
    "webhook_retry_sweep": SchedulerJobSpec(key=2, period_seconds=30),
    "smart_group_recompute": SchedulerJobSpec(key=3, period_seconds=5 * 60),
    "drift_sweep": SchedulerJobSpec(key=4, period_seconds=15 * 60),
    "drift_retention": SchedulerJobSpec(key=5, period_seconds=24 * 60 * 60),
    "compliance_evaluation_sweep": SchedulerJobSpec(key=6, period_seconds=15 * 60),
    "compliance_retention": SchedulerJobSpec(key=7, period_seconds=24 * 60 * 60),
    "approval_expiration": SchedulerJobSpec(key=8, period_seconds=5 * 60),
    "facts_refresh_sweep": SchedulerJobSpec(key=9, period_seconds=30 * 60),
    "session_sweeps": SchedulerJobSpec(key=10, period_seconds=60),
    "access_review_overdue": SchedulerJobSpec(key=11, period_seconds=60 * 60),
    "access_review_creation": SchedulerJobSpec(key=12, period_seconds=24 * 60 * 60),
    "session_approval_expiration": SchedulerJobSpec(key=13, period_seconds=60),
    "recording_retention": SchedulerJobSpec(key=14, period_seconds=24 * 60 * 60),
    "audit_delivery": SchedulerJobSpec(key=15, period_seconds=30),
    "lifecycle_recompute": SchedulerJobSpec(key=16, period_seconds=24 * 60 * 60),
    "lifecycle_emitter": SchedulerJobSpec(key=17, period_seconds=24 * 60 * 60),
    "report_schedules_due": SchedulerJobSpec(key=18, period_seconds=5 * 60),
    "revocation_drain": SchedulerJobSpec(key=19, period_seconds=30),
}


def _assert_keys_unique() -> None:
    """Fail fast at import time if two scheduler jobs map to the
    same advisory-lock key — that would mean two unrelated jobs
    serialize on each other across workers, which is silently wrong
    but easy to introduce in a rebase."""

    seen: Dict[int, str] = {}
    for name, spec in SCHEDULER_JOB_KEYS.items():
        if spec.key in seen:
            raise RuntimeError(
                f"SCHEDULER_JOB_KEYS collision: {name!r} and "
                f"{seen[spec.key]!r} both map to key {spec.key}"
            )
        seen[spec.key] = name


_assert_keys_unique()


@contextlib.contextmanager
def claim_scheduler_job(
    job_key: int,
    *,
    namespace: int = SCHEDULER_LOCK_NAMESPACE,
) -> Generator[bool, None, None]:
    """Try to acquire a session-level advisory lock for one scheduler
    job body.

    This is the PRA-157-style advisory-lock primitive: cheap, in-
    process, mutex-only. It does NOT guarantee one execution per
    cron tick on its own — for that,
    use :func:`claim_scheduler_tick`. This entry point remains
    exposed for the low-level namespace-independence test surface
    and for callers that want raw mutex semantics.

    Yields ``True`` if the lock was acquired (caller is the unique
    holder for this ``(namespace, job_key)`` for the duration of
    the context body). Yields ``False`` if the lock could not be
    acquired.
    """

    conn = engine.connect()
    try:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")

        acquired = bool(
            conn.execute(
                text("SELECT pg_try_advisory_lock(:ns, :id)"),
                {"ns": namespace, "id": job_key},
            ).scalar()
        )

        try:
            yield acquired
        finally:
            if acquired:
                try:
                    conn.execute(
                        text("SELECT pg_advisory_unlock(:ns, :id)"),
                        {"ns": namespace, "id": job_key},
                    )
                except Exception:  # pylint: disable=broad-except
                    logger.warning(
                        "pg_advisory_unlock failed for scheduler job "
                        "(ns=%s key=%s); falling back to session-end release.",
                        namespace,
                        job_key,
                    )
    finally:
        conn.invalidate()
        conn.close()


def _try_claim_rolling_window(
    conn,
    job_id: str,
    now: datetime,
    period_seconds: int,
) -> bool:
    """Atomic rolling-window claim attempt.

    Returns ``True`` if this worker is the unique holder of the
    next cadence cycle for ``job_id`` (the row was inserted fresh
    OR the existing row's ``last_fired_at`` was at least
    ``period_seconds`` behind the proposed ``now`` and has now
    been advanced). Returns ``False`` if another worker won the
    cadence cycle and this attempt must skip.

    Atomicity: the ``UNIQUE(job_id)`` constraint serializes
    concurrent INSERTs on the row, and the ``WHERE`` clause on
    the ``ON CONFLICT DO UPDATE`` branch fires while still under
    the same row lock so two simultaneous attempts cannot both
    see the cooldown as elapsed.
    """

    result = conn.execute(
        text(
            "INSERT INTO scheduler_job_locks "
            "(job_id, last_fired_at, created_at, updated_at) "
            "VALUES (:job_id, :now, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
            "ON CONFLICT ON CONSTRAINT scheduler_job_locks_job_id_uniq "
            "DO UPDATE SET "
            "last_fired_at = EXCLUDED.last_fired_at, "
            "updated_at = CURRENT_TIMESTAMP "
            "WHERE scheduler_job_locks.last_fired_at "
            "+ (:period_seconds * INTERVAL '1 second') "
            "<= EXCLUDED.last_fired_at "
            "RETURNING id"
        ),
        {
            "job_id": job_id,
            "now": now,
            "period_seconds": period_seconds,
        },
    )
    row = result.fetchone()
    return row is not None


@contextlib.contextmanager
def claim_scheduler_tick(
    job_id: str,
    *,
    period_seconds: int,
    advisory_key: int,
    namespace: int = SCHEDULER_LOCK_NAMESPACE,
    now: Optional[datetime] = None,
) -> Generator[bool, None, None]:
    """Try to claim one cadence cycle for ``job_id`` across workers.

    This is the PRA-169 rolling-window guarantee: yields ``True``
    for at most one worker per ``period_seconds`` cycle across the
    entire fleet, anchored to the most recent successful claim
    (not to wall-clock epoch bins). Lock losers — either lost the
    advisory-lock race OR found the cadence cooldown not yet
    elapsed in the durable row — get ``False`` and MUST skip the
    body promptly.

    Concretely, given two attempts ``A@t_a`` and ``B@t_b`` for the
    same ``job_id`` with ``t_a < t_b``:

    * If ``t_b < t_a + period_seconds`` → exactly one wins (the
      first one whose UPSERT commits); the other gets ``False``.
    * If ``t_b >= t_a + period_seconds`` → both win their own
      cycle; ``last_fired_at`` advances to ``t_b`` after B's
      claim.

    This is what fixes the boundary-straddle case: a worker at the end
    of one epoch bucket and a worker at the start of the next
    bucket — separated by less than ``period_seconds`` — both
    compare against the same ``last_fired_at`` anchor and only one
    wins.

    Two-level guard:

    1. Advisory lock on ``(namespace, advisory_key)`` — cheap in-
       process gate so workers in the same cadence cycle don't all
       hit the UPSERT path simultaneously.
    2. ``INSERT ... ON CONFLICT (job_id) DO UPDATE ... WHERE
       last_fired_at + period <= now RETURNING id`` — durable.
       The WHERE clause is the rolling-window correctness primitive.
    """

    current_now = now or datetime.utcnow()

    conn = engine.connect()
    try:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")

        acquired_advisory = bool(
            conn.execute(
                text("SELECT pg_try_advisory_lock(:ns, :id)"),
                {"ns": namespace, "id": advisory_key},
            ).scalar()
        )

        won_cycle = False
        if acquired_advisory:
            try:
                won_cycle = _try_claim_rolling_window(
                    conn, job_id, current_now, period_seconds
                )
            except Exception:  # pylint: disable=broad-except
                # If the UPSERT itself blew up (table missing in
                # tests, transient error), treat as lock loss so
                # we don't run the body twice across the failure
                # window.
                logger.exception(
                    "scheduler_job_locks claim upsert failed for job_id=%s "
                    "now=%s; treating as lock loss",
                    job_id,
                    current_now,
                )
                won_cycle = False

        try:
            yield won_cycle
        finally:
            if acquired_advisory:
                try:
                    conn.execute(
                        text("SELECT pg_advisory_unlock(:ns, :id)"),
                        {"ns": namespace, "id": advisory_key},
                    )
                except Exception:  # pylint: disable=broad-except
                    logger.warning(
                        "pg_advisory_unlock failed for scheduler job "
                        "(ns=%s key=%s); falling back to session-end release.",
                        namespace,
                        advisory_key,
                    )
    finally:
        conn.invalidate()
        conn.close()


@contextlib.contextmanager
def claim_recurring_tick(
    job_id: str,
    *,
    now: Optional[datetime] = None,
) -> Generator[bool, None, None]:
    """Convenience wrapper around :func:`claim_scheduler_tick` that
    pulls the advisory key + cadence period from
    :data:`SCHEDULER_JOB_KEYS`.

    Used by every recurring sweeper decorator in
    ``scheduler_service.py``. A stale ``job_id`` raises ``KeyError``
    rather than silently slipping through.
    """

    spec = SCHEDULER_JOB_KEYS[job_id]
    with claim_scheduler_tick(
        job_id,
        period_seconds=spec.period_seconds,
        advisory_key=spec.key,
        namespace=SCHEDULER_LOCK_NAMESPACE,
        now=now,
    ) as acquired:
        yield acquired


@contextlib.contextmanager
def claim_user_job_tick(
    row_id: int,
    *,
    now: Optional[datetime] = None,
) -> Generator[bool, None, None]:
    """Convenience wrapper around :func:`claim_scheduler_tick` for
    DB-defined ``Job`` rows.

    Uses ``f"user:{row_id}"`` as the durable claim id so user-job
    claims can't collide with recurring sweepers, and a fixed
    ``USER_JOB_TICK_PERIOD_SECONDS`` rolling cadence (1 minute,
    matching cron's minimum resolution).
    """

    with claim_scheduler_tick(
        f"user:{row_id}",
        period_seconds=USER_JOB_TICK_PERIOD_SECONDS,
        advisory_key=row_id,
        namespace=SCHEDULER_USER_JOB_NAMESPACE,
        now=now,
    ) as acquired:
        yield acquired
