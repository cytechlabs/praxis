"""PRA-169 Slice 1: cross-worker scheduler rolling-window claim tests.

Production can be configured with multiple Uvicorn workers, and each worker
boots its own APScheduler. Without a cross-worker claim, every recurring
callback in ``backend/app/services/scheduler_service.py`` fires once per worker
per cron tick — the lifecycle recompute / emitter case Linear PRA-169 calls out.

The slice has been through two earlier shapes:

* v1 used a PRA-157-style advisory lock alone. An early review
  caught that a staggered worker firing milliseconds after the
  winner releases can re-acquire and run the same tick again.
* v2 (Slice 1a) layered an epoch-anchored ``(job_id, tick_bucket)``
  claim row on top. A later review caught the boundary-straddle
  case: a 30s job firing at :59 lands in one epoch bucket and a
  fire at :61 lands in the next, both run inside one effective
  cadence cycle, the `(job_id, floor(now/period))` UNIQUE key lets
  both pass.

This file is the v3 (Slice 1b) test surface. The primitive now
enforces a **rolling per-job cadence window**: two body executions
for the same ``job_id`` must be at least ``period_seconds`` apart
anchored to the most recent successful claim, NOT to wall-clock
epoch bins. Concretely:

1. Concurrent overlapping callbacks (advisory lock catches them
   AND the rolling-window UPSERT catches them on the durable side).
2. Staggered same-cycle callbacks where the winner has already
   released the advisory lock — second attempt finds the durable
   row inside the cadence window and skips.
3. Boundary-straddling interval triggers (worker A at :29, worker B
   at :31 with a 30s cadence) — A claims, B compares against the
   anchor at :29 and the cooldown until :59 has not elapsed → B
   skips. This is the Slice 1a P1 regression.
4. Next legitimate cadence cycle (now >= last_fired_at +
   period_seconds) succeeds.

Out-of-scope mirror tests live in
``test_pra157_mirror_engine.py``. PRA-169 deliberately does NOT
guard the mirror sweep at the job level (see the audit note in
``scheduler_service._run_mirror_sync_due``).
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta
from typing import List
from unittest.mock import patch

import pytest
from sqlalchemy import text

from app.services import scheduler_lock, scheduler_service
from app.services.scheduler_lock import (
    SCHEDULER_JOB_KEYS,
    SCHEDULER_LOCK_NAMESPACE,
    SCHEDULER_USER_JOB_NAMESPACE,
    USER_JOB_TICK_PERIOD_SECONDS,
    SchedulerJobSpec,
    claim_recurring_tick,
    claim_scheduler_job,
    claim_scheduler_tick,
    claim_user_job_tick,
)

# Test advisory keys are deliberately well above the highest real
# entry in SCHEDULER_JOB_KEYS so a leaked lock from a flaky test
# cannot starve a real scheduler tick. Postgres advisory locks are
# session-scoped so the connection-close-on-context-exit pattern
# releases them either way, but the extra padding is cheap insurance.
_TEST_KEY_BASE = 0x7FFF_0000


@pytest.fixture(autouse=True)
def _clean_scheduler_job_locks():
    """Truncate the rolling-window state table between tests so each
    test sees a clean slate. The claim primitive uses an AUTOCOMMIT
    connection that bypasses the conftest outer-transaction rollback,
    so we MUST clean up explicitly."""

    from app.db.session import engine

    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE scheduler_job_locks"))
    yield
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE scheduler_job_locks"))


# ---------------------------------------------------------------------------
# Stable-API guards — locked constants
# ---------------------------------------------------------------------------


def test_scheduler_lock_namespaces_are_documented_constants():
    """Both namespaces are callouts in the module docstring; changing
    either value is a coordinated change with operators reading lock
    state from ``pg_locks``."""

    assert SCHEDULER_LOCK_NAMESPACE == 0x5343  # "SC" — Scheduler
    assert SCHEDULER_USER_JOB_NAMESPACE == 0x5355  # "SU" — Scheduler-User
    from app.services.mirror_lock import MIRROR_LOCK_NAMESPACE

    assert SCHEDULER_LOCK_NAMESPACE != MIRROR_LOCK_NAMESPACE
    assert SCHEDULER_USER_JOB_NAMESPACE != MIRROR_LOCK_NAMESPACE


def test_user_job_tick_period_is_one_minute():
    """Cron's minimum granularity is one minute. The constant is
    part of the API contract."""

    assert USER_JOB_TICK_PERIOD_SECONDS == 60


def test_scheduler_job_keys_are_unique():
    """Two scheduler jobs mapping to the same advisory key would
    serialize on each other across workers — silently wrong."""

    seen: dict[int, str] = {}
    for name, spec in SCHEDULER_JOB_KEYS.items():
        assert isinstance(spec, SchedulerJobSpec)
        assert (
            spec.key not in seen
        ), f"SCHEDULER_JOB_KEYS collision: {name!r} and {seen[spec.key]!r}"
        seen[spec.key] = name


def test_scheduler_job_specs_have_positive_periods():
    """A non-positive ``period_seconds`` would render the rolling-
    window WHERE clause meaningless. Catch it at import-test time."""

    for name, spec in SCHEDULER_JOB_KEYS.items():
        assert spec.period_seconds > 0, f"{name} has non-positive period"


def test_scheduler_job_keys_match_registered_scheduler_jobs():
    """Every recurring ``scheduler.add_job(id=...)`` registered in
    ``SchedulerService.start()`` MUST have a key in
    ``SCHEDULER_JOB_KEYS`` (or be the explicitly unguarded
    ``mirror_sync_due``)."""

    import inspect
    import re

    source = inspect.getsource(scheduler_service.SchedulerService.start)
    ids = set(re.findall(r"""id\s*=\s*["']([a-z_]+)["']""", source))
    expected_unguarded = {"mirror_sync_due"}
    guarded_ids = ids - expected_unguarded
    missing = guarded_ids - set(SCHEDULER_JOB_KEYS.keys())
    extra = set(SCHEDULER_JOB_KEYS.keys()) - guarded_ids
    assert not missing, (
        f"scheduler_service registers job ids {missing} that have no "
        f"SCHEDULER_JOB_KEYS entry — they would fire 4x in prod."
    )
    assert not extra, (
        f"SCHEDULER_JOB_KEYS has {extra} entries with no matching "
        f"scheduler_service.add_job(id=...) — stale rebase artifact?"
    )


# ---------------------------------------------------------------------------
# Advisory-lock primitive (PRA-157 pattern) — still exposed
# ---------------------------------------------------------------------------


def test_advisory_lock_loser_skips_promptly():
    """Two threads race for the same advisory lock; one wins, the
    other returns ``False`` quickly without blocking."""

    key = _TEST_KEY_BASE + 1
    barrier = threading.Barrier(2)
    results: dict[str, tuple[bool, float]] = {}

    def worker(name: str, hold_seconds: float) -> None:
        barrier.wait()
        start = time.monotonic()
        with claim_scheduler_job(key) as acquired:
            elapsed = time.monotonic() - start
            results[name] = (acquired, elapsed)
            if acquired:
                time.sleep(hold_seconds)

    t_a = threading.Thread(target=worker, args=("a", 0.5))
    t_b = threading.Thread(target=worker, args=("b", 0.5))
    t_a.start()
    t_b.start()
    t_a.join(timeout=5)
    t_b.join(timeout=5)

    a_acquired, _ = results["a"]
    b_acquired, _ = results["b"]
    assert (a_acquired, b_acquired) in [(True, False), (False, True)]
    loser = "a" if not a_acquired else "b"
    _, loser_elapsed = results[loser]
    assert (
        loser_elapsed < 0.2
    ), f"loser took {loser_elapsed:.3f}s — looks blocking, not pg_try_*"


def test_advisory_lock_released_after_winner_exits():
    """Sequential acquire after first holder exits succeeds — proves
    the dedicated-autocommit-connection release path works."""

    key = _TEST_KEY_BASE + 2

    with claim_scheduler_job(key) as first:
        assert first is True
    with claim_scheduler_job(key) as second:
        assert second is True


def test_advisory_lock_user_job_namespace_does_not_collide():
    """Same numeric key under two different namespaces must coexist."""

    shared_key = SCHEDULER_JOB_KEYS["lifecycle_recompute"].key

    with claim_scheduler_job(shared_key) as scheduler_acq:
        assert scheduler_acq is True
        with claim_scheduler_job(
            shared_key, namespace=SCHEDULER_USER_JOB_NAMESPACE
        ) as user_acq:
            assert user_acq is True


def test_advisory_lock_uses_dedicated_connection_with_autocommit():
    """Pool-correctness guarantee from PRA-157: dedicated connection,
    AUTOCOMMIT, invalidate + close on exit."""

    real_engine_connect = scheduler_lock.engine.connect
    seen: dict[str, object] = {}

    def spy_connect():
        conn = real_engine_connect()
        seen["conn"] = conn
        orig_invalidate = conn.invalidate
        orig_close = conn.close
        seen["invalidated"] = False
        seen["closed"] = False

        def track_invalidate(*a, **kw):
            seen["invalidated"] = True
            return orig_invalidate(*a, **kw)

        def track_close(*a, **kw):
            seen["closed"] = True
            return orig_close(*a, **kw)

        conn.invalidate = track_invalidate  # type: ignore[assignment]
        conn.close = track_close  # type: ignore[assignment]
        return conn

    with patch.object(scheduler_lock.engine, "connect", spy_connect):
        with claim_scheduler_job(_TEST_KEY_BASE + 5) as acquired:
            assert acquired is True

    assert seen["invalidated"] is True
    assert seen["closed"] is True


# ---------------------------------------------------------------------------
# Rolling-window per-tick durable claim — the v3 (Slice 1b) primitive
# ---------------------------------------------------------------------------


def test_rolling_claim_first_attempt_wins():
    """First worker into a fresh job_id gets ``True``."""

    now = datetime(2026, 5, 18, 12, 0, 0)
    with claim_scheduler_tick(
        "pra169-test-first",
        period_seconds=30,
        advisory_key=_TEST_KEY_BASE + 10,
        now=now,
    ) as won:
        assert won is True


def test_rolling_claim_inside_cooldown_loses():
    """A second attempt inside the rolling cadence window must lose
    — even though the advisory lock is free."""

    job_id = "pra169-test-inside-cooldown"
    now = datetime(2026, 5, 18, 12, 0, 0)

    with claim_scheduler_tick(
        job_id,
        period_seconds=30,
        advisory_key=_TEST_KEY_BASE + 11,
        now=now,
    ) as won_first:
        assert won_first is True

    inside_window = now + timedelta(seconds=15)
    with claim_scheduler_tick(
        job_id,
        period_seconds=30,
        advisory_key=_TEST_KEY_BASE + 11,
        now=inside_window,
    ) as won_second:
        assert won_second is False


def test_rolling_claim_at_or_after_cadence_boundary_wins():
    """After ``period_seconds`` has elapsed since the last successful
    claim, the next attempt wins. ``now == last_fired_at + period``
    counts as elapsed (WHERE uses ``<=``)."""

    job_id = "pra169-test-cadence-elapsed"
    base = datetime(2026, 5, 18, 12, 0, 0)
    period = 30

    with claim_scheduler_tick(
        job_id,
        period_seconds=period,
        advisory_key=_TEST_KEY_BASE + 12,
        now=base,
    ) as won_first:
        assert won_first is True

    # Exact boundary.
    with claim_scheduler_tick(
        job_id,
        period_seconds=period,
        advisory_key=_TEST_KEY_BASE + 12,
        now=base + timedelta(seconds=period),
    ) as won_second:
        assert won_second is True

    # And the next cycle after that.
    with claim_scheduler_tick(
        job_id,
        period_seconds=period,
        advisory_key=_TEST_KEY_BASE + 12,
        now=base + timedelta(seconds=2 * period),
    ) as won_third:
        assert won_third is True


def test_rolling_claim_boundary_straddle_p1_regression():
    """With a 30-second interval, a
    worker firing late in one epoch bucket and a worker firing
    slightly into the next epoch bucket must NOT both run their
    body. The epoch-bucket scheme accepted both; the rolling-window
    scheme rejects the second.

    Concretely: A@:29 claims, anchor is set to :29. B@:31 (which the
    old scheme placed in a different epoch bucket and accepted)
    compares against last_fired_at=:29 with cooldown until :59 →
    skip. The next legitimate cadence at :59 (or later) runs.
    """

    job_id = "pra169-test-boundary-straddle"
    period = 30

    a_at = datetime(2026, 5, 18, 12, 0, 29)
    b_at = datetime(2026, 5, 18, 12, 0, 31)
    next_cycle = datetime(2026, 5, 18, 12, 0, 59)

    with claim_scheduler_tick(
        job_id,
        period_seconds=period,
        advisory_key=_TEST_KEY_BASE + 13,
        now=a_at,
    ) as won_a:
        assert won_a is True

    # Under v1 (advisory-lock-only) AND v2 (epoch-bucket), this
    # would have returned True — the v3 rolling-window scheme is
    # what makes this assertion meaningful.
    with claim_scheduler_tick(
        job_id,
        period_seconds=period,
        advisory_key=_TEST_KEY_BASE + 13,
        now=b_at,
    ) as won_b:
        assert won_b is False, (
            "boundary-straddle within one cadence cycle must lose — "
            "Slice 1a P1 regression"
        )

    with claim_scheduler_tick(
        job_id,
        period_seconds=period,
        advisory_key=_TEST_KEY_BASE + 13,
        now=next_cycle,
    ) as won_next:
        assert won_next is True, (
            "next legitimate cadence cycle (now = last_fired + period) " "must succeed"
        )


def test_rolling_claim_overlapping_workers_only_one_wins():
    """Two threads enter the claim at the same instant for the same
    job. Exactly one gets ``True``."""

    job_id = "pra169-test-overlapping"
    barrier = threading.Barrier(2)
    results: dict[str, bool] = {}
    now = datetime(2026, 5, 18, 12, 0, 0)

    def worker(name: str) -> None:
        barrier.wait()
        with claim_scheduler_tick(
            job_id,
            period_seconds=30,
            advisory_key=_TEST_KEY_BASE + 14,
            now=now,
        ) as won:
            results[name] = won
            time.sleep(0.05)

    t_a = threading.Thread(target=worker, args=("a",))
    t_b = threading.Thread(target=worker, args=("b",))
    t_a.start()
    t_b.start()
    t_a.join(timeout=5)
    t_b.join(timeout=5)

    assert sorted(results.values()) == [False, True]


def test_rolling_claim_advances_last_fired_at_to_now_on_win():
    """The anchor must move forward to ``now`` on each successful
    claim — otherwise the rolling window would stay pinned to the
    very first claim forever and never let a later cycle run."""

    from app.db.session import engine

    job_id = "pra169-test-anchor-advances"
    first = datetime(2026, 5, 18, 12, 0, 0)
    second = first + timedelta(seconds=60)  # well past period=30

    with claim_scheduler_tick(
        job_id,
        period_seconds=30,
        advisory_key=_TEST_KEY_BASE + 15,
        now=first,
    ) as won:
        assert won is True

    with claim_scheduler_tick(
        job_id,
        period_seconds=30,
        advisory_key=_TEST_KEY_BASE + 15,
        now=second,
    ) as won:
        assert won is True

    with engine.begin() as conn:
        anchor = conn.execute(
            text(
                "SELECT last_fired_at FROM scheduler_job_locks "
                "WHERE job_id = :job_id"
            ),
            {"job_id": job_id},
        ).scalar()
    assert anchor == second, (
        f"anchor should have advanced to {second} after the second "
        f"successful claim; got {anchor}"
    )


def test_rolling_claim_distinct_job_ids_do_not_block():
    """Two distinct ``job_id`` values claim independently — the
    UNIQUE constraint is on ``job_id``, so unrelated jobs never
    serialize on each other."""

    now = datetime(2026, 5, 18, 12, 0, 0)
    with claim_scheduler_tick(
        "pra169-test-job-a",
        period_seconds=30,
        advisory_key=_TEST_KEY_BASE + 16,
        now=now,
    ) as won_a:
        assert won_a is True
        with claim_scheduler_tick(
            "pra169-test-job-b",
            period_seconds=30,
            advisory_key=_TEST_KEY_BASE + 17,
            now=now,
        ) as won_b:
            assert won_b is True


def test_rolling_claim_single_row_per_job_id():
    """The state table is bounded — one row per ``job_id``, never
    more. Repeated claims update the row in place rather than
    appending."""

    from app.db.session import engine

    job_id = "pra169-test-single-row"
    base = datetime(2026, 5, 18, 12, 0, 0)

    for k in range(5):
        with claim_scheduler_tick(
            job_id,
            period_seconds=30,
            advisory_key=_TEST_KEY_BASE + 18,
            now=base + timedelta(seconds=60 * k),
        ) as won:
            assert won is True

    with engine.begin() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM scheduler_job_locks " "WHERE job_id = :job_id"),
            {"job_id": job_id},
        ).scalar()
    assert count == 1


# ---------------------------------------------------------------------------
# Recurring-tick + user-job convenience wrappers
# ---------------------------------------------------------------------------


def test_claim_recurring_tick_uses_registered_spec():
    """``claim_recurring_tick("lifecycle_recompute")`` enforces the
    daily-cadence rolling window, not a generic default."""

    now = datetime(2026, 5, 18, 2, 15, 0)
    spec = SCHEDULER_JOB_KEYS["lifecycle_recompute"]
    assert spec.period_seconds == 24 * 60 * 60

    with claim_recurring_tick("lifecycle_recompute", now=now) as won:
        assert won is True

    # Same UTC day, much later — inside the 24h rolling window.
    same_day_later = now.replace(hour=23)
    with claim_recurring_tick("lifecycle_recompute", now=same_day_later) as won:
        assert won is False, (
            f"daily cadence rolling window must collapse {now} and "
            f"{same_day_later} into one cycle"
        )

    # And the next day after the cooldown elapses.
    next_day = now + timedelta(seconds=spec.period_seconds)
    with claim_recurring_tick("lifecycle_recompute", now=next_day) as won:
        assert won is True


def test_claim_recurring_tick_unknown_job_raises():
    with pytest.raises(KeyError):
        with claim_recurring_tick("pra169-not-a-real-id") as _won:
            pass


def test_claim_user_job_tick_uses_one_minute_rolling_window():
    """Two attempts inside the same 60-second rolling window share
    the cycle; crossing the cooldown boundary unlocks the next claim."""

    base = datetime(2026, 5, 18, 12, 0, 5)
    with claim_user_job_tick(424242, now=base) as won_first:
        assert won_first is True

    inside = base + timedelta(seconds=40)
    with claim_user_job_tick(424242, now=inside) as won_second:
        assert won_second is False

    boundary = base + timedelta(seconds=USER_JOB_TICK_PERIOD_SECONDS)
    with claim_user_job_tick(424242, now=boundary) as won_third:
        assert won_third is True


def test_claim_user_job_tick_distinct_rows_do_not_block():
    """Two different user-job ids in the same minute claim independently."""

    now = datetime(2026, 5, 18, 12, 0, 0)
    with claim_user_job_tick(700001, now=now) as won_a:
        assert won_a is True
        with claim_user_job_tick(700002, now=now) as won_b:
            assert won_b is True


# ---------------------------------------------------------------------------
# Decorator + callback wiring — one body per cycle across simulated workers
# ---------------------------------------------------------------------------


class _RecordingScheduler:
    """Stand-in for ``SchedulerService`` for guarded-method tests.

    Each worker thread calls the same method against a different
    instance to mirror prod, where each uvicorn worker has its own
    ``SchedulerService()`` singleton.
    """

    def __init__(self, call_log: List[str], label: str, hold: float):
        self._call_log = call_log
        self._label = label
        self._hold = hold

    @scheduler_service._guarded("lifecycle_recompute")
    def run(self):
        self._call_log.append(self._label)
        time.sleep(self._hold)


def test_guarded_callback_executes_once_per_cycle_across_workers():
    """Two ``SchedulerService``-like instances (= two uvicorn workers)
    call the same guarded callback concurrently. Exactly one body
    executes per cadence cycle."""

    call_log: List[str] = []
    barrier = threading.Barrier(2)

    worker_a = _RecordingScheduler(call_log, "a", hold=0.3)
    worker_b = _RecordingScheduler(call_log, "b", hold=0.3)

    def race(w: _RecordingScheduler):
        barrier.wait()
        w.run()

    t_a = threading.Thread(target=race, args=(worker_a,))
    t_b = threading.Thread(target=race, args=(worker_b,))
    t_a.start()
    t_b.start()
    t_a.join(timeout=5)
    t_b.join(timeout=5)

    assert len(call_log) == 1, (
        f"expected exactly one worker's body to execute per cycle, " f"got {call_log}"
    )
    assert call_log[0] in {"a", "b"}


def test_guarded_callback_staggered_within_cycle_does_not_re_execute():
    """A worker that calls the guarded
    callback AFTER the winner has fully exited (no advisory-lock
    contention) must still be skipped if it's inside the cadence
    rolling window.

    The decorated method's period is daily (lifecycle_recompute);
    two sequential calls in the same Python turn are easily inside
    the 24h window.
    """

    call_log: List[str] = []
    _RecordingScheduler(call_log, "a", hold=0.0).run()
    _RecordingScheduler(call_log, "b", hold=0.0).run()

    assert call_log == ["a"], (
        f"only the first worker in a cadence cycle should run the "
        f"body; got {call_log} — PRA-169 first P1 regression"
    )


def test_guarded_callback_returns_none_on_cycle_loss():
    """Loser of the cross-worker race returns ``None`` — callers see
    a clean no-op rather than an exception."""

    call_log: List[str] = []
    first_result = _RecordingScheduler(call_log, "winner", hold=0.0).run()
    assert first_result is None  # body ran but returned nothing

    loser_log: List[str] = []
    second_result = _RecordingScheduler(loser_log, "loser", hold=0.0).run()
    assert second_result is None
    assert loser_log == [], "loser's body must NOT have executed"
