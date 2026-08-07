"""Multi-worker-safe advisory lock claim for mirror sync (PRA-157 slice #1).

Prod can run multiple Uvicorn workers, so every worker boots its own
APScheduler. Mirror sync is NOT idempotent at the subprocess level —
two concurrent debmirrors targeting the same directory corrupt
state. This module is the claim primitive that ensures a given
mirror is being synced by at most one worker at a time.

Locked design (project_pra157_design_locks.md):

* ``pg_try_advisory_lock`` (non-blocking). Lock-loser SKIPS — never
  blocks waiting on a multi-hour sync to finish.
* Session-level lock on a *dedicated* connection separate from
  request transactions. Sync subprocesses can run for hours; a
  transaction-scoped lock would force an absurdly long transaction
  holding row locks and breaking pool sanity.
* Lock key is ``(MIRROR_LOCK_NAMESPACE, mirror_repo.id)`` — keyed
  off the database id, NOT the slug. Slugs can change someday;
  ids don't.
* The dedicated connection holds ONLY the advisory lock — no
  transaction. Callers do stale-row updates and run-row inserts in
  short transactions on regular pooled ``SessionLocal()`` sessions
  while the lock is held.

Pool-correctness note: SQLAlchemy's ``Connection.close()`` returns
the connection to the pool *without* ending the Postgres session,
so an advisory lock held on a pooled connection persists across
checkouts unless explicitly released. We protect against forget-to-
unlock by invalidating the connection on exit (``conn.invalidate()``
marks the connection as discardable so ``close()`` actually closes
it, ending the session and releasing any locks Postgres still
remembers we hold). ``pg_advisory_unlock_all()`` belts the
suspenders.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Generator

from sqlalchemy import text

from ..db.session import engine

logger = logging.getLogger(__name__)

# 16-bit namespace used as the first arg to two-arg pg_try_advisory_lock.
# 0x4D52 = "MR" in ASCII — Mirror namespace. Future scheduler-claimed
# resources should each get their own constant to avoid collisions
# (Postgres advisory lock keys live in a single global pool).
MIRROR_LOCK_NAMESPACE = 0x4D52

# id=0 is reserved for the global concurrency gate (real mirror_repo
# ids start at 1, so there's no collision risk). The gate serializes
# the count-and-insert decision that enforces
# PRAXIS_MIRROR_MAX_CONCURRENT_SYNCS across distinct mirrors and
# across all uvicorn workers.
GLOBAL_CONCURRENCY_GATE_ID = 0


@contextlib.contextmanager
def claim_mirror_for_sync(
    mirror_repo_id: int,
) -> Generator[bool, None, None]:
    """Try to acquire a session-level advisory lock for one mirror.

    Yields ``True`` if the lock was acquired (caller is the unique
    holder for this mirror, must do its sync work + finalize, then
    exit the context to release). Yields ``False`` if the lock could
    not be acquired (another worker holds it — caller MUST skip the
    mirror and return promptly; do not block).

    The lock is automatically released on context exit via
    ``pg_advisory_unlock_all()`` plus connection invalidation. On
    process crash, Postgres detects the connection drop and releases
    session-level locks held by it; on graceful exit, we release
    explicitly.
    """
    conn = engine.connect()
    try:
        # AUTOCOMMIT keeps the connection from accumulating an open
        # transaction across the multi-hour sync. Lock acquisition
        # and release are single-shot statements that don't need
        # transactional semantics on this connection.
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")

        acquired = bool(
            conn.execute(
                text("SELECT pg_try_advisory_lock(:ns, :id)"),
                {"ns": MIRROR_LOCK_NAMESPACE, "id": mirror_repo_id},
            ).scalar()
        )

        try:
            yield acquired
        finally:
            if acquired:
                try:
                    conn.execute(
                        text("SELECT pg_advisory_unlock(:ns, :id)"),
                        {
                            "ns": MIRROR_LOCK_NAMESPACE,
                            "id": mirror_repo_id,
                        },
                    )
                except Exception:  # pylint: disable=broad-except
                    # Release failure is recoverable — connection
                    # invalidation below ends the session, which
                    # Postgres treats as releasing all advisory
                    # locks held by it.
                    logger.warning(
                        "pg_advisory_unlock failed for mirror %d; "
                        "falling back to session-end release.",
                        mirror_repo_id,
                    )
    finally:
        # Invalidate so close() actually disconnects rather than
        # returning a session-state-laden connection to the pool.
        # Belt + suspenders — if our explicit unlock above somehow
        # missed, session end cleans up.
        conn.invalidate()
        conn.close()


@contextlib.contextmanager
def global_claim_gate() -> Generator[None, None, None]:
    """Serialize the count-and-insert decision that enforces
    ``PRAXIS_MIRROR_MAX_CONCURRENT_SYNCS``.

    This is a **blocking** ``pg_advisory_lock`` on a shared sentinel
    key, NOT the per-mirror try-lock. Hold time is sub-millisecond
    (count rows + maybe insert one + commit), so blocking is safe —
    workers serialize through cleanly without long waits. The
    blocking semantics are what give us atomicity: two workers can't
    both decide "count is N-1, take the slot" simultaneously.

    The per-mirror non-blocking lock prevents same-mirror duplicate
    syncs; this global gate prevents over-commit across distinct
    mirrors (e.g. 5 due mirrors with a cap of 2 → 2 claims, 3
    skipped). Without this gate, the per-mirror lock alone would
    allow N workers to each claim a different mirror, busting the
    global cap.

    Nest INSIDE the per-mirror context, scoped only to the count-
    and-insert critical section. Hold time must stay sub-ms; never
    wrap subprocess execution or any other long-running work in
    this gate, or all workers serialize on it.
    """
    conn = engine.connect()
    try:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(
            text("SELECT pg_advisory_lock(:ns, :id)"),
            {
                "ns": MIRROR_LOCK_NAMESPACE,
                "id": GLOBAL_CONCURRENCY_GATE_ID,
            },
        )
        try:
            yield
        finally:
            try:
                conn.execute(
                    text("SELECT pg_advisory_unlock(:ns, :id)"),
                    {
                        "ns": MIRROR_LOCK_NAMESPACE,
                        "id": GLOBAL_CONCURRENCY_GATE_ID,
                    },
                )
            except Exception:  # pylint: disable=broad-except
                logger.warning(
                    "pg_advisory_unlock failed for global concurrency "
                    "gate; falling back to session-end release."
                )
    finally:
        conn.invalidate()
        conn.close()
