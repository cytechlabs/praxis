"""PRA-169: rolling-window per-job scheduler claim state.

The PRA-157 advisory lock alone provides mutual exclusion only
while a job body is running. An early review of PRA-169
Slice 1 caught the staggered-after-release case; Slice 1a's epoch-
anchored ``(job_id, tick_bucket)`` claim closed that gap for
same-bucket re-execution but still allowed boundary-straddling
duplicates for interval triggers (worker A fires at the end of
one epoch bucket, worker B fires at the start of the next bucket,
both bodies execute within one effective cadence cycle).

``SchedulerJobLock`` is the rolling-window claim state:

* Exactly one row per ``job_id`` — the most recent successful claim's
  ``last_fired_at`` is the rolling cadence anchor.
* ``UNIQUE(job_id)`` lets the claim path use
  ``INSERT ... ON CONFLICT (job_id) DO UPDATE SET ... WHERE
  scheduler_job_locks.last_fired_at + (period * INTERVAL '1 second')
  <= EXCLUDED.last_fired_at RETURNING id``. Two concurrent attempts
  serialize on the constraint; the worker whose proposed
  ``last_fired_at`` advances the row by at least ``period_seconds``
  wins, all others get zero rows back and skip.

The advisory lock from PRA-157 is preserved as a cheap in-process
gate to prevent thundering INSERT attempts, but correctness lives
in this table's UNIQUE + WHERE-on-UPDATE clause.

Bounded size
------------
Single row per ``job_id``: 18 recurring sweepers + however many
DB-defined ``Job`` rows the operator has scheduled. No retention
sweeper needed.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, UniqueConstraint
from sqlalchemy import text as sa_text

from .base import Base


class SchedulerJobLock(Base):  # pylint: disable=too-few-public-methods
    """Rolling-window claim state for one scheduler job.

    Rows are written by the PRA-169 claim primitive at
    ``backend/app/services/scheduler_lock.claim_scheduler_tick``.
    See the module docstring there for the rolling-window contract.
    """

    __tablename__ = "scheduler_job_locks"

    id = Column(Integer, primary_key=True, autoincrement=True)

    job_id = Column(String(128), nullable=False)
    last_fired_at = Column(DateTime, nullable=False)

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=sa_text("CURRENT_TIMESTAMP"),
    )

    __table_args__ = (
        UniqueConstraint(
            "job_id",
            name="scheduler_job_locks_job_id_uniq",
        ),
    )
