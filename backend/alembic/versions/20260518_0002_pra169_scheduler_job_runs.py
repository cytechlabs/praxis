"""PRA-169 Slice 1: rolling-window per-job scheduler claim state.

An early review of Slice 1 caught the staggered-after-release
case; Slice 1a's epoch-anchored ``(job_id, tick_bucket)`` claim
fixed that for same-bucket re-execution but still allowed boundary-
straddling duplicates for interval-triggered jobs (worker A fires
late in one bucket, worker B fires early in the next bucket, both
bodies execute within one effective cadence cycle).

Slice 1b replaces the epoch-bucket scheme with a rolling per-job
cadence window: one row per ``job_id`` with ``last_fired_at``, and
an ``INSERT ... ON CONFLICT (job_id) DO UPDATE SET ... WHERE
last_fired_at + (period * INTERVAL '1 second') <= EXCLUDED.last_fired_at
RETURNING id`` claim. Two concurrent attempts serialize on the
UNIQUE constraint; the one that advances ``last_fired_at`` by at
least the cadence wins, all others get zero rows and skip.

Migration revision id stays ``pra169_scheduler_job_runs`` so anyone
who applied the Slice 1a shape locally has a clean downgrade path
via ``alembic downgrade pra178_report_schedules`` followed by
``alembic upgrade head``. The new table is named
``scheduler_job_locks`` to match the new semantic (one row per
job, not per tick).

Locks:

* ``UNIQUE (job_id)`` — single row per job. The rolling-window
  WHERE clause on the upsert is the correctness primitive.
* ``last_fired_at`` is the rolling cadence anchor, written in UTC.
* No retention sweeper: the table is bounded at O(scheduler-jobs).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra169_scheduler_job_runs"
down_revision: Union[str, None] = "pra178_report_schedules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scheduler_job_locks",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.String(128), nullable=False),
        sa.Column("last_fired_at", sa.DateTime, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint(
            "job_id",
            name="scheduler_job_locks_job_id_uniq",
        ),
    )


def downgrade() -> None:
    op.drop_table("scheduler_job_locks")
