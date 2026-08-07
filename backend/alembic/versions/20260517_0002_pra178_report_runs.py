"""PRA-178 slice 2: durable report-run substrate.

Creates ``report_runs`` — a durable, audit-grade record of every
report/export run. Slice 2 only persists rows for manual operator
exports triggered by the Slice 1 routes; later PRA-178 slices that
add a scheduler will reuse the same row shape without another
migration by writing ``triggered_by = 'system_scheduled'`` instead.

Locks (PRA-178 Slice 2):

* ``report_kind`` is a bounded short string with an explicit DB
  CHECK constraint listing the current vocabulary. Later slices that
  add new report kinds must also extend this CHECK in a follow-on
  additive migration.
* ``triggered_by`` is a bounded short string with a DB CHECK so
  ``system_scheduled`` cannot appear by accident before the
  scheduler slice lands. Slice 2 only writes ``user``.
* ``state`` is a bounded short string with a CHECK that covers the
  lifecycle vocabulary (``started`` / ``succeeded`` / ``failed``).
  The ``started`` value is intentionally reserved here so a future
  long-running export can persist a row before completion without a
  schema change.
* ``filters_snapshot`` is JSONB; the service layer is responsible
  for bounding/sanitizing what gets written. Operator-supplied
  filters only — no headers, tokens, cookies, or session blobs.
* ``triggered_by_user_id`` is ``ON DELETE SET NULL`` so removing
  the actor's user row preserves the report-run history (the actor
  username is captured separately in ``triggered_by_username`` at
  write time).
* All timestamps are absolute UTC; ``created_at`` and ``updated_at``
  have a server default so raw-SQL inserts still satisfy NOT NULL.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra178_report_runs"
down_revision: Union[str, None] = "pra176_execution_outcome"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "report_runs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("report_kind", sa.String(64), nullable=False),
        sa.Column(
            "triggered_by",
            sa.String(32),
            nullable=False,
            server_default="user",
        ),
        sa.Column(
            "triggered_by_user_id",
            sa.Integer,
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("triggered_by_username", sa.String(255), nullable=True),
        sa.Column("format", sa.String(16), nullable=True),
        sa.Column(
            "filters_snapshot",
            sa.dialects.postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("row_count", sa.Integer, nullable=True),
        sa.Column(
            "state",
            sa.String(16),
            nullable=False,
            server_default="started",
        ),
        sa.Column("error_message", sa.String(2048), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("completed_at", sa.DateTime, nullable=True),
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
        sa.CheckConstraint(
            "report_kind IN ("
            "'patch_executions', "
            "'compliance_remediation_requests', "
            "'compliance_evidence'"
            ")",
            name="report_runs_report_kind_vocab",
        ),
        sa.CheckConstraint(
            "triggered_by IN ('user', 'system_scheduled')",
            name="report_runs_triggered_by_vocab",
        ),
        sa.CheckConstraint(
            "state IN ('started', 'succeeded', 'failed')",
            name="report_runs_state_vocab",
        ),
        sa.CheckConstraint(
            "format IS NULL OR format IN ('csv', 'json', 'jsonl')",
            name="report_runs_format_vocab",
        ),
        sa.CheckConstraint(
            "row_count IS NULL OR row_count >= 0",
            name="report_runs_row_count_nonneg",
        ),
    )
    op.create_index(
        "ix_report_runs_kind_started_at",
        "report_runs",
        ["report_kind", "started_at"],
    )
    op.create_index(
        "ix_report_runs_state",
        "report_runs",
        ["state"],
    )
    op.create_index(
        "ix_report_runs_triggered_by",
        "report_runs",
        ["triggered_by"],
    )


def downgrade() -> None:
    op.drop_index("ix_report_runs_triggered_by", table_name="report_runs")
    op.drop_index("ix_report_runs_state", table_name="report_runs")
    op.drop_index("ix_report_runs_kind_started_at", table_name="report_runs")
    op.drop_table("report_runs")
