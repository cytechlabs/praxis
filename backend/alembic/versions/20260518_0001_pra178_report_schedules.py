"""PRA-178 slice 5: durable scheduled report definitions.

Creates ``report_schedules`` — the per-operator recurring schedule
that fires through the existing Slice 1/4 export substrate and
writes ``triggered_by='system_scheduled'`` ``report_runs`` rows.

Locks (PRA-178 Slice 5):

* ``report_kind`` reuses the Slice 2/4 vocabulary already enforced
  on ``report_runs.report_kind`` — the same eight values are
  accepted here.
* ``cadence`` is plain-language only (``daily`` / ``weekly`` /
  ``monthly``) per ``feedback_no_cron.md``. No cron expression
  ever lands on the wire.
* ``filters_snapshot`` is JSONB; the service layer enforces the
  same 16 KiB bound + JSON-serializability check as
  ``report_runs.filters_snapshot``.
* ``next_run_at`` is the scheduler tick's claim anchor; it is
  computed at create/update time and advanced (last + cadence)
  after a successful run. A NULL value disables the schedule
  effectively, so the column is nullable with no default.
* ``last_run_at`` / ``last_run_id`` / ``last_run_state`` give the
  read API a fast O(1) "most recent firing" snapshot without
  joining back to ``report_runs``.
* ``created_by`` is ``ON DELETE SET NULL`` so an operator can be
  deleted without erasing the schedule history. The audit row
  carries the original actor id.
* All timestamps are absolute UTC with ``CURRENT_TIMESTAMP``
  server defaults so a raw-SQL insert still satisfies NOT NULL.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra178_report_schedules"
down_revision: Union[str, None] = "pra178_report_kind_extend"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "report_schedules",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("report_kind", sa.String(64), nullable=False),
        sa.Column(
            "cadence",
            sa.String(16),
            nullable=False,
        ),
        sa.Column(
            "filters_snapshot",
            sa.dialects.postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "format",
            sa.String(16),
            nullable=False,
            server_default="csv",
        ),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("next_run_at", sa.DateTime, nullable=True),
        sa.Column("last_run_at", sa.DateTime, nullable=True),
        sa.Column("last_run_id", sa.Integer, nullable=True),
        sa.Column("last_run_state", sa.String(16), nullable=True),
        sa.Column(
            "created_by",
            sa.Integer,
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
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
            "'compliance_evidence', "
            "'patch_update_plans', "
            "'patch_reboot_queues', "
            "'patch_rollback_runs', "
            "'compliance_remediation_plans', "
            "'compliance_remediation_executions'"
            ")",
            name="report_schedules_report_kind_vocab",
        ),
        sa.CheckConstraint(
            "cadence IN ('daily', 'weekly', 'monthly')",
            name="report_schedules_cadence_vocab",
        ),
        sa.CheckConstraint(
            "format IN ('csv', 'json')",
            name="report_schedules_format_vocab",
        ),
        sa.CheckConstraint(
            "last_run_state IS NULL OR last_run_state IN "
            "('started', 'succeeded', 'failed')",
            name="report_schedules_last_run_state_vocab",
        ),
    )
    op.create_index(
        "ix_report_schedules_next_run_at",
        "report_schedules",
        ["next_run_at"],
    )
    op.create_index(
        "ix_report_schedules_enabled",
        "report_schedules",
        ["enabled"],
    )
    op.create_index(
        "ix_report_schedules_report_kind",
        "report_schedules",
        ["report_kind"],
    )


def downgrade() -> None:
    op.drop_index("ix_report_schedules_report_kind", table_name="report_schedules")
    op.drop_index("ix_report_schedules_enabled", table_name="report_schedules")
    op.drop_index("ix_report_schedules_next_run_at", table_name="report_schedules")
    op.drop_table("report_schedules")
