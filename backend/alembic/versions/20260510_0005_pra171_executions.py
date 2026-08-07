"""PRA-171 slice 1: patch_update_executions + patch_update_execution_hosts.

Execution-run substrate consumed by future PRA-171 slices. Slice 1
proves the safety gate, state vocabulary, wave/host materialization,
metadata-only controls (start/pause/resume/cancel), audit emission,
and progress contract WITHOUT invoking SSH, agent ops, package
managers, or mutating package history. Future slices attach
per-host package-manager dispatch on top of this substrate.

Tables:

* ``patch_update_executions`` — one row per execution attempt for an
  approved-or-scheduled :class:`PatchUpdatePlan`. References its
  source plan ``ON DELETE RESTRICT`` so the audit trail can never be
  silently broken by deleting the plan an execution was built from.
  Snapshots the plan state, policy, and execution config at start
  time so a later policy edit cannot change what the execution was
  built from. Slice 1 enforces "at most one non-terminal execution
  per plan" via a partial unique index on
  ``state IN ('pending', 'running', 'paused')``.

* ``patch_update_execution_hosts`` — one row per host materialized
  from the plan. References ``patch_update_plan_hosts.id``
  ``ON DELETE RESTRICT`` so the plan-host artifact cannot vanish
  out from under an execution that referenced it. Snapshots
  ``system_id`` / ``system_hostname`` / ``wave_index`` /
  ``selected_package_count`` so the execution stays auditable even
  after later host removal or selection refresh on the parent plan.

Vocabularies (CHECK-constrained at the DB level; ORM mirrors):

* ``patch_update_executions.state`` ∈
  ``{pending, running, paused, succeeded, failed, canceled}``.
  ``succeeded`` and ``failed`` are RESERVED for later PRA-171
  slices (no Slice 1 transition reaches them).
* ``patch_update_execution_hosts.state`` ∈
  ``{pending, running, succeeded, failed, skipped, paused,
  canceled}``. Slice 1 only writes ``pending``, ``skipped``, and
  ``canceled``; ``running`` / ``succeeded`` / ``failed`` /
  ``paused`` are RESERVED for later slices that wire real
  package-manager dispatch.

Indexes / constraints:

* UNIQUE ``(execution_id, plan_host_id)`` so a single plan-host
  can never appear twice in the same execution.
* INDEX ``(plan_id, state)`` on executions so the
  "latest non-terminal execution for a plan" lookup the route
  layer makes is cheap.
* PARTIAL UNIQUE ``(plan_id) WHERE state IN ('pending', 'running',
  'paused')`` so two concurrent operators cannot start two
  non-terminal executions for the same plan; later slices will
  decide retry/historical semantics.
* INDEX ``(execution_id, wave_index)`` on hosts so the progress
  endpoint can fetch a wave's worth of hosts cheaply.
* INDEX ``(execution_id, state)`` on hosts for the count rollup.

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra171_executions"
down_revision: Union[str, None] = "pra164_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


EXECUTION_STATES = (
    "pending",
    "running",
    "paused",
    "succeeded",
    "failed",
    "canceled",
)

EXECUTION_HOST_STATES = (
    "pending",
    "running",
    "succeeded",
    "failed",
    "skipped",
    "paused",
    "canceled",
)


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.create_table(
        "patch_update_executions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "plan_id",
            sa.Integer,
            sa.ForeignKey("patch_update_plans.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column(
            "started_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("paused_at", sa.DateTime, nullable=True),
        sa.Column("canceled_at", sa.DateTime, nullable=True),
        sa.Column("max_parallel_per_wave", sa.Integer, nullable=False),
        sa.Column("failure_threshold_percent", sa.Integer, nullable=True),
        sa.Column("pause_reason", sa.Text, nullable=True),
        sa.Column("cancel_reason", sa.Text, nullable=True),
        sa.Column(
            "plan_state_snapshot",
            sa.String(32),
            nullable=False,
        ),
        sa.Column(
            "policy_snapshot",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "execution_config_snapshot",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "progress_summary",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
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
            _check_in("state", EXECUTION_STATES),
            name="patch_update_executions_state_vocab",
        ),
        sa.CheckConstraint(
            "max_parallel_per_wave >= 1",
            name="patch_update_executions_parallel_min",
        ),
        sa.CheckConstraint(
            "failure_threshold_percent IS NULL OR "
            "(failure_threshold_percent >= 0 AND failure_threshold_percent <= 100)",
            name="patch_update_executions_threshold_range",
        ),
    )
    op.create_index(
        "ix_patch_update_executions_plan_state",
        "patch_update_executions",
        ["plan_id", "state"],
    )
    # Partial unique: at most one non-terminal execution per plan.
    op.create_index(
        "uq_patch_update_executions_plan_active",
        "patch_update_executions",
        ["plan_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('pending', 'running', 'paused')"),
    )

    op.create_table(
        "patch_update_execution_hosts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "execution_id",
            sa.Integer,
            sa.ForeignKey("patch_update_executions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "plan_host_id",
            sa.Integer,
            sa.ForeignKey("patch_update_plan_hosts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("system_id_snapshot", sa.Integer, nullable=True),
        sa.Column("system_hostname_snapshot", sa.String(255), nullable=True),
        sa.Column("wave_index", sa.Integer, nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column(
            "selected_package_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "skip_reasons",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "error_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("started_at", sa.DateTime, nullable=True),
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
        sa.UniqueConstraint(
            "execution_id",
            "plan_host_id",
            name="uq_patch_update_execution_hosts_target",
        ),
        sa.CheckConstraint(
            _check_in("state", EXECUTION_HOST_STATES),
            name="patch_update_execution_hosts_state_vocab",
        ),
        sa.CheckConstraint(
            "wave_index >= 0",
            name="patch_update_execution_hosts_wave_index_nonneg",
        ),
        sa.CheckConstraint(
            "selected_package_count >= 0",
            name="patch_update_execution_hosts_selected_count_nonneg",
        ),
    )
    op.create_index(
        "ix_patch_update_execution_hosts_execution_wave",
        "patch_update_execution_hosts",
        ["execution_id", "wave_index"],
    )
    op.create_index(
        "ix_patch_update_execution_hosts_execution_state",
        "patch_update_execution_hosts",
        ["execution_id", "state"],
    )
    op.create_index(
        "ix_patch_update_execution_hosts_plan_host",
        "patch_update_execution_hosts",
        ["plan_host_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_execution_hosts_plan_host",
        table_name="patch_update_execution_hosts",
    )
    op.drop_index(
        "ix_patch_update_execution_hosts_execution_state",
        table_name="patch_update_execution_hosts",
    )
    op.drop_index(
        "ix_patch_update_execution_hosts_execution_wave",
        table_name="patch_update_execution_hosts",
    )
    op.drop_table("patch_update_execution_hosts")
    op.drop_index(
        "uq_patch_update_executions_plan_active",
        table_name="patch_update_executions",
    )
    op.drop_index(
        "ix_patch_update_executions_plan_state",
        table_name="patch_update_executions",
    )
    op.drop_table("patch_update_executions")
