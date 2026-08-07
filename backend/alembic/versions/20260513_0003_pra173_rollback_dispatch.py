"""PRA-173 slice 3: rollback dispatch substrate.

Three new tables that mirror the PRA-171 execution shape so the
PRA-171 live-progress UI component can render rollback dispatch
without a new component family:

* ``patch_rollback_dispatch_runs`` — one row per explicit operator
  rollback-dispatch start. FK to the rollback feasibility header
  and the rollback approval link (the *specific* frozen snapshot
  operators voted on). State vocabulary:
  ``pending`` / ``running`` / ``paused`` / ``succeeded`` /
  ``failed`` / ``canceled``. Slice 3 writes ``running`` at start,
  ``succeeded`` / ``failed`` on completion, ``canceled`` on
  explicit cancel.
* ``patch_rollback_dispatch_hosts`` — one row per host in the
  frozen snapshot. State vocabulary:
  ``pending`` / ``running`` / ``succeeded`` / ``failed`` /
  ``skipped`` / ``canceled``. Mirrors PRA-171's host shape so the
  same progress component can render rollback host status.
* ``patch_rollback_dispatch_host_packages`` — one row per package
  per host. Carries the approved ``target_rollback_version``
  (snapshotted from the frozen plan) + the observed
  ``installed_version_before`` / ``installed_version_after`` so
  the audit trail records what version a host actually landed on.

Constraints / indexes:

* UNIQUE ``(rollback_id)`` partial index WHERE state IN
  (pending, running, paused) on the dispatch-runs table — at most
  one live dispatch run per rollback. Mirrors the PRA-171
  ``uq_patch_update_executions_plan_active`` shape.
* UNIQUE ``(rollback_dispatch_run_id, rollback_host_id)`` on the
  hosts table — one host row per dispatch run.
* UNIQUE ``(rollback_dispatch_host_id, package_name)`` on the
  packages table — one package row per host per dispatch run.
* Indexes on ``(rollback_id, state)`` (hosts) and
  ``(rollback_dispatch_host_id, outcome)`` (packages) for the
  per-state rollups the read API computes.
* Indexes on ``(rollback_approval_link_id)`` and
  ``(rollback_id, state)`` on the dispatch-runs table so the
  plan-/execution-scoped read endpoints stay cheap.

ORM ``__table_args__`` mirrors every constraint / index here
(PRA-161 1a-a parity rule carry-forward).

**No SSH / agent transport / package-history mutation in this
migration.** The dispatch service consumes the frozen plan from
``patch_update_execution_rollback_approvals.frozen_plan_snapshot``
and writes per-host / per-package outcome rows; PackageHistory
integration is Slice 4 scope.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra173_rollback_dispatch"
down_revision: Union[str, None] = "pra173_rollback_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


DISPATCH_RUN_STATES = (
    "pending",
    "running",
    "paused",
    "succeeded",
    "failed",
    "canceled",
)
DISPATCH_HOST_STATES = (
    "pending",
    "running",
    "succeeded",
    "failed",
    "skipped",
    "canceled",
)
DISPATCH_PACKAGE_OUTCOMES = (
    "pending",
    "succeeded",
    "failed",
    "skipped",
    "unknown",
)
PACKAGE_FAMILY_VALUES = ("apt", "dnf", "unknown")


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    # ------------------------------------------------------------------
    # patch_rollback_dispatch_runs (header, one per dispatch attempt)
    # ------------------------------------------------------------------
    op.create_table(
        "patch_rollback_dispatch_runs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "rollback_id",
            sa.Integer,
            sa.ForeignKey("patch_update_execution_rollbacks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "rollback_approval_link_id",
            sa.Integer,
            sa.ForeignKey(
                "patch_update_execution_rollback_approvals.id",
                ondelete="RESTRICT",
            ),
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
        sa.Column("max_parallel", sa.Integer, nullable=False),
        sa.Column("pause_reason", sa.Text, nullable=True),
        sa.Column("cancel_reason", sa.Text, nullable=True),
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
            _check_in("state", DISPATCH_RUN_STATES),
            name="patch_rollback_dispatch_runs_state_vocab",
        ),
        sa.CheckConstraint(
            "max_parallel >= 1",
            name="patch_rollback_dispatch_runs_max_parallel_min",
        ),
    )
    op.create_index(
        "ix_patch_rollback_dispatch_runs_rollback_state",
        "patch_rollback_dispatch_runs",
        ["rollback_id", "state"],
    )
    op.create_index(
        "ix_patch_rollback_dispatch_runs_approval_link",
        "patch_rollback_dispatch_runs",
        ["rollback_approval_link_id"],
    )
    # At most one live dispatch run per rollback. Mirrors the
    # PRA-171 ``uq_patch_update_executions_plan_active`` partial
    # unique index.
    op.create_index(
        "uq_patch_rollback_dispatch_runs_rollback_active",
        "patch_rollback_dispatch_runs",
        ["rollback_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('pending', 'running', 'paused')"),
    )

    # ------------------------------------------------------------------
    # patch_rollback_dispatch_hosts (one per host in the frozen snapshot)
    # ------------------------------------------------------------------
    op.create_table(
        "patch_rollback_dispatch_hosts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "rollback_dispatch_run_id",
            sa.Integer,
            sa.ForeignKey("patch_rollback_dispatch_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "rollback_host_id",
            sa.Integer,
            sa.ForeignKey(
                "patch_update_execution_rollback_hosts.id", ondelete="CASCADE"
            ),
            nullable=False,
        ),
        sa.Column("system_id_snapshot", sa.Integer, nullable=True),
        sa.Column("system_hostname_snapshot", sa.String(255), nullable=True),
        sa.Column("state", sa.String(32), nullable=False),
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
            "rollback_dispatch_run_id",
            "rollback_host_id",
            name="uq_patch_rollback_dispatch_hosts_target",
        ),
        sa.CheckConstraint(
            _check_in("state", DISPATCH_HOST_STATES),
            name="patch_rollback_dispatch_hosts_state_vocab",
        ),
    )
    op.create_index(
        "ix_patch_rollback_dispatch_hosts_run_state",
        "patch_rollback_dispatch_hosts",
        ["rollback_dispatch_run_id", "state"],
    )
    op.create_index(
        "ix_patch_rollback_dispatch_hosts_rollback_host",
        "patch_rollback_dispatch_hosts",
        ["rollback_host_id"],
    )

    # ------------------------------------------------------------------
    # patch_rollback_dispatch_host_packages (per package, per host)
    # ------------------------------------------------------------------
    op.create_table(
        "patch_rollback_dispatch_host_packages",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "rollback_dispatch_host_id",
            sa.Integer,
            sa.ForeignKey("patch_rollback_dispatch_hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # FK SET NULL: the source feasibility package row may be
        # archived later; the snapshot columns preserve audit-grade
        # intent so historical reads survive.
        sa.Column(
            "rollback_package_id",
            sa.Integer,
            sa.ForeignKey(
                "patch_update_execution_rollback_packages.id", ondelete="SET NULL"
            ),
            nullable=True,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("package_manager_family_snapshot", sa.String(16), nullable=False),
        sa.Column("target_rollback_version_snapshot", sa.String(255), nullable=True),
        sa.Column("installed_version_before", sa.String(255), nullable=True),
        sa.Column("installed_version_after", sa.String(255), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column(
            "details",
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
        sa.UniqueConstraint(
            "rollback_dispatch_host_id",
            "package_name",
            name="uq_patch_rollback_dispatch_host_packages_target",
        ),
        sa.CheckConstraint(
            _check_in("outcome", DISPATCH_PACKAGE_OUTCOMES),
            name="patch_rollback_dispatch_host_packages_outcome_vocab",
        ),
        sa.CheckConstraint(
            _check_in("package_manager_family_snapshot", PACKAGE_FAMILY_VALUES),
            name="patch_rollback_dispatch_host_packages_family_vocab",
        ),
    )
    op.create_index(
        "ix_patch_rollback_dispatch_host_packages_host_outcome",
        "patch_rollback_dispatch_host_packages",
        ["rollback_dispatch_host_id", "outcome"],
    )
    op.create_index(
        "ix_patch_rollback_dispatch_host_packages_rb_pkg",
        "patch_rollback_dispatch_host_packages",
        ["rollback_package_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_rollback_dispatch_host_packages_rb_pkg",
        table_name="patch_rollback_dispatch_host_packages",
    )
    op.drop_index(
        "ix_patch_rollback_dispatch_host_packages_host_outcome",
        table_name="patch_rollback_dispatch_host_packages",
    )
    op.drop_table("patch_rollback_dispatch_host_packages")

    op.drop_index(
        "ix_patch_rollback_dispatch_hosts_rollback_host",
        table_name="patch_rollback_dispatch_hosts",
    )
    op.drop_index(
        "ix_patch_rollback_dispatch_hosts_run_state",
        table_name="patch_rollback_dispatch_hosts",
    )
    op.drop_table("patch_rollback_dispatch_hosts")

    op.drop_index(
        "uq_patch_rollback_dispatch_runs_rollback_active",
        table_name="patch_rollback_dispatch_runs",
    )
    op.drop_index(
        "ix_patch_rollback_dispatch_runs_approval_link",
        table_name="patch_rollback_dispatch_runs",
    )
    op.drop_index(
        "ix_patch_rollback_dispatch_runs_rollback_state",
        table_name="patch_rollback_dispatch_runs",
    )
    op.drop_table("patch_rollback_dispatch_runs")
