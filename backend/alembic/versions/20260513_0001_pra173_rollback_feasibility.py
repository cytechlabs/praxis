"""PRA-173 slice 1: rollback feasibility substrate.

Persistent feasibility/read storage for a completed
:class:`PatchUpdateExecution`. Slice 1 ships *only* the storage
substrate and read surface: per-execution rollback header row,
per-execution-host rollback row, and per-package rollback row,
populated from the existing PRA-164 preflight snapshots, PRA-171
execution package results, and PRA-159/164 content-profile / mirror
indexes. **No rollback commands, no command planning, no approval,
no execution/dispatch, no SSH/agent calls, no package history
mutation, no re-scan/verification loop, no automatic rollback.**

Three tables, three layers:

* ``patch_update_execution_rollbacks`` — one row per execution
  (the rollback feasibility "plan"). Captures the moment-in-time
  feasibility decision plus the plan/execution snapshot the
  decision drew on, so the audit trail survives later policy or
  host edits.
* ``patch_update_execution_rollback_hosts`` — one row per
  execution host. Mirrors the plan-host artifact: every in-scope
  execution host gets an explicit row, including
  skipped/failed/unsupported hosts with structured refusal
  details.
* ``patch_update_execution_rollback_packages`` — one row per
  (execution-host, package_name) candidate, sourced from the
  PRA-171 ``patch_update_execution_host_packages`` evidence.
  Captures the old version, target/current version, family,
  feasibility state, refusal reason, and the structured content
  evidence proving the old version is available.

State vocabulary (CHECK-constrained at the DB layer; ORM mirrors):

* ``patch_update_execution_rollbacks.state``: ``evaluated`` /
  ``refused``. ``refused`` records the plan-level refusal codes
  (e.g. ``execution_not_terminal``) so the read surface can render
  the "why we cannot evaluate this execution" message without
  inventing a state on the route layer.
* ``patch_update_execution_rollback_hosts.state``: ``feasible`` /
  ``partial_feasible`` / ``infeasible``. ``feasible`` only when
  every package row under the host is feasible; ``partial_feasible``
  when at least one package row is feasible but others are not;
  ``infeasible`` when no package rows are feasible (or none exist).
* ``patch_update_execution_rollback_packages.state``: ``feasible``
  / ``infeasible``. ``refusal_reason`` is set whenever ``state`` is
  ``infeasible``; null otherwise.

Refusal codes (carried in ``refusal_reason`` + ``refusal_details``
JSONB) cover the structured non-feasibility cases the slice spec
calls out:

* ``execution_not_terminal`` — plan-level refusal; execution is
  still pending/running/paused.
* ``host_not_succeeded`` — host-level refusal; execution-host state
  is not ``succeeded``.
* ``package_not_succeeded`` — package-level refusal; package outcome
  is not ``succeeded``.
* ``missing_before_version`` — package-level; the execution did not
  capture the pre-update installed version.
* ``missing_after_version`` — package-level; neither
  ``installed_version_after`` nor ``requested_version_snapshot``
  is known, so there is no target to roll back from.
* ``version_unchanged`` — package-level; the before/after versions
  match, so there is nothing to roll back to.
* ``unsupported_package_family`` — package-level; family is
  ``unknown`` (or otherwise not apt/dnf).
* ``content_profile_missing`` — package-level; the host has no
  resolved content profile, so old-version availability cannot be
  proven.
* ``old_version_unavailable`` — package-level; the host has a
  resolved content profile but no mirror in it publishes the
  ``installed_version_before`` value.
* ``content_evidence_missing`` — package-level; the content profile
  resolves but no mirror sync run produces evidence (e.g. no
  successful runs / no pinned run / index gap).

``content_evidence`` JSONB on the package row records which
channel/mirror/run was inspected and what matched, so the audit
trail proves *why* a row is feasible (or unavailable) without a
re-query.

Indexes / constraints:

* UNIQUE ``(execution_id)`` on the header — one rollback row per
  execution; re-evaluating must upsert, not duplicate.
* UNIQUE ``(rollback_id, execution_host_id)`` on the host table.
* UNIQUE ``(rollback_host_id, package_name)`` on the package
  table.
* INDEX ``(execution_id)`` on the host table for the per-execution
  drill-down.
* INDEX ``(rollback_id, state)`` on the host table for the
  per-state rollup the read API computes.
* INDEX ``(rollback_host_id, state)`` on the package table for the
  per-host rollup.
* INDEX ``(plan_id_snapshot)`` on the header for the plan-scoped
  read endpoint (one plan can have multiple executions over time).

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra173_rollback_feasibility"
down_revision: Union[str, None] = "pra172_reboot_verify"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


ROLLBACK_PLAN_STATES = ("evaluated", "refused")
ROLLBACK_HOST_STATES = ("feasible", "partial_feasible", "infeasible")
ROLLBACK_PACKAGE_STATES = ("feasible", "infeasible")
PACKAGE_FAMILY_VALUES = ("apt", "dnf", "unknown")


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    # ------------------------------------------------------------------
    # patch_update_execution_rollbacks (header, one per execution)
    # ------------------------------------------------------------------
    op.create_table(
        "patch_update_execution_rollbacks",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "execution_id",
            sa.Integer,
            sa.ForeignKey("patch_update_executions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("plan_id_snapshot", sa.Integer, nullable=False),
        sa.Column("execution_state_snapshot", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("refusal_reason", sa.String(64), nullable=True),
        sa.Column(
            "refusal_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "feasibility_summary",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("evaluated_at", sa.DateTime, nullable=False),
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
            name="uq_patch_update_execution_rollbacks_execution",
        ),
        sa.CheckConstraint(
            _check_in("state", ROLLBACK_PLAN_STATES),
            name="patch_update_execution_rollbacks_state_vocab",
        ),
    )
    op.create_index(
        "ix_patch_update_execution_rollbacks_plan",
        "patch_update_execution_rollbacks",
        ["plan_id_snapshot"],
    )

    # ------------------------------------------------------------------
    # patch_update_execution_rollback_hosts (one per execution-host)
    # ------------------------------------------------------------------
    op.create_table(
        "patch_update_execution_rollback_hosts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "rollback_id",
            sa.Integer,
            sa.ForeignKey("patch_update_execution_rollbacks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "execution_host_id",
            sa.Integer,
            sa.ForeignKey("patch_update_execution_hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("plan_host_id_snapshot", sa.Integer, nullable=False),
        sa.Column("system_id_snapshot", sa.Integer, nullable=True),
        sa.Column("system_hostname_snapshot", sa.String(255), nullable=True),
        sa.Column("wave_index", sa.Integer, nullable=False),
        sa.Column("execution_host_state_snapshot", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("refusal_reason", sa.String(64), nullable=True),
        sa.Column(
            "refusal_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "content_profile_snapshot",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "package_summary",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("evaluated_at", sa.DateTime, nullable=False),
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
            "rollback_id",
            "execution_host_id",
            name="uq_patch_update_execution_rollback_hosts_target",
        ),
        sa.CheckConstraint(
            _check_in("state", ROLLBACK_HOST_STATES),
            name="patch_update_execution_rollback_hosts_state_vocab",
        ),
        sa.CheckConstraint(
            "wave_index >= 0",
            name="patch_update_execution_rollback_hosts_wave_index_nonneg",
        ),
    )
    op.create_index(
        "ix_patch_update_execution_rollback_hosts_rollback_state",
        "patch_update_execution_rollback_hosts",
        ["rollback_id", "state"],
    )
    op.create_index(
        "ix_patch_update_execution_rollback_hosts_execution_host",
        "patch_update_execution_rollback_hosts",
        ["execution_host_id"],
    )

    # ------------------------------------------------------------------
    # patch_update_execution_rollback_packages (one per package candidate)
    # ------------------------------------------------------------------
    op.create_table(
        "patch_update_execution_rollback_packages",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "rollback_host_id",
            sa.Integer,
            sa.ForeignKey(
                "patch_update_execution_rollback_hosts.id", ondelete="CASCADE"
            ),
            nullable=False,
        ),
        # ``execution_host_package_id`` is SET NULL because the source
        # PRA-171 ``patch_update_execution_host_packages`` row may be
        # archived later. The snapshot columns preserve audit-grade
        # intent even after the FK target disappears.
        sa.Column(
            "execution_host_package_id",
            sa.Integer,
            sa.ForeignKey(
                "patch_update_execution_host_packages.id", ondelete="SET NULL"
            ),
            nullable=True,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("package_manager_family_snapshot", sa.String(16), nullable=False),
        sa.Column(
            "installed_version_before_snapshot",
            sa.String(255),
            nullable=True,
        ),
        sa.Column(
            "installed_version_after_snapshot",
            sa.String(255),
            nullable=True,
        ),
        sa.Column("requested_version_snapshot", sa.String(255), nullable=True),
        sa.Column("target_rollback_version", sa.String(255), nullable=True),
        sa.Column("package_outcome_snapshot", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("refusal_reason", sa.String(64), nullable=True),
        sa.Column(
            "refusal_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "content_evidence",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("evaluated_at", sa.DateTime, nullable=False),
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
            "rollback_host_id",
            "package_name",
            name="uq_patch_update_execution_rollback_packages_target",
        ),
        sa.CheckConstraint(
            _check_in("state", ROLLBACK_PACKAGE_STATES),
            name="patch_update_execution_rollback_packages_state_vocab",
        ),
        sa.CheckConstraint(
            _check_in("package_manager_family_snapshot", PACKAGE_FAMILY_VALUES),
            name="patch_update_execution_rollback_packages_family_vocab",
        ),
    )
    op.create_index(
        "ix_patch_update_execution_rollback_packages_host_state",
        "patch_update_execution_rollback_packages",
        ["rollback_host_id", "state"],
    )
    op.create_index(
        "ix_patch_update_execution_rollback_packages_exec_pkg",
        "patch_update_execution_rollback_packages",
        ["execution_host_package_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_execution_rollback_packages_exec_pkg",
        table_name="patch_update_execution_rollback_packages",
    )
    op.drop_index(
        "ix_patch_update_execution_rollback_packages_host_state",
        table_name="patch_update_execution_rollback_packages",
    )
    op.drop_table("patch_update_execution_rollback_packages")

    op.drop_index(
        "ix_patch_update_execution_rollback_hosts_execution_host",
        table_name="patch_update_execution_rollback_hosts",
    )
    op.drop_index(
        "ix_patch_update_execution_rollback_hosts_rollback_state",
        table_name="patch_update_execution_rollback_hosts",
    )
    op.drop_table("patch_update_execution_rollback_hosts")

    op.drop_index(
        "ix_patch_update_execution_rollbacks_plan",
        table_name="patch_update_execution_rollbacks",
    )
    op.drop_table("patch_update_execution_rollbacks")
