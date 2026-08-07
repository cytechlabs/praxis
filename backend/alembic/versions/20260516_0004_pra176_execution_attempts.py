"""PRA-176 slice 1: compliance remediation execution-attempt substrate.

Creates ``compliance_remediation_execution_attempts`` — the durable
record of an operator's intent to dispatch a current, acknowledged,
ready-for-execution package remediation plan. Slice 1 is intentionally
pre-dispatch: an attempt row records the snapshot + actor + approval
lineage and emits an audit event, but no SSH/agent/runner is touched
and no host is mutated. Later PRA-176 slices add transport selection,
dispatch, and outcome recording without another schema migration.

Locks (PRA-176 Slice 1):

* ``request_id`` is ``ON DELETE CASCADE`` to mirror the Slice 1
  request → plan cascade: removing the source remediation request
  drops its attempts.
* ``plan_id`` is ``ON DELETE SET NULL`` so plan supersede / rebuild
  (or a future plan delete) never erases the attempt history.
* ``system_id`` is ``ON DELETE CASCADE`` to mirror evidence/request
  semantics — host removal drops attempts too.
* ``approval_decided_by`` is ``ON DELETE SET NULL`` so removing the
  deciding admin's user row leaves the attempt's snapshot identity
  intact (the approval moment is recorded in ``approval_decided_at``).
* ``state`` defaults to ``pending`` at the DB level so a raw-SQL
  insert cannot land a stateless attempt. Slice 1 only writes
  ``pending``; later slices will move attempts through
  ``dispatched``/``succeeded``/``failed``/``cancelled`` without
  another migration.
* ``transport`` is bounded to 32 chars so a stray write cannot store
  an unbounded transport identifier. NULL means "transport not yet
  selected"; later slices will record the governed patch transport.
* ``failure_reason`` (short stable code) and ``error_message``
  (bounded operator-readable text) are reserved here so later
  dispatch slices do not need another migration.
* All timestamps are UTC ``CURRENT_TIMESTAMP`` server defaults so
  rows persisted via raw SQL still satisfy ``NOT NULL`` on the
  ``created_at``/``updated_at`` columns.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra176_execution_attempts"
down_revision: Union[str, None] = "pra167_plan_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compliance_remediation_execution_attempts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "request_id",
            sa.Integer,
            sa.ForeignKey("compliance_remediation_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "plan_id",
            sa.Integer,
            sa.ForeignKey("compliance_remediation_plans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("policy_id", sa.Integer, nullable=False),
        sa.Column("check_id", sa.Integer, nullable=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_slug", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.Integer, nullable=False),
        sa.Column("check_slug", sa.String(64), nullable=False),
        sa.Column("check_kind", sa.String(64), nullable=False),
        sa.Column("severity_snapshot", sa.String(16), nullable=False),
        sa.Column("plan_kind_snapshot", sa.String(64), nullable=False),
        sa.Column("package_name", sa.String(256), nullable=True),
        sa.Column("package_version_target", sa.String(128), nullable=True),
        sa.Column(
            "approval_decided_by",
            sa.Integer,
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("approval_decided_at", sa.DateTime, nullable=True),
        sa.Column(
            "state",
            sa.String(16),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("transport", sa.String(32), nullable=True),
        sa.Column("failure_reason", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(2048), nullable=True),
        sa.Column("dispatched_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=False,
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
    )
    op.create_index(
        "ix_compliance_remediation_execution_attempts_request",
        "compliance_remediation_execution_attempts",
        ["request_id"],
    )
    op.create_index(
        "ix_compliance_remediation_execution_attempts_plan",
        "compliance_remediation_execution_attempts",
        ["plan_id"],
    )
    op.create_index(
        "ix_compliance_remediation_execution_attempts_system",
        "compliance_remediation_execution_attempts",
        ["system_id"],
    )
    op.create_index(
        "ix_compliance_remediation_execution_attempts_state",
        "compliance_remediation_execution_attempts",
        ["state"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_compliance_remediation_execution_attempts_state",
        table_name="compliance_remediation_execution_attempts",
    )
    op.drop_index(
        "ix_compliance_remediation_execution_attempts_system",
        table_name="compliance_remediation_execution_attempts",
    )
    op.drop_index(
        "ix_compliance_remediation_execution_attempts_plan",
        table_name="compliance_remediation_execution_attempts",
    )
    op.drop_index(
        "ix_compliance_remediation_execution_attempts_request",
        table_name="compliance_remediation_execution_attempts",
    )
    op.drop_table("compliance_remediation_execution_attempts")
