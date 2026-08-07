"""PRA-167 slice 1: compliance remediation request substrate.

Creates ``compliance_remediation_requests`` for non-executing
remediation intent + approval state tied to failing compliance
evidence rows. Slice 1 stores intent and approval-gate state only —
no execution, no host mutation, no dispatch.

Locks (PRA-167 Slice 1):

* ``policy_id`` is ``ON DELETE CASCADE`` to match the evidence-table
  semantics: dropping a policy removes its remediation history.
* ``check_id`` is ``ON DELETE SET NULL`` so editing/deleting a check
  does not erase remediation history; the denormalized
  ``check_slug``/``check_kind``/``policy_slug``/``policy_version``
  keep the row auditor-readable.
* ``evidence_id`` is ``ON DELETE SET NULL`` so retention sweeps that
  prune old evidence rows do not erase the remediation history that
  referenced them.
* ``system_id`` is ``ON DELETE CASCADE`` to match the evidence-row
  cascade: a host removal drops its remediation requests.
* ``state`` defaults to ``requested`` at the DB level so an
  application-layer bug cannot create a row without an explicit
  state.
* All timestamps are UTC ``CURRENT_TIMESTAMP`` server defaults so
  rows persisted via raw SQL still satisfy ``NOT NULL``.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra167_remediation_requests"
down_revision: Union[str, None] = "pra165_compliance_evidence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compliance_remediation_requests",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "policy_id",
            sa.Integer,
            sa.ForeignKey("compliance_policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "check_id",
            sa.Integer,
            sa.ForeignKey("compliance_policy_checks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.Integer,
            sa.ForeignKey("compliance_policy_evidence.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("policy_slug", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.Integer, nullable=False),
        sa.Column("check_slug", sa.String(64), nullable=False),
        sa.Column("check_kind", sa.String(64), nullable=False),
        sa.Column("evaluation_run_id", sa.String(36), nullable=True),
        sa.Column("verdict_snapshot", sa.String(16), nullable=False),
        sa.Column("verdict_reason_snapshot", sa.String(512), nullable=True),
        sa.Column("severity_snapshot", sa.String(16), nullable=False),
        sa.Column("remediation_guidance_snapshot", sa.Text, nullable=True),
        sa.Column(
            "state",
            sa.String(16),
            nullable=False,
            server_default="requested",
        ),
        sa.Column("justification", sa.Text, nullable=True),
        sa.Column(
            "requested_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column(
            "decided_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime, nullable=True),
        sa.Column("decided_reason", sa.Text, nullable=True),
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
        "ix_compliance_remediation_requests_policy",
        "compliance_remediation_requests",
        ["policy_id"],
    )
    op.create_index(
        "ix_compliance_remediation_requests_check",
        "compliance_remediation_requests",
        ["check_id"],
    )
    op.create_index(
        "ix_compliance_remediation_requests_system",
        "compliance_remediation_requests",
        ["system_id"],
    )
    op.create_index(
        "ix_compliance_remediation_requests_evidence",
        "compliance_remediation_requests",
        ["evidence_id"],
    )
    op.create_index(
        "ix_compliance_remediation_requests_state",
        "compliance_remediation_requests",
        ["state"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_compliance_remediation_requests_state",
        table_name="compliance_remediation_requests",
    )
    op.drop_index(
        "ix_compliance_remediation_requests_evidence",
        table_name="compliance_remediation_requests",
    )
    op.drop_index(
        "ix_compliance_remediation_requests_system",
        table_name="compliance_remediation_requests",
    )
    op.drop_index(
        "ix_compliance_remediation_requests_check",
        table_name="compliance_remediation_requests",
    )
    op.drop_index(
        "ix_compliance_remediation_requests_policy",
        table_name="compliance_remediation_requests",
    )
    op.drop_table("compliance_remediation_requests")
