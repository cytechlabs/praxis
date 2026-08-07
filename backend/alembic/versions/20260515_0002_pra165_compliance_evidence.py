"""PRA-165 slice 2: compliance evaluation evidence + last_run_at.

Adds ``compliance_policies.last_run_at`` and the
``compliance_policy_evidence`` table.

Locks:

* Evidence is append-oriented. Retention sweeps DELETE; nothing
  UPDATEs an existing row after insert.
* Denormalized identity fields (``policy_slug``, ``check_slug``,
  ``check_kind``, ``policy_version``, ``severity``) live on the
  evidence row so verdicts remain auditor-readable after the source
  policy/check is edited or the check is deleted.
* ``check_id`` is ``ON DELETE SET NULL`` (not CASCADE) so evidence
  survives check edits/deletions; ``policy_id`` is CASCADE so a
  full policy delete removes evidence too.
* Indexes target the hot read paths: ``(policy_id, evaluated_at)``
  for per-policy timelines, ``(system_id, evaluated_at)`` for
  per-host timelines, ``evaluated_at`` for the retention sweep,
  and ``evaluation_run_id`` so a single sweep run is greppable.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra165_compliance_evidence"
down_revision: Union[str, None] = "pra165_compliance_policies"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "compliance_policies",
        sa.Column("last_run_at", sa.DateTime, nullable=True),
    )

    op.create_table(
        "compliance_policy_evidence",
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
        sa.Column("policy_slug", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.Integer, nullable=False),
        sa.Column("check_slug", sa.String(64), nullable=False),
        sa.Column("check_kind", sa.String(64), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("verdict_reason", sa.String(512), nullable=True),
        sa.Column("observed_value", sa.Text, nullable=True),
        sa.Column("expected_value", sa.Text, nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("evaluation_run_id", sa.String(36), nullable=False),
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
    )
    op.create_index(
        "ix_compliance_policy_evidence_policy_evaluated_at",
        "compliance_policy_evidence",
        ["policy_id", "evaluated_at"],
    )
    op.create_index(
        "ix_compliance_policy_evidence_system_evaluated_at",
        "compliance_policy_evidence",
        ["system_id", "evaluated_at"],
    )
    op.create_index(
        "ix_compliance_policy_evidence_check",
        "compliance_policy_evidence",
        ["check_id"],
    )
    op.create_index(
        "ix_compliance_policy_evidence_verdict",
        "compliance_policy_evidence",
        ["verdict"],
    )
    op.create_index(
        "ix_compliance_policy_evidence_run_id",
        "compliance_policy_evidence",
        ["evaluation_run_id"],
    )
    op.create_index(
        "ix_compliance_policy_evidence_evaluated_at",
        "compliance_policy_evidence",
        ["evaluated_at"],
    )


def downgrade() -> None:
    for idx in (
        "ix_compliance_policy_evidence_evaluated_at",
        "ix_compliance_policy_evidence_run_id",
        "ix_compliance_policy_evidence_verdict",
        "ix_compliance_policy_evidence_check",
        "ix_compliance_policy_evidence_system_evaluated_at",
        "ix_compliance_policy_evidence_policy_evaluated_at",
    ):
        op.drop_index(idx, table_name="compliance_policy_evidence")
    op.drop_table("compliance_policy_evidence")
    op.drop_column("compliance_policies", "last_run_at")
