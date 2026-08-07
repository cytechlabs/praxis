"""PRA-167 slice 2: compliance remediation plan preview substrate.

Creates ``compliance_remediation_plans`` for non-executing,
deterministic plan previews tied 1:1 to approved Slice 1
remediation requests.

Locks (PRA-167 Slice 2):

* ``request_id`` is ``ON DELETE CASCADE`` and ``UNIQUE`` — exactly
  one plan per request, so rebuilds are idempotent and a request
  delete drops its plan.
* Snapshot identity columns mirror the Slice 1 request: dropping
  the request still preserves auditor identity for the historical
  plan via the cascade-then-replay shape of the existing audit
  events; the columns are intentionally not FKs (the request is
  the FK seam).
* ``plan_steps`` is JSONB so later read paths can index without a
  schema migration; the service caps payload size.
* All timestamps are UTC ``CURRENT_TIMESTAMP`` server defaults so
  rows persisted via raw SQL still satisfy ``NOT NULL``.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra167_remediation_plans"
down_revision: Union[str, None] = "pra167_remediation_requests"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compliance_remediation_plans",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "request_id",
            sa.Integer,
            sa.ForeignKey("compliance_remediation_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_id", sa.Integer, nullable=False),
        sa.Column("check_id", sa.Integer, nullable=True),
        sa.Column("system_id", sa.Integer, nullable=False),
        sa.Column("policy_slug", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.Integer, nullable=False),
        sa.Column("check_slug", sa.String(64), nullable=False),
        sa.Column("check_kind", sa.String(64), nullable=False),
        sa.Column("severity_snapshot", sa.String(16), nullable=False),
        sa.Column(
            "state",
            sa.String(16),
            nullable=False,
            server_default="planned",
        ),
        sa.Column("plan_kind", sa.String(64), nullable=False),
        sa.Column(
            "plan_steps",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("unsupported_reason", sa.String(512), nullable=True),
        sa.Column("error_message", sa.String(512), nullable=True),
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
        sa.UniqueConstraint(
            "request_id",
            name="uq_compliance_remediation_plans_request",
        ),
    )
    op.create_index(
        "ix_compliance_remediation_plans_request",
        "compliance_remediation_plans",
        ["request_id"],
    )
    op.create_index(
        "ix_compliance_remediation_plans_state",
        "compliance_remediation_plans",
        ["state"],
    )
    op.create_index(
        "ix_compliance_remediation_plans_plan_kind",
        "compliance_remediation_plans",
        ["plan_kind"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_compliance_remediation_plans_plan_kind",
        table_name="compliance_remediation_plans",
    )
    op.drop_index(
        "ix_compliance_remediation_plans_state",
        table_name="compliance_remediation_plans",
    )
    op.drop_index(
        "ix_compliance_remediation_plans_request",
        table_name="compliance_remediation_plans",
    )
    op.drop_table("compliance_remediation_plans")
