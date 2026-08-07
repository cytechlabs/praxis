"""PRA-167 slice 3: plan lifecycle (acknowledgement + supersede + readiness).

Extends ``compliance_remediation_plans`` with non-executing lifecycle
fields: ``check_definition_fingerprint``, ``acknowledged_at``,
``acknowledged_by``, ``superseded_by_plan_id``. Replaces the Slice 2
hard ``UNIQUE(request_id)`` constraint with a partial unique index
that enforces "exactly one current plan per request" — current here
means ``superseded_by_plan_id IS NULL``.

Locks (PRA-167 Slice 3):

* ``superseded_by_plan_id`` is a self-FK with ``ON DELETE SET NULL``
  so deleting the new current plan does not cascade-delete prior
  rows; the prior row simply detaches and becomes orphan history.
* The partial unique index is the only way to guarantee one-current-
  per-request without a write-time check; postgres-specific
  ``postgresql_where`` is fine because the rest of the schema is
  already Postgres-only.
* The fingerprint column is a 64-char SHA-256 hex string and is
  nullable so plans built against a deleted check still persist
  (the live-def lookup returns ``None`` in that case).
* No data migration needed: every existing Slice 2 row is "current"
  by definition because the old UNIQUE prevented any superseded
  history — they all have ``superseded_by_plan_id IS NULL`` after
  the column is added.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra167_plan_lifecycle"
down_revision: Union[str, None] = "pra167_remediation_plans"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "compliance_remediation_plans",
        sa.Column(
            "check_definition_fingerprint",
            sa.String(64),
            nullable=True,
        ),
    )
    op.add_column(
        "compliance_remediation_plans",
        sa.Column("acknowledged_at", sa.DateTime, nullable=True),
    )
    op.add_column(
        "compliance_remediation_plans",
        sa.Column(
            "acknowledged_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "compliance_remediation_plans",
        sa.Column(
            "superseded_by_plan_id",
            sa.Integer,
            sa.ForeignKey("compliance_remediation_plans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_compliance_remediation_plans_superseded_by",
        "compliance_remediation_plans",
        ["superseded_by_plan_id"],
    )
    # Drop the Slice 2 hard UNIQUE so we can have multiple historical
    # rows per request.
    op.drop_constraint(
        "uq_compliance_remediation_plans_request",
        "compliance_remediation_plans",
        type_="unique",
    )
    # Replace with a partial unique enforcing exactly-one-current.
    op.create_index(
        "uq_compliance_remediation_plans_current",
        "compliance_remediation_plans",
        ["request_id"],
        unique=True,
        postgresql_where=sa.text("superseded_by_plan_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_compliance_remediation_plans_current",
        table_name="compliance_remediation_plans",
    )
    op.create_unique_constraint(
        "uq_compliance_remediation_plans_request",
        "compliance_remediation_plans",
        ["request_id"],
    )
    op.drop_index(
        "ix_compliance_remediation_plans_superseded_by",
        table_name="compliance_remediation_plans",
    )
    op.drop_column("compliance_remediation_plans", "superseded_by_plan_id")
    op.drop_column("compliance_remediation_plans", "acknowledged_by")
    op.drop_column("compliance_remediation_plans", "acknowledged_at")
    op.drop_column("compliance_remediation_plans", "check_definition_fingerprint")
