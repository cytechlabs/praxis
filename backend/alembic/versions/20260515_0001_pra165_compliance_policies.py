"""PRA-165 slice 1: compliance policy framework substrate.

Creates ``compliance_policies`` and ``compliance_policy_checks`` for
named Praxis-shaped compliance policies. Slice 1 stores definition
and metadata only — no probe execution, no per-host evidence rows,
no scheduler hookup. Those land in PRA-165 Slice 2 (package/fact
runner) and later.

Locks:

* ``starter_pack_key`` has a partial unique index (only enforced
  when non-NULL) so operator-authored policies don't collide on the
  NULL value, and the starter-pack seeder stays purely additive.
* ``definition_json`` is JSONB so later read paths can index
  individual fields (e.g. by package name) without another
  migration.
* ``built_in=True`` flags starter-pack rows; service refuses to
  delete those — operators may disable instead.
* All timestamps are UTC ``CURRENT_TIMESTAMP`` server defaults so
  rows persisted via raw SQL still satisfy ``NOT NULL``.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra165_compliance_policies"
down_revision: Union[str, None] = "pra173_rollback_verify"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "compliance_policies",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column(
            "severity",
            sa.String(16),
            nullable=False,
            server_default="medium",
        ),
        sa.Column(
            "category",
            sa.String(64),
            nullable=False,
            server_default="custom",
        ),
        sa.Column(
            "schedule_interval_hours",
            sa.Integer,
            nullable=False,
            server_default="24",
        ),
        sa.Column(
            "evidence_retention_days",
            sa.Integer,
            nullable=False,
            server_default="90",
        ),
        sa.Column("remediation_guidance", sa.Text, nullable=True),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "version",
            sa.Integer,
            nullable=False,
            server_default="1",
        ),
        sa.Column(
            "built_in",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("starter_pack_key", sa.String(128), nullable=True),
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
        sa.UniqueConstraint("slug", name="uq_compliance_policies_slug"),
    )
    op.create_index(
        "ix_compliance_policies_slug",
        "compliance_policies",
        ["slug"],
    )
    op.create_index(
        "ix_compliance_policies_starter_pack_key",
        "compliance_policies",
        ["starter_pack_key"],
    )
    # Partial unique index — NULLs allowed (multiple operator-authored
    # rows), non-NULL values are unique so seed is idempotent.
    op.create_index(
        "uq_compliance_policies_starter_pack_key",
        "compliance_policies",
        ["starter_pack_key"],
        unique=True,
        postgresql_where=sa.text("starter_pack_key IS NOT NULL"),
    )

    op.create_table(
        "compliance_policy_checks",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "policy_id",
            sa.Integer,
            sa.ForeignKey("compliance_policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column(
            "definition_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("severity_override", sa.String(16), nullable=True),
        sa.Column("remediation_guidance", sa.Text, nullable=True),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "display_order",
            sa.Integer,
            nullable=False,
            server_default="0",
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
            "policy_id",
            "slug",
            name="uq_compliance_policy_checks_policy_slug",
        ),
    )
    op.create_index(
        "ix_compliance_policy_checks_policy",
        "compliance_policy_checks",
        ["policy_id"],
    )
    op.create_index(
        "ix_compliance_policy_checks_kind",
        "compliance_policy_checks",
        ["kind"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_compliance_policy_checks_kind",
        table_name="compliance_policy_checks",
    )
    op.drop_index(
        "ix_compliance_policy_checks_policy",
        table_name="compliance_policy_checks",
    )
    op.drop_table("compliance_policy_checks")

    op.drop_index(
        "uq_compliance_policies_starter_pack_key",
        table_name="compliance_policies",
    )
    op.drop_index(
        "ix_compliance_policies_starter_pack_key",
        table_name="compliance_policies",
    )
    op.drop_index(
        "ix_compliance_policies_slug",
        table_name="compliance_policies",
    )
    op.drop_table("compliance_policies")
