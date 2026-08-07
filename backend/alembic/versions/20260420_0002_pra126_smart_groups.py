"""PRA-126: smart groups + cached membership

Revision ID: pra126_smartgroups
Revises: pra125_webhooks
Create Date: 2026-04-20

Creates smart_groups (rule-based dynamic system groups) and
smart_group_memberships (materialised cache of resolved systems).
Also adds alert_configs.scope_smart_group_id so alert configs can be
scoped to a smart group (PRA-126 integration).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra126_smartgroups"
down_revision: Union[str, None] = "pra125_webhooks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "smart_groups",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("rule_json", sa.Text(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("user.id"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_smart_groups_id", "smart_groups", ["id"])

    op.create_table(
        "smart_group_memberships",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "smart_group_id",
            sa.Integer(),
            sa.ForeignKey("smart_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_smart_group_memberships_smart_group_id",
        "smart_group_memberships",
        ["smart_group_id"],
    )
    op.create_index(
        "ix_smart_group_memberships_system_id",
        "smart_group_memberships",
        ["system_id"],
    )
    op.create_unique_constraint(
        "uq_smart_group_memberships_group_system",
        "smart_group_memberships",
        ["smart_group_id", "system_id"],
    )

    op.add_column(
        "alert_configs",
        sa.Column(
            "scope_smart_group_id",
            sa.Integer(),
            sa.ForeignKey("smart_groups.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_alert_configs_scope_smart_group_id",
        "alert_configs",
        ["scope_smart_group_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_alert_configs_scope_smart_group_id", table_name="alert_configs")
    op.drop_column("alert_configs", "scope_smart_group_id")
    op.drop_constraint(
        "uq_smart_group_memberships_group_system",
        "smart_group_memberships",
        type_="unique",
    )
    op.drop_index(
        "ix_smart_group_memberships_system_id",
        table_name="smart_group_memberships",
    )
    op.drop_index(
        "ix_smart_group_memberships_smart_group_id",
        table_name="smart_group_memberships",
    )
    op.drop_table("smart_group_memberships")
    op.drop_index("ix_smart_groups_id", table_name="smart_groups")
    op.drop_table("smart_groups")
