"""add alert_configs and alert_history tables (PRA-41)

Revision ID: m2n3o4p5q6r7
Revises: k1l2m3n4o5p6
Create Date: 2026-04-10

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "m2n3o4p5q6r7"
down_revision: Union[str, None] = "k1l2m3n4o5p6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alert_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("alert_type", sa.String(50), nullable=False),
        sa.Column("destination", sa.Text(), nullable=False),
        sa.Column("events", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("user.id"), nullable=True),
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
    op.create_index("ix_alert_configs_id", "alert_configs", ["id"])

    op.create_table(
        "alert_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "alert_config_id",
            sa.Integer(),
            sa.ForeignKey("alert_configs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "sent_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("response_code", sa.Integer(), nullable=True),
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
    op.create_index("ix_alert_history_id", "alert_history", ["id"])
    op.create_index(
        "ix_alert_history_alert_config_id", "alert_history", ["alert_config_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_alert_history_alert_config_id", table_name="alert_history")
    op.drop_index("ix_alert_history_id", table_name="alert_history")
    op.drop_table("alert_history")
    op.drop_index("ix_alert_configs_id", table_name="alert_configs")
    op.drop_table("alert_configs")
