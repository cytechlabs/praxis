"""add global_connection_settings table (PRA-62)

Revision ID: pra62_conn_cfg1
Revises: s1t2u3v4w5x6
Create Date: 2026-04-13

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra62_conn_cfg1"
down_revision: Union[str, None] = "m5f6g7h8i9j0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "global_connection_settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "connection_timeout",
            sa.Integer(),
            nullable=False,
            server_default="10",
            comment="SSH connection timeout in seconds",
        ),
        sa.Column(
            "max_pool_size",
            sa.Integer(),
            nullable=False,
            server_default="50",
            comment="Maximum concurrent SSH connections in pool",
        ),
        sa.Column(
            "pool_cleanup_interval",
            sa.Integer(),
            nullable=False,
            server_default="300",
            comment="Seconds between pool cleanup sweeps",
        ),
        sa.Column(
            "max_idle_time",
            sa.Integer(),
            nullable=False,
            server_default="600",
            comment="Seconds before an idle connection is closed",
        ),
        sa.Column(
            "unreachable_threshold",
            sa.Integer(),
            nullable=False,
            server_default="2",
            comment="Consecutive failures before system marked Unreachable",
        ),
        sa.Column(
            "default_ssh_port",
            sa.Integer(),
            nullable=False,
            server_default="22",
            comment="Default SSH port when system metadata has none",
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

    # Seed the single settings row with defaults
    op.execute(
        "INSERT INTO global_connection_settings "
        "(connection_timeout, max_pool_size, pool_cleanup_interval, "
        "max_idle_time, unreachable_threshold, default_ssh_port) "
        "VALUES (10, 50, 300, 600, 2, 22)"
    )


def downgrade() -> None:
    op.drop_table("global_connection_settings")
