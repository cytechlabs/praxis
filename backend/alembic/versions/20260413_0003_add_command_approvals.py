"""add requires_approval to command_whitelist and command_approvals table (PRA-80)

Revision ID: pra80_approvals
Revises: pra100_notifprf
Create Date: 2026-04-13

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra80_approvals"
down_revision: Union[str, None] = "pra100_notifprf"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add requires_approval to command_whitelist
    op.add_column(
        "command_whitelist",
        sa.Column(
            "requires_approval",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )

    # Create command_approvals table
    op.create_table(
        "command_approvals",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("command", sa.String(1000), nullable=False),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "whitelist_entry_id",
            sa.Integer(),
            sa.ForeignKey("command_whitelist.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "requested_by",
            sa.Integer(),
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column(
            "decided_by",
            sa.Integer(),
            sa.ForeignKey("user.id"),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=True),
        sa.Column("session_id", sa.String(255), nullable=True),
        sa.Column(
            "requested_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
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


def downgrade() -> None:
    op.drop_table("command_approvals")
    op.drop_column("command_whitelist", "requires_approval")
