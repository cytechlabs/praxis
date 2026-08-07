"""PRA-128 + PRA-129: CA rotation history + approval votes + expiration

Revision ID: pra128_129_ssh
Revises: pra127_drift
Create Date: 2026-04-20

Adds:
  - ca_rotations (history of rotate/revoke events)
  - command_approvals.expires_at + required_approvals
  - command_approval_votes (per-admin vote)
  - command_whitelist.required_approvals
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra128_129_ssh"
down_revision: Union[str, None] = "pra127_drift"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PRA-128 — CA rotation history
    op.create_table(
        "ca_rotations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(20), nullable=False),
        sa.Column("ca_identifier", sa.String(100), nullable=True),
        sa.Column("ca_public_key", sa.Text(), nullable=True),
        sa.Column(
            "performed_by", sa.Integer(), sa.ForeignKey("user.id"), nullable=True
        ),
        sa.Column(
            "performed_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
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
    op.create_index("ix_ca_rotations_performed_at", "ca_rotations", ["performed_at"])

    # PRA-129 — approval expiration + multi-level
    op.add_column(
        "command_approvals",
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_command_approvals_expires_at", "command_approvals", ["expires_at"]
    )
    op.add_column(
        "command_approvals",
        sa.Column(
            "required_approvals",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "command_whitelist",
        sa.Column(
            "required_approvals",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )

    op.create_table(
        "command_approval_votes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "approval_id",
            sa.Integer(),
            sa.ForeignKey("command_approvals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
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
        "ix_command_approval_votes_approval_id",
        "command_approval_votes",
        ["approval_id"],
    )
    op.create_unique_constraint(
        "uq_command_approval_votes_approval_user",
        "command_approval_votes",
        ["approval_id", "user_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_command_approval_votes_approval_user",
        "command_approval_votes",
        type_="unique",
    )
    op.drop_index(
        "ix_command_approval_votes_approval_id",
        table_name="command_approval_votes",
    )
    op.drop_table("command_approval_votes")
    op.drop_column("command_whitelist", "required_approvals")
    op.drop_column("command_approvals", "required_approvals")
    op.drop_index("ix_command_approvals_expires_at", table_name="command_approvals")
    op.drop_column("command_approvals", "expires_at")
    op.drop_index("ix_ca_rotations_performed_at", table_name="ca_rotations")
    op.drop_table("ca_rotations")
