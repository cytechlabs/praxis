"""PRA-147: session approvals (single-use, time-windowed grants)

Revision ID: pra147_appr
Revises: pra146_locks
Create Date: 2026-04-24

Adds session_approvals — a row per request to open a session that
needs four-eyes approval. State machine:

    pending -> granted -> consumed
            -> denied
            -> expired (granted but not consumed before expires_at)

Match key (requester_id, system_id, fleet_role_id, login) lets
open_session look up a usable grant deterministically.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra147_appr"
down_revision: Union[str, None] = "pra146_locks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "session_approvals",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "requester_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "fleet_role_id",
            sa.Integer(),
            sa.ForeignKey("fleet_roles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("login", sa.String(100), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        # pending | granted | denied | expired | consumed
        sa.Column("state", sa.String(20), nullable=False, server_default="pending"),
        sa.Column(
            "approver_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        # Set when state -> granted; the requester must consume before this
        sa.Column("expires_at", sa.DateTime(), nullable=True),
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
        "ix_session_approvals_requester_id", "session_approvals", ["requester_id"]
    )
    op.create_index("ix_session_approvals_state", "session_approvals", ["state"])
    op.create_index(
        "ix_session_approvals_expires_at", "session_approvals", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_session_approvals_expires_at", table_name="session_approvals")
    op.drop_index("ix_session_approvals_state", table_name="session_approvals")
    op.drop_index("ix_session_approvals_requester_id", table_name="session_approvals")
    op.drop_table("session_approvals")
