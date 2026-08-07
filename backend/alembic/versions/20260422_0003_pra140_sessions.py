"""PRA-140: interactive SSH session ledger

Revision ID: pra140_sessions
Revises: pra139_totp_access
Create Date: 2026-04-22

Adds the ``sessions`` table. Rows are created when a user opens a terminal
session via /sessions and updated as the lifecycle progresses (opening ->
active -> closed/idle_kill/max_duration/errored). PRA-141's recording
attaches a Recording row linked to this session_id.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra140_sessions"
down_revision: Union[str, None] = "pra139_totp_access"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
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
            sa.ForeignKey("fleet_roles.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("login", sa.String(100), nullable=False),
        sa.Column("cert_serial", sa.String(255), nullable=True),
        sa.Column("client_ip", sa.String(64), nullable=True),
        # opening / active / closed / idle_kill / max_duration / errored
        sa.Column("status", sa.String(20), nullable=False, server_default="opening"),
        sa.Column("close_reason", sa.Text(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_activity_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("max_expires_at", sa.DateTime(), nullable=False),
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
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_system_id", "sessions", ["system_id"])
    op.create_index("ix_sessions_status", "sessions", ["status"])


def downgrade() -> None:
    op.drop_index("ix_sessions_status", table_name="sessions")
    op.drop_index("ix_sessions_system_id", table_name="sessions")
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
