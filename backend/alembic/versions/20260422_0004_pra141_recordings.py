"""PRA-141: session recording ledger + per-fleet retention

Revision ID: pra141_recordings
Revises: pra140_sessions
Create Date: 2026-04-22

Adds:
  - recordings table — one row per interactive session capture
  - fleet_roles.recording_retention_days — per-fleet retention window
    (default 90). A nightly sweeper deletes expired captures.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra141_recordings"
down_revision: Union[str, None] = "pra140_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "fleet_roles",
        sa.Column(
            "recording_retention_days",
            sa.Integer(),
            nullable=False,
            server_default="90",
        ),
    )

    op.create_table(
        "recordings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "session_id",
            sa.Integer(),
            sa.ForeignKey("sessions.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("frame_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "started_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("retention_expires_at", sa.DateTime(), nullable=False),
        # active | finalized | pruned | errored
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
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
    op.create_index("ix_recordings_session_id", "recordings", ["session_id"])
    op.create_index("ix_recordings_user_id", "recordings", ["user_id"])
    op.create_index(
        "ix_recordings_retention_expires_at",
        "recordings",
        ["retention_expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_recordings_retention_expires_at", table_name="recordings")
    op.drop_index("ix_recordings_user_id", table_name="recordings")
    op.drop_index("ix_recordings_session_id", table_name="recordings")
    op.drop_table("recordings")
    op.drop_column("fleet_roles", "recording_retention_days")
