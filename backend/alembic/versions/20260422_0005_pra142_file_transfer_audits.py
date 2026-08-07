"""PRA-142: file transfer audit ledger

Revision ID: pra142_xferaudits
Revises: pra141_recordings
Create Date: 2026-04-22

Adds ``file_transfer_audits`` — one row per SFTP upload / download /
mkdir / unlink through the Praxis web UI. Captures who, what login, which
host, direction, bytes, sha256, start/end, outcome, and client IP.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra142_xferaudits"
down_revision: Union[str, None] = "pra141_recordings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "file_transfer_audits",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
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
        sa.Column("login", sa.String(100), nullable=False),
        # upload | download | mkdir | unlink
        sa.Column("direction", sa.String(20), nullable=False),
        sa.Column("remote_path", sa.Text(), nullable=False),
        sa.Column("local_filename", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("sha256", sa.String(64), nullable=True),
        # in_progress | success | error
        sa.Column(
            "status", sa.String(20), nullable=False, server_default="in_progress"
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("client_ip", sa.String(64), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
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
        "ix_file_transfer_audits_user_id", "file_transfer_audits", ["user_id"]
    )
    op.create_index(
        "ix_file_transfer_audits_system_id", "file_transfer_audits", ["system_id"]
    )
    op.create_index(
        "ix_file_transfer_audits_status", "file_transfer_audits", ["status"]
    )


def downgrade() -> None:
    op.drop_index("ix_file_transfer_audits_status", table_name="file_transfer_audits")
    op.drop_index(
        "ix_file_transfer_audits_system_id", table_name="file_transfer_audits"
    )
    op.drop_index("ix_file_transfer_audits_user_id", table_name="file_transfer_audits")
    op.drop_table("file_transfer_audits")
