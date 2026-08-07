"""PRA-146: session locks (emergency cut-off)

Revision ID: pra146_locks
Revises: pra143_audit
Create Date: 2026-04-24

Adds:
  - session_locks — emergency cut-off rows. While an active lock matches a
    subject (user OR app-level role), authorize_action rejects all gated
    actions for that subject (session_open, command_exec, file_transfer)
    and lock create kills any live sessions belonging to the subject.

XOR on subject is enforced with a CHECK constraint: exactly one of
subject_user_id / subject_app_role_id must be non-null.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra146_locks"
down_revision: Union[str, None] = "pra143_audit"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "session_locks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "subject_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "subject_app_role_id",
            sa.Integer(),
            sa.ForeignKey("role.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("released_at", sa.DateTime(), nullable=True),
        sa.Column(
            "released_by",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "(subject_user_id IS NOT NULL) <> (subject_app_role_id IS NOT NULL)",
            name="ck_session_locks_subject_xor",
        ),
    )
    op.create_index(
        "ix_session_locks_subject_user_id", "session_locks", ["subject_user_id"]
    )
    op.create_index(
        "ix_session_locks_subject_app_role_id",
        "session_locks",
        ["subject_app_role_id"],
    )
    op.create_index("ix_session_locks_released_at", "session_locks", ["released_at"])


def downgrade() -> None:
    op.drop_index("ix_session_locks_released_at", table_name="session_locks")
    op.drop_index("ix_session_locks_subject_app_role_id", table_name="session_locks")
    op.drop_index("ix_session_locks_subject_user_id", table_name="session_locks")
    op.drop_table("session_locks")
