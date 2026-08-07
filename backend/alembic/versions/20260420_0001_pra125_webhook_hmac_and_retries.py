"""PRA-125: HMAC secret on alert_configs + retry/delivery fields on alert_history

Revision ID: pra125_webhooks
Revises: pra86_log_commands
Create Date: 2026-04-20

Adds:
  - alert_configs.secret        nullable — HMAC-SHA256 key for X-Praxis-Signature
  - alert_history.payload       nullable — serialized request body (for retry)
  - alert_history.attempt_count default 1 — how many delivery attempts so far
  - alert_history.next_retry_at nullable — when sweeper should retry; null = done
  - alert_history.last_attempted_at nullable — most recent attempt timestamp

Status column (String(20)) already exists; new values 'pending' and 'dead_letter'
are written by the service layer without schema change.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra125_webhooks"
down_revision: Union[str, None] = "pra86_log_commands"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "alert_configs",
        sa.Column("secret", sa.String(255), nullable=True),
    )
    op.add_column(
        "alert_history",
        sa.Column("payload", sa.Text(), nullable=True),
    )
    op.add_column(
        "alert_history",
        sa.Column(
            "attempt_count",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "alert_history",
        sa.Column("next_retry_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "alert_history",
        sa.Column("last_attempted_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_alert_history_next_retry_at",
        "alert_history",
        ["next_retry_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_alert_history_next_retry_at", table_name="alert_history")
    op.drop_column("alert_history", "last_attempted_at")
    op.drop_column("alert_history", "next_retry_at")
    op.drop_column("alert_history", "attempt_count")
    op.drop_column("alert_history", "payload")
    op.drop_column("alert_configs", "secret")
