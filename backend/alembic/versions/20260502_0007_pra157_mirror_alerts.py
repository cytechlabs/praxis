"""PRA-157 slice #1: mirror_alert_state dedup table.

Mirrors the PRA-156 ``lifecycle_notification_state`` shape: an
upstream "did we notify already?" gate consulted by the alert path
in slice #2b before calling ``alert_service.send_alert``. Prevents
flooding (e.g. 5 consecutive failed syncs → 1 alert + cooldown,
not 5 alerts).

Slice #2b is the first writer; the table lives in #1 so the alert
plumbing slice has nothing to migrate.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra157_mirror_alerts"
down_revision: Union[str, None] = "pra157_mirror_sync_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mirror_alert_state",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "mirror_repo_id",
            sa.Integer,
            sa.ForeignKey("mirror_repos.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("last_fired_at", sa.DateTime, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint(
            "mirror_repo_id",
            "event_type",
            name="mirror_alert_state_unique_key",
        ),
        sa.CheckConstraint(
            "event_type IN ("
            "'mirror_sync_failed', "
            "'mirror_sync_completed', "
            "'mirror_disk_pressure'"
            ")",
            name="mirror_alert_state_event_type_valid",
        ),
    )


def downgrade() -> None:
    op.drop_table("mirror_alert_state")
