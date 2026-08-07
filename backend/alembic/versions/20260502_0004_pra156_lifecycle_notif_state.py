"""PRA-156 slice #3e-c: lifecycle_notification_state dedup table.

Records that Praxis has emitted a lifecycle event for a given host at
a given threshold + EOL date. The emitter consults this before firing
so each (system, threshold, EOL date) combination notifies exactly
once.

``effective_eol_date`` is part of the dedup key so an override
extension that moves a host's EOL date out causes the dedup keys to
change — the new EOL date triggers a fresh threshold sequence rather
than being silently swallowed by state from the prior date.

NOT a replacement for ``alert_history``. That table is external
delivery history per ``alert_config``, populated downstream by
``alert_service.send_alert``. This table is the upstream "did we
emit?" gate — the emitter writes here after deciding to send,
regardless of how many configs matched or whether delivery
succeeded.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra156_lifecycle_notif_state"
down_revision: Union[str, None] = "pra156_rename_eol_warning_event"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "lifecycle_notification_state",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("threshold_days", sa.Integer, nullable=False),
        sa.Column("effective_eol_date", sa.Date, nullable=False),
        sa.Column(
            "notified_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
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
            "system_id",
            "event_type",
            "threshold_days",
            "effective_eol_date",
            name="lifecycle_notification_state_unique_key",
        ),
        sa.CheckConstraint(
            "event_type IN ('host_eol_approaching', 'host_eol_reached')",
            name="lifecycle_notification_state_event_type_valid",
        ),
    )


def downgrade() -> None:
    op.drop_table("lifecycle_notification_state")
