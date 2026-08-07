"""PRA-158 #4b: extend mirror_alert_state event_type CHECK to allow
``mirror_upstream_signature_invalid``.

Slice #4b's pre-sync verification gate fires this event on upstream
signature failure (rejected sync, refused promotion). Constraint
update is a drop+recreate per Postgres semantics — no data migration
needed since no rows of the new type exist yet.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra158_upstream_alert"
down_revision: Union[str, None] = "pra158_upstream_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "mirror_alert_state_event_type_valid",
        "mirror_alert_state",
        type_="check",
    )
    op.create_check_constraint(
        "mirror_alert_state_event_type_valid",
        "mirror_alert_state",
        "event_type IN ("
        "'mirror_sync_failed', "
        "'mirror_sync_completed', "
        "'mirror_disk_pressure', "
        "'mirror_upstream_signature_invalid'"
        ")",
    )


def downgrade() -> None:
    op.drop_constraint(
        "mirror_alert_state_event_type_valid",
        "mirror_alert_state",
        type_="check",
    )
    op.create_check_constraint(
        "mirror_alert_state_event_type_valid",
        "mirror_alert_state",
        "event_type IN ("
        "'mirror_sync_failed', "
        "'mirror_sync_completed', "
        "'mirror_disk_pressure'"
        ")",
    )
