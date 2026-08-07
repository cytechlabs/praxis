"""PRA-287: persist conservative recording retention on the session.

A shared login can resolve to multiple fleet roles; the compatibility gate
resolves session policy conservatively (longest recording retention wins). That
value was only computed in ``AuthorizationResult`` — recording retention was still
derived from the session's representative ``fleet_role_id``, so a looser role that
won as representative could shorten the actual persisted recording window.

Adds a nullable ``sessions.recording_retention_days`` stamped at session open with
the conservative value; ``recording_service`` prefers it and enforces it. NULL on
rows created before this migration — recording falls back to the representative
role's value for those.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra287_rec_retention"
down_revision: Union[str, None] = "pra285_revocation_work"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sessions",
        sa.Column("recording_retention_days", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sessions", "recording_retention_days")
