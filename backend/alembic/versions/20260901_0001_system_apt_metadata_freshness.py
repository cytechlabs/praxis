"""Record APT metadata freshness on each system.

An APT scan reads the host's cached package lists. When the repository refresh
fails (an unentitled source, a missing suite, a signature error, no network),
the cached lists still answer, so the scan used to look identical to one made
against current metadata.

Four nullable columns hold the latest observation per host:

* ``apt_metadata_state``: ``fresh``, ``partial``, ``failed`` or ``cached``.
* ``apt_metadata_checked_at``: when the latest check was observed.
* ``apt_metadata_refreshed_at``: the last verified complete refresh. Only a
  fresh observation advances it; the other states preserve it.
* ``apt_metadata_detail``: bounded, redacted, repository-scoped detail.

Existing rows start NULL, meaning unknown. Nothing is inferred from
``last_audited``, which keeps its inventory meaning. The downgrade drops the
columns and the recorded observations with them.

Revision ID: system_apt_metadata_freshness
Revises: bootstrap_admin_state
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "system_apt_metadata_freshness"
down_revision: Union[str, None] = "bootstrap_admin_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "systems",
        sa.Column("apt_metadata_state", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("apt_metadata_refreshed_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("apt_metadata_checked_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("apt_metadata_detail", sa.String(length=500), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("systems", "apt_metadata_detail")
    op.drop_column("systems", "apt_metadata_checked_at")
    op.drop_column("systems", "apt_metadata_refreshed_at")
    op.drop_column("systems", "apt_metadata_state")
