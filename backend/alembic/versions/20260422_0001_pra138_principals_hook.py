"""PRA-138: track AuthorizedPrincipalsCommand deployment state

Revision ID: pra138_principals_hook
Revises: pra137_fleet_access
Create Date: 2026-04-22

Adds columns to systems:
  - principals_hook_deployed (bool, default false)
  - principals_hook_deployed_at (datetime, nullable)

These track whether PRA-138's sshd AuthorizedPrincipalsCommand wiring +
praxis-principals script are installed on the host. Separate from the
PRA-44 ca_trust_deployed flag because a host may have CA trust without
the principals hook (legacy state) but not the other way round.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra138_principals_hook"
down_revision: Union[str, None] = "pra137_fleet_access"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "systems",
        sa.Column(
            "principals_hook_deployed",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.add_column(
        "systems",
        sa.Column(
            "principals_hook_deployed_at",
            sa.DateTime(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("systems", "principals_hook_deployed_at")
    op.drop_column("systems", "principals_hook_deployed")
