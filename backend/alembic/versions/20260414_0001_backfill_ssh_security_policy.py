"""backfill Default SSH security policy onto existing systems (PRA-119)

Revision ID: pra119_hostkey
Revises: pra44_sshidty
Create Date: 2026-04-14

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra119_hostkey"
down_revision: Union[str, None] = "pra44_sshidty"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Backfill systems.ssh_security_policy_id = Default policy id
    # where it's currently NULL. Safe no-op if no Default policy exists
    # (seed script runs after this migration but the join yields 0 rows,
    # so nothing is updated — a later startup will re-run and the seed
    # will have already created the Default row by then).
    op.execute(
        """
        UPDATE systems
        SET ssh_security_policy_id = (
            SELECT id FROM ssh_security_policies WHERE name = 'Default' LIMIT 1
        )
        WHERE ssh_security_policy_id IS NULL
          AND EXISTS (SELECT 1 FROM ssh_security_policies WHERE name = 'Default')
        """
    )


def downgrade() -> None:
    # Set systems back to NULL where they were backfilled to the Default policy
    op.execute(
        """
        UPDATE systems
        SET ssh_security_policy_id = NULL
        WHERE ssh_security_policy_id = (
            SELECT id FROM ssh_security_policies WHERE name = 'Default' LIMIT 1
        )
        """
    )
