"""Align the groups ID sequence with existing rows.

The original startup seed inserted the default group with an explicit ID,
leaving PostgreSQL's sequence at its initial value. The next group creation
could therefore collide with the default row. Fresh seeds now use the sequence;
this migration repairs databases created before that correction.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "align_groups_id_sequence"
down_revision: Union[str, None] = "pra359_host_facts_ssh_sysctl"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        SELECT setval(
            pg_get_serial_sequence('groups', 'id'),
            COALESCE(MAX(id), 1),
            MAX(id) IS NOT NULL
        )
        FROM groups
        """)


def downgrade() -> None:
    """Sequence alignment is data repair and must not be reversed."""
