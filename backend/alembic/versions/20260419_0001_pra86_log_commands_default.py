"""PRA-86: flip log_commands default to True on existing SSH security policies

Revision ID: pra86_log_commands
Revises: pra63_pkgerror
Create Date: 2026-04-19

The default SSH security policy shipped with log_commands=False, which
suppressed command_execution audit events for every managed host. Surfaced
by the M9 SSH security validation — for a product whose sell is the audit
trail, silent command execution is the wrong default. Flip existing rows
that are still at the old default to True. Users who explicitly turned
logging off are left alone.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "pra86_log_commands"
down_revision: Union[str, None] = "pra63_pkgerror"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "UPDATE ssh_security_policies "
        "SET log_commands = TRUE "
        "WHERE name = 'Default' AND log_commands = FALSE"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE ssh_security_policies "
        "SET log_commands = FALSE "
        "WHERE name = 'Default' AND log_commands = TRUE"
    )
