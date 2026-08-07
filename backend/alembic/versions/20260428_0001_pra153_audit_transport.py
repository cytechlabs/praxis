"""PRA-153 slice #2: durable transport columns on the audit ledgers.

Adds ``transport`` (VARCHAR(8), nullable) to:

    sessions                    — interactive PTY sessions
    file_transfer_audits        — SFTP / file_get / file_put rows
    command_execution_results   — exec/run-command results

Existing rows are left as NULL — pre-PRA-153 history is "unknown
transport," not "ssh." The audit emitters in slice #3 set it
explicitly per op (``"ssh"`` or ``"agent"``); a NULL after PRA-153
ships is a code-path bug worth investigating.

Per the locked design, the column is short (VARCHAR(8)) and
unconstrained at the DB level — application code is the source of
truth for the valid values ``"ssh"`` and ``"agent"``. Adding a new
transport identifier longer than 8 characters would require a
separate migration to widen the column.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra153_transport"
down_revision: Union[str, None] = "pra150_agent"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TARGET_TABLES = (
    "sessions",
    "file_transfer_audits",
    "command_execution_results",
)


def upgrade() -> None:
    for table in _TARGET_TABLES:
        op.add_column(
            table,
            sa.Column("transport", sa.String(length=8), nullable=True),
        )


def downgrade() -> None:
    # LIFO so the schema rolls back cleanly even if a partial upgrade
    # only touched the first table (matches alembic best practice).
    for table in reversed(_TARGET_TABLES):
        op.drop_column(table, "transport")
