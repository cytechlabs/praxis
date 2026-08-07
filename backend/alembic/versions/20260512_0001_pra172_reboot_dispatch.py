"""PRA-172 slice 3: reboot dispatch columns on patch_update_execution_reboots.

Adds per-row dispatch result columns the Slice 3 reboot transport
populates when a ``scheduled`` row gets a real reboot command issued.

Columns added:

* ``transport_kind`` (str(16), nullable) — transport used for the
  dispatch attempt; Slice 3 only writes ``"ssh"`` (agent reserved
  for a later slice).
* ``command_snapshot`` (text, nullable) — the exact shell command
  argv joined for audit-grade history. Captured even on dispatch
  failure so the operator UI can render "the reboot we tried".
* ``exit_signal_kind`` (str(32), nullable) — controlled vocabulary:
  ``exit_zero`` / ``connection_lost_clean`` / ``non_zero`` /
  ``timeout`` / ``transport_error`` / ``transport_unavailable``.
  ``exit_zero`` and ``connection_lost_clean`` are SUCCESS signals
  (the host accepted the reboot command and the SSH session died
  legitimately because the kernel is rebooting). The remaining
  codes are dispatch failures and flip the row from ``scheduled``
  to ``failed`` directly.
* ``dispatch_details`` (JSONB, default ``'{}'``) — structured
  context the operator UI can render: exit code, truncated
  stderr, duration_ms, transport_name, plus the
  ``failure_threshold_pause`` marker when applicable.

All new columns are nullable / default-empty so existing Slice 1+2
rows survive the migration without backfill.

ORM ``__table_args__`` on :class:`PatchUpdateExecutionReboot`
mirrors the new vocabulary (PRA-161 1a-a parity rule
carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra172_reboot_dispatch"
down_revision: Union[str, None] = "pra172_reboot_queue"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


EXIT_SIGNAL_KINDS = (
    "exit_zero",
    "connection_lost_clean",
    "non_zero",
    "timeout",
    "transport_error",
    "transport_unavailable",
)


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.add_column(
        "patch_update_execution_reboots",
        sa.Column("transport_kind", sa.String(16), nullable=True),
    )
    op.add_column(
        "patch_update_execution_reboots",
        sa.Column("command_snapshot", sa.Text, nullable=True),
    )
    op.add_column(
        "patch_update_execution_reboots",
        sa.Column("exit_signal_kind", sa.String(32), nullable=True),
    )
    op.add_column(
        "patch_update_execution_reboots",
        sa.Column(
            "dispatch_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_check_constraint(
        "patch_update_execution_reboots_exit_signal_kind_vocab",
        "patch_update_execution_reboots",
        f"exit_signal_kind IS NULL OR {_check_in('exit_signal_kind', EXIT_SIGNAL_KINDS)}",
    )


def downgrade() -> None:
    op.drop_constraint(
        "patch_update_execution_reboots_exit_signal_kind_vocab",
        "patch_update_execution_reboots",
        type_="check",
    )
    op.drop_column("patch_update_execution_reboots", "dispatch_details")
    op.drop_column("patch_update_execution_reboots", "exit_signal_kind")
    op.drop_column("patch_update_execution_reboots", "command_snapshot")
    op.drop_column("patch_update_execution_reboots", "transport_kind")
