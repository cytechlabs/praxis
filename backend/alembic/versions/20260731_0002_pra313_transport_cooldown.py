"""PRA-313: per-host transport circuit breaker (failing-host isolation).

Adds narrowly scoped transport-cooldown metadata so one bad/half-open SSH host
can't make unrelated pages, dashboard/status requests, or scheduler work wait on
that host's SSH timeout:

- ``system_metadata.transport_failures`` — consecutive banner/connect/socket
  failure count (NOT auth failures; those mean the host is reachable).
- ``system_metadata.transport_cooldown_until`` — while in the future the host's
  normal ops fast-fail without opening a socket; explicit operator rechecks bypass.
- ``system_metadata.last_transport_error`` — bounded operator-readable reason.

- ``global_connection_settings.transport_failure_threshold`` /
  ``transport_cooldown_seconds`` — tunables (default 3 failures / 60s), kept
  separate from ``unreachable_threshold`` so a fast auth failure never trips the
  slowness breaker.

All columns are additive with server defaults, so existing rows keep working
without a cooldown until they actually accrue transport failures.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra313_transport_cooldown"
down_revision: Union[str, None] = "pra312_run_status"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "system_metadata",
        sa.Column(
            "transport_failures",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "system_metadata",
        sa.Column("transport_cooldown_until", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "system_metadata",
        sa.Column("last_transport_error", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "global_connection_settings",
        sa.Column(
            "transport_failure_threshold",
            sa.Integer(),
            nullable=False,
            server_default="3",
        ),
    )
    op.add_column(
        "global_connection_settings",
        sa.Column(
            "transport_cooldown_seconds",
            sa.Integer(),
            nullable=False,
            server_default="60",
        ),
    )


def downgrade() -> None:
    op.drop_column("global_connection_settings", "transport_cooldown_seconds")
    op.drop_column("global_connection_settings", "transport_failure_threshold")
    op.drop_column("system_metadata", "last_transport_error")
    op.drop_column("system_metadata", "transport_cooldown_until")
    op.drop_column("system_metadata", "transport_failures")
