"""PRA-161 slice 1d: ``patch_policies.is_fleet_default`` + partial unique.

Adds the terminal-fallback marker for the effective-policy resolver.
``is_fleet_default`` is a boolean column with default ``false``; the
partial unique index ensures **at most one row** can have
``is_fleet_default = true`` at any time. ``enabled = false`` is
allowed alongside ``is_fleet_default = true`` (a configured-but-
inactive fleet default), but the resolver skips disabled policies
at every tier including this one.

The single-active-fleet-default invariant is enforced at:

1. The DB layer via the partial unique index (defense in depth).
2. The service layer in :func:`patch_policy_service.set_fleet_default`,
   which atomically clears any prior fleet default before flipping
   the new one. The DB index is the safety net for races that
   bypass the service.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra161_fleet_default"
down_revision: Union[str, None] = "pra161_policy_bindings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "patch_policies",
        sa.Column(
            "is_fleet_default",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.create_index(
        "uq_patch_policies_single_fleet_default",
        "patch_policies",
        ["is_fleet_default"],
        unique=True,
        postgresql_where=sa.text("is_fleet_default = true"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_patch_policies_single_fleet_default",
        table_name="patch_policies",
    )
    op.drop_column("patch_policies", "is_fleet_default")
