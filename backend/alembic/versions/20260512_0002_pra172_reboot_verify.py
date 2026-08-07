"""PRA-172 slice 4: reboot verification columns on patch_update_execution_reboots.

Adds the per-row verification result columns the Slice 4 verifier
populates when a ``rebooting`` row gets a real health probe.

Columns added:

* ``verified_at`` (datetime, nullable) — naive-UTC timestamp the
  verification probe completed (success or terminal failure).
  Wire payloads serialize this through ``utc_iso`` for the
  ``...Z`` suffix.
* ``verification_details`` (JSONB, default ``'{}'``) — structured
  context the operator UI renders: observed boot_id / uptime
  evidence, probe attempts, last error, the failure reason code
  on terminal failure (``reachability_failed`` /
  ``no_reboot_evidence`` / ``probe_timeout`` /
  ``transport_error``).

All new columns are nullable / default-empty so existing Slice 1-3
rows survive the migration without backfill.

The state vocabulary check constraint added in Slice 1 already
allows ``verifying`` / ``healthy`` / ``failed``; no CHECK update
needed here.

ORM ``__table_args__`` on :class:`PatchUpdateExecutionReboot`
mirrors the column adds (PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra172_reboot_verify"
down_revision: Union[str, None] = "pra172_reboot_dispatch"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "patch_update_execution_reboots",
        sa.Column("verified_at", sa.DateTime, nullable=True),
    )
    op.add_column(
        "patch_update_execution_reboots",
        sa.Column(
            "verification_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("patch_update_execution_reboots", "verification_details")
    op.drop_column("patch_update_execution_reboots", "verified_at")
