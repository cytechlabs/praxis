"""PRA-158 #2a: signing-related columns on mirror_sync_runs.

Adds three columns to ``mirror_sync_runs``:
  * ``run_kind`` — ``sync | sign_only`` (default ``sync``). slice #2c's
    ``POST /mirrors/{id}/sign-current`` writes ``sign_only`` rows for
    pre-PRA-158 trees and ``imported_offline`` mirrors that refuse
    on-demand sync. Kept as an explicit column rather than a status
    sub-flag so PRA-157's ``status IN (running, ok, failed)``
    semantics stay clean.
  * ``manifest_signature_path`` — absolute path of the detached
    ``<run_id>.manifest.json.sig`` sidecar in ``snapshots/``. NULL on
    pre-PRA-158 rows and on the slice #2a column-only landing (the
    signing engine wires the value in #2c).
  * ``signed_with_key_id`` — FK to ``mirror_signing_keys.id``. NULL
    on pre-PRA-158 rows. ON DELETE SET NULL so retiring a key row
    doesn't break the sync history.

All three default to NULL/'sync' so existing rows remain valid and
slice #2a can land before the orchestrator refactor in #2c.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra158_sync_signing_cols"
down_revision: Union[str, None] = "pra158_signing_uniques"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "mirror_sync_runs",
        sa.Column(
            "run_kind",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'sync'"),
        ),
    )
    op.add_column(
        "mirror_sync_runs",
        sa.Column("manifest_signature_path", sa.String(512), nullable=True),
    )
    op.add_column(
        "mirror_sync_runs",
        sa.Column(
            "signed_with_key_id",
            sa.Integer,
            sa.ForeignKey("mirror_signing_keys.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_check_constraint(
        "mirror_sync_runs_run_kind_valid",
        "mirror_sync_runs",
        "run_kind IN ('sync', 'sign_only')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "mirror_sync_runs_run_kind_valid",
        "mirror_sync_runs",
        type_="check",
    )
    op.drop_column("mirror_sync_runs", "signed_with_key_id")
    op.drop_column("mirror_sync_runs", "manifest_signature_path")
    op.drop_column("mirror_sync_runs", "run_kind")
