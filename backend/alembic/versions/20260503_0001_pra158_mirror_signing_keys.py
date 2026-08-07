"""PRA-158 slice #1: mirror_signing_keys table.

Per-mirror GPG signing keys (private material lives in Vault; this
table stores fingerprint + uid + status + Vault path only).

Locks (project_pra158_design_locks.md):
  * Per-mirror, not Praxis-wide — matches per-source ``signed-by=`` /
    ``gpgkey=`` install model and limits blast radius on key compromise.
  * Status machine: ``active | pending_cutover | rotating_out | retired``.
    Invariants enforced at the service layer (one ``active`` per mirror;
    one ``pending_cutover`` per mirror); slice #5 wires rotation.
  * No key-level expiry on the GPG material itself — status column
    governs lifecycle.
  * No private key bytes in DB; ``vault_path`` points to the KV entry
    holding armored private + public.

Slice #1 ships the model + lazy generation primitive; slices #2..#5
add signing-engine wiring, distribution endpoints, upstream verification,
and rotation/UI.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra158_mirror_signing_keys"
down_revision: Union[str, None] = "pra157_mirror_alerts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mirror_signing_keys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "mirror_repo_id",
            sa.Integer,
            sa.ForeignKey("mirror_repos.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("gpg_fingerprint", sa.String(64), nullable=False),
        sa.Column("key_uid", sa.String(255), nullable=False),
        sa.Column("vault_path", sa.String(255), nullable=False),
        sa.Column("cutover_at", sa.DateTime, nullable=True),
        sa.Column("retired_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint(
            "gpg_fingerprint",
            name="mirror_signing_keys_fingerprint_unique",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'pending_cutover', 'rotating_out', 'retired')",
            name="mirror_signing_keys_status_valid",
        ),
    )
    op.create_index(
        "ix_mirror_signing_keys_repo_status",
        "mirror_signing_keys",
        ["mirror_repo_id", "status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_mirror_signing_keys_repo_status",
        table_name="mirror_signing_keys",
    )
    op.drop_table("mirror_signing_keys")
