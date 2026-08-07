"""PRA-160 slice #1: airgap_bundle_signing_keys table.

Instance-wide GPG signing key for airgap bundle descriptors. Mirrors
the PRA-158 ``mirror_signing_keys`` shape (status machine, partial
unique on the ``active`` row) but is **Praxis-instance scoped**, not
per-mirror — the bundle descriptor signature proves "this Praxis
instance built this bundle," distinct from the per-mirror signatures
that ride along inside the bundle.

Locks (PRA-160 design conversation):
  * Single active key per Praxis instance (DB-enforced via partial
    unique index on the row where status='active').
  * Status machine: ``active | rotating_out | retired``. Slice #1
    only writes ``active`` — rotation is post-PRA-160.
  * Private + public material lives in Vault at
    ``praxis/bundle-signing-key/<gpg_fingerprint>``. DB stores
    fingerprint + uid + status + Vault path only.
  * ``armored_public_key`` is cached on the row (PRA-158 #3a pattern)
    so import-side trust install never reads private material out of
    Vault.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra160_airgap_signing_keys"
down_revision: Union[str, None] = "pra159_serve_creds_drop_unique"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "airgap_bundle_signing_keys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("gpg_fingerprint", sa.String(64), nullable=False),
        sa.Column("key_uid", sa.String(255), nullable=False),
        sa.Column("vault_path", sa.String(255), nullable=False),
        sa.Column("armored_public_key", sa.Text, nullable=True),
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
            name="airgap_bundle_signing_keys_fingerprint_unique",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'rotating_out', 'retired')",
            name="airgap_bundle_signing_keys_status_valid",
        ),
    )
    op.create_index(
        "uq_airgap_bundle_signing_keys_one_active",
        "airgap_bundle_signing_keys",
        ["status"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_airgap_bundle_signing_keys_one_active",
        table_name="airgap_bundle_signing_keys",
    )
    op.drop_table("airgap_bundle_signing_keys")
