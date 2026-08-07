"""PRA-160 slice #3: airgap_import_trust_keys + airgap_imports.path columns.

Two surfaces:

1. ``airgap_import_trust_keys`` — operator-pinned bundle public keys
   used to verify ``bundle.json.sig`` at import time. The importer
   trusts ONLY keys in this table (armored
   bytes inside the bundle are not trust anchors). Soft-delete via
   ``deleted_at`` for audit retention; verifier filters
   ``deleted_at IS NULL``.

2. ``airgap_imports.path`` — the on-disk tar location for a given
   import. Persisted so an operator can inspect a failed-import row
   and find the source artifact. Nullable on legacy rows but the
   slice #3 importer always sets it.

3. ``airgap_imports.target_mirror_slugs`` — JSONB list of the
   imported-prefixed mirror slugs the importer created (or attempted
   to create). Useful for "what did this bundle bring in" forensic
   queries without joining mirrors → bundle by slug-prefix
   convention.

Locks:
  * Trust-key fingerprints unique across active rows. Re-pinning
    after delete is allowed (separate row, separate added_at).
  * armored_public_key text is non-secret (public key) — stored in
    DB rather than Vault.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra160_import_trust_keys"
down_revision: Union[str, None] = "pra160_run_kind_import"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "airgap_import_trust_keys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("gpg_fingerprint", sa.String(64), nullable=False),
        sa.Column("key_uid", sa.String(255), nullable=False),
        sa.Column("armored_public_key", sa.Text, nullable=False),
        sa.Column(
            "added_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("deleted_at", sa.DateTime, nullable=True),
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
    )
    # Partial unique on active fingerprints — same key can be
    # re-pinned after soft-delete (separate row).
    op.create_index(
        "uq_airgap_import_trust_keys_active_fingerprint",
        "airgap_import_trust_keys",
        ["gpg_fingerprint"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    op.add_column(
        "airgap_imports",
        sa.Column("path", sa.String(1024), nullable=True),
    )
    op.add_column(
        "airgap_imports",
        sa.Column(
            "target_mirror_slugs",
            sa.dialects.postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("airgap_imports", "target_mirror_slugs")
    op.drop_column("airgap_imports", "path")
    op.drop_index(
        "uq_airgap_import_trust_keys_active_fingerprint",
        table_name="airgap_import_trust_keys",
    )
    op.drop_table("airgap_import_trust_keys")
