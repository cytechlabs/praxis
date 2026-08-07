"""PRA-158 #4a: mirror_upstream_keys table — Praxis-wide trust anchors
for verifying upstream repo metadata signatures before re-signing.

Stores armored PUBLIC keys in the DB, not Vault — these are public
material by definition (Ubuntu Archive, Debian, Rocky, etc. all
publish their signing keys openly), and putting them in Vault would
add a private-secret blast-radius layer for no security gain. Vault
remains the source of truth for the Praxis-managed signing keys
themselves (slice #1).

Slice #4b's pre-sync gate builds a transient gpg keyring from this
table and verifies upstream Release.gpg / repomd.xml.asc against it.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra158_upstream_keys"
down_revision: Union[str, None] = "pra158_trust_dist_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mirror_upstream_keys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("gpg_fingerprint", sa.String(64), nullable=False),
        sa.Column("armored_public_key", sa.Text, nullable=False),
        sa.Column("notes", sa.Text, nullable=True),
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
            name="mirror_upstream_keys_fingerprint_unique",
        ),
    )


def downgrade() -> None:
    op.drop_table("mirror_upstream_keys")
