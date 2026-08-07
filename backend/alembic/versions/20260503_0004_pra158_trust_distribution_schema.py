"""PRA-158 #3a: trust-distribution schema (public-key column + host trust table).

Two schema additions in one revision:

1. ``mirror_signing_keys.armored_public_key`` — armored public key
   cached on the row so trust-bundle reads don't pull private key
   material into the request path on every fetch. Nullable so existing rows backfill
   lazily on first read.

2. ``host_mirror_trust`` — per (host, mirror) record of which signing-
   key fingerprints are currently installed on the host. JSONB list
   per project_pra158_design_locks.md "host_mirror_trust" lock.
   Slice #3c's install primitive writes; slice #5's cutover gate reads.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "pra158_trust_dist_schema"
down_revision: Union[str, None] = "pra158_sync_signing_cols"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "mirror_signing_keys",
        sa.Column("armored_public_key", sa.Text, nullable=True),
    )

    op.create_table(
        "host_mirror_trust",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "host_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "mirror_id",
            sa.Integer,
            sa.ForeignKey("mirror_repos.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "installed_fingerprints",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("last_installed_at", sa.DateTime, nullable=True),
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
            "host_id",
            "mirror_id",
            name="host_mirror_trust_host_mirror_unique",
        ),
    )
    op.create_index(
        "ix_host_mirror_trust_mirror",
        "host_mirror_trust",
        ["mirror_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_host_mirror_trust_mirror", table_name="host_mirror_trust")
    op.drop_table("host_mirror_trust")
    op.drop_column("mirror_signing_keys", "armored_public_key")
