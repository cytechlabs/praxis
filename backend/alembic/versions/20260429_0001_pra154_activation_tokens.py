"""PRA-154 slice #1a: activation tokens + redemption ledger.

Adds two tables for the M14 one-line agent enrollment flow:

    activation_tokens               — issued enrollment secrets
    activation_token_redemptions    — durable idempotency ledger

Slice #1a is schema + service only. No HTTP endpoints, no host create
path, no bootstrap script. The redemption ledger lets future slices
make `(token, host_fingerprint) -> system_id` stable across reruns.

Tokens are stored as bcrypt hashes; raw secrets never touch the DB
and are returned to the operator exactly once at create time. The
``token_prefix`` column holds the first 8 chars of the base32 body
for UI/debug display.

Host create vs link is intentionally left to a later slice. #1a is
schema-shaped to support both; the service layer in this slice
records redemptions but does not yet wire host creation.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra154_activation_tokens"
down_revision: Union[str, None] = "pra153_transport"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "activation_tokens",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False),
        sa.Column("token_prefix", sa.String(16), nullable=False),
        sa.Column(
            "default_group_id",
            sa.Integer,
            sa.ForeignKey("groups.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "default_tag_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("ttl_expires_at", sa.DateTime, nullable=False),
        sa.Column("max_uses", sa.Integer, nullable=False),
        sa.Column(
            "uses_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
        sa.Column(
            "revoked_by_user_id",
            sa.Integer,
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_by_user_id",
            sa.Integer,
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
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
        sa.CheckConstraint("max_uses >= 1", name="activation_tokens_max_uses_positive"),
        sa.CheckConstraint(
            "uses_count >= 0 AND uses_count <= max_uses",
            name="activation_tokens_uses_within_bounds",
        ),
    )
    # token_prefix lookup is the verify hot path; many rows share a
    # prefix only on a real collision, but indexing keeps verify O(1).
    op.create_index(
        "ix_activation_tokens_token_prefix",
        "activation_tokens",
        ["token_prefix"],
    )
    op.create_index(
        "ix_activation_tokens_default_group_id",
        "activation_tokens",
        ["default_group_id"],
    )

    op.create_table(
        "activation_token_redemptions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "activation_token_id",
            sa.Integer,
            sa.ForeignKey("activation_tokens.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # sha256 hex of the host-supplied fingerprint, never the raw
        # fingerprint. Fixed length so the unique index is cheap.
        sa.Column("host_fingerprint_hash", sa.String(64), nullable=False),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("first_redeemed_at", sa.DateTime, nullable=False),
        sa.Column("last_redeemed_at", sa.DateTime, nullable=False),
        sa.Column(
            "redeem_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("last_seen_hostname", sa.String(255), nullable=True),
        sa.Column("last_seen_ip", postgresql.INET(), nullable=True),
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
            "activation_token_id",
            "host_fingerprint_hash",
            name="uq_activation_redemptions_token_fingerprint",
        ),
        sa.UniqueConstraint(
            "activation_token_id",
            "system_id",
            name="uq_activation_redemptions_token_system",
        ),
    )
    op.create_index(
        "ix_activation_redemptions_system_id",
        "activation_token_redemptions",
        ["system_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_activation_redemptions_system_id",
        table_name="activation_token_redemptions",
    )
    op.drop_table("activation_token_redemptions")
    op.drop_index(
        "ix_activation_tokens_default_group_id",
        table_name="activation_tokens",
    )
    op.drop_index(
        "ix_activation_tokens_token_prefix",
        table_name="activation_tokens",
    )
    op.drop_table("activation_tokens")
