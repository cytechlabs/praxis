"""PRA-40: Add OIDC provider table and oidc_issuer to user

Revision ID: m5f6g7h8i9j0
Revises: m5a1b2c3d4e5
Create Date: 2026-04-12

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "m5f6g7h8i9j0"
down_revision: Union[str, None] = "m5a1b2c3d4e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add oidc_issuer to user table
    op.add_column("user", sa.Column("oidc_issuer", sa.String(), nullable=True))

    # Remove unique constraint on oidc_sub (multi-IdP: sub+issuer is the unique pair)
    op.drop_index("ix_user_oidc_sub", table_name="user", if_exists=True)

    # Create OIDC provider table
    op.create_table(
        "oidc_provider",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("discovery_url", sa.String(1024), nullable=False),
        sa.Column("client_id", sa.String(255), nullable=False),
        sa.Column("client_secret", sa.String(512), nullable=False),
        sa.Column("role_claim", sa.String(255), nullable=False, server_default="roles"),
        sa.Column("role_mapping", sa.Text(), nullable=True),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_oidc_provider_id"), "oidc_provider", ["id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_oidc_provider_id"), table_name="oidc_provider")
    op.drop_table("oidc_provider")
    op.drop_column("user", "oidc_issuer")
