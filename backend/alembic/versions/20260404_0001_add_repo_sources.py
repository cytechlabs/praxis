"""add repo_sources table

Revision ID: a1b2c3d4e5f6
Revises: 240b0ad2f12f
Create Date: 2026-04-04

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "240b0ad2f12f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "repo_sources",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("system_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("repo_type", sa.String(length=50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("file_path", sa.String(length=500), nullable=True),
        sa.Column("gpg_key_url", sa.Text(), nullable=True),
        sa.Column("components", sa.String(length=500), nullable=True),
        sa.Column("distribution", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["system_id"], ["systems.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_repo_sources_id"), "repo_sources", ["id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_repo_sources_id"), table_name="repo_sources")
    op.drop_table("repo_sources")
