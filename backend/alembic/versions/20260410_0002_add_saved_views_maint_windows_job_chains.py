"""add saved_views, maintenance_windows tables and job chain columns (PRA-114, PRA-79, PRA-81)

Revision ID: s1t2u3v4w5x6
Revises: m2n3o4p5q6r7
Create Date: 2026-04-10

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "s1t2u3v4w5x6"
down_revision: Union[str, None] = "m2n3o4p5q6r7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PRA-114: Saved views
    op.create_table(
        "saved_views",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("filters", sa.Text(), nullable=False),
        sa.Column(
            "is_default",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "is_shared",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_saved_views_id", "saved_views", ["id"])
    op.create_index("ix_saved_views_user_id", "saved_views", ["user_id"])

    # PRA-79: Maintenance windows
    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=True),
        sa.Column("schedule", sa.Text(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_maintenance_windows_id", "maintenance_windows", ["id"])

    # PRA-81: Job chaining columns on jobs table
    op.add_column(
        "jobs",
        sa.Column(
            "depends_on_job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "jobs",
        sa.Column(
            "chain_condition",
            sa.String(50),
            nullable=False,
            server_default="on_success",
        ),
    )


def downgrade() -> None:
    op.drop_column("jobs", "chain_condition")
    op.drop_column("jobs", "depends_on_job_id")
    op.drop_index("ix_maintenance_windows_id", table_name="maintenance_windows")
    op.drop_table("maintenance_windows")
    op.drop_index("ix_saved_views_user_id", table_name="saved_views")
    op.drop_index("ix_saved_views_id", table_name="saved_views")
    op.drop_table("saved_views")
