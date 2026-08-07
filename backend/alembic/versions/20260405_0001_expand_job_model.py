"""expand job model for rich targeting

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-04-05

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new columns to jobs table
    op.add_column(
        "jobs",
        sa.Column("name", sa.String(200), nullable=False, server_default="Unnamed Job"),
    )
    op.add_column(
        "jobs",
        sa.Column("description", sa.Text(), nullable=True),
    )
    op.add_column(
        "jobs",
        sa.Column("is_recurring", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "jobs",
        sa.Column(
            "target_type", sa.String(50), nullable=False, server_default="system"
        ),
    )
    op.add_column(
        "jobs",
        sa.Column("target_ids", sa.Text(), nullable=True),
    )
    op.add_column(
        "jobs",
        sa.Column("package_filter", sa.Text(), nullable=True),
    )

    # Make schedule nullable (null for one-time jobs)
    op.alter_column("jobs", "schedule", existing_type=sa.String(100), nullable=True)

    # Remove system_id column and its foreign key
    op.drop_constraint("jobs_system_id_fkey", "jobs", type_="foreignkey")
    op.drop_column("jobs", "system_id")

    # Add new columns to job_history table
    op.add_column(
        "job_history",
        sa.Column("systems_targeted", sa.Integer(), nullable=True, server_default="0"),
    )
    op.add_column(
        "job_history",
        sa.Column("systems_completed", sa.Integer(), nullable=True, server_default="0"),
    )
    op.add_column(
        "job_history",
        sa.Column("systems_failed", sa.Integer(), nullable=True, server_default="0"),
    )


def downgrade() -> None:
    # Remove new columns from job_history
    op.drop_column("job_history", "systems_failed")
    op.drop_column("job_history", "systems_completed")
    op.drop_column("job_history", "systems_targeted")

    # Re-add system_id column to jobs
    op.add_column(
        "jobs",
        sa.Column("system_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "jobs_system_id_fkey", "jobs", "systems", ["system_id"], ["id"]
    )

    # Make schedule non-nullable again
    op.alter_column("jobs", "schedule", existing_type=sa.String(100), nullable=False)

    # Remove new columns from jobs
    op.drop_column("jobs", "package_filter")
    op.drop_column("jobs", "target_ids")
    op.drop_column("jobs", "target_type")
    op.drop_column("jobs", "is_recurring")
    op.drop_column("jobs", "description")
    op.drop_column("jobs", "name")
