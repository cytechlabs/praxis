"""add fleet_operations and fleet_operation_results tables (PRA-115)

Revision ID: j0k1l2m3n4o5
Revises: i9j0k1l2m3n4
Create Date: 2026-04-08

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "j0k1l2m3n4o5"
down_revision: Union[str, None] = "i9j0k1l2m3n4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "fleet_operations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("operation_type", sa.String(length=100), nullable=False),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column("target_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("success_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("parameters", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=50),
            nullable=False,
            server_default="running",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_fleet_operations_operation_type",
        "fleet_operations",
        ["operation_type"],
    )
    op.create_index("ix_fleet_operations_id", "fleet_operations", ["id"])

    op.create_table(
        "fleet_operation_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "fleet_operation_id",
            sa.Integer(),
            sa.ForeignKey("fleet_operations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
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
    op.create_index(
        "ix_fleet_operation_results_fleet_operation_id",
        "fleet_operation_results",
        ["fleet_operation_id"],
    )
    op.create_index("ix_fleet_operation_results_id", "fleet_operation_results", ["id"])


def downgrade() -> None:
    op.drop_index("ix_fleet_operation_results_id", table_name="fleet_operation_results")
    op.drop_index(
        "ix_fleet_operation_results_fleet_operation_id",
        table_name="fleet_operation_results",
    )
    op.drop_table("fleet_operation_results")
    op.drop_index("ix_fleet_operations_id", table_name="fleet_operations")
    op.drop_index("ix_fleet_operations_operation_type", table_name="fleet_operations")
    op.drop_table("fleet_operations")
