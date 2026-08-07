"""PRA-127: baselines + baseline_checks for drift detection

Revision ID: pra127_drift
Revises: pra126_smartgroups
Create Date: 2026-04-20
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra127_drift"
down_revision: Union[str, None] = "pra126_smartgroups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "baselines",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "scope_smart_group_id",
            sa.Integer(),
            sa.ForeignKey("smart_groups.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("rules_json", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "schedule_interval_hours",
            sa.Integer(),
            nullable=False,
            server_default="24",
        ),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("user.id"), nullable=True),
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
        "ix_baselines_scope_smart_group_id",
        "baselines",
        ["scope_smart_group_id"],
    )

    op.create_table(
        "baseline_checks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "baseline_id",
            sa.Integer(),
            sa.ForeignKey("baselines.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "run_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("drift_details_json", sa.Text(), nullable=True),
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
        "ix_baseline_checks_baseline_id", "baseline_checks", ["baseline_id"]
    )
    op.create_index("ix_baseline_checks_system_id", "baseline_checks", ["system_id"])
    op.create_index("ix_baseline_checks_run_at", "baseline_checks", ["run_at"])


def downgrade() -> None:
    op.drop_index("ix_baseline_checks_run_at", table_name="baseline_checks")
    op.drop_index("ix_baseline_checks_system_id", table_name="baseline_checks")
    op.drop_index("ix_baseline_checks_baseline_id", table_name="baseline_checks")
    op.drop_table("baseline_checks")
    op.drop_index("ix_baselines_scope_smart_group_id", table_name="baselines")
    op.drop_table("baselines")
