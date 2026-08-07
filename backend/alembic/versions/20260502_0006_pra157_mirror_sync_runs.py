"""PRA-157 slice #1: mirror_sync_runs table.

One row per sync attempt — every attempt, success or failure. The UI
calls all rows "sync history" and surfaces only ``status='ok'`` rows
as "snapshots / manifests." Single-table over a two-table split
(runs + snapshots with FK) was chosen during effort scoping: the
nullable manifest columns are easier to reason about than a second
table whose only job is to filter ok rows.

Service-level invariant (enforced by tests, not DB constraint for
v1):

  * status='ok'      → manifest_sha256, manifest_path, byte_count,
                       package_count, finished_at all non-null
  * status='running' → manifest fields and finished_at all null
  * status='failed'  → manifest fields null; finished_at may be set

A partial DB constraint can be added later if it pulls weight; the
service test is enough for slice #1.

``estimate_unavailable`` is a slice-#2a column carved in now so that
slice #2a doesn't need to migrate again — it captures whether the
pre-sync estimate gate had a number to work with.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra157_mirror_sync_runs"
down_revision: Union[str, None] = "pra157_mirror_repos"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mirror_sync_runs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "mirror_repo_id",
            sa.Integer,
            sa.ForeignKey("mirror_repos.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("finished_at", sa.DateTime, nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("byte_count", sa.BigInteger, nullable=True),
        sa.Column("package_count", sa.Integer, nullable=True),
        sa.Column("manifest_sha256", sa.String(64), nullable=True),
        sa.Column("manifest_path", sa.String(512), nullable=True),
        sa.Column("error_text", sa.Text, nullable=True),
        sa.Column(
            "estimate_unavailable",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("FALSE"),
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
        sa.CheckConstraint(
            "status IN ('running', 'ok', 'failed')",
            name="mirror_sync_runs_status_valid",
        ),
        sa.Index(
            "ix_mirror_sync_runs_repo_started",
            "mirror_repo_id",
            "started_at",
        ),
    )


def downgrade() -> None:
    op.drop_table("mirror_sync_runs")
