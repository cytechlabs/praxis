"""PRA-157 slice #1: mirror_repos table.

Top-level mirror definition: one row per (upstream_url, distribution)
tuple. Naming chosen to be unmistakably distinct from the existing
per-host ``RepoSource`` model — that's what's installed on a managed
host; this is what Praxis pulls into local storage.

Snapshots / sync history live in mirror_sync_runs (next migration).
Alert dedup state lives in mirror_alert_state (third migration).

Locks (see project_pra157_design_locks.md):
  * package_family is 'deb' or 'rpm' — yum/dnf share rpm metadata.
  * source_mode flips to 'imported_offline' via PRA-160's importer.
    Slice #1 carves the column so that retrofit isn't needed.
  * deleted_at is LOCAL to mirror_repos (not on Base). Soft-delete
    semantics stay within this table.
  * disk_budget_bytes is nullable: an unset budget means "global
    free-space reserve is the only cap." When set, the per-mirror
    estimate gate becomes stricter.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra157_mirror_repos"
down_revision: Union[str, None] = "pra156_lifecycle_notif_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mirror_repos",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("package_family", sa.String(8), nullable=False),
        sa.Column("upstream_url", sa.String(512), nullable=False),
        sa.Column("distribution", sa.String(64), nullable=False),
        # JSON-encoded string lists. apt mirrors carry components
        # (main, universe, ...); dnf mirrors typically have none and
        # store ``[]``. Architectures applies to both.
        sa.Column(
            "components",
            sa.Text,
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "architectures",
            sa.Text,
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("sync_schedule_cron", sa.String(128), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column(
            "source_mode",
            sa.String(20),
            nullable=False,
            server_default=sa.text("'upstream_sync'"),
        ),
        sa.Column(
            "verify_upstream_signature",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column(
            "retention_keep_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("10"),
        ),
        sa.Column(
            "retention_keep_within_days",
            sa.Integer,
            nullable=False,
            server_default=sa.text("30"),
        ),
        sa.Column("disk_budget_bytes", sa.BigInteger, nullable=True),
        sa.Column("last_sync_started_at", sa.DateTime, nullable=True),
        sa.Column("last_sync_finished_at", sa.DateTime, nullable=True),
        sa.Column(
            "last_sync_status",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'idle'"),
        ),
        sa.Column("last_sync_error", sa.Text, nullable=True),
        sa.Column(
            "current_disk_bytes",
            sa.BigInteger,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("deleted_at", sa.DateTime, nullable=True),
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
        sa.UniqueConstraint("slug", name="mirror_repos_slug_unique"),
        sa.CheckConstraint(
            "package_family IN ('deb', 'rpm')",
            name="mirror_repos_package_family_valid",
        ),
        sa.CheckConstraint(
            "source_mode IN ('upstream_sync', 'imported_offline')",
            name="mirror_repos_source_mode_valid",
        ),
        sa.CheckConstraint(
            "last_sync_status IN ('idle', 'running', 'ok', 'failed')",
            name="mirror_repos_last_sync_status_valid",
        ),
        sa.CheckConstraint(
            "retention_keep_count >= 1",
            name="mirror_repos_retention_keep_count_positive",
        ),
        sa.CheckConstraint(
            "retention_keep_within_days >= 0",
            name="mirror_repos_retention_keep_within_days_nonneg",
        ),
        sa.CheckConstraint(
            "disk_budget_bytes IS NULL OR disk_budget_bytes > 0",
            name="mirror_repos_disk_budget_positive",
        ),
        sa.CheckConstraint(
            "current_disk_bytes >= 0",
            name="mirror_repos_current_disk_bytes_nonneg",
        ),
    )


def downgrade() -> None:
    op.drop_table("mirror_repos")
