"""PRA-164 slice 3: preflight snapshots + mirror_sync_run_packages index.

Adds the strict version-level content-availability substrate. Three
storage changes in one migration:

* ``mirror_sync_run_packages`` (new, derived index): one row per
  ``(mirror_sync_run_id, package_name, version, arch)`` from a
  successful sync's manifest. Populated at sync completion (after
  ``build_manifest`` runs) so the preflight resolver answers
  "does mirror X publish package P at version V?" by SQL query
  rather than reading the on-disk manifest JSON each time. The
  manifest file remains the source of truth; this table is a
  derived index. ``ON DELETE CASCADE`` from both
  ``mirror_sync_runs`` and ``mirror_repos`` keeps the index aligned
  with retention.

* ``patch_update_plan_preflight_snapshots`` (new): one row per
  ``(plan_host_id, package_name)`` for every Slice 2 selected
  package on a ``planned`` host. ``content_availability_state``
  CHECK enum covers all four spec states. ``installed_version_at_preflight``
  null when the package isn't installed at preflight time.
  ``package_manager_family_snapshot`` derived from existing
  ``HostFacts.package_manager`` / ``HostFacts.distro_id_facts``;
  ``unknown`` when neither maps cleanly.

* ``patch_update_plan_hosts.preflight_summary`` (added column):
  JSONB nullable rollup of preflight rows by
  ``content_availability_state`` plus ``installed_drift_count``
  (count of selected packages whose installed version at
  preflight differs from the Slice 2 snapshot).

Per the slice spec, manifest reads are allowed only inside the
sync-completion hook + a scoped backfill helper for runs missing
index rows. The preflight resolver itself queries the DB index
exclusively — no filesystem touches at preflight time.

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra164_preflight"
down_revision: Union[str, None] = "pra164_selection_preview"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


PACKAGE_MANAGER_FAMILIES = ("apt", "dnf", "unknown")
CONTENT_AVAILABILITY_STATES = (
    "available",
    "unavailable",
    "profile_missing",
    "not_applicable",
)


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    # -- mirror_sync_run_packages (derived index) ----------------------------
    op.create_table(
        "mirror_sync_run_packages",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "mirror_sync_run_id",
            sa.Integer,
            sa.ForeignKey("mirror_sync_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "mirror_repo_id",
            sa.Integer,
            sa.ForeignKey("mirror_repos.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("arch", sa.String(64), nullable=True),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.BigInteger, nullable=False),
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
            "mirror_sync_run_id",
            "package_name",
            "version",
            "arch",
            name="uq_mirror_sync_run_packages_target",
        ),
    )
    # Strict-availability lookup: per-mirror "is (name, version) published
    # in any indexed sync run for this mirror?" Indexed both ways so the
    # preflight resolver can pick the per-mirror plan.
    op.create_index(
        "ix_mirror_sync_run_packages_repo_name_version",
        "mirror_sync_run_packages",
        ["mirror_repo_id", "package_name", "version"],
    )
    op.create_index(
        "ix_mirror_sync_run_packages_run",
        "mirror_sync_run_packages",
        ["mirror_sync_run_id"],
    )
    # Slice 3a fix: the full UNIQUE includes ``arch``,
    # but PostgreSQL treats NULL as distinct in plain UNIQUE — so
    # two ``(run_id, name, version, NULL)`` rows would slip through.
    # Real manifests always carry arch, but a malformed or
    # future-format manifest entry could still produce duplicates.
    # The partial unique closes that gap by making the null-arch
    # case strictly one row per (run, name, version).
    op.create_index(
        "uq_mirror_sync_run_packages_no_arch",
        "mirror_sync_run_packages",
        ["mirror_sync_run_id", "package_name", "version"],
        unique=True,
        postgresql_where=sa.text("arch IS NULL"),
    )

    # -- patch_update_plan_hosts.preflight_summary --------------------------
    op.add_column(
        "patch_update_plan_hosts",
        sa.Column("preflight_summary", postgresql.JSONB, nullable=True),
    )

    # -- patch_update_plan_preflight_snapshots ------------------------------
    op.create_table(
        "patch_update_plan_preflight_snapshots",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "plan_host_id",
            sa.Integer,
            sa.ForeignKey("patch_update_plan_hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("installed_version_at_preflight", sa.String(255), nullable=True),
        sa.Column("package_manager_family_snapshot", sa.String(16), nullable=False),
        sa.Column("content_availability_state", sa.String(32), nullable=False),
        sa.Column(
            "availability_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("evaluated_at", sa.DateTime, nullable=False),
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
            "plan_host_id",
            "package_name",
            name="uq_patch_update_plan_preflight_snapshots_target",
        ),
        sa.CheckConstraint(
            _check_in("package_manager_family_snapshot", PACKAGE_MANAGER_FAMILIES),
            name="patch_update_plan_preflight_snapshots_family_vocab",
        ),
        sa.CheckConstraint(
            _check_in("content_availability_state", CONTENT_AVAILABILITY_STATES),
            name="patch_update_plan_preflight_snapshots_state_vocab",
        ),
    )
    op.create_index(
        "ix_patch_update_plan_preflight_snapshots_plan_host",
        "patch_update_plan_preflight_snapshots",
        ["plan_host_id"],
    )
    op.create_index(
        "ix_patch_update_plan_preflight_snapshots_plan_host_state",
        "patch_update_plan_preflight_snapshots",
        ["plan_host_id", "content_availability_state"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_plan_preflight_snapshots_plan_host_state",
        table_name="patch_update_plan_preflight_snapshots",
    )
    op.drop_index(
        "ix_patch_update_plan_preflight_snapshots_plan_host",
        table_name="patch_update_plan_preflight_snapshots",
    )
    op.drop_table("patch_update_plan_preflight_snapshots")
    op.drop_column("patch_update_plan_hosts", "preflight_summary")
    op.drop_index(
        "uq_mirror_sync_run_packages_no_arch",
        table_name="mirror_sync_run_packages",
    )
    op.drop_index(
        "ix_mirror_sync_run_packages_run",
        table_name="mirror_sync_run_packages",
    )
    op.drop_index(
        "ix_mirror_sync_run_packages_repo_name_version",
        table_name="mirror_sync_run_packages",
    )
    op.drop_table("mirror_sync_run_packages")
