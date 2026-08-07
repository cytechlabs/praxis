"""PRA-163 slice 1: patch_advisories + patch_advisory_fixed_packages + patch_advisory_imports.

Advisory schema and native-source advisory metadata import foundation.
This slice is metadata-only — no package-manager execution, no plan
generation, no preflight, no probes, no reboot/rollback, no mirror
rebuild/re-sign, no airgap changes.

Tables:

* ``patch_advisories`` — one row per ``(source_kind,
  source_advisory_id)``. Source identity is preserved
  (USN-1234-1, RHSA-2024:5678, CVE-... never collapsed into a single
  ambiguous string). ``digest`` is the sha256 of the canonical-JSON
  raw payload and drives refresh detection so a re-import that did
  not change anything is a true no-op (no audit, no row write).
* ``patch_advisory_fixed_packages`` — one row per
  ``(advisory, distro_id, distro_release, package_name)`` with the
  fixed-version constraint that satisfies the advisory on that
  release. CASCADE on advisory delete; replace-all on advisory
  refresh. PRA-164 will join this table by (host distro_id,
  distro_release, installed package_name) for applicability.
* ``patch_advisory_imports`` — per-run summary row recording counts
  of imported / refreshed / unchanged / errors and run status. Gives
  operators a run history without per-advisory audit explosion. The
  per-advisory ``imported`` / ``refreshed`` audit events still fire
  on real mutations.

Vocabularies are CHECK-constrained:

* ``source_kind`` ∈ ``{ubuntu_usn, debian_security, redhat_updateinfo}``.
* ``advisory_class`` ∈ ``{security, bugfix, enhancement, other}``
  (compatible with PRA-161 ``scope_kind=security_only`` semantics —
  PRA-164 will filter advisories by class when planning).
* ``severity`` ∈ ``{critical, high, medium, low, negligible, unknown}``.
* ``distro_family`` ∈ ``{debian, rhel}``.
* ``status`` (imports) ∈ ``{success, partial, failed}``.

ORM ``__table_args__`` mirrors every constraint and index in this
migration (PRA-161 slice 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra163_advisories"
down_revision: Union[str, None] = "pra162_gate_definitions_signals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


SOURCE_KINDS = ("ubuntu_usn", "debian_security", "redhat_updateinfo")
ADVISORY_CLASSES = ("security", "bugfix", "enhancement", "other")
SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")
DISTRO_FAMILIES = ("debian", "rhel")
IMPORT_STATUSES = ("success", "partial", "failed")


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.create_table(
        "patch_advisories",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("source_advisory_id", sa.String(128), nullable=False),
        sa.Column("advisory_class", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("distro_family", sa.String(32), nullable=False),
        sa.Column("published_at", sa.DateTime, nullable=True),
        sa.Column("source_updated_at", sa.DateTime, nullable=True),
        sa.Column("cve_ids", postgresql.JSONB, nullable=True),
        sa.Column("external_refs", postgresql.JSONB, nullable=True),
        sa.Column("raw", postgresql.JSONB, nullable=True),
        sa.Column("digest", sa.String(64), nullable=False),
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
            "source_kind",
            "source_advisory_id",
            name="uq_patch_advisories_source_id",
        ),
        sa.CheckConstraint(
            _check_in("source_kind", SOURCE_KINDS),
            name="patch_advisories_source_kind_vocab",
        ),
        sa.CheckConstraint(
            _check_in("advisory_class", ADVISORY_CLASSES),
            name="patch_advisories_advisory_class_vocab",
        ),
        sa.CheckConstraint(
            _check_in("severity", SEVERITIES),
            name="patch_advisories_severity_vocab",
        ),
        sa.CheckConstraint(
            _check_in("distro_family", DISTRO_FAMILIES),
            name="patch_advisories_distro_family_vocab",
        ),
    )
    op.create_index(
        "ix_patch_advisories_source_kind_severity",
        "patch_advisories",
        ["source_kind", "severity"],
    )
    op.create_index(
        "ix_patch_advisories_advisory_class",
        "patch_advisories",
        ["advisory_class"],
    )
    op.create_index(
        "ix_patch_advisories_distro_family",
        "patch_advisories",
        ["distro_family"],
    )

    op.create_table(
        "patch_advisory_fixed_packages",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "advisory_id",
            sa.Integer,
            sa.ForeignKey("patch_advisories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("distro_id", sa.String(32), nullable=False),
        sa.Column("distro_release", sa.String(64), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("fixed_version", sa.String(255), nullable=True),
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
            "advisory_id",
            "distro_id",
            "distro_release",
            "package_name",
            name="uq_patch_advisory_fixed_packages_target",
        ),
    )
    # PRA-164 applicability driver: (distro_id, distro_release,
    # package_name) is the join shape from a host's installed package
    # to the set of advisories that name it. Multi-column index keeps
    # the planner from filtering by package alone across distros.
    op.create_index(
        "ix_patch_advisory_fixed_packages_target",
        "patch_advisory_fixed_packages",
        ["distro_id", "distro_release", "package_name"],
    )
    op.create_index(
        "ix_patch_advisory_fixed_packages_advisory",
        "patch_advisory_fixed_packages",
        ["advisory_id"],
    )

    op.create_table(
        "patch_advisory_imports",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime, nullable=False),
        sa.Column("finished_at", sa.DateTime, nullable=True),
        sa.Column(
            "imported_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "refreshed_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "unchanged_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "error_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("error_details", postgresql.JSONB, nullable=True),
        sa.Column(
            "created_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
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
        sa.CheckConstraint(
            _check_in("source_kind", SOURCE_KINDS),
            name="patch_advisory_imports_source_kind_vocab",
        ),
        sa.CheckConstraint(
            _check_in("status", IMPORT_STATUSES),
            name="patch_advisory_imports_status_vocab",
        ),
    )
    # Operator timeline driver: most-recent-run per source.
    op.create_index(
        "ix_patch_advisory_imports_source_started",
        "patch_advisory_imports",
        ["source_kind", sa.text("started_at DESC")],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_advisory_imports_source_started",
        table_name="patch_advisory_imports",
    )
    op.drop_table("patch_advisory_imports")
    op.drop_index(
        "ix_patch_advisory_fixed_packages_advisory",
        table_name="patch_advisory_fixed_packages",
    )
    op.drop_index(
        "ix_patch_advisory_fixed_packages_target",
        table_name="patch_advisory_fixed_packages",
    )
    op.drop_table("patch_advisory_fixed_packages")
    op.drop_index(
        "ix_patch_advisories_distro_family",
        table_name="patch_advisories",
    )
    op.drop_index(
        "ix_patch_advisories_advisory_class",
        table_name="patch_advisories",
    )
    op.drop_index(
        "ix_patch_advisories_source_kind_severity",
        table_name="patch_advisories",
    )
    op.drop_table("patch_advisories")
