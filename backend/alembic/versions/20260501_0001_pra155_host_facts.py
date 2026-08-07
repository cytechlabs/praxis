"""PRA-155 slice #2a: host_facts table.

Canonical fleet inventory facts. One current row per system; history is
explicitly deferred. Schema is transport-neutral — agent, SSH, and
manual import all funnel through ``FactsService.ingest`` and write the
same shape. Slice #2a wires only the agent-side and enroll paths;
``source_transport='ssh'`` and ``'manual'`` are reserved values, written
by later slices.

Cascade decision:
    ``system_id`` is ``ON DELETE CASCADE``. Facts are derivative inventory
    of a host; if the host row is removed, its facts have no meaning.
    No other row references ``host_facts`` so cascade is the right
    blast radius — RESTRICT here would force operators to manually
    drop facts before retiring a system, which is paperwork without
    a real safety benefit.

Disks / cloud_instance_metadata / partial_errors are JSONB v1. The
locked disk shape is ``{mountpoint, filesystem, total_bytes, free_bytes}``
but it is stored unstructured to defer the side-table decision until
mount-level filtering is actually needed.

``schema_version`` starts at 1. Bump only on incompatible/semantic
payload contract change, not on additive nullable columns.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra155_host_facts"
down_revision: Union[str, None] = "pra154_target_system"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "host_facts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("schema_version", sa.Integer, nullable=False),
        sa.Column("collected_at", sa.DateTime, nullable=False),
        sa.Column("source_transport", sa.String(16), nullable=False),
        # Normalized scalar fact columns — nullable so a partial collect
        # records what it has and leaves the rest NULL.
        sa.Column("cpu_model", sa.String(255), nullable=True),
        sa.Column("cpu_cores", sa.Integer, nullable=True),
        sa.Column("ram_total_bytes", sa.BigInteger, nullable=True),
        sa.Column("kernel_version", sa.String(255), nullable=True),
        sa.Column("distro_id_facts", sa.String(64), nullable=True),
        sa.Column("distro_release", sa.String(64), nullable=True),
        sa.Column("uptime_seconds", sa.BigInteger, nullable=True),
        sa.Column("reboot_required", sa.Boolean, nullable=True),
        sa.Column("package_manager", sa.String(32), nullable=True),
        sa.Column("package_manager_version", sa.String(64), nullable=True),
        sa.Column("virtualization", sa.String(32), nullable=True),
        sa.Column("cloud_provider", sa.String(32), nullable=True),
        # Sanitized cloud metadata only (provider/instance_id/region/zone).
        # Sanitizer in FactsService is the gate; never write raw payloads.
        sa.Column(
            "cloud_instance_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "disks",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        # Partial-collect failures: list of {key, error} entries. Empty
        # array means the collector reported no per-field failures; NULL
        # means we have no opinion (e.g. legacy import).
        sa.Column(
            "partial_errors",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
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
            "source_transport IN ('agent', 'ssh', 'manual')",
            name="host_facts_source_transport_valid",
        ),
        sa.CheckConstraint(
            "schema_version >= 1",
            name="host_facts_schema_version_positive",
        ),
        sa.CheckConstraint(
            "cpu_cores IS NULL OR cpu_cores >= 0",
            name="host_facts_cpu_cores_nonneg",
        ),
        sa.CheckConstraint(
            "ram_total_bytes IS NULL OR ram_total_bytes >= 0",
            name="host_facts_ram_nonneg",
        ),
        sa.CheckConstraint(
            "uptime_seconds IS NULL OR uptime_seconds >= 0",
            name="host_facts_uptime_nonneg",
        ),
    )
    # Filtering by these is the smart-group / fleet-search hot path
    # (#2d). Cheap to land now; saves a follow-up migration.
    op.create_index("ix_host_facts_kernel_version", "host_facts", ["kernel_version"])
    op.create_index("ix_host_facts_distro_id_facts", "host_facts", ["distro_id_facts"])
    op.create_index("ix_host_facts_reboot_required", "host_facts", ["reboot_required"])
    op.create_index(
        "ix_host_facts_source_transport", "host_facts", ["source_transport"]
    )


def downgrade() -> None:
    op.drop_index("ix_host_facts_source_transport", table_name="host_facts")
    op.drop_index("ix_host_facts_reboot_required", table_name="host_facts")
    op.drop_index("ix_host_facts_distro_id_facts", table_name="host_facts")
    op.drop_index("ix_host_facts_kernel_version", table_name="host_facts")
    op.drop_table("host_facts")
