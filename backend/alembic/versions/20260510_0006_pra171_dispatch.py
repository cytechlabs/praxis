"""PRA-171 slice 2: patch_update_execution_host_packages.

Per-package execution result row created when a host is dispatched.
One row per package the dispatcher attempted on a host. Captures the
intent (requested version snapshot, package family snapshot from the
preflight rollup) and the outcome (succeeded / failed / skipped /
unknown) plus the bytes the dispatcher saw (truncated stdout/stderr,
exit code summary, structured failure code, timing).

Slice 2 stays trigger-based: one ``POST /dispatch-next`` call writes
one bounded batch of these rows. There is no continuous worker, no
reboot, no rollback, no version re-pin, no mirror mutation, no airgap
behavior. Per-package versions captured here are derived from the
PRA-164 preflight snapshot (``installed_version_at_preflight``) plus
the dispatcher's own observation of the post-execution package state
where the package-family command supports it; otherwise
``installed_version_after`` stays NULL and the JSONB ``details``
column carries any structured per-package metadata the dispatcher
recorded.

Tables:

* ``patch_update_execution_host_packages`` — one row per package per
  execution-host dispatch attempt. References
  ``patch_update_execution_hosts.id`` ``ON DELETE CASCADE`` so the
  per-package rows go away when their parent execution-host is
  archived. The package row is keyed by package_name (no FK to
  ``patch_update_plan_selected_packages`` because the source row may
  be deleted between dispatch time and a much later audit query —
  the snapshot columns preserve the audit-grade intent).

Vocabularies (CHECK-constrained at the DB level; ORM mirrors):

* ``outcome`` ∈ ``{succeeded, failed, skipped, unknown}``. ``unknown``
  covers the case where the package-family command finished but the
  per-package outcome cannot be derived from the result (e.g. the
  command bundles many packages and the family doesn't surface
  per-package success). Slice 2 fills this in for the simple
  apt/dnf success-or-failure-bundle path; later slices may parse
  per-package output.
* ``package_manager_family_snapshot`` ∈ ``{apt, dnf, unknown}`` —
  matches the existing PRA-164 preflight vocabulary. ``unknown``
  here mirrors the host-level unsupported-family skip path (the
  host is failed with structured reason; per-package rows are
  written with this snapshot for audit completeness).

Indexes:

* UNIQUE ``(execution_host_id, package_name)`` so a single
  dispatch attempt cannot write two rows for the same package on
  the same host. A re-dispatch (deferred to a later slice) will
  need to either upsert or write to a new execution-host row.
* INDEX ``(execution_host_id, outcome)`` for the per-host outcome
  rollup the progress endpoint computes.
* INDEX ``(execution_host_id, package_name)`` for the per-package
  drill-down read.

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra171_dispatch"
down_revision: Union[str, None] = "pra171_executions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


PACKAGE_OUTCOMES = ("succeeded", "failed", "skipped", "unknown")
PACKAGE_FAMILIES = ("apt", "dnf", "unknown")


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.create_table(
        "patch_update_execution_host_packages",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "execution_host_id",
            sa.Integer,
            sa.ForeignKey("patch_update_execution_hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("requested_version_snapshot", sa.String(255), nullable=True),
        sa.Column("installed_version_before", sa.String(255), nullable=True),
        sa.Column("installed_version_after", sa.String(255), nullable=True),
        sa.Column(
            "package_manager_family_snapshot",
            sa.String(16),
            nullable=False,
        ),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
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
        sa.UniqueConstraint(
            "execution_host_id",
            "package_name",
            name="uq_patch_update_execution_host_packages_target",
        ),
        sa.CheckConstraint(
            _check_in("outcome", PACKAGE_OUTCOMES),
            name="patch_update_execution_host_packages_outcome_vocab",
        ),
        sa.CheckConstraint(
            _check_in("package_manager_family_snapshot", PACKAGE_FAMILIES),
            name="patch_update_execution_host_packages_family_vocab",
        ),
    )
    op.create_index(
        "ix_patch_update_execution_host_packages_host_outcome",
        "patch_update_execution_host_packages",
        ["execution_host_id", "outcome"],
    )
    op.create_index(
        "ix_patch_update_execution_host_packages_host_package",
        "patch_update_execution_host_packages",
        ["execution_host_id", "package_name"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_execution_host_packages_host_package",
        table_name="patch_update_execution_host_packages",
    )
    op.drop_index(
        "ix_patch_update_execution_host_packages_host_outcome",
        table_name="patch_update_execution_host_packages",
    )
    op.drop_table("patch_update_execution_host_packages")
