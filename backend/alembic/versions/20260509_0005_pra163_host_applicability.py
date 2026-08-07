"""PRA-163 slice 2: patch_advisory_host_applicability.

Per-(host, advisory, package_name) materialized applicability state.
Operators (and PRA-164 plan generation) read this table to know which
advisories are open against which hosts. The resolver in
``patch_advisory_service.compute_host_applicability`` writes it.

Metadata-only — the resolver reads existing DB rows
(``HostFacts.distro_id_facts`` / ``HostFacts.distro_release`` /
``Package.name`` / ``Package.installed_version``) joined against
PRA-163 Slice 1 ``patch_advisory_fixed_packages``. **No package-manager
calls, no SSH scans, no live network fetch, no plan/preflight/probe/
reboot/rollback, no mirror/airgap, no UI.**

Columns:

* ``system_id`` FK ``systems.id`` ``ON DELETE CASCADE`` — host removal
  drops its applicability rows.
* ``advisory_id`` FK ``patch_advisories.id`` ``ON DELETE CASCADE`` —
  removing an advisory removes the rows it produced.
* ``fixed_package_id`` FK ``patch_advisory_fixed_packages.id``
  ``ON DELETE SET NULL`` — historical applicability rows survive a
  refresh that drops a per-release target so the audit trail stays
  intact (Slice 1 ``replace-all`` pattern).
* ``package_name`` is denormalized so the row is queryable without
  always joining the source target. The resolver computes it from
  the Slice 1 fixed-package row that produced the applicability row.
* ``installed_version`` from ``Package.installed_version`` at
  resolve time; nullable for ``not_applicable`` rows where the
  package isn't installed.
* ``required_version`` from
  ``patch_advisory_fixed_packages.fixed_version`` at resolve time;
  nullable for advisories with no published fix.
* ``state`` ∈ ``{applicable, fixed, not_applicable, unknown}``
  CHECK-constrained.
* ``reason`` short free text used for ``unknown`` (why we couldn't
  classify) and ``not_applicable`` (why) — keeps the row
  self-explanatory for operators without a separate join.
* ``evaluated_at`` records when the resolver wrote the row (separate
  from ``updated_at`` so a no-op recompute that doesn't change the
  row also doesn't bump it; the resolver sets ``evaluated_at`` only
  when the row is actually written).

Constraints / indexes:

* UNIQUE ``(system_id, advisory_id, package_name)`` — replace-all
  per host is keyed off this tuple.
* INDEX ``(system_id, state)`` — per-host card / per-state filter.
* INDEX ``(advisory_id)`` — fleet-severity counts and
  advisory-driven recompute fanout.

ORM ``__table_args__`` mirrors every constraint and index in this
migration (PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra163_host_applicability"
down_revision: Union[str, None] = "pra163_advisories"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


APPLICABILITY_STATES = ("applicable", "fixed", "not_applicable", "unknown")


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.create_table(
        "patch_advisory_host_applicability",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "advisory_id",
            sa.Integer,
            sa.ForeignKey("patch_advisories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "fixed_package_id",
            sa.Integer,
            sa.ForeignKey("patch_advisory_fixed_packages.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("installed_version", sa.String(255), nullable=True),
        sa.Column("required_version", sa.String(255), nullable=True),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(255), nullable=True),
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
            "system_id",
            "advisory_id",
            "package_name",
            name="uq_patch_advisory_host_applicability_target",
        ),
        sa.CheckConstraint(
            _check_in("state", APPLICABILITY_STATES),
            name="patch_advisory_host_applicability_state_vocab",
        ),
    )
    op.create_index(
        "ix_patch_advisory_host_applicability_system_state",
        "patch_advisory_host_applicability",
        ["system_id", "state"],
    )
    op.create_index(
        "ix_patch_advisory_host_applicability_advisory",
        "patch_advisory_host_applicability",
        ["advisory_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_advisory_host_applicability_advisory",
        table_name="patch_advisory_host_applicability",
    )
    op.drop_index(
        "ix_patch_advisory_host_applicability_system_state",
        table_name="patch_advisory_host_applicability",
    )
    op.drop_table("patch_advisory_host_applicability")
