"""PRA-164 slice 2: patch_update_plan_selected_packages + selection_summary.

Per-host package/advisory selection preview rows for an update plan,
plus a per-host count rollup column. Reads existing DB facts only —
``Package``, ``PackageUpdate``, ``PatchAdvisoryHostApplicability`` —
and writes preview rows under the existing Slice 1 plan envelope.
NO execution semantics: no package-manager calls, no SSH, no agent
invocation, no live facts collection, no preflight refresh, no
approval / probe / reboot / rollback / mirror / airgap.

Tables / columns:

* ``patch_update_plan_selected_packages`` (new)
  - ``plan_host_id`` FK ``patch_update_plan_hosts.id`` ``CASCADE`` so
    deleting a plan cleans its preview rows automatically.
  - ``package_name`` (denormalized; queryable without joining
    ``Package`` / ``PackageUpdate``). Empty string is the sentinel
    for the per-host ``inventory_missing`` placeholder row described
    by the slice spec.
  - ``installed_version_snapshot`` / ``available_version_snapshot``
    nullable (e.g. allowlist drift, advisory without published
    fix, inventory missing).
  - ``advisory_id_snapshot`` FK ``patch_advisories.id``
    ``ON DELETE SET NULL`` so historical preview rows survive an
    advisory refresh that drops the source row.
  - ``advisory_source_kind_snapshot`` / ``advisory_class_snapshot``
    / ``advisory_severity_snapshot`` nullable; populated together
    when ``advisory_id_snapshot`` is set so the operator UI can
    render severity without a join.
  - ``selection_reason`` CHECK enum:
      ``policy_full``                  scope=full default-select
      ``policy_security_advisory``     scope=security_only,
                                       advisory-driven row
      ``policy_allowlist_match``       scope=package_allowlist hit
      ``policy_denylist_excluded``     scope=package_denylist hit
      ``policy_denylist_default_select``
                                       scope=package_denylist,
                                       package not denylisted
                                       (added beyond the spec's
                                       initial 6 values per the
                                       slice packet's "policy_full
                                       or an equivalent clearly
                                       documented non-denylisted
                                       reason that passes
                                       schema/DB checks" clause —
                                       a distinct value keeps the
                                       reason column self-explanatory
                                       without parsing ``details``)
      ``no_available_update``          allowlist entry / advisory
                                       without ``PackageUpdate``
                                       candidate
      ``inventory_missing``            host has no Package /
                                       PackageUpdate rows yet
  - ``state`` CHECK enum: ``selected`` / ``excluded`` /
    ``unresolvable``.
  - ``details`` JSONB for per-row structured context the UI / audit
    surface needs (advisory tuple, denylist match value, etc.).
  - UNIQUE ``(plan_host_id, package_name, advisory_id_snapshot)`` —
    handles the security_only case where multiple advisories may
    target the same package on the same host.
  - Partial UNIQUE on ``(plan_host_id, package_name) WHERE
    advisory_id_snapshot IS NULL`` — handles the non-advisory case
    where PostgreSQL treats NULL ≠ NULL in plain UNIQUE and would
    otherwise allow duplicate ``(plan_host_id, package_name, NULL)``
    rows. The empty-string ``package_name`` sentinel for
    ``inventory_missing`` uses this same partial unique so a host
    can carry at most one placeholder row.
  - Indexes on ``plan_host_id``, ``state``, and
    ``(plan_host_id, state)`` for the per-host card / fleet
    selected-state filters in slice 4.

* ``patch_update_plan_hosts.selection_summary`` JSONB nullable —
  per-host count rollup of selected-package rows by ``state``
  (``{"selected": N, "excluded": N, "unresolvable": N,
  "inventory_missing": bool}``). Nullable so existing Slice 1
  rows stay readable until selection runs against them; refresh
  populates it for every ``planned`` host.

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra164_selection_preview"
down_revision: Union[str, None] = "pra164_update_plans"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


SELECTION_REASONS = (
    "policy_full",
    "policy_security_advisory",
    "policy_allowlist_match",
    "policy_denylist_excluded",
    "policy_denylist_default_select",
    "no_available_update",
    "inventory_missing",
)

SELECTION_STATES = ("selected", "excluded", "unresolvable")


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.add_column(
        "patch_update_plan_hosts",
        sa.Column(
            "selection_summary",
            postgresql.JSONB,
            nullable=True,
        ),
    )

    op.create_table(
        "patch_update_plan_selected_packages",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "plan_host_id",
            sa.Integer,
            sa.ForeignKey("patch_update_plan_hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("installed_version_snapshot", sa.String(255), nullable=True),
        sa.Column("available_version_snapshot", sa.String(255), nullable=True),
        sa.Column(
            "advisory_id_snapshot",
            sa.Integer,
            sa.ForeignKey("patch_advisories.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("advisory_source_kind_snapshot", sa.String(32), nullable=True),
        sa.Column("advisory_class_snapshot", sa.String(32), nullable=True),
        sa.Column("advisory_severity_snapshot", sa.String(32), nullable=True),
        sa.Column("selection_reason", sa.String(48), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
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
            "plan_host_id",
            "package_name",
            "advisory_id_snapshot",
            name="uq_patch_update_plan_selected_packages_target",
        ),
        sa.CheckConstraint(
            _check_in("selection_reason", SELECTION_REASONS),
            name="patch_update_plan_selected_packages_reason_vocab",
        ),
        sa.CheckConstraint(
            _check_in("state", SELECTION_STATES),
            name="patch_update_plan_selected_packages_state_vocab",
        ),
    )
    # Partial unique closes the PostgreSQL NULL-distinct gap so that
    # non-advisory rows (full / allowlist / denylist /
    # inventory_missing) cannot duplicate by (plan_host_id, package_name).
    op.create_index(
        "uq_patch_update_plan_selected_packages_no_advisory",
        "patch_update_plan_selected_packages",
        ["plan_host_id", "package_name"],
        unique=True,
        postgresql_where=sa.text("advisory_id_snapshot IS NULL"),
    )
    op.create_index(
        "ix_patch_update_plan_selected_packages_plan_host",
        "patch_update_plan_selected_packages",
        ["plan_host_id"],
    )
    op.create_index(
        "ix_patch_update_plan_selected_packages_state",
        "patch_update_plan_selected_packages",
        ["state"],
    )
    op.create_index(
        "ix_patch_update_plan_selected_packages_plan_host_state",
        "patch_update_plan_selected_packages",
        ["plan_host_id", "state"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_plan_selected_packages_plan_host_state",
        table_name="patch_update_plan_selected_packages",
    )
    op.drop_index(
        "ix_patch_update_plan_selected_packages_state",
        table_name="patch_update_plan_selected_packages",
    )
    op.drop_index(
        "ix_patch_update_plan_selected_packages_plan_host",
        table_name="patch_update_plan_selected_packages",
    )
    op.drop_index(
        "uq_patch_update_plan_selected_packages_no_advisory",
        table_name="patch_update_plan_selected_packages",
    )
    op.drop_table("patch_update_plan_selected_packages")
    op.drop_column("patch_update_plan_hosts", "selection_summary")
