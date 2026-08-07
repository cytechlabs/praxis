"""PRA-164 slice 1: patch_update_plans + patch_update_plan_hosts.

Dry-run update-plan substrate. Persists the inputs and computed
host-wave layout for a future patch rollout, but does NOT execute
anything: no package-manager calls, no SSH scans, no preflight
package collection, no approval row creation, no probes / reboot /
rollback / mirror rebuild / airgap mutations. Later PRA-164 slices
add package selection preview, preflight snapshots, content
availability checks, and approval integration. Execution remains
PRA-171/172/173.

Tables:

* ``patch_update_plans`` — one row per draft / approved / scheduled
  plan. References its source policy (``ON DELETE RESTRICT``) so the
  audit trail can never be silently broken by deleting the policy
  the plan was built from. Snapshots policy / ring sequence / caller
  request / plan-level block reasons in JSONB so a later policy
  edit cannot change what the plan was built from.

* ``patch_update_plan_hosts`` — one row per host in the plan.
  References ``systems.id`` ``ON DELETE SET NULL`` so historical
  plan rows survive system removal; host identity is preserved in
  the snapshotted columns. Each row carries the effective patch
  policy snapshot, effective ring snapshot, ``wave_index``
  (``0`` for immediate policies, ring sort-order-derived for staged
  policies), effective content-profile snapshot, ``state``
  (``planned`` or ``blocked``), and structured per-host
  ``block_reasons`` JSONB.

Vocabularies (CHECK-constrained at the DB level; ORM mirrors):

* ``patch_update_plans.state`` ∈
  ``{draft, awaiting_approval, approved, scheduled, blocked,
  superseded, canceled}``.
* ``patch_update_plan_hosts.state`` ∈ ``{planned, blocked}``.
* ``patch_update_plan_hosts.policy_resolution_kind`` ∈
  ``{direct_host, static_group, smart_group, fleet_default,
  no_policy}`` (mirrors patch_policy_service ``RESOLUTION_*``).
* ``patch_update_plan_hosts.content_profile_state`` ∈
  ``{resolved, no_profile, conflict}`` (mirrors
  ContentProfileService ``ResolutionState``).
* ``patch_update_plan_hosts.ring_resolution_status`` ∈
  ``{resolved, no_ring, conflict, not_applicable}`` —
  ``not_applicable`` covers immediate-cadence policies that don't
  consult the ring resolver.

Indexes / constraints:

* UNIQUE ``(plan_id, system_id)`` on ``patch_update_plan_hosts`` so
  a single host can never appear twice in the same plan.
* INDEX ``(state)`` on plans and ``(state)`` on plan-hosts for the
  fleet dashboard / blocked-host filters PRA-164 slice 4 will use.
* INDEX ``(plan_id, wave_index)`` on plan-hosts so the route can
  return a wave's worth of hosts cheaply.
* INDEX ``(policy_id)`` on plans so deleting a policy can detect
  the RESTRICT FK at the cheapest cost.

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra164_update_plans"
down_revision: Union[str, None] = "pra163_host_applicability"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


PLAN_STATES = (
    "draft",
    "awaiting_approval",
    "approved",
    "scheduled",
    "blocked",
    "superseded",
    "canceled",
)

PLAN_HOST_STATES = ("planned", "blocked")

POLICY_RESOLUTION_KINDS = (
    "direct_host",
    "static_group",
    "smart_group",
    "fleet_default",
    "no_policy",
)

CONTENT_PROFILE_STATES = ("resolved", "no_profile", "conflict")

RING_RESOLUTION_STATUSES = ("resolved", "no_ring", "conflict", "not_applicable")


def _check_in(column: str, values) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.create_table(
        "patch_update_plans",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "policy_id",
            sa.Integer,
            sa.ForeignKey("patch_policies.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("scheduled_start_at", sa.DateTime, nullable=True),
        sa.Column(
            "maintenance_window_id",
            sa.Integer,
            sa.ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "reboot_window_id",
            sa.Integer,
            sa.ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "policy_snapshot",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "ring_sequence_snapshot",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "request_snapshot",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "block_reasons",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
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
            _check_in("state", PLAN_STATES),
            name="patch_update_plans_state_vocab",
        ),
    )
    op.create_index(
        "ix_patch_update_plans_policy",
        "patch_update_plans",
        ["policy_id"],
    )
    op.create_index(
        "ix_patch_update_plans_state",
        "patch_update_plans",
        ["state"],
    )

    op.create_table(
        "patch_update_plan_hosts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "plan_id",
            sa.Integer,
            sa.ForeignKey("patch_update_plans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("system_hostname_snapshot", sa.String(255), nullable=True),
        sa.Column("policy_id_snapshot", sa.Integer, nullable=True),
        sa.Column("policy_slug_snapshot", sa.String(64), nullable=True),
        sa.Column("policy_resolution_kind", sa.String(32), nullable=False),
        sa.Column("ring_id_snapshot", sa.Integer, nullable=True),
        sa.Column("ring_slug_snapshot", sa.String(64), nullable=True),
        sa.Column("ring_name_snapshot", sa.String(128), nullable=True),
        sa.Column("ring_sort_order_snapshot", sa.Integer, nullable=True),
        sa.Column("ring_source_tier", sa.String(32), nullable=True),
        sa.Column("ring_resolution_status", sa.String(32), nullable=False),
        sa.Column("wave_index", sa.Integer, nullable=False),
        sa.Column("content_profile_state", sa.String(32), nullable=False),
        sa.Column("content_profile_id_snapshot", sa.Integer, nullable=True),
        sa.Column("content_profile_slug_snapshot", sa.String(64), nullable=True),
        sa.Column(
            "content_profile_display_name_snapshot",
            sa.String(128),
            nullable=True,
        ),
        sa.Column(
            "content_profile_package_family_snapshot",
            sa.String(8),
            nullable=True,
        ),
        sa.Column(
            "content_profile_conflict_snapshot",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column(
            "block_reasons",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
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
            "plan_id",
            "system_id",
            name="uq_patch_update_plan_hosts_plan_system",
        ),
        sa.CheckConstraint(
            _check_in("state", PLAN_HOST_STATES),
            name="patch_update_plan_hosts_state_vocab",
        ),
        sa.CheckConstraint(
            _check_in("policy_resolution_kind", POLICY_RESOLUTION_KINDS),
            name="patch_update_plan_hosts_policy_resolution_kind_vocab",
        ),
        sa.CheckConstraint(
            _check_in("content_profile_state", CONTENT_PROFILE_STATES),
            name="patch_update_plan_hosts_content_profile_state_vocab",
        ),
        sa.CheckConstraint(
            _check_in("ring_resolution_status", RING_RESOLUTION_STATUSES),
            name="patch_update_plan_hosts_ring_resolution_status_vocab",
        ),
        sa.CheckConstraint(
            "wave_index >= 0",
            name="patch_update_plan_hosts_wave_index_nonneg",
        ),
    )
    op.create_index(
        "ix_patch_update_plan_hosts_plan_wave",
        "patch_update_plan_hosts",
        ["plan_id", "wave_index"],
    )
    op.create_index(
        "ix_patch_update_plan_hosts_state",
        "patch_update_plan_hosts",
        ["state"],
    )
    op.create_index(
        "ix_patch_update_plan_hosts_system",
        "patch_update_plan_hosts",
        ["system_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_plan_hosts_system",
        table_name="patch_update_plan_hosts",
    )
    op.drop_index(
        "ix_patch_update_plan_hosts_state",
        table_name="patch_update_plan_hosts",
    )
    op.drop_index(
        "ix_patch_update_plan_hosts_plan_wave",
        table_name="patch_update_plan_hosts",
    )
    op.drop_table("patch_update_plan_hosts")
    op.drop_index(
        "ix_patch_update_plans_state",
        table_name="patch_update_plans",
    )
    op.drop_index(
        "ix_patch_update_plans_policy",
        table_name="patch_update_plans",
    )
    op.drop_table("patch_update_plans")
