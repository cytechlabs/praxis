"""PRA-161 slice 1b: patch_policies.

Declarative patch policy. Defines what a future plan may select
(scope), under what governance (approval), how it rolls out
(immediate vs staged via rings), and where it may apply
(maintenance window). Bindings to hosts / groups / smart-groups
and the effective-policy resolver are deliberately deferred to
slice 1c.

Two MaintenanceWindow FKs:
* ``maintenance_window_id`` — when patches may apply.
* ``reboot_window_id`` — when post-patch reboots may occur (used
  by PRA-172). Both nullable; both ``ON DELETE SET NULL`` so
  deleting a window does not cascade-delete the policy.

Locks (M16 design locks, 2026-05-07):

* ``scope_kind`` / ``reboot_policy`` / ``rollout_cadence`` /
  ``failure_policy`` are CHECK-constrained at the DB level.
  Adding values requires a migration, by design.
* ``required_approvals >= 1`` — never zero, never negative.
* ``slug`` unique. App layer also validates shape (lowercase
  alphanumeric + ``-`` / ``_``, length 1..64).
* ``scope_packages`` is JSONB (not stringified JSON) per
  M16 implementation lock #1.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra161_patch_policies"
down_revision: Union[str, None] = "pra161_patch_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_policies",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("scope_kind", sa.String(32), nullable=False),
        sa.Column(
            "scope_packages",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("reboot_policy", sa.String(32), nullable=False),
        sa.Column(
            "reboot_window_id",
            sa.Integer,
            sa.ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "maintenance_window_id",
            sa.Integer,
            sa.ForeignKey("maintenance_windows.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "requires_approval",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "required_approvals",
            sa.Integer,
            nullable=False,
            server_default="1",
        ),
        sa.Column("rollout_cadence", sa.String(32), nullable=False),
        sa.Column("failure_policy", sa.String(32), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
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
        sa.UniqueConstraint("slug", name="uq_patch_policies_slug"),
        sa.CheckConstraint(
            "scope_kind IN ('security_only', 'full', "
            "'package_allowlist', 'package_denylist')",
            name="patch_policies_scope_kind_valid",
        ),
        sa.CheckConstraint(
            "reboot_policy IN ('never', 'if_required', 'always')",
            name="patch_policies_reboot_policy_valid",
        ),
        sa.CheckConstraint(
            "rollout_cadence IN ('immediate', 'staged')",
            name="patch_policies_rollout_cadence_valid",
        ),
        sa.CheckConstraint(
            "failure_policy IN ('continue', 'pause_fleet')",
            name="patch_policies_failure_policy_valid",
        ),
        sa.CheckConstraint(
            "required_approvals >= 1",
            name="patch_policies_required_approvals_positive",
        ),
    )


def downgrade() -> None:
    op.drop_table("patch_policies")
