"""PRA-161 slice 1c: policy → host / group / smart-group binding tables.

Three sibling tables that bind a ``patch_policy`` to a host, a static
group, or a smart group respectively. Together with the (slice-1d)
fleet-default flag they form the four-tier source set the
effective-policy resolver consumes.

Locks:

* ``ON DELETE CASCADE`` from both sides — deleting either the policy
  or the target row drops the binding rather than orphaning it.
* Unique ``(policy_id, target_id)`` per kind so the same target
  cannot be bound to the same policy twice. A second policy
  binding the same target IS allowed at this layer; the resolver
  (slice 1d) is the one that turns multi-policy-at-same-tier into a
  loud conflict.
* Per-target indexes on ``system_id`` / ``group_id`` /
  ``smart_group_id`` so the resolver can answer "which policies
  target this host" without a sequential scan.

Audit:

* ``patch_policy.bound`` / ``patch_policy.unbound`` event-type
  strings were reserved in slice 1b; this slice is the first one to
  actually emit them.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra161_policy_bindings"
down_revision: Union[str, None] = "pra161_patch_policies"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _common_columns() -> list:
    return [
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "policy_id",
            sa.Integer,
            sa.ForeignKey("patch_policies.id", ondelete="CASCADE"),
            nullable=False,
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
    ]


def upgrade() -> None:
    op.create_table(
        "patch_policy_host_bindings",
        *_common_columns(),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "policy_id",
            "system_id",
            name="uq_patch_policy_host_bindings_policy_system",
        ),
    )
    op.create_index(
        "ix_patch_policy_host_bindings_system",
        "patch_policy_host_bindings",
        ["system_id"],
    )
    op.create_index(
        "ix_patch_policy_host_bindings_policy",
        "patch_policy_host_bindings",
        ["policy_id"],
    )

    op.create_table(
        "patch_policy_group_bindings",
        *_common_columns(),
        sa.Column(
            "group_id",
            sa.Integer,
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "policy_id",
            "group_id",
            name="uq_patch_policy_group_bindings_policy_group",
        ),
    )
    op.create_index(
        "ix_patch_policy_group_bindings_group",
        "patch_policy_group_bindings",
        ["group_id"],
    )
    op.create_index(
        "ix_patch_policy_group_bindings_policy",
        "patch_policy_group_bindings",
        ["policy_id"],
    )

    op.create_table(
        "patch_policy_smart_group_bindings",
        *_common_columns(),
        sa.Column(
            "smart_group_id",
            sa.Integer,
            sa.ForeignKey("smart_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "policy_id",
            "smart_group_id",
            name="uq_patch_policy_smart_group_bindings_policy_smart_group",
        ),
    )
    op.create_index(
        "ix_patch_policy_smart_group_bindings_smart_group",
        "patch_policy_smart_group_bindings",
        ["smart_group_id"],
    )
    op.create_index(
        "ix_patch_policy_smart_group_bindings_policy",
        "patch_policy_smart_group_bindings",
        ["policy_id"],
    )


def downgrade() -> None:
    for table, indexes in (
        (
            "patch_policy_smart_group_bindings",
            [
                "ix_patch_policy_smart_group_bindings_policy",
                "ix_patch_policy_smart_group_bindings_smart_group",
            ],
        ),
        (
            "patch_policy_group_bindings",
            [
                "ix_patch_policy_group_bindings_policy",
                "ix_patch_policy_group_bindings_group",
            ],
        ),
        (
            "patch_policy_host_bindings",
            [
                "ix_patch_policy_host_bindings_policy",
                "ix_patch_policy_host_bindings_system",
            ],
        ),
    ):
        for idx in indexes:
            op.drop_index(idx, table_name=table)
        op.drop_table(table)
