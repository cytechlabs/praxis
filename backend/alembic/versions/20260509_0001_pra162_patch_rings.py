"""PRA-162 slice 1: patch_rings + ring membership binding tables.

First-class ring model for staged rollout. Rings define rollout
order, membership, and (later) promotion gates. They do **not**
execute updates — that's PRA-171.

Schema:

* ``patch_rings`` — first-class ring rows. ``slug`` and ``sort_order``
  are both unique. ``sort_order`` is constrained to ``>= 1`` so the
  ordering is meaningful and the canary/pilot/prod default seed has
  a stable position vocabulary (1, 2, 3).
* Three sibling membership tables (host / static-group / smart-group)
  parallel to the patch-policy binding tables from PRA-161. FK
  CASCADE both sides; unique ``(ring_id, target_id)`` per kind.

Locks:

* Slugs unique app-wide so the resolver (slice 2) can disambiguate
  rings without joining additional context.
* ``sort_order`` is unique-per-row but **not** the only basis for
  promotion semantics; the resolver layer in slice 2 owns precedence
  + same-tier conflict detection. Sort order here just gives display
  + iteration determinism.
* ORM ``__table_args__`` mirrors every constraint and index in this
  file (slice 1a-a parity rule).

No data is seeded by this migration. The ``seed_default_rings``
service helper performs the canary→pilot→prod seed idempotently when
an operator invokes the corresponding API.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra162_patch_rings"
down_revision: Union[str, None] = "pra161_fleet_default"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _common_binding_columns() -> list:
    return [
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "ring_id",
            sa.Integer,
            sa.ForeignKey("patch_rings.id", ondelete="CASCADE"),
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
        "patch_rings",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("sort_order", sa.Integer, nullable=False),
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
        sa.UniqueConstraint("slug", name="uq_patch_rings_slug"),
        sa.UniqueConstraint("sort_order", name="uq_patch_rings_sort_order"),
        sa.CheckConstraint(
            "sort_order >= 1",
            name="patch_rings_sort_order_positive",
        ),
    )

    op.create_table(
        "patch_ring_host_bindings",
        *_common_binding_columns(),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "ring_id",
            "system_id",
            name="uq_patch_ring_host_bindings_ring_system",
        ),
    )
    op.create_index(
        "ix_patch_ring_host_bindings_ring",
        "patch_ring_host_bindings",
        ["ring_id"],
    )
    op.create_index(
        "ix_patch_ring_host_bindings_system",
        "patch_ring_host_bindings",
        ["system_id"],
    )

    op.create_table(
        "patch_ring_group_bindings",
        *_common_binding_columns(),
        sa.Column(
            "group_id",
            sa.Integer,
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "ring_id",
            "group_id",
            name="uq_patch_ring_group_bindings_ring_group",
        ),
    )
    op.create_index(
        "ix_patch_ring_group_bindings_ring",
        "patch_ring_group_bindings",
        ["ring_id"],
    )
    op.create_index(
        "ix_patch_ring_group_bindings_group",
        "patch_ring_group_bindings",
        ["group_id"],
    )

    op.create_table(
        "patch_ring_smart_group_bindings",
        *_common_binding_columns(),
        sa.Column(
            "smart_group_id",
            sa.Integer,
            sa.ForeignKey("smart_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "ring_id",
            "smart_group_id",
            name="uq_patch_ring_smart_group_bindings_ring_smart_group",
        ),
    )
    op.create_index(
        "ix_patch_ring_smart_group_bindings_ring",
        "patch_ring_smart_group_bindings",
        ["ring_id"],
    )
    op.create_index(
        "ix_patch_ring_smart_group_bindings_smart_group",
        "patch_ring_smart_group_bindings",
        ["smart_group_id"],
    )


def downgrade() -> None:
    for table, indexes in (
        (
            "patch_ring_smart_group_bindings",
            [
                "ix_patch_ring_smart_group_bindings_smart_group",
                "ix_patch_ring_smart_group_bindings_ring",
            ],
        ),
        (
            "patch_ring_group_bindings",
            [
                "ix_patch_ring_group_bindings_group",
                "ix_patch_ring_group_bindings_ring",
            ],
        ),
        (
            "patch_ring_host_bindings",
            [
                "ix_patch_ring_host_bindings_system",
                "ix_patch_ring_host_bindings_ring",
            ],
        ),
    ):
        for idx in indexes:
            op.drop_index(idx, table_name=table)
        op.drop_table(table)
    op.drop_table("patch_rings")
