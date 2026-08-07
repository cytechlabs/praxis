"""PRA-162 slice 3: patch_policy_ring_bindings.

Joins ``patch_policies`` to ``patch_rings`` so a staged policy can
declare which ring set it is allowed to roll out across. Policies
with ``rollout_cadence='immediate'`` do not use ring sets; the bind
service rejects those at the application layer.

Schema:

* ``policy_id`` FK CASCADE to ``patch_policies``
* ``ring_id`` FK CASCADE to ``patch_rings``
* unique ``(policy_id, ring_id)``
* per-FK indexes for both lookup directions

ORM ``__table_args__`` mirrors every constraint and index in this
migration (slice 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra162_policy_ring_bindings"
down_revision: Union[str, None] = "pra162_patch_rings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_policy_ring_bindings",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "policy_id",
            sa.Integer,
            sa.ForeignKey("patch_policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
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
        sa.UniqueConstraint(
            "policy_id",
            "ring_id",
            name="uq_patch_policy_ring_bindings_policy_ring",
        ),
    )
    op.create_index(
        "ix_patch_policy_ring_bindings_policy",
        "patch_policy_ring_bindings",
        ["policy_id"],
    )
    op.create_index(
        "ix_patch_policy_ring_bindings_ring",
        "patch_policy_ring_bindings",
        ["ring_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_policy_ring_bindings_ring",
        table_name="patch_policy_ring_bindings",
    )
    op.drop_index(
        "ix_patch_policy_ring_bindings_policy",
        table_name="patch_policy_ring_bindings",
    )
    op.drop_table("patch_policy_ring_bindings")
