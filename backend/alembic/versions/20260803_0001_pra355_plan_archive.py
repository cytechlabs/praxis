"""PRA-355: patch update plan archive/retire + nullable policy_id.

Founder-approved cleanup model for patch update plans:

- ``patch_update_plans.policy_id`` becomes nullable. Hard-delete stays limited
  to true pre-history plans; plans with approval/schedule/execution history are
  archived instead. When an admin deletes a policy whose only remaining links
  are archived plans, those plans are detached (``policy_id`` → NULL) rather
  than destroyed — ``policy_snapshot`` preserves the policy identity for the
  tombstone. Active (non-archived) plans still block the policy delete via the
  RESTRICT FK.
- Adds the archive tombstone columns: ``archived_at`` (soft-delete marker),
  ``archived_by`` (SET NULL so removing a user does not drop the tombstone),
  and ``archive_reason``. Archived plans keep every evidence row and stay
  queryable/exportable; they are only hidden from normal operator lists.

Additive + a nullability relaxation — existing rows keep working (all archive
columns default NULL, i.e. not archived).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra355_plan_archive"
down_revision: Union[str, None] = "pra313_transport_cooldown"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "patch_update_plans",
        "policy_id",
        existing_type=sa.Integer(),
        nullable=True,
    )
    op.add_column(
        "patch_update_plans",
        sa.Column("archived_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "patch_update_plans",
        sa.Column("archived_by", sa.Integer(), nullable=True),
    )
    op.add_column(
        "patch_update_plans",
        sa.Column("archive_reason", sa.Text(), nullable=True),
    )
    op.create_foreign_key(
        "fk_patch_update_plans_archived_by_user",
        "patch_update_plans",
        "user",
        ["archived_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_patch_update_plans_archived_at",
        "patch_update_plans",
        ["archived_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_plans_archived_at",
        table_name="patch_update_plans",
    )
    op.drop_constraint(
        "fk_patch_update_plans_archived_by_user",
        "patch_update_plans",
        type_="foreignkey",
    )
    op.drop_column("patch_update_plans", "archive_reason")
    op.drop_column("patch_update_plans", "archived_by")
    op.drop_column("patch_update_plans", "archived_at")
    # Detached tombstones (policy_id IS NULL) would violate a NOT NULL
    # restore; only safe when no such rows exist. Guarded per-row cleanup
    # is intentionally left to the operator before downgrading.
    op.alter_column(
        "patch_update_plans",
        "policy_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
