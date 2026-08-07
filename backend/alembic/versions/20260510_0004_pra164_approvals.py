"""PRA-164 slice 4: patch_update_plan_approvals link table.

Joins :class:`PatchUpdatePlan` rows to PRA-161 :class:`PatchApproval`
rows so the plan service can query the approval status for a given
plan in one trivial join (and the audit-export bundle can name the
approval rows it folded in). Approval rows themselves remain owned
by ``patch_approval_service`` (subject_kind='plan',
subject_id=plan.id); this table is purely a navigation index.

* ``plan_id`` FK ``patch_update_plans.id`` ``ON DELETE CASCADE`` so
  deleting a plan cleans its approval link rows automatically. The
  ``patch_approvals`` row is preserved by the RESTRICT FK below; an
  approval row that outlives its plan is rare in practice (canceled
  plans keep their links until the plan itself is deleted).
* ``approval_id`` FK ``patch_approvals.id`` ``ON DELETE RESTRICT``
  so the audit trail cannot vanish out from under a plan that
  references it. Operators must explicitly cancel/reject approvals
  through ``patch_approval_service`` before the row can be removed.
* UNIQUE ``(plan_id, approval_id)`` so a single plan ↔ approval link
  is unambiguous (an approval row may legitimately be re-requested
  for the same plan after a previous request expired; each gets its
  own link row).
* Index ``(plan_id)`` for the per-plan lookup the service queries
  every time it answers "is this plan approved?".

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).

This slice does NOT add any new audit table — the new event-type
strings (``patch_update_plan.approval_requested`` / ``approved`` /
``rejected`` / ``scheduled`` / ``superseded`` / ``exported``) are
emitted by ``patch_update_plan_service`` via ``safe_emit`` no
``db=`` per the established session-boundary lock and land in the
existing ``audit_events`` table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra164_approvals"
down_revision: Union[str, None] = "pra164_preflight"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_update_plan_approvals",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "plan_id",
            sa.Integer,
            sa.ForeignKey("patch_update_plans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "approval_id",
            sa.Integer,
            sa.ForeignKey("patch_approvals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "requested_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column("requested_at", sa.DateTime, nullable=False),
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
            "approval_id",
            name="uq_patch_update_plan_approvals_target",
        ),
    )
    op.create_index(
        "ix_patch_update_plan_approvals_plan",
        "patch_update_plan_approvals",
        ["plan_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_plan_approvals_plan",
        table_name="patch_update_plan_approvals",
    )
    op.drop_table("patch_update_plan_approvals")
