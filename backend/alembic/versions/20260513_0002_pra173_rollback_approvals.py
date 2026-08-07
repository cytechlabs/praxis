"""PRA-173 slice 2: rollback command plans + rollback approval link.

Slice 2 adds the command-planning and approval surfaces on top of
the Slice 1 feasibility substrate. Two schema changes:

* ``patch_update_execution_rollback_packages.command_plan`` (JSONB,
  nullable, default ``'{}'``) — the package-family-specific rollback
  command shape rendered at evaluation time for feasible packages.
  Null/empty for infeasible packages so the read surface stays
  honest about which rows are dispatch-ready. The shape is a
  freezeable JSONB blob (family, primary command argv +
  command_string, held/versionlock handling metadata,
  pre/post-step placeholders). Slice 3 dispatch reads this
  exact shape so what operators approved is what runs.

* ``patch_update_execution_rollback_approvals`` (new join table,
  mirrors ``patch_update_plan_approvals``) — links a
  ``patch_update_execution_rollbacks`` header row to a
  ``patch_approvals`` row (``subject_kind='rollback'`` enforced at
  the service layer, not at the DB). Captures the moment-in-time
  frozen command-plan snapshot (``frozen_plan_snapshot`` JSONB)
  the operators voted on, so a later re-evaluate that refreshes
  the live ``command_plan`` columns cannot silently rewrite what
  was approved. FK to ``patch_update_execution_rollbacks`` is
  CASCADE so deleting the rollback header (CASCADE from the
  execution) cleans the link too; FK to ``patch_approvals`` is
  RESTRICT so an in-flight approval cannot be vacuumed out from
  under the link.

Slice 2 does NOT add any dispatch / execution / package-history
mutation / SSH or agent transport / rescan / verification work.
The command plan is rendered text + structured metadata; the
approval row records intent; neither path issues a real package-
manager command.

Indexes / constraints:

* UNIQUE ``(rollback_id, approval_id)`` on the link table — the
  same rollback can have multiple approval rows across history
  (e.g. expired/rejected followed by re-request) but each link is
  recorded once.
* INDEX ``(rollback_id)`` on the link table for the per-rollback
  read of "current/latest approval link".
* INDEX ``(approval_id)`` on the link table so a navigate-from-
  approval (e.g. UI showing approval detail with backlink) is
  cheap.

ORM ``__table_args__`` mirrors every constraint and index here
(PRA-161 1a-a parity rule carry-forward).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "pra173_rollback_approvals"
down_revision: Union[str, None] = "pra173_rollback_feasibility"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # Command plan column on the rollback package row. Nullable so
    # infeasible rows stay null; default ``'{}'`` keeps re-evaluate
    # write paths consistent with the rest of the patch lifecycle
    # JSONB columns.
    # ------------------------------------------------------------------
    op.add_column(
        "patch_update_execution_rollback_packages",
        sa.Column(
            "command_plan",
            postgresql.JSONB,
            nullable=True,
        ),
    )

    # ------------------------------------------------------------------
    # patch_update_execution_rollback_approvals (link, one row per
    # rollback ↔ approval pair).
    # ------------------------------------------------------------------
    op.create_table(
        "patch_update_execution_rollback_approvals",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "rollback_id",
            sa.Integer,
            sa.ForeignKey("patch_update_execution_rollbacks.id", ondelete="CASCADE"),
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
            "frozen_plan_snapshot",
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
            "rollback_id",
            "approval_id",
            name="uq_patch_update_execution_rollback_approvals_target",
        ),
    )
    op.create_index(
        "ix_patch_update_execution_rollback_approvals_rollback",
        "patch_update_execution_rollback_approvals",
        ["rollback_id"],
    )
    op.create_index(
        "ix_patch_update_execution_rollback_approvals_approval",
        "patch_update_execution_rollback_approvals",
        ["approval_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_patch_update_execution_rollback_approvals_approval",
        table_name="patch_update_execution_rollback_approvals",
    )
    op.drop_index(
        "ix_patch_update_execution_rollback_approvals_rollback",
        table_name="patch_update_execution_rollback_approvals",
    )
    op.drop_table("patch_update_execution_rollback_approvals")
    op.drop_column(
        "patch_update_execution_rollback_packages",
        "command_plan",
    )
