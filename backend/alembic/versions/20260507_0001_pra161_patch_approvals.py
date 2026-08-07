"""PRA-161 slice 1a: patch_approvals + patch_approval_votes.

Patch-scoped approval primitive shared by 161 (policy bind),
164 (plan), and 173 (rollback). Polymorphic subject via
``(subject_kind, subject_id)``; FK is enforced at the app layer.

**Key contract — different from CommandApproval:**

* No auto-execute on threshold. ``patch_approval_service.record_vote``
  flips status and returns; the caller queries
  ``get_approval_status`` and decides whether to proceed.
* Local exception class in the service so this primitive cannot
  accidentally couple back to ``command_approval_service``.

Locks (M16 design locks, 2026-05-07):

* ``subject_kind`` is constrained to ``policy`` / ``plan`` /
  ``rollback`` at the DB level. Adding new kinds requires a
  migration, by design — accidental subjects should fail loudly.
* ``status`` and ``decision`` are likewise CHECK-constrained.
* One vote per (approval_id, user_id) — unique index plus
  service-layer guard.
* ``required_approvals >= 1`` enforced at DB level so a misuse
  at any layer surfaces immediately.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra161_patch_approvals"
down_revision: Union[str, None] = "pra160_import_trust_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "patch_approvals",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("subject_kind", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.Integer, nullable=False),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "required_approvals",
            sa.Integer,
            nullable=False,
            server_default="1",
        ),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column(
            "requested_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column(
            "decided_by",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime, nullable=True),
        sa.Column("comment", sa.Text, nullable=True),
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
            "subject_kind IN ('policy', 'plan', 'rollback')",
            name="patch_approvals_subject_kind_valid",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired')",
            name="patch_approvals_status_valid",
        ),
        sa.CheckConstraint(
            "required_approvals >= 1",
            name="patch_approvals_required_approvals_positive",
        ),
    )
    op.create_index(
        "ix_patch_approvals_subject",
        "patch_approvals",
        ["subject_kind", "subject_id"],
    )
    # Sweeper lookup: pending approvals past their expiry.
    op.create_index(
        "ix_patch_approvals_pending_expires_at",
        "patch_approvals",
        ["expires_at"],
        postgresql_where=sa.text("status = 'pending' AND expires_at IS NOT NULL"),
    )

    op.create_table(
        "patch_approval_votes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "approval_id",
            sa.Integer,
            sa.ForeignKey("patch_approvals.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "user_id",
            sa.Integer,
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("comment", sa.Text, nullable=True),
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
            "decision IN ('approve', 'reject')",
            name="patch_approval_votes_decision_valid",
        ),
        sa.UniqueConstraint(
            "approval_id",
            "user_id",
            name="uq_patch_approval_votes_one_per_user",
        ),
    )


def downgrade() -> None:
    op.drop_table("patch_approval_votes")
    op.drop_index(
        "ix_patch_approvals_pending_expires_at",
        table_name="patch_approvals",
    )
    op.drop_index("ix_patch_approvals_subject", table_name="patch_approvals")
    op.drop_table("patch_approvals")
