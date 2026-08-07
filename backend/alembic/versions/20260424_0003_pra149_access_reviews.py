"""PRA-149: access reviews + per-binding review items

Revision ID: pra149_review
Revises: pra147_appr
Create Date: 2026-04-24

Adds:
  - access_reviews — periodic "are these grants still right?" sweeps
  - access_review_items — one row per AccessBinding in scope at review
    creation time, with the reviewer's decision (attest|revoke|extend)
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra149_review"
down_revision: Union[str, None] = "pra147_appr"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "access_reviews",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        # all | binding | user | role
        sa.Column("scope", sa.String(20), nullable=False),
        # nullable for scope=all; meaning depends on scope
        sa.Column("scope_ref_id", sa.Integer(), nullable=True),
        # pending | completed | expired
        sa.Column("state", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("due_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column(
            "reviewer_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_access_reviews_state", "access_reviews", ["state"])
    op.create_index("ix_access_reviews_due_at", "access_reviews", ["due_at"])

    op.create_table(
        "access_review_items",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "review_id",
            sa.Integer(),
            sa.ForeignKey("access_reviews.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "binding_id",
            sa.Integer(),
            # SET NULL so the row stays in the audit even if the binding
            # is later deleted.
            sa.ForeignKey("access_bindings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # JSON snapshot of the binding shape at review creation. Keeps
        # the review meaningful even when the live binding has drifted.
        sa.Column("binding_snapshot_json", sa.Text(), nullable=False),
        # pending | attest | revoke | extend
        sa.Column("action", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column(
            "decided_by",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_access_review_items_review_id", "access_review_items", ["review_id"]
    )
    op.create_index("ix_access_review_items_action", "access_review_items", ["action"])


def downgrade() -> None:
    op.drop_index("ix_access_review_items_action", table_name="access_review_items")
    op.drop_index("ix_access_review_items_review_id", table_name="access_review_items")
    op.drop_table("access_review_items")
    op.drop_index("ix_access_reviews_due_at", table_name="access_reviews")
    op.drop_index("ix_access_reviews_state", table_name="access_reviews")
    op.drop_table("access_reviews")
