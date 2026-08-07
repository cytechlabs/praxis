"""PRA-285: persisted access-revocation / host-reconcile work outbox.

Adds ``revocation_work`` — the durable queue that the guarded scheduler drain
processes so pending host cleanup survives a process restart. Rows are enqueued in
the same transaction as the grant recompute that narrowed access (outbox), and are
a signal to reconverge a ``(user, system, login)`` scope, not a stored "remove"
imperative. See ``app.services.revocation_service``.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra285_revocation_work"
down_revision: Union[str, None] = "pra284_grant_expiry"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "revocation_work",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("reason", sa.String(length=48), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("login", sa.String(length=100), nullable=True),
        sa.Column(
            "status", sa.String(length=16), nullable=False, server_default="pending"
        ),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_retry_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index(op.f("ix_revocation_work_user_id"), "revocation_work", ["user_id"])
    op.create_index(
        op.f("ix_revocation_work_system_id"), "revocation_work", ["system_id"]
    )
    op.create_index(op.f("ix_revocation_work_status"), "revocation_work", ["status"])
    op.create_index(
        op.f("ix_revocation_work_next_retry_at"),
        "revocation_work",
        ["next_retry_at"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_revocation_work_next_retry_at"), table_name="revocation_work"
    )
    op.drop_index(op.f("ix_revocation_work_status"), table_name="revocation_work")
    op.drop_index(op.f("ix_revocation_work_system_id"), table_name="revocation_work")
    op.drop_index(op.f("ix_revocation_work_user_id"), table_name="revocation_work")
    op.drop_table("revocation_work")
