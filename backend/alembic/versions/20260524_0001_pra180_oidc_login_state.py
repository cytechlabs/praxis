"""PRA-180 Remediation 1A (PRA-218): shared OIDC login state table.

Creates ``oidc_login_state`` so the OIDC authorization-code flow's
``state`` / ``nonce`` survive across the multiple uvicorn workers the
production backend runs by default. The login step (one worker) inserts a
row; the callback step (possibly a different worker) consumes it. Rows are
single-use (deleted on successful validation) and TTL-bounded via
``expires_at``.

``redirect_uri`` is stored so the callback's token exchange re-uses the exact
value sent to the IdP at authorize time (PRA-217 redirect consistency).

Locks:

* ``state`` is unique + indexed; the callback looks rows up by it.
* ``expires_at`` is indexed for the opportunistic expired-row sweep.
* Base-class columns ``id`` / ``created_at`` / ``updated_at`` are included to
  match the declarative model.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra180_oidc_login_state"
down_revision: Union[str, None] = "pra175_compliance_dispatch"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oidc_login_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=128), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("provider_id", sa.Integer(), nullable=False),
        sa.Column("redirect_uri", sa.String(length=1024), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_oidc_login_state_id"), "oidc_login_state", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_oidc_login_state_state"),
        "oidc_login_state",
        ["state"],
        unique=True,
    )
    op.create_index(
        op.f("ix_oidc_login_state_expires_at"),
        "oidc_login_state",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_oidc_login_state_expires_at"), table_name="oidc_login_state")
    op.drop_index(op.f("ix_oidc_login_state_state"), table_name="oidc_login_state")
    op.drop_index(op.f("ix_oidc_login_state_id"), table_name="oidc_login_state")
    op.drop_table("oidc_login_state")
