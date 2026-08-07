"""PRA-154 slice #1d-α: target_system_id on activation_tokens.

Adds a required FK from ``activation_tokens`` to ``systems`` so each
token is bound to exactly one pre-registered host. This is the
schema half of the bootstrap UX: the operator picks the target
System at create time, and the bootstrap one-liner can hard-code
``PRAXIS_SYSTEM_ID`` rather than asking the host operator to fill it
in.

Link-only redemption stays the rule for #1c. ``max_uses`` is no
longer functionally meaningful (the (token_id, system_id) ledger
unique already implies max_uses=1 once a target is bound), so the
``activation_tokens`` create route forces ``max_uses=1`` while this
column is required. The column is kept on the schema so a later
slice can re-enable bulk enrollment when create-on-redemption lands.

Migration is non-empty-table-safe in the conservative sense: we add
the column NOT NULL with no default. If any existing tokens were
issued before this migration ran, the upgrade will fail loudly
rather than silently backfill a wrong target. There are no
production tokens yet (PRA-154 has not shipped), so failing closed
on a non-empty table is the right paranoia.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra154_target_system"
down_revision: Union[str, None] = "pra154_activation_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    existing = bind.execute(
        sa.text("SELECT COUNT(*) FROM activation_tokens")
    ).scalar_one()
    if existing and existing > 0:
        # Failing closed: any pre-existing token cannot be safely
        # backfilled with a target system. Operator must drop the
        # rows or write a one-off backfill before re-running.
        raise RuntimeError(
            f"refusing to add NOT NULL target_system_id with "
            f"{existing} existing activation_tokens row(s); "
            "drop or backfill before upgrading"
        )

    op.add_column(
        "activation_tokens",
        sa.Column(
            "target_system_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="RESTRICT"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_activation_tokens_target_system_id",
        "activation_tokens",
        ["target_system_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_activation_tokens_target_system_id",
        table_name="activation_tokens",
    )
    op.drop_column("activation_tokens", "target_system_id")
