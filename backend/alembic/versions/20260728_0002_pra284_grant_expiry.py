"""PRA-284: persist effective grant expiry for synchronous authz enforcement.

Adds a nullable, indexed ``access_grants.expires_at`` copied from the source
``AccessBinding.expires_at`` at recompute. Authorization filters grants live with
``expires_at IS NULL OR expires_at > now``, so an expired grant stops authorizing
at the decision boundary without waiting for a recompute or cleanup sweep.

Existing rows are backfilled from ``via_binding_id -> access_bindings.expires_at``.
Implicit app-admin grants (``via_binding_id IS NULL``) keep ``expires_at = NULL``
(never expire; their boundary is app role + active user, per PRA-290). A row whose
source binding has already expired gets a past ``expires_at`` and is therefore
denied immediately by the synchronous authz filter, then dropped on the next
recompute. NULL = never expires.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra284_grant_expiry"
down_revision: Union[str, None] = "pra282_privilege_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "access_grants",
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        op.f("ix_access_grants_expires_at"),
        "access_grants",
        ["expires_at"],
        unique=False,
    )
    # Backfill effective expiry from the source binding. Grants with no binding
    # (implicit app-admin) stay NULL.
    op.execute("""
        UPDATE access_grants ag
        SET expires_at = ab.expires_at
        FROM access_bindings ab
        WHERE ag.via_binding_id = ab.id
        """)


def downgrade() -> None:
    op.drop_index(op.f("ix_access_grants_expires_at"), table_name="access_grants")
    op.drop_column("access_grants", "expires_at")
