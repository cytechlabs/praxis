"""PRA-180 Remediation P2F (PRA-225, MIRROR-01): mirror-serve token_id lookup.

Adds a public, non-secret ``token_id`` lookup column to
``host_mirror_serve_credentials``. New bearers are minted as
``<token_id>.<secret>``; the verifier looks the single matching row up by the
indexed ``token_id`` and runs pbkdf2 once, instead of scanning every active
credential fleet-wide (the prior O(N) behavior).

The column is nullable: credentials issued before this migration (legacy
plaintext with no ``.`` separator) keep ``token_id IS NULL`` and still verify
via a bounded fallback scan over only the legacy rows, which drains as those
credentials expire/rotate.

Locks:

* ``token_id`` is indexed (non-unique — the secret still gates acceptance; the
  index is purely a lookup narrowing).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra225_mirror_serve_token_id"
down_revision: Union[str, None] = "pra180_oidc_login_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "host_mirror_serve_credentials",
        sa.Column("token_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        op.f("ix_host_mirror_serve_credentials_token_id"),
        "host_mirror_serve_credentials",
        ["token_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_host_mirror_serve_credentials_token_id"),
        table_name="host_mirror_serve_credentials",
    )
    op.drop_column("host_mirror_serve_credentials", "token_id")
