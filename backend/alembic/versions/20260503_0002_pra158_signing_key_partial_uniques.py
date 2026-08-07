"""PRA-158 #1-a: partial unique indexes for signing-key status invariants.

Review on slice #1 flagged that the bootstrap endpoint races
were "documented and accepted" but actually corrupting: a second
concurrent POST could insert a second ``active`` row, and the very
next ``get_active().one_or_none()`` would raise
``MultipleResultsFound`` instead of returning a key. The service-layer
invariant "at most one active per mirror, at most one pending_cutover
per mirror" needs a DB-backed enforcement so the race is a clean
``IntegrityError`` the bootstrap path can recover from, not a latent
multi-row corruption.

Postgres partial unique indexes are the right shape: they only cover
the rows that need uniqueness (``active`` + ``pending_cutover``),
leaving ``rotating_out`` and ``retired`` rows free to multiply (a
mirror accumulates retired keys over time across many rotations).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra158_signing_uniques"
down_revision: Union[str, None] = "pra158_mirror_signing_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "uq_mirror_signing_keys_one_active_per_mirror",
        "mirror_signing_keys",
        ["mirror_repo_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "uq_mirror_signing_keys_one_pending_per_mirror",
        "mirror_signing_keys",
        ["mirror_repo_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending_cutover'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_mirror_signing_keys_one_pending_per_mirror",
        table_name="mirror_signing_keys",
    )
    op.drop_index(
        "uq_mirror_signing_keys_one_active_per_mirror",
        table_name="mirror_signing_keys",
    )
