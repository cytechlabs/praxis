"""PRA-173 slice 4a: verified_at on rollback dispatch packages.

A successful "package not installed"
observation was stored as ``installed_version_after = NULL`` —
the same sentinel the verifier used to mean "not verified yet".
Idempotency / completion could not distinguish the two states,
so a host where the rollback succeeded and the package is
intentionally absent would loop forever in the "still due"
bucket.

Fix: add an explicit ``verified_at`` (naive-UTC, nullable)
column on ``patch_rollback_dispatch_host_packages``. ``NULL``
means "not yet verified"; a non-null value means "verifier
observed the host's state at this moment, the
``installed_version_after`` value is authoritative (including a
null value meaning 'host reports package not installed')".

The column is nullable + default-null so existing dispatch
package rows survive the migration without backfill — rows that
predate this slice will correctly read as "not yet verified" until
verify-due is run.

ORM ``__table_args__`` carry-forward: the model gains the
``verified_at`` column; no new constraints / indexes.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra173_rollback_verify"
down_revision: Union[str, None] = "pra173_rollback_dispatch"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "patch_rollback_dispatch_host_packages",
        sa.Column("verified_at", sa.DateTime, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("patch_rollback_dispatch_host_packages", "verified_at")
