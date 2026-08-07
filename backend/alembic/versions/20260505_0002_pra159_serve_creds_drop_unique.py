"""PRA-159 #3-a: drop partial unique on (host_id, mirror_id) for serve creds.

The slice #2 migration created
``ux_host_mirror_serve_creds_one_active(host_id, mirror_id) WHERE
revoked_at IS NULL`` to enforce "at most one active credential per
(host, mirror)" at the DB level.

Slice #3 review (P2) flagged the operator-visible problem:
the orchestrator's "rotate the bearer on every apply" path was
revoking the prior active credential BEFORE the new auth file
landed on the host. If any later apply step failed, the host's
``auth.conf`` / ``.repo`` still pointed at the old bearer, but
Praxis had already revoked it — package manager fails until the
operator retries the apply. That broke the slice's "last-good
preservation" contract.

Fix: orchestrator now issues the new credential WITHOUT revoking,
writes the host config, and only revokes the prior credential after
the writes succeed. During the write window two active credentials
coexist for the same (host, mirror) pair. The verifier is unchanged
— it scans active candidates and runs ``pbkdf2_sha256.verify`` per
row, so accepting either bearer is the natural behaviour.

Forward-only: dropping the index doesn't require any data
migration. The downgrade re-adds the index, which a re-deployed
slice #2 path would also re-create.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra159_serve_creds_drop_unique"
down_revision: Union[str, None] = "pra159_serve_credentials"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index(
        "ux_host_mirror_serve_creds_one_active",
        table_name="host_mirror_serve_credentials",
    )


def downgrade() -> None:
    op.create_index(
        "ux_host_mirror_serve_creds_one_active",
        "host_mirror_serve_credentials",
        ["host_id", "mirror_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
