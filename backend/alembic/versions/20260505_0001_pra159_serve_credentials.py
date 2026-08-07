"""PRA-159 slice #2: host_mirror_serve_credentials.

Per-(host, mirror) bearer credential used by hosts to authenticate
to ``GET /mirrors/{slug}/serve/{path:path}``. Issued at trust-install
or apply time (slice #3), embedded in the host's apt
``/etc/apt/auth.conf.d/praxis-mirror-<slug>.conf`` (mode 0600 root)
or in the dnf ``.repo`` ``username=``/``password=`` fields (also
mode 0600 root). World-readable ``.list``/``.repo`` files do NOT
contain the secret.

Locks (PRA-159 design conversation):
  * One ACTIVE credential per ``(host_id, mirror_id)`` at a time. A
    new ``issue`` revokes any prior active row. Enforced via partial
    unique index ``(host_id, mirror_id) WHERE revoked_at IS NULL``.
  * Storage is ``token_hash`` only — the plaintext is returned ONCE
    at issue time and never stored in the DB or logs. Verification
    uses ``passlib.hash.pbkdf2_sha256.verify`` against the hash.
    NOTE: pbkdf2_sha256 is per-row salted, so the verifier CANNOT
    look up by hashing the presented token — it scans candidate
    rows and runs ``verify`` per row. Future optimisation
    (truncated public token id keyed lookup) is documented in the
    service module; v1 is the scan.
  * ``expires_at`` is wall-clock TTL (default 365d, overridable per
    issue call). Verifier rejects ``expires_at <= now`` even if the
    row is not explicitly revoked.
  * ``last_used_at`` is updated best-effort by the serve route on
    successful verify (no transactional read-then-write — last write
    wins under contention is fine for an "approximate last use"
    diagnostic).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra159_serve_credentials"
down_revision: Union[str, None] = "pra159_content_channels"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "host_mirror_serve_credentials",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "host_id",
            sa.Integer,
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "mirror_id",
            sa.Integer,
            sa.ForeignKey("mirror_repos.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(255), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
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
    )
    # At most one active credential per (host, mirror). A new issue
    # MUST revoke the prior row (set revoked_at) before insert; the
    # service handles this in a single short transaction.
    op.create_index(
        "ux_host_mirror_serve_creds_one_active",
        "host_mirror_serve_credentials",
        ["host_id", "mirror_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    # NB: NO unique index on token_hash — pbkdf2_sha256 is per-row
    # salted, so two rows holding the same plaintext would hash
    # differently and a unique index wouldn't catch the duplicate
    # anyway. The verifier scans candidates and runs
    # ``pbkdf2_sha256.verify`` per row; there's no lookup-by-hash
    # path to short-circuit.


def downgrade() -> None:
    op.drop_index(
        "ux_host_mirror_serve_creds_one_active",
        table_name="host_mirror_serve_credentials",
    )
    op.drop_table("host_mirror_serve_credentials")
