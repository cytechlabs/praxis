"""PRA-150: agent identity columns on systems

Revision ID: pra150_agent
Revises: pra149_review
Create Date: 2026-04-25

Adds the System columns that back the M13 thin agent identity / lifecycle.

Single source of truth for agent state is ``agent_status``:

    not_enrolled  ->  active  <->  disabled
                         |
                         v
                      revoked  (terminal — cert serial blocklisted;
                                re-enrollment must mint a new serial)

Operator routing intent (``transport_preference``) is a separate axis from
identity lifecycle.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra150_agent"
down_revision: Union[str, None] = "pra149_review"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    agent_status_enum = sa.Enum(
        "not_enrolled",
        "active",
        "disabled",
        "revoked",
        name="agent_status_enum",
    )
    transport_pref_enum = sa.Enum(
        "auto", "ssh", "agent", name="transport_preference_enum"
    )
    agent_status_enum.create(op.get_bind(), checkfirst=True)
    transport_pref_enum.create(op.get_bind(), checkfirst=True)

    op.add_column(
        "systems",
        sa.Column(
            "agent_status",
            agent_status_enum,
            nullable=False,
            server_default="not_enrolled",
        ),
    )
    op.add_column(
        "systems",
        sa.Column("agent_cert_serial", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("agent_cert_fingerprint", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("agent_cert_expires_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("agent_revoked_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("agent_status_reason", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("agent_revocation_reason", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("agent_last_seen_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column("agent_version", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "systems",
        sa.Column(
            "transport_preference",
            transport_pref_enum,
            nullable=False,
            server_default="auto",
        ),
    )

    # UNIQUE on serial: Vault PKI mints monotonically unique serials per CA, so
    # duplicates can only happen on a bug or replay. Postgres allows multiple
    # NULLs under a unique index, so unenrolled systems are fine.
    op.create_index(
        "ix_systems_agent_cert_serial",
        "systems",
        ["agent_cert_serial"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_systems_agent_cert_serial", table_name="systems")
    for col in (
        "transport_preference",
        "agent_version",
        "agent_last_seen_at",
        "agent_revocation_reason",
        "agent_status_reason",
        "agent_revoked_at",
        "agent_cert_expires_at",
        "agent_cert_fingerprint",
        "agent_cert_serial",
        "agent_status",
    ):
        op.drop_column("systems", col)

    sa.Enum(name="transport_preference_enum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="agent_status_enum").drop(op.get_bind(), checkfirst=True)
