"""add SSH identity (zero-trust CA) columns and settings (PRA-44)

Revision ID: pra44_sshidty
Revises: pra80_approvals
Create Date: 2026-04-13

"""

import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra44_sshidty"
down_revision: Union[str, None] = "pra80_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add CA trust tracking to systems
    op.add_column(
        "systems",
        sa.Column(
            "ca_trust_deployed",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.add_column(
        "systems",
        sa.Column("ca_trust_deployed_at", sa.DateTime(), nullable=True),
    )

    # Create ssh_identity_settings singleton
    op.create_table(
        "ssh_identity_settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_cert_ttl_seconds",
            sa.Integer(),
            nullable=False,
            server_default="300",
        ),
        sa.Column("default_principal", sa.String(100), nullable=True),
        sa.Column("ca_identifier", sa.String(100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Seed default settings row with a unique CA identifier
    identifier = f"praxis-{uuid.uuid4().hex[:12]}"
    op.execute(
        "INSERT INTO ssh_identity_settings "
        "(user_cert_ttl_seconds, default_principal, ca_identifier) "
        f"VALUES (300, NULL, '{identifier}')"
    )


def downgrade() -> None:
    op.drop_table("ssh_identity_settings")
    op.drop_column("systems", "ca_trust_deployed_at")
    op.drop_column("systems", "ca_trust_deployed")
