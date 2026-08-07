"""add credential sudo fields

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-04-04

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "credentials",
        sa.Column(
            "sudo_method",
            sa.String(length=50),
            nullable=False,
            server_default="none",
        ),
    )
    op.add_column(
        "credentials",
        sa.Column("sudo_password", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("credentials", "sudo_password")
    op.drop_column("credentials", "sudo_method")
