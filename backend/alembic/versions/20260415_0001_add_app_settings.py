"""Add app_settings key-value table (PRA-85)

Revision ID: pra85_appsettings
Revises: pra119_hostkey
Create Date: 2026-04-15

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra85_appsettings"
down_revision: Union[str, None] = "pra119_hostkey"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "setting_key",
            sa.String(100),
            unique=True,
            nullable=False,
            index=True,
        ),
        sa.Column("setting_value", sa.Text(), nullable=False),
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

    # Seed defaults
    op.execute(
        "INSERT INTO app_settings (setting_key, setting_value) VALUES "
        "('app_name', 'Praxis'), "
        "('timezone', 'UTC'), "
        "('date_format', 'YYYY-MM-DD'), "
        "('time_format', '24h')"
    )


def downgrade() -> None:
    op.drop_table("app_settings")
