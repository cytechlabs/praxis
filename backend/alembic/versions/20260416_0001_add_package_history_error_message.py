"""Add error_message to package_history (PRA-63)

Revision ID: pra63_pkgerror
Revises: pra85_appsettings
Create Date: 2026-04-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra63_pkgerror"
down_revision: Union[str, None] = "pra85_appsettings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "package_history",
        sa.Column("error_message", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("package_history", "error_message")
