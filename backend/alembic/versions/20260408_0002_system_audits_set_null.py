"""make system_audits.system_id nullable with ON DELETE SET NULL (PRA-14)

Revision ID: k1l2m3n4o5p6
Revises: j0k1l2m3n4o5
Create Date: 2026-04-08

Audit history must survive system deletion. The original schema declared
system_audits.system_id as NOT NULL with a default-action FK; this migration
relaxes the column to NULL and switches the FK to ON DELETE SET NULL so
deleted-system audit rows persist with system_id=NULL.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "k1l2m3n4o5p6"
down_revision: Union[str, None] = "j0k1l2m3n4o5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "system_audits",
        "system_id",
        existing_type=sa.Integer(),
        nullable=True,
    )
    op.drop_constraint(
        "system_audits_system_id_fkey", "system_audits", type_="foreignkey"
    )
    op.create_foreign_key(
        "system_audits_system_id_fkey",
        "system_audits",
        "systems",
        ["system_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "system_audits_system_id_fkey", "system_audits", type_="foreignkey"
    )
    op.create_foreign_key(
        "system_audits_system_id_fkey",
        "system_audits",
        "systems",
        ["system_id"],
        ["id"],
    )
    op.alter_column(
        "system_audits",
        "system_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
