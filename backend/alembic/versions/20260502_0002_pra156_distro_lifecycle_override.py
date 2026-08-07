"""PRA-156 slice #3e-a: distro_lifecycle_override table.

Per-scope lifecycle overrides — operators with Ubuntu Pro / RHEL ELS /
vendor extended-support contracts mark the relevant smart group as
eligible here, and ``LifecycleService.compute`` picks up the override's
later eol_date instead of the global standard row.

Scope is locked to ``smart_group`` for v1. ``scope_type`` is a real
column with a CHECK constraint so future static-group / customer
scope additions are explicit, documented schema changes rather than
silent breaks. Same discipline applies to ``support_kind`` —
``extended`` only for v1.

Lookup precedence is the same as the standard row in #3a-α: exact
release wins, then RHEL-family major fallback. Among matching
overrides, latest eol_date wins, then newest updated_at, then highest
id (deterministic tie-break).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pra156_distro_lifecycle_override"
down_revision: Union[str, None] = "pra156_distro_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "distro_lifecycle_override",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("scope_type", sa.String(16), nullable=False),
        sa.Column("scope_id", sa.Integer, nullable=False),
        sa.Column("distro_id", sa.String(64), nullable=False),
        sa.Column("release", sa.String(64), nullable=False),
        sa.Column("eol_date", sa.Date, nullable=False),
        sa.Column("support_kind", sa.String(16), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
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
        sa.UniqueConstraint(
            "scope_type",
            "scope_id",
            "distro_id",
            "release",
            name="distro_lifecycle_override_unique_per_scope",
        ),
        sa.CheckConstraint(
            "scope_type IN ('smart_group')",
            name="distro_lifecycle_override_scope_type_valid",
        ),
        sa.CheckConstraint(
            "support_kind IN ('extended')",
            name="distro_lifecycle_override_support_kind_valid",
        ),
    )
    op.create_index(
        "ix_distro_lifecycle_override_scope",
        "distro_lifecycle_override",
        ["scope_type", "scope_id", "distro_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_distro_lifecycle_override_scope",
        table_name="distro_lifecycle_override",
    )
    op.drop_table("distro_lifecycle_override")
