"""PRA-139: TOTP enrollment + step-up challenges + JIT access requests

Revision ID: pra139_totp_access
Revises: pra138_principals_hook
Create Date: 2026-04-22

Adds:
  - user.totp_secret, user.totp_enrolled_at, user.totp_recovery_codes (JSON)
  - totp_challenges (per-user short-lived "fresh TOTP" markers)
  - access_requests (user-initiated JIT access requests, resolved into
    time-bound AccessBinding rows on approval)
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra139_totp_access"
down_revision: Union[str, None] = "pra138_principals_hook"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -------------------------------------------------------- TOTP on user
    op.add_column("user", sa.Column("totp_secret", sa.String(64), nullable=True))
    op.add_column("user", sa.Column("totp_enrolled_at", sa.DateTime(), nullable=True))
    # JSON list of bcrypt-hashed recovery codes; each burns on use.
    op.add_column("user", sa.Column("totp_recovery_codes", sa.Text(), nullable=True))

    # --------------------------------------------------------- totp_challenges
    # A successful step-up mints a challenge row valid for ~15 minutes.
    # authorization_service consults this when fleet_role.totp_required.
    op.create_table(
        "totp_challenges",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_totp_challenges_user_id", "totp_challenges", ["user_id"])
    op.create_index("ix_totp_challenges_expires_at", "totp_challenges", ["expires_at"])

    # --------------------------------------------------------- access_requests
    op.create_table(
        "access_requests",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "requested_by",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "fleet_role_id",
            sa.Integer(),
            sa.ForeignKey("fleet_roles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scope_group_id",
            sa.Integer(),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "scope_smart_group_id",
            sa.Integer(),
            sa.ForeignKey("smart_groups.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column(
            "duration_seconds", sa.Integer(), nullable=False, server_default="3600"
        ),
        # pending / approved / rejected / expired / revoked
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column(
            "decided_by",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("decision_comment", sa.Text(), nullable=True),
        # Set when approved: the AccessBinding this request produced.
        sa.Column(
            "resulting_binding_id",
            sa.Integer(),
            sa.ForeignKey("access_bindings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "requested_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
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
    op.create_index(
        "ix_access_requests_requested_by", "access_requests", ["requested_by"]
    )
    op.create_index("ix_access_requests_status", "access_requests", ["status"])


def downgrade() -> None:
    op.drop_index("ix_access_requests_status", table_name="access_requests")
    op.drop_index("ix_access_requests_requested_by", table_name="access_requests")
    op.drop_table("access_requests")

    op.drop_index("ix_totp_challenges_expires_at", table_name="totp_challenges")
    op.drop_index("ix_totp_challenges_user_id", table_name="totp_challenges")
    op.drop_table("totp_challenges")

    op.drop_column("user", "totp_recovery_codes")
    op.drop_column("user", "totp_enrolled_at")
    op.drop_column("user", "totp_secret")
