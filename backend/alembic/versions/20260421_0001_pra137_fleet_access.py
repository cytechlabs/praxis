"""PRA-137: fleet access model + provisioning spine

Revision ID: pra137_fleet_access
Revises: pra128_129_ssh
Create Date: 2026-04-21

Creates the access-broker data model:
  - fleet_roles (role definitions with login mode, approvals, sudoers, OS groups)
  - access_bindings (subject x scope x fleet_role)
  - access_grants (materialised user x system x login grants)
  - host_user_states (ledger of provisioned accounts per host)

Seeds three built-in fleet roles mirroring the app-level roles:
admin, maintainer, auditor.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "pra137_fleet_access"
down_revision: Union[str, None] = "pra128_129_ssh"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -------------------------------------------------------------- fleet_roles
    op.create_table(
        "fleet_roles",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "login_mode",
            sa.String(20),
            nullable=False,
            server_default="per_user",
        ),
        sa.Column("role_account_name", sa.String(100), nullable=True),
        sa.Column("allowed_actions_json", sa.Text(), nullable=False),
        sa.Column(
            "session_requires_approval",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "totp_required",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column(
            "idle_timeout_s",
            sa.Integer(),
            nullable=False,
            server_default="900",
        ),
        sa.Column(
            "max_session_s",
            sa.Integer(),
            nullable=False,
            server_default="3600",
        ),
        sa.Column(
            "os_groups_json",
            sa.Text(),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("sudoers_snippet", sa.Text(), nullable=True),
        sa.Column(
            "is_builtin",
            sa.Boolean(),
            nullable=False,
            server_default="false",
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
    op.create_index("ix_fleet_roles_id", "fleet_roles", ["id"])

    # ---------------------------------------------------------- access_bindings
    op.create_table(
        "access_bindings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "subject_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "subject_app_role_id",
            sa.Integer(),
            sa.ForeignKey("role.id", ondelete="CASCADE"),
            nullable=True,
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
        sa.Column(
            "fleet_role_id",
            sa.Integer(),
            sa.ForeignKey("fleet_roles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("user.id"),
            nullable=True,
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
        "ix_access_bindings_subject_user_id",
        "access_bindings",
        ["subject_user_id"],
    )
    op.create_index(
        "ix_access_bindings_subject_app_role_id",
        "access_bindings",
        ["subject_app_role_id"],
    )
    op.create_index(
        "ix_access_bindings_scope_group_id",
        "access_bindings",
        ["scope_group_id"],
    )
    op.create_index(
        "ix_access_bindings_scope_smart_group_id",
        "access_bindings",
        ["scope_smart_group_id"],
    )
    op.create_index(
        "ix_access_bindings_fleet_role_id",
        "access_bindings",
        ["fleet_role_id"],
    )

    # ------------------------------------------------------------ access_grants
    op.create_table(
        "access_grants",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "fleet_role_id",
            sa.Integer(),
            sa.ForeignKey("fleet_roles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("login", sa.String(100), nullable=False),
        sa.Column(
            "via_binding_id",
            sa.Integer(),
            sa.ForeignKey("access_bindings.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "is_implicit_admin",
            sa.Boolean(),
            nullable=False,
            server_default="false",
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
    op.create_index("ix_access_grants_user_id", "access_grants", ["user_id"])
    op.create_index("ix_access_grants_system_id", "access_grants", ["system_id"])
    op.create_index(
        "ix_access_grants_fleet_role_id", "access_grants", ["fleet_role_id"]
    )
    op.create_index(
        "ix_access_grants_via_binding_id", "access_grants", ["via_binding_id"]
    )
    op.create_unique_constraint(
        "uq_access_grant_user_system_role_login",
        "access_grants",
        ["user_id", "system_id", "fleet_role_id", "login"],
    )

    # ---------------------------------------------------------- host_user_states
    op.create_table(
        "host_user_states",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("login", sa.String(100), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column(
            "state",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_reconciled_at", sa.DateTime(), nullable=True),
        sa.Column("home_archive_path", sa.Text(), nullable=True),
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
    op.create_index("ix_host_user_states_system_id", "host_user_states", ["system_id"])
    op.create_unique_constraint(
        "uq_host_user_state_system_login",
        "host_user_states",
        ["system_id", "login"],
    )

    # ------------------------------------------------------- seed built-in roles
    # Mirrors app-level roles (admin / maintainer / auditor) so the fleet-layer
    # role names match the app-layer role names operators already use.
    #   admin     — full access, wheel group, NOPASSWD sudo
    #   maintainer— full access, no OS group by default, NOPASSWD sudo
    #   auditor   — read-only session, no sudo, no exec, no transfer
    op.execute(
        """
        INSERT INTO fleet_roles (
            name, description, login_mode, role_account_name,
            allowed_actions_json, session_requires_approval, totp_required,
            idle_timeout_s, max_session_s, os_groups_json, sudoers_snippet,
            is_builtin
        ) VALUES
        (
            'admin',
            'Full administrative access. Interactive shell, command execution, file transfer, passwordless sudo. Added to wheel / sudo group (whichever exists on the host).',
            'per_user', NULL,
            '["session_open", "command_exec", "file_transfer"]',
            false, false, 900, 3600,
            '["wheel", "sudo"]',
            'ALL=(ALL) NOPASSWD:ALL',
            true
        ),
        (
            'maintainer',
            'Fleet operator. Interactive shell, command execution, file transfer, passwordless sudo.',
            'per_user', NULL,
            '["session_open", "command_exec", "file_transfer"]',
            false, false, 900, 3600,
            '[]',
            'ALL=(ALL) NOPASSWD:ALL',
            true
        ),
        (
            'auditor',
            'Read-only access. Interactive shell only. No command execution API, no file transfer, no sudo.',
            'per_user', NULL,
            '["session_open"]',
            false, false, 900, 3600,
            '[]',
            NULL,
            true
        );
        """
    )


def downgrade() -> None:
    op.drop_index("ix_host_user_states_system_id", table_name="host_user_states")
    op.drop_constraint(
        "uq_host_user_state_system_login",
        "host_user_states",
        type_="unique",
    )
    op.drop_table("host_user_states")

    op.drop_constraint(
        "uq_access_grant_user_system_role_login",
        "access_grants",
        type_="unique",
    )
    op.drop_index("ix_access_grants_via_binding_id", table_name="access_grants")
    op.drop_index("ix_access_grants_fleet_role_id", table_name="access_grants")
    op.drop_index("ix_access_grants_system_id", table_name="access_grants")
    op.drop_index("ix_access_grants_user_id", table_name="access_grants")
    op.drop_table("access_grants")

    op.drop_index("ix_access_bindings_fleet_role_id", table_name="access_bindings")
    op.drop_index(
        "ix_access_bindings_scope_smart_group_id", table_name="access_bindings"
    )
    op.drop_index("ix_access_bindings_scope_group_id", table_name="access_bindings")
    op.drop_index(
        "ix_access_bindings_subject_app_role_id", table_name="access_bindings"
    )
    op.drop_index("ix_access_bindings_subject_user_id", table_name="access_bindings")
    op.drop_table("access_bindings")

    op.drop_index("ix_fleet_roles_id", table_name="fleet_roles")
    op.drop_table("fleet_roles")
