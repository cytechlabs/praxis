"""M5: Vault token to env, credential redesign - all secrets to Vault

PRA-91: Remove token from vault_config (now read from VAULT_TOKEN env var)
PRA-93: Credential model redesign - rename type->auth_method, drop secret columns

Revision ID: m5a1b2c3d4e5
Revises: s1t2u3v4w5x6
Create Date: 2026-04-12

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "m5a1b2c3d4e5"
down_revision: Union[str, None] = "s1t2u3v4w5x6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PRA-91: Remove token from vault_config, make created_by nullable
    op.drop_column("vault_config", "token")
    op.alter_column("vault_config", "created_by", nullable=True)

    # PRA-93: Credential model redesign
    # Rename type -> auth_method
    op.alter_column(
        "credentials", "type", new_column_name="auth_method", type_=sa.String(50)
    )

    # Add vault_path column (will be populated by data migration)
    op.add_column("credentials", sa.Column("vault_path", sa.String(512), nullable=True))

    # Data migration: set vault_path for existing credentials
    # For vault-type credentials, copy vault_kv_path to vault_path
    # For password/ssh_key types, generate vault_path from name
    conn = op.get_bind()

    # Get all credentials
    results = conn.execute(
        sa.text("SELECT id, name, auth_method, vault_kv_path FROM credentials")
    ).fetchall()

    for row in results:
        cred_id, name, auth_method, vault_kv_path = row
        if auth_method == "vault" and vault_kv_path:
            # Grandfathered vault credentials keep their custom path
            vault_path = vault_kv_path
            # Determine actual auth_method by inspecting vault secret (not possible in migration)
            # Default to password for vault-type, can be corrected later
            new_auth_method = "password"
        else:
            # Generate standard path for non-vault credentials
            safe_name = "".join(
                c if c.isalnum() or c in "-_" else "-" for c in name.lower()
            )
            vault_path = f"praxis/credentials/{safe_name}"
            new_auth_method = auth_method

        conn.execute(
            sa.text(
                "UPDATE credentials SET vault_path = :vault_path, auth_method = :auth_method WHERE id = :id"
            ),
            {"vault_path": vault_path, "auth_method": new_auth_method, "id": cred_id},
        )

    # Drop old secret columns and vault_kv_path
    op.drop_column("credentials", "password")
    op.drop_column("credentials", "ssh_key")
    op.drop_column("credentials", "sudo_password")
    op.drop_column("credentials", "vault_kv_path")


def downgrade() -> None:
    # Restore secret columns
    op.add_column("credentials", sa.Column("password", sa.Text, nullable=True))
    op.add_column("credentials", sa.Column("ssh_key", sa.Text, nullable=True))
    op.add_column("credentials", sa.Column("sudo_password", sa.Text, nullable=True))
    op.add_column(
        "credentials", sa.Column("vault_kv_path", sa.String(255), nullable=True)
    )

    # Rename auth_method back to type
    op.alter_column(
        "credentials", "auth_method", new_column_name="type", type_=sa.String(50)
    )

    # Drop vault_path
    op.drop_column("credentials", "vault_path")

    # Restore vault_config.token
    op.add_column(
        "vault_config",
        sa.Column("token", sa.String(255), nullable=True),
    )
    op.alter_column("vault_config", "created_by", nullable=False)
