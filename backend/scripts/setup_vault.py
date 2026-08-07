"""Auto-configure Vault connection on startup.

Behavior:
- If VAULT_TOKEN is unset: skip configuration entirely (operator must configure later).
- If VAULT_ADDR is set to anything other than the bundled vault (http://vault:8200):
    create an external VaultConfig pointing at that URL.
- Otherwise: create an internal VaultConfig (uses the bundled vault container).

Idempotent — if an active config already exists, leaves it alone.
"""

import os

from app.db.models import VaultConfig
from app.db.session import SessionLocal

INTERNAL_VAULT_URL = "http://vault:8200"


def setup_vault():
    vault_token = os.getenv("VAULT_TOKEN", "")
    if not vault_token:
        print("No VAULT_TOKEN set - skipping Vault auto-configuration")
        return

    vault_addr = os.getenv("VAULT_ADDR", "").strip()
    is_external = bool(vault_addr) and vault_addr != INTERNAL_VAULT_URL

    db = SessionLocal()
    try:
        active = db.query(VaultConfig).filter(VaultConfig.is_active.is_(True)).first()
        if active:
            print(f"Active Vault config exists (id={active.id})")
            return

        config = VaultConfig(
            is_internal=not is_external,
            server_url=vault_addr if is_external else None,
            is_active=True,
        )
        db.add(config)
        db.commit()
        mode = "external" if is_external else "internal"
        print(
            f"Vault configuration auto-created ({mode}"
            f"{': ' + vault_addr if is_external else ''})"
        )
    finally:
        db.close()


if __name__ == "__main__":
    setup_vault()
