"""
Seed a default SSHSecurityPolicy on startup (PRA-119).

Idempotent — if a policy named "Default" already exists, do nothing.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.db.models import System, User  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.db.ssh_security_models import SSHSecurityPolicy  # noqa: E402


def main():
    db = SessionLocal()
    try:
        policy = (
            db.query(SSHSecurityPolicy)
            .filter(SSHSecurityPolicy.name == "Default")
            .first()
        )

        if not policy:
            admin = db.query(User).filter(User.username == "admin").first()
            if not admin:
                print("Admin user not found — skipping SSHSecurityPolicy seed.")
                return
            policy = SSHSecurityPolicy(
                name="Default",
                description="Seeded default policy. Enforces host key verification (TOFU) and sensible crypto defaults.",
                require_host_key_verification=True,
                log_commands=True,
                created_by=admin.id,
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
            print(f"Default SSHSecurityPolicy created (id={policy.id}).")
        else:
            print("Default SSHSecurityPolicy already exists.")

        # Backfill any system missing a policy
        orphans = db.query(System).filter(System.ssh_security_policy_id.is_(None)).all()
        if orphans:
            for system in orphans:
                system.ssh_security_policy_id = policy.id
            db.commit()
            print(f"Attached Default policy to {len(orphans)} existing system(s).")
    finally:
        db.close()


if __name__ == "__main__":
    main()
