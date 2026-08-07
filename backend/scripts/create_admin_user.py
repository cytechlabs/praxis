import os

from app.core.auth import get_password_hash
from app.core.startup_validation import validate_production_env
from app.db.models import Role, User
from app.db.session import SessionLocal


def create_admin_user():
    db = SessionLocal()

    # Ensure admin role exists
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(name="admin", description="Administrator role")
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)
        print("Admin role created.")

    # Ensure maintainer and auditor roles exist
    for role_name, role_desc in [
        ("maintainer", "Maintainer role"),
        ("auditor", "Auditor role"),
    ]:
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            db.add(Role(name=role_name, description=role_desc))
            db.commit()
            print(f"{role_name.capitalize()} role created.")

    # Read admin credentials from env.
    # PRA-304: default the bootstrap USERNAME to ``praxisadmin`` (not ``admin``).
    # Per-user fleet access maps the Praxis username to the managed Linux login, and
    # real hosts commonly already have an ``admin`` user/group — which PRA-286
    # ownership-marker hardening (correctly) fails closed on. ``praxisadmin`` is far
    # less collision-prone. The application role stays ``admin``/Administrator.
    admin_username = os.getenv("ADMIN_USERNAME", "praxisadmin")
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    admin_email = os.getenv("ADMIN_EMAIL", "praxisadmin@praxis.dev")

    # PRA-179 Slice 5: in production, an empty ADMIN_PASSWORD on a
    # fresh deployment (user_count == 0) leaves the system with no
    # usable login. validate_production_env raises a clear
    # StartupValidationError in that case instead of letting this
    # script silently skip. In dev/test or on a deployment that
    # already has users, the gate is a no-op.
    existing_user_count = db.query(User).count()
    validate_production_env(user_count=existing_user_count)

    if not admin_password:
        print(
            "\n"
            "========================================\n"
            "  ADMIN_PASSWORD not set - skipping admin user creation.\n"
            "  Set ADMIN_PASSWORD in your .env file to create an admin user.\n"
            "========================================"
        )
        return

    # Check if admin user already exists
    admin_user = db.query(User).filter(User.username == admin_username).first()
    if not admin_user:
        new_admin = User(
            username=admin_username,
            email=admin_email,
            hashed_password=get_password_hash(admin_password),
            is_active=True,
            roles=[admin_role],
        )
        db.add(new_admin)
        db.commit()
        print(f"Admin user created: {admin_username}")
    else:
        print(f"Admin user '{admin_username}' already exists.")


if __name__ == "__main__":
    create_admin_user()
