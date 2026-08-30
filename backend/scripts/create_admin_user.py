"""Bootstrap the first administrator. Runs on every boot, acts on the first.

The decision lives in ``app.services.bootstrap_admin_service``; this is the
entry point the production start script calls. An installation is provisioned
once, and a deliberately deleted, renamed, disabled, or de-roled administrator
is never recreated by a later restart.
"""

from app.db.session import SessionLocal
from app.services import bootstrap_admin_service as bootstrap

# Operator-facing summary of each outcome. The password is never read, echoed,
# or described here.
MESSAGES = {
    bootstrap.PROVISIONED: "Admin user created.",
    bootstrap.ADOPTED: (
        "This installation already has users; recorded as initialized. "
        "No admin user was created."
    ),
    bootstrap.ALREADY_INITIALIZED: (
        "This installation is already initialized. No admin user was created."
    ),
    bootstrap.SKIPPED_NO_PASSWORD: (
        "\n"
        "========================================\n"
        "  ADMIN_PASSWORD not set - skipping admin user creation.\n"
        "  Set ADMIN_PASSWORD in your .env file to create an admin user.\n"
        "========================================"
    ),
}


def create_admin_user():
    db = SessionLocal()
    outcome = bootstrap.ensure_bootstrap_admin(db)
    print(MESSAGES[outcome])
    return outcome


if __name__ == "__main__":
    create_admin_user()
