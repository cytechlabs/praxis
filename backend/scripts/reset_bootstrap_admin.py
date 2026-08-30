"""Clear the first-run record so a locked-out installation can bootstrap again.

Run by hand, never from startup:

    docker compose exec backend python /app/scripts/reset_bootstrap_admin.py

Deleting every user leaves an installation with no way to sign in, and the
first-run record stops the next boot from provisioning one. This clears that
record; the following restart provisions the administrator from the configured
environment exactly as a first boot would.

It refuses while any user exists. The record is what keeps a deliberately
deleted administrator deleted, so clearing it on an installation that still has
a login would hand back the behavior it removes. Nothing here reads, prints, or
accepts credential material.
"""

from app.db.session import SessionLocal
from app.services import bootstrap_admin_service as bootstrap

MESSAGES = {
    bootstrap.RESET_CLEARED: (
        "First-run record cleared. Restart the backend to provision the "
        "administrator from the configured environment."
    ),
    bootstrap.RESET_NOT_INITIALIZED: (
        "This installation has no first-run record; nothing to clear. The next "
        "boot will provision the administrator."
    ),
}


def reset_bootstrap_admin() -> int:
    db = SessionLocal()
    try:
        outcome = bootstrap.reset_bootstrap_state(db)
    except bootstrap.BootstrapAdminError as exc:
        print(f"Refused. {exc}")
        return 1
    print(MESSAGES[outcome])
    return 0


if __name__ == "__main__":
    raise SystemExit(reset_bootstrap_admin())
