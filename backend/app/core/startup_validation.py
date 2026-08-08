"""PRA-179 Slice 5: production env / startup fail-clear validation.

This module's single public entry point ``validate_production_env`` is
called from ``backend/app/api/main.py`` at import time, *after* the
existing ``required_env_vars`` check has run. It complements the
existing weak-SECRET_KEY rejection in ``backend/app/core/auth.py``.

Design rules:

  * Production-only. Each rejection fires only when
    ``ENVIRONMENT == 'production'``; dev and test defaults stay
    untouched. The exception is the closed-set check on
    ``ENVIRONMENT`` itself, which always runs because an unknown
    value (e.g. the common typo ``ENVIRONMENT=prod``) silently
    disables every other production gate — including the existing
    weak-SECRET_KEY rejection. Closed set: ``development`` /
    ``production`` / ``test``.
  * Each failure raises ``RuntimeError`` with an actionable
    message: which env var, what value tripped the gate, and how to
    fix it. The message names the variable explicitly so the operator
    can ``grep .env`` for it.
  * No I/O. The validator only reads environment variables (and an
    optional ``vault_token_path`` if explicitly passed). It does NOT
    talk to Vault, Postgres, or the filesystem. That keeps it cheap to
    call at every backend / broker boot and easy to unit-test with
    ``monkeypatch.setenv``.
  * The validator can be re-called safely. Backend, broker, and any
    future short-lived process all benefit from the same gate.
"""

from __future__ import annotations

import os
from typing import Optional

# Closed set of accepted ``ENVIRONMENT`` values. Both ``test`` and
# ``testing`` are included because pytest paths in this repo use
# ``ENVIRONMENT=testing`` (CI workflow + ``TESTING=True`` shim) and
# other paths use ``ENVIRONMENT=test`` — both have been load-bearing
# in the codebase. Anything outside this set is rejected at every
# startup to catch the typo class (``prod``, ``Production``, etc.)
# that would otherwise silently disable every production-only check.
ALLOWED_ENVIRONMENTS = frozenset({"development", "production", "test", "testing"})

# Default bundled-mode Postgres password from ``docker-compose.yml``
# and ``.env.example``. If an operator leaves this in place when
# ENVIRONMENT=production they ship the default credential to whatever
# their bundled ``db`` container is reachable from.
DEFAULT_POSTGRES_PASSWORD = "postgres"

# Bundled-mode VAULT_ADDR. The backend treats this as the signal that
# the operator is *not* on external Vault and the bundled init script
# is responsible for issuing the backend token via the shared volume.
BUNDLED_VAULT_ADDR = "http://vault:8200"


class StartupValidationError(RuntimeError):
    """Raised when a production-env invariant is violated."""


def _is_bundled_vault(vault_addr: Optional[str]) -> bool:
    """Bundled Vault ⇔ VAULT_ADDR is empty/unset (use default) OR
    explicitly matches the in-stack ``http://vault:8200`` URL.
    Anything else is treated as external."""
    if not vault_addr:
        return True
    return vault_addr.strip() == BUNDLED_VAULT_ADDR


def _is_bundled_postgres(database_url: Optional[str]) -> bool:
    """Bundled Postgres ⇔ ``DATABASE_URL`` is unset (compose builds
    the default), OR points at the in-stack ``db`` host (matches the
    docker-compose service name)."""
    if not database_url:
        return True
    # The bundled DSN built by docker-compose.yml looks like:
    #   postgresql://${POSTGRES_USER:-postgres}:${POSTGRES_PASSWORD:-postgres}@db:5432/${POSTGRES_DB:-praxis}
    # so any DSN whose host is exactly ``db`` is bundled.
    return (
        "@db:" in database_url
        or database_url.endswith("@db")
        or database_url.startswith("postgresql://postgres:postgres@db")
    )


def validate_production_env(
    env: Optional[dict] = None,
    *,
    user_count: Optional[int] = None,
) -> None:
    """Apply production fail-clear rejections.

    :param env: optional dict to use in place of ``os.environ`` for
        unit-test purposes. Defaults to ``os.environ``.
    :param user_count: optional count of existing users in the
        database. Passed in by the backend boot path *after* the
        admin-create step has run. ``None`` means "don't enforce the
        ADMIN_PASSWORD rule" (test/unit-call) — when the boot path
        passes ``0`` and ``ADMIN_PASSWORD`` is empty, we know no
        admin will be created and the deployment will have no
        usable login. Production callers should pass a real count.
    :raises StartupValidationError: when any production invariant is
        violated. Message names the variable and the corrective action.
    """
    src = env if env is not None else os.environ

    environment = (src.get("ENVIRONMENT") or "development").strip()

    # Closed-set ENVIRONMENT check fires in every mode. A typo like
    # ``ENVIRONMENT=prod`` would otherwise silently demote the
    # deployment to development behavior (docs/openapi visible, weak
    # SECRET_KEY accepted, etc.).
    if environment not in ALLOWED_ENVIRONMENTS:
        raise StartupValidationError(
            f"ENVIRONMENT='{environment}' is not in the closed set "
            f"{sorted(ALLOWED_ENVIRONMENTS)}. Set ENVIRONMENT to one "
            "of 'development', 'production', or 'test' in your .env."
        )

    if environment != "production":
        return

    # ── Production-only checks ───────────────────────────────────────

    # 1. POSTGRES_PASSWORD in bundled mode must not be the well-known
    #    default. External-Postgres operators set DATABASE_URL with
    #    their own credentials, so the gate is bundled-only.
    pg_password = src.get("POSTGRES_PASSWORD", "")
    database_url = src.get("DATABASE_URL", "")
    if _is_bundled_postgres(database_url) and pg_password == DEFAULT_POSTGRES_PASSWORD:
        raise StartupValidationError(
            "POSTGRES_PASSWORD is set to the default 'postgres' value "
            "in a bundled production deployment. Generate a strong "
            'password (e.g. `python -c "import secrets; '
            'print(secrets.token_urlsafe(32))"`) and set '
            "POSTGRES_PASSWORD in your .env."
        )

    # 2. VAULT_TOKEN must be non-empty when running with external
    #    Vault. In bundled mode the backend reads the token from
    #    /vault/data/backend-token at runtime, so empty is correct.
    vault_addr = src.get("VAULT_ADDR", "")
    vault_token = src.get("VAULT_TOKEN", "")
    if not _is_bundled_vault(vault_addr) and not vault_token:
        raise StartupValidationError(
            f"VAULT_ADDR='{vault_addr}' is set (external Vault), but "
            "VAULT_TOKEN is empty. External Vault deployments must "
            "supply a token via VAULT_TOKEN. Bundled-Vault deployments "
            "should leave VAULT_ADDR unset or set to "
            f"'{BUNDLED_VAULT_ADDR}'."
        )

    # 3. ADMIN_PASSWORD must be non-empty when no admin user exists
    #    yet. The backend's ``scripts/create_admin_user.py`` silently
    #    skips creation when ADMIN_PASSWORD is empty, which leaves a
    #    production deployment with no usable login. We only enforce
    #    this when the caller passes a real user_count; tests and
    #    repeated boots against an existing DB skip the gate.
    admin_password = src.get("ADMIN_PASSWORD", "")
    if user_count is not None and user_count == 0 and not admin_password:
        raise StartupValidationError(
            "ADMIN_PASSWORD is empty and no users exist yet in the "
            "database. A production deployment without an initial "
            "admin user is unreachable. Set ADMIN_PASSWORD in your "
            ".env so scripts/create_admin_user.py provisions the "
            "first admin."
        )
