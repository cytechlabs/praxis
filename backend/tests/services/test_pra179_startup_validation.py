"""PRA-179 Slice 5: fail-clear production startup validation.

Unit-style tests for ``app.core.startup_validation.validate_production_env``.
Each test isolates the env by passing an explicit dict, so the suite never
touches ``os.environ`` or the running stack.
"""

from __future__ import annotations

import pytest

from app.core.startup_validation import (
    BUNDLED_VAULT_ADDR,
    DEFAULT_POSTGRES_PASSWORD,
    StartupValidationError,
    validate_production_env,
)

# ---------------------------------------------------------------- ENVIRONMENT


def test_unknown_environment_is_rejected_in_every_mode() -> None:
    """A typo like ``ENVIRONMENT=prod`` would otherwise silently demote
    a production deployment to dev behavior — docs/openapi exposed,
    weak SECRET_KEY accepted. The closed-set check fires unconditionally
    so the typo class is caught before any other gate."""
    with pytest.raises(StartupValidationError, match="ENVIRONMENT='prod'"):
        validate_production_env(env={"ENVIRONMENT": "prod"})


def test_known_environments_are_accepted() -> None:
    """``development`` / ``production`` / ``test`` are the closed set."""
    # development: no production rules fire.
    validate_production_env(env={"ENVIRONMENT": "development"})
    # test: same as development for env validation.
    validate_production_env(env={"ENVIRONMENT": "test"})
    # production with otherwise-clean env: must not raise.
    validate_production_env(
        env={
            "ENVIRONMENT": "production",
            "POSTGRES_PASSWORD": "real-non-default-password",
            "VAULT_ADDR": BUNDLED_VAULT_ADDR,
        },
    )


def test_empty_environment_defaults_to_development() -> None:
    """Missing ENVIRONMENT must NOT crash the gate (matches the
    existing dev-default posture)."""
    validate_production_env(env={})


# ---------------------------------------------------------------- POSTGRES


def test_default_postgres_password_rejected_in_bundled_production() -> None:
    """The ``postgres`` default ships in ``.env.example`` for dev
    convenience. Leaving it on a bundled production deployment is the
    classic accidental-default credential. External-Postgres operators
    set their own DATABASE_URL, so the check is bundled-only."""
    with pytest.raises(StartupValidationError, match="POSTGRES_PASSWORD"):
        validate_production_env(
            env={
                "ENVIRONMENT": "production",
                "POSTGRES_PASSWORD": DEFAULT_POSTGRES_PASSWORD,
                "VAULT_ADDR": BUNDLED_VAULT_ADDR,
            },
        )


def test_non_default_postgres_password_accepted_in_bundled_production() -> None:
    """Any value other than the literal ``postgres`` default passes."""
    validate_production_env(
        env={
            "ENVIRONMENT": "production",
            "POSTGRES_PASSWORD": "rotated-secret",
            "VAULT_ADDR": BUNDLED_VAULT_ADDR,
        },
    )


def test_default_postgres_password_accepted_in_external_postgres_mode() -> None:
    """External-Postgres deployments set DATABASE_URL with their own
    credentials. POSTGRES_PASSWORD is irrelevant in that mode (it only
    feeds the bundled-db init), so the gate must not fire there."""
    validate_production_env(
        env={
            "ENVIRONMENT": "production",
            "POSTGRES_PASSWORD": DEFAULT_POSTGRES_PASSWORD,
            "DATABASE_URL": "postgresql://praxis_app:realpw@db.corp.example:5432/praxis",
            "VAULT_ADDR": BUNDLED_VAULT_ADDR,
        },
    )


# ---------------------------------------------------------------- VAULT


def test_empty_vault_token_rejected_in_external_vault_mode() -> None:
    """External Vault → backend MUST present a token. In bundled mode
    the token is read from the shared volume at runtime, so empty is
    correct; the gate fires only when VAULT_ADDR is non-bundled."""
    with pytest.raises(StartupValidationError, match="VAULT_TOKEN is empty"):
        validate_production_env(
            env={
                "ENVIRONMENT": "production",
                "POSTGRES_PASSWORD": "rotated-secret",
                "VAULT_ADDR": "https://vault.corp.example:8200",
                "VAULT_TOKEN": "",
            },
        )


def test_empty_vault_token_accepted_in_bundled_vault_mode() -> None:
    """Bundled-Vault deployments read the token from the shared
    /vault/data/backend-token at runtime, so VAULT_TOKEN unset is
    the correct posture."""
    validate_production_env(
        env={
            "ENVIRONMENT": "production",
            "POSTGRES_PASSWORD": "rotated-secret",
            "VAULT_ADDR": BUNDLED_VAULT_ADDR,
            "VAULT_TOKEN": "",
        },
    )


def test_external_vault_with_token_accepted() -> None:
    validate_production_env(
        env={
            "ENVIRONMENT": "production",
            "POSTGRES_PASSWORD": "rotated-secret",
            "VAULT_ADDR": "https://vault.corp.example:8200",
            "VAULT_TOKEN": "s.abc123-real-token",
        },
    )


# ---------------------------------------------------------------- ADMIN


def test_empty_admin_password_rejected_in_production_with_no_users() -> None:
    """A fresh deployment with no admin user and no ADMIN_PASSWORD
    has no usable login — the validator surfaces this loudly instead
    of letting ``create_admin_user.py`` silently skip."""
    with pytest.raises(StartupValidationError, match="ADMIN_PASSWORD is empty"):
        validate_production_env(
            env={
                "ENVIRONMENT": "production",
                "POSTGRES_PASSWORD": "rotated-secret",
                "VAULT_ADDR": BUNDLED_VAULT_ADDR,
                "ADMIN_PASSWORD": "",
            },
            user_count=0,
        )


def test_empty_admin_password_accepted_when_users_already_exist() -> None:
    """Subsequent boots of a production deployment that already has
    users skip the ADMIN_PASSWORD gate — the operator has presumably
    rotated to per-user logins."""
    validate_production_env(
        env={
            "ENVIRONMENT": "production",
            "POSTGRES_PASSWORD": "rotated-secret",
            "VAULT_ADDR": BUNDLED_VAULT_ADDR,
            "ADMIN_PASSWORD": "",
        },
        user_count=5,
    )


def test_admin_password_gate_skipped_when_user_count_is_none() -> None:
    """``validate_production_env`` is called from the FastAPI module
    import path without a ``user_count`` (no DB connection at that
    layer). The gate is deferred to ``create_admin_user.py`` where
    the count is known."""
    validate_production_env(
        env={
            "ENVIRONMENT": "production",
            "POSTGRES_PASSWORD": "rotated-secret",
            "VAULT_ADDR": BUNDLED_VAULT_ADDR,
            "ADMIN_PASSWORD": "",
        },
        # user_count omitted => None => skip
    )


# ---------------------------------------------------------------- aggregate


def test_clean_production_env_passes() -> None:
    """The happy path: every gate satisfied."""
    validate_production_env(
        env={
            "ENVIRONMENT": "production",
            "POSTGRES_PASSWORD": "rotated-secret",
            "VAULT_ADDR": BUNDLED_VAULT_ADDR,
            "VAULT_TOKEN": "",
            "ADMIN_PASSWORD": "strong-admin-password",
        },
        user_count=0,
    )
