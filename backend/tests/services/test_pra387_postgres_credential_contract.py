"""PRA-387: bundled PostgreSQL credential contract.

No database password ships in this repository. The deployment supplies it, and
enforcement happens at **startup**, not at Compose interpolation.

That boundary is deliberate. Compose evaluates every interpolation eagerly,
regardless of which profile is active, so a required ``POSTGRES_PASSWORD`` would
also force external-database deployments to define a variable they never use.
The contract is therefore:

- external mode needs only a complete ``DATABASE_URL`` and renders and runs with
  ``POSTGRES_PASSWORD`` unset;
- bundled mode renders an empty-password URL when no credential was supplied,
  and every process that would use it exits first: the ``db`` entrypoint before
  the server accepts connections, the backend and broker in
  ``validate_database_credentials`` before binding a listener, and
  ``scripts/backup.sh`` before ``pg_dump`` runs;
- the retired ``postgres`` value is rejected the same way as a missing one.

Source assertions parse the compose files as text (no PyYAML in the backend/CI
image). Rendered ``docker compose config`` checks are bonus coverage and skip
when docker is unavailable, mirroring ``test_pra299_prod_compose_contract``.
Renders run against an empty env file so a developer's repo-root ``.env`` cannot
satisfy a case that must fail.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app.core.startup_validation import (
    DEFAULT_POSTGRES_PASSWORD,
    StartupValidationError,
    validate_database_credentials,
)

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "docker-compose.yml"
COMPOSE_PROD = REPO / "docker-compose.prod.yml"
BACKUP_SH = REPO / "scripts" / "backup.sh"
ENV_EXAMPLE = REPO / ".env.example"
BACKEND_ENV_EXAMPLE = REPO / "backend" / ".env.example"
ALEMBIC_ENV = REPO / "backend" / "alembic" / "env.py"

if not COMPOSE.exists() or not COMPOSE_PROD.exists():  # pragma: no cover - layout
    pytest.skip(
        "compose files not available (repo root missing)", allow_module_level=True
    )

TEST_PASSWORD = "pra387testpassword"
EXTERNAL_DSN = "postgresql://praxis_app:externalpw@db.corp.example:5432/praxis"

# A non-empty default for POSTGRES_PASSWORD in any form, e.g. the
# ``${POSTGRES_PASSWORD:-postgres}`` shape the static analyzer flagged. The
# empty form ``${POSTGRES_PASSWORD:-}`` is the supported shape: it supplies no
# credential and keeps external mode from needing the variable at all.
NONEMPTY_FALLBACK = re.compile(r"\$\{POSTGRES_PASSWORD:-[^}]+\}")


# --------------------------------------------------- source assertions


def test_compose_files_ship_no_password_and_no_fallback():
    for path in (COMPOSE, COMPOSE_PROD):
        text = path.read_text()
        assert not NONEMPTY_FALLBACK.search(
            text
        ), f"{path.name} must not define a POSTGRES_PASSWORD fallback value"
        assert (
            "postgres:postgres@" not in text
        ), f"{path.name} must not embed a literal postgres:postgres credential"


def test_compose_does_not_require_the_password_at_interpolation():
    """A ``:?`` guard would abort rendering for external deployments too, since
    Compose interpolates every service regardless of the active profile."""
    for path in (COMPOSE, COMPOSE_PROD):
        assert (
            "${POSTGRES_PASSWORD:?" not in path.read_text()
        ), f"{path.name} must not make POSTGRES_PASSWORD a required variable"


def test_every_bundled_connection_site_uses_the_empty_default():
    """The three flagged connection strings plus both services that carry the
    credential all read POSTGRES_PASSWORD with no value of their own."""
    lines = [
        ln
        for ln in COMPOSE.read_text().splitlines()
        if "POSTGRES_PASSWORD" in ln
        and not ln.lstrip().startswith("#")
        and "echo" not in ln
        and "$$POSTGRES_PASSWORD" not in ln
    ]
    # backend DATABASE_URL + TEST_DATABASE_URL, broker DATABASE_URL, db, db_backup
    assert len(lines) == 5, f"unexpected POSTGRES_PASSWORD sites: {lines}"
    for ln in lines:
        assert "${POSTGRES_PASSWORD:-}" in ln, f"unexpected shape: {ln.strip()}"


def test_db_service_preflights_the_credential_before_starting_postgres():
    """The stock image only rejects an empty password while initializing an
    empty volume, so the entrypoint has to check on every start."""
    text = COMPOSE.read_text()
    assert 'if [ -z "$$POSTGRES_PASSWORD" ]; then' in text
    assert 'if [ "$$POSTGRES_PASSWORD" = "postgres" ]; then' in text
    assert (
        'exec docker-entrypoint.sh "$$@"' in text
    ), "preflight must hand off to the stock entrypoint on success"
    assert (
        '[ "$$#" -eq 0 ] && set -- postgres' in text
    ), "declaring an entrypoint clears the image command, so it must be restored"


def test_backup_script_has_no_password_fallback():
    text = BACKUP_SH.read_text()
    assert not NONEMPTY_FALLBACK.search(
        text
    ), "backup.sh must not fall back to a password"
    assert (
        "${POSTGRES_PASSWORD:?" in text
    ), "backup.sh must exit before dumping without a credential"


def test_env_examples_ship_no_credential_value():
    """These files are copied verbatim; any value here is a repository-defined
    credential in every fresh install."""
    for ln in ENV_EXAMPLE.read_text().splitlines():
        if ln.startswith("POSTGRES_PASSWORD"):
            assert ln.strip() == "POSTGRES_PASSWORD=", f"value shipped: {ln!r}"
    for ln in BACKEND_ENV_EXAMPLE.read_text().splitlines():
        stripped = ln.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith(
            "DATABASE_URL="
        ), f"backend/.env.example must not ship an active DSN: {ln!r}"
        if stripped.startswith("POSTGRES_PASSWORD"):
            assert stripped == "POSTGRES_PASSWORD=", f"value shipped: {ln!r}"


def test_alembic_url_builder_has_no_password_default():
    assert (
        'os.getenv("POSTGRES_PASSWORD", "postgres")' not in ALEMBIC_ENV.read_text()
    ), "migrations must not default the database password"


# --------------------------------------------------- rendered config


def _compose_config(args, env_overrides=None, env_file=None):
    """Run ``docker compose config`` with a controlled environment."""
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"POSTGRES_PASSWORD", "DATABASE_URL", "TEST_DATABASE_URL"}
    }
    env.setdefault("SECRET_KEY", "test-secret")
    if env_overrides:
        env.update(env_overrides)
    try:
        return subprocess.run(
            ["docker", "compose", "--env-file", str(env_file), *args, "config"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        pytest.skip("docker compose config not runnable here")


@pytest.fixture
def empty_env_file(tmp_path):
    """Compose otherwise reads the repo-root ``.env``, which on a developer
    machine already defines POSTGRES_PASSWORD."""
    path = tmp_path / "empty.env"
    path.write_text("")
    return path


BASE = ["-f", str(COMPOSE)]
PROD = ["-f", str(COMPOSE), "-f", str(COMPOSE_PROD)]
BUNDLED = ["--profile", "bundled"]
PROXY = ["--profile", "proxy"]

ALL_SHAPES = [
    pytest.param(BASE, id="base"),
    pytest.param(BASE + BUNDLED, id="base-bundled"),
    pytest.param(PROD + BUNDLED + PROXY, id="prod-bundled-proxy"),
]


@pytest.mark.parametrize("args", ALL_SHAPES)
def test_external_database_url_renders_without_postgres_password(args, empty_env_file):
    """The selected contract: external mode needs only its own DATABASE_URL and
    must never require an unused duplicate secret."""
    proc = _compose_config(args, {"DATABASE_URL": EXTERNAL_DSN}, empty_env_file)
    assert proc.returncode == 0, (
        "external mode must render with POSTGRES_PASSWORD unset, but Compose "
        f"failed: {proc.stderr[:300]}"
    )
    assert (
        "POSTGRES_PASSWORD" not in proc.stderr
    ), f"Compose must not warn or error about POSTGRES_PASSWORD: {proc.stderr[:300]}"
    rendered = [
        ln.strip()
        for ln in proc.stdout.splitlines()
        if ln.strip().startswith("DATABASE_URL:")
    ]
    assert rendered, "no DATABASE_URL rendered"
    for ln in rendered:
        assert ln == f"DATABASE_URL: {EXTERNAL_DSN}", ln


@pytest.mark.parametrize("args", ALL_SHAPES)
def test_explicit_password_renders_and_is_the_only_credential(args, empty_env_file):
    proc = _compose_config(args, {"POSTGRES_PASSWORD": TEST_PASSWORD}, empty_env_file)
    if proc.returncode != 0:  # pragma: no cover - plugin/env unavailable
        pytest.skip(f"docker compose config failed: {proc.stderr[:200]}")
    assert TEST_PASSWORD in proc.stdout, "explicit credential did not reach the config"
    assert (
        "postgres:postgres@" not in proc.stdout
    ), "rendered config still carries the known default credential"


@pytest.mark.parametrize("args", ALL_SHAPES)
def test_bundled_without_a_credential_renders_an_unusable_url(args, empty_env_file):
    """Rendering succeeds by design; the credential is enforced at startup. The
    URL that reaches the services must carry no password at all, so the
    preflight has something unambiguous to reject."""
    proc = _compose_config(args, None, empty_env_file)
    if proc.returncode != 0:  # pragma: no cover
        pytest.skip(f"docker compose config failed: {proc.stderr[:200]}")
    rendered = [
        ln.strip()
        for ln in proc.stdout.splitlines()
        if ln.strip().startswith("DATABASE_URL:")
    ]
    assert rendered, "no DATABASE_URL rendered"
    for ln in rendered:
        assert ln.endswith(
            "postgresql://postgres:@db:5432/praxis"
        ), f"expected an empty-password bundled URL, got {ln}"
    # And the empty URL is exactly what the runtime preflight refuses.
    with pytest.raises(StartupValidationError):
        validate_database_credentials(
            {"DATABASE_URL": "postgresql://postgres:@db:5432/praxis"}
        )


# --------------------------------------------------- startup preflight

BUNDLED_DSN = "postgresql://postgres:{pw}@db:5432/praxis"


@pytest.mark.parametrize(
    "dsn",
    [
        pytest.param("postgresql://postgres:@db:5432/praxis", id="empty-password"),
        pytest.param("postgresql://postgres@db:5432/praxis", id="no-password"),
        pytest.param("postgresql://postgres:@db/praxis", id="no-port"),
    ],
)
def test_bundled_url_without_a_password_is_refused(dsn):
    with pytest.raises(StartupValidationError, match="carries no password"):
        validate_database_credentials({"DATABASE_URL": dsn})


def test_bundled_url_with_the_retired_default_is_refused():
    with pytest.raises(StartupValidationError, match="retired default"):
        validate_database_credentials(
            {"DATABASE_URL": BUNDLED_DSN.format(pw=DEFAULT_POSTGRES_PASSWORD)}
        )


def test_percent_encoded_retired_default_is_decoded_before_comparison():
    with pytest.raises(StartupValidationError, match="retired default"):
        validate_database_credentials(
            {"DATABASE_URL": "postgresql://postgres:%70ostgres@db:5432/praxis"}
        )


def test_bundled_url_with_an_explicit_password_is_accepted():
    validate_database_credentials({"DATABASE_URL": BUNDLED_DSN.format(pw="s3cret")})


def test_the_preflight_runs_in_every_mode_not_only_production():
    """Compose defaults ENVIRONMENT to production, but a development bundled
    stack must not quietly run on a credential-less URL either."""
    for environment in ("development", "test", "production"):
        with pytest.raises(StartupValidationError):
            validate_database_credentials(
                {
                    "ENVIRONMENT": environment,
                    "DATABASE_URL": "postgresql://postgres:@db:5432/praxis",
                }
            )


@pytest.mark.parametrize(
    "dsn",
    [
        pytest.param(EXTERNAL_DSN, id="with-password"),
        pytest.param(
            "postgresql://praxis_app@db.corp.example:5432/praxis", id="no-password"
        ),
        pytest.param(
            "postgresql://postgres:postgres@localhost:5432/praxis", id="localhost"
        ),
    ],
)
def test_external_urls_are_never_inspected(dsn):
    """External deployments own their own credential handling, including
    passwordless authentication such as peer, TLS certs, or a pgpass file."""
    validate_database_credentials({"DATABASE_URL": dsn})


def test_unset_database_url_is_left_to_the_url_builder():
    """Nothing has been assembled yet; DatabaseSettings raises on its own."""
    validate_database_credentials({})


# --------------------------------------------------- application URL assembly


def test_database_settings_refuse_to_assemble_an_unauthenticated_url(monkeypatch):
    from app.db.config import DatabaseSettings

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
    settings = DatabaseSettings()
    with pytest.raises(RuntimeError, match="No database credentials configured"):
        _ = settings.sync_database_url


def test_database_settings_assemble_from_an_explicit_password(monkeypatch):
    from app.db.config import DatabaseSettings

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("POSTGRES_PASSWORD", TEST_PASSWORD)
    assert TEST_PASSWORD in DatabaseSettings().sync_database_url


# --------------------------------------------------- broker preflight


def test_broker_preflights_credentials_before_serving():
    """The broker receives only DATABASE_URL and never reached the production
    validator, so it calls the credential preflight itself."""
    source = (REPO / "backend" / "app" / "broker" / "main.py").read_text()
    main_body = source.split("def main()", 1)[1]
    assert "validate_database_credentials()" in main_body
    assert main_body.index("validate_database_credentials()") < main_body.index(
        "asyncio.run(serve())"
    ), "the preflight must run before the listener is bound"
