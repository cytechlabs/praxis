"""
Shared pytest fixtures for Praxis backend tests.

Provides:
- `test_engine` / `tables`: session-scoped test DB setup (praxis_test)
- `db`: function-scoped session rolled back per test
- `client`: FastAPI TestClient with get_db dependency overridden
- `admin_user`, `maintainer_user`, `auditor_user`: seeded users with role mappings
- `authed_client`: TestClient authenticated as admin via login flow
- `mock_vault`: monkeypatched VaultService so tests never touch real Vault
"""

import itertools
import os
from typing import Any, Dict, Generator, Iterator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture(autouse=True)
def _default_entitlements():
    """PRA-132: default every test to the fully-entitled enterprise edition.

    Free/no-EE mode is the production default (the registry starts empty), but
    many pre-existing tests exercise paid routes (session locks/approvals,
    access reviews, command approvals/metrics, compliance exports, scheduled
    report exports) and must keep testing real behavior rather than the paywall.
    The entitlement gate tests opt back into free mode explicitly with
    ``registry.reset()``.
    """
    from app.core.entitlements import registry

    registry.enable_enterprise()
    yield
    registry.reset()


def _resolve_test_database_url() -> str:
    """PRA-170 Slice 2: always route backend tests to a dedicated test
    database, never to the shared dev/prod ``praxis`` DB.

    The dev container exports ``DATABASE_URL=postgresql://...@db:5432/praxis``
    at startup. Slice 1's previous ``os.environ.setdefault("DATABASE_URL",
    "...praxis_test")`` was a no-op against that env var, so tests ran
    against the same DB that local dev-fixture seeding
    populates with real test hosts. That leaked seeded systems into any
    test that counts rows by status, producing 63 local-only failures
    (none in CI, because CI runs against an empty postgres service).

    Resolution order:

    1. ``TEST_DATABASE_URL`` if set explicitly — operator override path.
    2. ``DATABASE_URL`` with the database name swapped to its
       ``<name>_test`` sibling — covers both local
       (``praxis`` → ``praxis_test``) and CI (``praxis`` → ``praxis_test``,
       auto-created below) uniformly.
    3. A hardcoded fallback for the bare-import / no-env case.

    Assignment (``os.environ[...] = ...``), not ``setdefault``, so the
    dev container's exported value is replaced rather than preserved.
    """

    explicit = os.getenv("TEST_DATABASE_URL")
    if explicit:
        return explicit

    base = os.getenv("DATABASE_URL")
    if base:
        try:
            url = make_url(base)
            db_name = url.database or "praxis"
            if not db_name.endswith("_test"):
                db_name = f"{db_name}_test"
            # ``render_as_string(hide_password=False)`` because the
            # default ``str(URL)`` masks the password as ``***`` for
            # safe logging, which would silently break the test
            # connection.
            return url.set(database=db_name).render_as_string(hide_password=False)
        except Exception:  # pylint: disable=broad-except
            # Fall through to the hardcoded default on any parse error.
            pass

    return "postgresql://postgres:postgres@db:5432/praxis_test"


def _ensure_test_database_exists(url: str) -> None:
    """Idempotent ``CREATE DATABASE`` for the test DB.

    Connects to the ``postgres`` template database on the same server
    via a separate AUTOCOMMIT connection (``CREATE DATABASE`` cannot run
    inside a transaction block) and creates ``<dbname>`` if missing.
    The ``pg_database`` pre-check makes the call safe to repeat across
    pytest sessions; the single-process local/CI test path doesn't race
    on this so the pre-check is sufficient.
    """

    target = make_url(url)
    target_name = target.database
    if not target_name:
        return

    admin_url = target.set(database="postgres").render_as_string(hide_password=False)
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            existing = conn.exec_driver_sql(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (target_name,),
            ).scalar()
            if not existing:
                conn.exec_driver_sql(f'CREATE DATABASE "{target_name}"')
    finally:
        admin_engine.dispose()


_TEST_DATABASE_URL = _resolve_test_database_url()
_ensure_test_database_exists(_TEST_DATABASE_URL)

os.environ.setdefault("TESTING", "True")
# PRA-170 Slice 2: assignment, not setdefault — the dev container's
# DATABASE_URL=praxis must be overridden, not preserved.
os.environ["DATABASE_URL"] = _TEST_DATABASE_URL
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("ALGORITHM", "HS256")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
os.environ["TRUSTED_HOSTS"] = "testserver,localhost,127.0.0.1,backend"

# Quiet libraries the tests don't care about.
import warnings  # noqa: E402

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*PydanticDeprecatedSince20.*")
warnings.filterwarnings("ignore", message=".*orm_mode.*")


@pytest.fixture(scope="session")
def test_engine():
    """Engine bound to the dedicated test DB. Migrations applied
    once per session.

    PRA-170 Slice 2 fix: this fixture used to call
    ``Base.metadata.create_all``, which only knows about the
    declarative models — it skips migration-only seed data such as
    the built-in ``fleet_roles`` rows that PRA-137's migration
    INSERTs. CI's workflow already runs ``alembic upgrade head``
    against ``DATABASE_URL`` (which used to be ``praxis``) before
    pytest starts, so the pre-PRA-170 test runs got those seeds
    for free. After Slice 2 redirected tests to ``praxis_test``,
    that brand-new DB had the schema but no seeds, breaking 19
    auth tests + 1 migration-roundtrip test in CI run 26072805778.

    Running ``command.upgrade(alembic_cfg, "head")`` here is
    idempotent (a no-op on an already-migrated DB locally, the
    full migration chain on a freshly-auto-created DB in CI) and
    makes the local and CI paths use the same schema-bootstrap
    mechanism.
    """

    from alembic import command
    from alembic.config import Config

    engine = create_engine(os.environ["DATABASE_URL"])

    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])
    command.upgrade(alembic_cfg, "head")

    yield engine
    engine.dispose()


@pytest.fixture
def db(test_engine) -> Generator[Session, None, None]:
    """
    Per-test DB session with outer-transaction rollback.

    Uses SAVEPOINT pattern so route handlers that call .commit() only commit
    within the outer transaction, which we roll back at teardown.
    """
    connection = test_engine.connect()
    transaction = connection.begin()
    # PRA-170: match production `SessionLocal(autoflush=False)` so
    # mutation-then-query bugs that would be stale in prod surface in
    # the test suite instead of being hidden by SQLAlchemy's
    # autoflush default. Tests that genuinely need a pending change
    # visible to a subsequent query must call `db.flush()` or
    # restructure the query.
    TestSession = sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)
    session = TestSession()

    nested = connection.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, trans):  # pragma: no cover - plumbing
        nonlocal nested
        if trans.nested and not trans._parent.nested:
            nested = connection.begin_nested()

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def client(db, mock_vault) -> Iterator[TestClient]:
    """TestClient with get_db + VaultService overridden."""
    from app.api.main import app
    from app.db.session import get_db

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def mock_vault(monkeypatch) -> MagicMock:
    """
    Replace VaultService everywhere it's imported with an in-memory mock.

    The mock stores secrets in a dict keyed by path. Tests can inspect
    `mock_vault.secrets` or pre-seed it to simulate existing Vault state.
    """
    store: Dict[str, Dict[str, Any]] = {}

    mock_cls = MagicMock()
    instance = MagicMock()

    def write_secret(path, data):
        store[path] = dict(data)
        return True

    def read_secret(path):
        return dict(store[path]) if path in store else None

    def delete_secret(path):
        store.pop(path, None)
        return True

    instance.write_secret.side_effect = write_secret
    instance.read_secret.side_effect = read_secret
    instance.delete_secret.side_effect = delete_secret
    instance.get_ssh_ca_public_key.return_value = "ssh-ed25519 TESTCA test@praxis"
    mock_cls.return_value = instance
    mock_cls.secrets = store

    # Patch all known import sites
    for module_path in [
        "app.api.routes.credentials.VaultService",
        "app.api.routes.ssh_identity.VaultService",
        "app.services.ssh_service.VaultService",
        # Guided onboarding preflight reads the credential secret to
        # authenticate against a host that is not managed yet.
        "app.services.onboarding_preflight_service.VaultService",
        # PRA-158 #1: signing-key service hits Vault for armored
        # private+public storage. Tests get the in-memory store.
        "app.services.mirror_signing_key_service.VaultService",
        # PRA-160 slice #1: airgap bundle signing key (instance-wide)
        # + orchestrator (reads private armored material out of Vault
        # to sign the descriptor in an ephemeral GNUPGHOME). Both
        # need the in-memory store.
        "app.services.airgap.signing_key_service.VaultService",
        "app.services.airgap.orchestrator.VaultService",
    ]:
        try:
            monkeypatch.setattr(module_path, mock_cls)
        except (AttributeError, ModuleNotFoundError):
            pass

    return mock_cls


# ── Test host addressing ───────────────────────────────────────────────

_TEST_IP_COUNTER = itertools.count(1)


def unique_test_ip() -> str:
    """A distinct address for a test-created system.

    ``systems.ip_address`` is unique in the database, so a fixture that builds
    more than one host needs a different address for each. Tests that care
    about a specific address still pass their own; this is for the many that
    only need *an* address.
    """
    n = next(_TEST_IP_COUNTER)
    return f"10.200.{(n // 254) % 254}.{(n % 254) + 1}"


# ── Seed-data fixtures ─────────────────────────────────────────────────


@pytest.fixture
def seed_roles(db) -> Dict[str, Any]:
    """Ensure admin/maintainer/auditor/viewer roles exist."""
    from app.db.models import Role

    roles = {}
    for name in ("admin", "maintainer", "auditor", "viewer"):
        role = db.query(Role).filter_by(name=name).first()
        if not role:
            role = Role(name=name, description=f"{name} role")
            db.add(role)
            db.flush()
        roles[name] = role
    return roles


@pytest.fixture
def seed_distro(db):
    """Ensure at least one distro row exists for systems tests."""
    from datetime import date

    from app.db.models import Distro

    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if not distro:
        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()
    return distro


def _make_user(db, roles_map, username: str, role_names: list):
    from app.core.auth import get_password_hash
    from app.db.models import User

    user = User(
        username=username,
        email=f"{username}@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    for r in role_names:
        user.roles.append(roles_map[r])
    db.add(user)
    db.flush()
    return user


@pytest.fixture
def admin_user(db, seed_roles):
    return _make_user(db, seed_roles, "admintest", ["admin"])


@pytest.fixture
def maintainer_user(db, seed_roles):
    return _make_user(db, seed_roles, "maintainertest", ["maintainer"])


@pytest.fixture
def auditor_user(db, seed_roles):
    return _make_user(db, seed_roles, "auditortest", ["auditor"])


@pytest.fixture
def authed_client(client, admin_user) -> TestClient:
    """
    TestClient with admin bearer token pre-set on default headers.

    The backend is stateless — cookie-based auth is a frontend concern. For
    direct backend tests we pass the JWT in the Authorization header as the
    OAuth2PasswordBearer dependency expects.
    """
    res = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    token = res.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client
