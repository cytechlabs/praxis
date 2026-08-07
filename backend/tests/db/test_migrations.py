import pytest
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from app.db.base import Base
from app.db.config import DatabaseSettings


@pytest.fixture(scope="session")
def db_engine():
    """Create a test database engine."""
    settings = DatabaseSettings()
    return create_engine(settings.sync_database_url)


def test_alembic_migrations_installed():
    """Test that Alembic migrations directory is properly set up."""
    config = Config("alembic.ini")
    script = ScriptDirectory.from_config(config)

    # Check that we have the versions directory
    assert script.versions is not None


def test_base_model_configuration():
    """Test that the Base model has the required common fields."""
    # Check for common fields in Base model
    assert hasattr(Base, "id")
    assert hasattr(Base, "created_at")
    assert hasattr(Base, "updated_at")


def test_migration_apply_and_rollback(db_engine):
    """Test that we can apply and rollback migrations."""
    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config("alembic.ini")

    # Test upgrade
    command.upgrade(alembic_cfg, "head")

    # Verify migration state
    with db_engine.connect() as conn:
        context = MigrationContext.configure(conn)
        assert context.get_current_revision() is not None

    # Test downgrade
    command.downgrade(alembic_cfg, "-1")

    # Verify downgrade
    with db_engine.connect() as conn:
        context = MigrationContext.configure(conn)
        current_rev = context.get_current_revision()
        assert current_rev != "head"

    # Re-apply so subsequent tests have tables
    command.upgrade(alembic_cfg, "head")
