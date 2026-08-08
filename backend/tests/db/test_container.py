import pytest
from sqlalchemy import create_engine, text

from app.db.config import DatabaseSettings


@pytest.fixture(scope="session")
def db_engine():
    """Create a test database engine."""
    settings = DatabaseSettings()
    return create_engine(settings.sync_database_url)


def test_database_settings():
    """Test that database settings are properly configured."""
    settings = DatabaseSettings()
    assert settings.POSTGRES_DB == "praxis"
    assert settings.POSTGRES_USER == "postgres"
    assert settings.POSTGRES_SERVER == "db"
    assert settings.POSTGRES_PORT == "5432"


def test_database_connection(db_engine):
    """Test that we can connect to the database."""
    with db_engine.connect() as conn:
        result = conn.execute(text("SELECT 1"))
        assert result.scalar() == 1


def test_database_health_check(db_engine):
    """Test that health check is responding."""
    with db_engine.connect() as conn:
        result = conn.execute(text("SELECT pg_is_in_recovery()"))
        assert result.scalar() is not None


def test_database_persistence(db_engine):
    """Test that data persists after writing."""
    # Create a test table
    with db_engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS test_persistence (
                id serial PRIMARY KEY,
                value TEXT
            )
        """))
        conn.execute(text("INSERT INTO test_persistence (value) VALUES ('test_value')"))
        conn.commit()

        # Verify data was written
        result = conn.execute(text("SELECT value FROM test_persistence")).scalar()
        assert result == "test_value"

        # Cleanup
        conn.execute(text("DROP TABLE test_persistence"))
        conn.commit()


# Clean up after all tests
@pytest.fixture(autouse=True)
def cleanup(db_engine):
    yield
    with db_engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS test_persistence"))
        conn.commit()
