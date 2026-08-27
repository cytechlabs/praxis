import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# This is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging. Migrations also run in-process,
# where application loggers already exist, and fileConfig disables every logger
# the ini file does not name unless told otherwise. Leaving that default in place
# would silently mute the application's own loggers for the rest of the process.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import our models
from app.db.base import Base

# These names are deliberately unused. Importing app.db.models executes the model
# modules so that every table registers on Base.metadata before target_metadata
# is read below. If this import is dropped and the package-level registration in
# app/db/__init__.py ever changes, Base.metadata can be empty and autogenerate
# would emit drop_table operations for live tables.
from app.db.models import (  # noqa: F401; pylint: disable=unused-import
    RefreshToken,
    Role,
    User,
)


# Get database URL from environment
def get_url():
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    user = os.getenv("POSTGRES_USER", "postgres")
    # No password default. Migrations run against real data, so an unset
    # credential must surface as a configuration error rather than silently
    # attempting a connection with a password this repository chose.
    password = os.getenv("POSTGRES_PASSWORD", "")
    if not password:
        raise RuntimeError(
            "No database credentials available for migrations. Set DATABASE_URL, "
            "or set POSTGRES_PASSWORD to the deployment database password."
        )
    server = os.getenv("POSTGRES_SERVER", "db")
    db = os.getenv("POSTGRES_DB", "praxis")
    return f"postgresql://{user}:{password}@{server}/{db}"


# Set the URL in Alembic's context
config.set_main_option("sqlalchemy.url", get_url())

# Include our models' metadata
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
