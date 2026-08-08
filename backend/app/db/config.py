"""Configuration settings for the database connection."""

import os

from pydantic_settings import BaseSettings


class DatabaseSettings(BaseSettings):
    """Settings for the database connection."""

    POSTGRES_SERVER: str = "db"
    POSTGRES_USER: str = "postgres"
    # No password default. The deployment supplies the credential through
    # DATABASE_URL or POSTGRES_PASSWORD; a built-in value would let a
    # misconfigured deployment connect with a password this repository chose.
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "praxis"
    POSTGRES_PORT: str = "5432"

    @property
    def sync_database_url(self) -> str:
        """Get SQLAlchemy URL for synchronous connections.

        :raises RuntimeError: when neither ``DATABASE_URL`` nor
            ``POSTGRES_PASSWORD`` is set, so a missing credential fails
            clearly instead of assembling an unauthenticated URL.
        """
        url = os.getenv("DATABASE_URL")
        if url:
            return url
        if not self.POSTGRES_PASSWORD:
            raise RuntimeError(
                "No database credentials configured. Set DATABASE_URL, or set "
                "POSTGRES_PASSWORD to the deployment database password."
            )
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
