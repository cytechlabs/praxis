"""Configuration settings for the database connection."""

import os

from pydantic_settings import BaseSettings


class DatabaseSettings(BaseSettings):
    """Settings for the database connection."""

    POSTGRES_SERVER: str = "db"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "praxis"
    POSTGRES_PORT: str = "5432"

    @property
    def sync_database_url(self) -> str:
        """Get SQLAlchemy URL for synchronous connections."""
        url = os.getenv("DATABASE_URL")
        if url:
            return url
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
