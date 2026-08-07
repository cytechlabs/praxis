"""Configuration module for application settings."""

from typing import List

from pydantic_settings import (  # pylint: disable=no-name-in-module
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):  # pylint: disable=too-few-public-methods
    """Application settings loaded from environment variables or default values."""

    # Application
    app_name: str = "Praxis"
    api_v1_str: str = "/api/v1"
    environment: str = "development"
    debug: bool = True
    admin_email: str = "admin@example.com"
    items_per_user: int = 50

    # Security
    jwt_secret: str
    secret_key: str
    access_token_expire_minutes: int = 30
    algorithm: str = "HS256"

    # Database
    database_url: str
    database_test_url: str = "postgresql://postgres:postgres@db:5432/praxis_test"

    # CORS
    backend_cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Logging
    log_level: str = "DEBUG"

    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=True, env_file_encoding="utf-8"
    )


settings = Settings()
