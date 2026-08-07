"""
Vault API schemas.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


class VaultConfigCreate(BaseModel):
    """Schema for creating a new Vault configuration.

    Token is read from VAULT_TOKEN env var, not provided in request.
    """

    is_internal: bool = Field(
        ..., description="Whether to use the internal Vault container"
    )
    server_url: Optional[str] = Field(
        None,
        description="URL of the external Vault server (only needed if is_internal=False)",
    )

    @validator("server_url")
    def validate_server_url(cls, v, values):  # pylint: disable=no-self-argument
        """Validate that server_url is provided if is_internal is False."""
        if not values.get("is_internal") and not v:
            raise ValueError("server_url is required when is_internal is False")
        return v


class VaultConfigUpdate(BaseModel):
    """Schema for updating an existing Vault configuration."""

    is_internal: bool = Field(
        ..., description="Whether to use the internal Vault container"
    )
    server_url: Optional[str] = Field(
        None,
        description="URL of the external Vault server (only needed if is_internal=False)",
    )

    @validator("server_url")
    def validate_server_url(cls, v, values):  # pylint: disable=no-self-argument
        """Validate that server_url is provided if is_internal is False."""
        if not values.get("is_internal") and not v:
            raise ValueError("server_url is required when is_internal is False")
        return v


class VaultConfigResponse(BaseModel):
    """Schema for Vault configuration response."""

    id: int
    is_internal: bool
    server_url: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_health_check: Optional[datetime] = None
    health_status: Optional[str] = None

    class Config:  # pylint: disable=too-few-public-methods
        """Pydantic config."""

        orm_mode = True


class VaultHealthResponse(BaseModel):
    """Schema for Vault health check response."""

    healthy: bool
    status: str
    initialized: Optional[bool] = None
    sealed: Optional[bool] = None
    version: Optional[str] = None


class VaultKVStoreResponse(BaseModel):
    """Schema for KV store response."""

    name: str


class VaultKVStoresResponse(BaseModel):
    """Schema for KV stores list response."""

    kv_stores: List[str]


class VaultSecretResponse(BaseModel):
    """Schema for secret response."""

    name: str
    path: str


class VaultSecretsResponse(BaseModel):
    """Schema for secrets list response."""

    secrets: List[str]
    path: str


class VaultSecretVersionResponse(BaseModel):
    """Schema for secret version response."""

    version: int
    created_time: str
    data: Dict[str, Any]


class VaultSecretVersionsResponse(BaseModel):
    """Schema for secret versions list response."""

    versions: List[int]
    current_version: int
    path: str


class VaultSecretDataResponse(BaseModel):
    """Schema for secret data response."""

    data: Dict[str, Any]
    metadata: Dict[str, Any]
    path: str


class VaultSecretCreateRequest(BaseModel):
    """Schema for creating a new secret."""

    path: str
    data: Dict[str, str]


class VaultSecretPasswordUpdateRequest(BaseModel):
    """Schema for updating a password in a secret."""

    path: str = Field(..., description="Path to the secret")
    username: str = Field(..., description="Username whose password to update")
    new_password: str = Field(..., description="New password value")
