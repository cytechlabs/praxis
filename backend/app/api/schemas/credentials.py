"""
Schemas for credential management.

All secrets are stored in Vault. DB stores metadata only.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, validator

VALID_AUTH_METHODS = {"password", "ssh_key"}
VALID_SUDO_METHODS = {"none", "nopasswd", "password"}


class SystemBase(BaseModel):
    """Base schema for system information in credential responses."""

    id: int
    hostname: str
    ip_address: str


class CredentialCreate(BaseModel):
    """Schema for creating a new credential.

    Secrets (password, ssh_key, sudo_password) are written to Vault, not stored in DB.
    """

    name: str
    auth_method: str
    sudo_method: Optional[str] = "none"
    # Custom vault path (optional — auto-generated if not provided).
    # When set to an existing Vault secret, the credential is "linked" rather
    # than having its secrets re-written. Declared before username/password
    # so the validators below can read it from `values`.
    vault_path: Optional[str] = None
    username: Optional[str] = None
    # Secrets — written to Vault, not persisted in DB
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    sudo_password: Optional[str] = None

    @validator("auth_method")
    def validate_auth_method(cls, v):  # pylint: disable=no-self-argument
        if v not in VALID_AUTH_METHODS:
            raise ValueError(
                f"auth_method must be one of: {', '.join(VALID_AUTH_METHODS)}"
            )
        return v

    @validator("sudo_method")
    def validate_sudo_method(cls, v):  # pylint: disable=no-self-argument
        if v not in VALID_SUDO_METHODS:
            raise ValueError(
                f"sudo_method must be one of: {', '.join(VALID_SUDO_METHODS)}"
            )
        return v

    @validator("password", always=True)
    def validate_password(cls, v, values):  # pylint: disable=no-self-argument
        # Vault-backed credentials point at an existing secret — the password
        # already lives in Vault, so it does not need to be in the request.
        if values.get("vault_path"):
            return v
        if values.get("auth_method") == "password" and not v:
            raise ValueError("password is required for password auth_method")
        return v

    @validator("ssh_key", always=True)
    def validate_ssh_key(cls, v, values):  # pylint: disable=no-self-argument
        if values.get("vault_path"):
            return v
        if values.get("auth_method") == "ssh_key" and not v:
            raise ValueError("ssh_key is required for ssh_key auth_method")
        return v

    @validator("username", always=True)
    def validate_username(cls, v, values):  # pylint: disable=no-self-argument
        # Username is metadata; for vault-backed creds it can be pulled from
        # the linked secret by the route handler.
        if values.get("vault_path"):
            return v
        if values.get("auth_method") == "password" and not v:
            raise ValueError("username is required for password auth_method")
        return v


class CredentialUpdate(BaseModel):
    """Schema for updating an existing credential."""

    name: Optional[str] = None
    auth_method: Optional[str] = None
    username: Optional[str] = None
    sudo_method: Optional[str] = None
    # Secrets — written to Vault if provided
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    sudo_password: Optional[str] = None

    @validator("auth_method")
    def validate_auth_method(cls, v):  # pylint: disable=no-self-argument
        if v is not None and v not in VALID_AUTH_METHODS:
            raise ValueError(
                f"auth_method must be one of: {', '.join(VALID_AUTH_METHODS)}"
            )
        return v

    @validator("sudo_method")
    def validate_sudo_method(cls, v):  # pylint: disable=no-self-argument
        if v is not None and v not in VALID_SUDO_METHODS:
            raise ValueError(
                f"sudo_method must be one of: {', '.join(VALID_SUDO_METHODS)}"
            )
        return v


class CredentialResponse(BaseModel):
    """Schema for credential response — metadata only, no secrets."""

    id: int
    name: str
    auth_method: str
    username: Optional[str] = None
    vault_path: Optional[str] = None
    sudo_method: str = "none"
    systems: Optional[List[SystemBase]] = []
    created_at: datetime
    updated_at: datetime

    class Config:  # pylint: disable=too-few-public-methods
        """Pydantic config."""

        from_attributes = True
