"""
Pydantic schemas for SSH security management.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class SSHSecurityPolicyBase(BaseModel):
    """Base schema for SSH security policy."""

    name: str = Field(..., description="Name of the security policy")
    description: Optional[str] = Field(None, description="Description of the policy")
    max_auth_tries: Optional[int] = Field(
        3, description="Maximum authentication attempts"
    )
    connection_timeout: Optional[int] = Field(
        10, description="Connection timeout in seconds"
    )
    idle_timeout: Optional[int] = Field(600, description="Idle timeout in seconds")
    require_host_key_verification: Optional[bool] = Field(
        True, description="Require host key verification"
    )
    minimum_key_size: Optional[int] = Field(
        2048, description="Minimum SSH key size in bits"
    )
    allowed_auth_methods: Optional[str] = Field(
        "publickey,password", description="Allowed authentication methods"
    )
    allowed_ciphers: Optional[str] = Field(
        "aes256-ctr,aes192-ctr,aes128-ctr", description="Allowed ciphers"
    )
    allowed_macs: Optional[str] = Field(
        "hmac-sha2-512,hmac-sha2-256", description="Allowed MACs"
    )
    allowed_kex: Optional[str] = Field(
        "diffie-hellman-group-exchange-sha256", description="Allowed key exchanges"
    )
    log_commands: Optional[bool] = Field(True, description="Log command executions")
    log_file_transfers: Optional[bool] = Field(True, description="Log file transfers")


class SSHSecurityPolicyCreate(SSHSecurityPolicyBase):
    """Schema for creating SSH security policy."""


class SSHSecurityPolicyUpdate(BaseModel):
    """Schema for updating SSH security policy."""

    name: Optional[str] = Field(None, description="Name of the security policy")
    description: Optional[str] = Field(None, description="Description of the policy")
    max_auth_tries: Optional[int] = Field(
        None, description="Maximum authentication attempts"
    )
    connection_timeout: Optional[int] = Field(
        None, description="Connection timeout in seconds"
    )
    idle_timeout: Optional[int] = Field(None, description="Idle timeout in seconds")
    require_host_key_verification: Optional[bool] = Field(
        None, description="Require host key verification"
    )
    minimum_key_size: Optional[int] = Field(
        None, description="Minimum SSH key size in bits"
    )
    allowed_auth_methods: Optional[str] = Field(
        None, description="Allowed authentication methods"
    )
    allowed_ciphers: Optional[str] = Field(None, description="Allowed ciphers")
    allowed_macs: Optional[str] = Field(None, description="Allowed MACs")
    allowed_kex: Optional[str] = Field(None, description="Allowed key exchanges")
    log_commands: Optional[bool] = Field(None, description="Log command executions")
    log_file_transfers: Optional[bool] = Field(None, description="Log file transfers")


class SSHSecurityPolicy(SSHSecurityPolicyBase):
    """Schema for SSH security policy response."""

    id: int
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    created_by: int

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class SSHSecurityLogBase(BaseModel):
    """Base schema for SSH security log."""

    system_id: int
    event_type: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    success: bool = False


class SSHSecurityLog(SSHSecurityLogBase):
    """Schema for SSH security log response."""

    id: int
    event_details: Optional[str] = None
    timestamp: Optional[datetime]

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class SSHHostKeyBase(BaseModel):
    """Base schema for SSH host key."""

    system_id: int
    hostname: str
    key_type: str
    public_key: str
    fingerprint: str
    verified: bool = False


class SSHHostKeyCreate(SSHHostKeyBase):
    """Schema for creating SSH host key."""


class SSHHostKeyUpdate(BaseModel):
    """Schema for updating SSH host key."""

    verified: Optional[bool] = None


class SSHHostKey(SSHHostKeyBase):
    """Schema for SSH host key response."""

    id: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        """Pydantic configuration."""

        from_attributes = True


class SSHSecurityPolicyList(BaseModel):
    """Schema for SSH security policy list response."""

    policies: List[SSHSecurityPolicy]
    total: int


class SSHSecurityLogList(BaseModel):
    """Schema for SSH security log list response."""

    logs: List[SSHSecurityLog]
    total: int


class SSHHostKeyList(BaseModel):
    """Schema for SSH host key list response."""

    host_keys: List[SSHHostKey]
    total: int
