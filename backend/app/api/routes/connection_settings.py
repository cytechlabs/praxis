"""
API routes for global connection settings (PRA-62).
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from ...core.auth import require_role
from ...db.models import GlobalConnectionSettings, User
from ...db.session import get_db

router = APIRouter(redirect_slashes=False)


class ConnectionSettingsResponse(BaseModel):
    connection_timeout: int
    max_pool_size: int
    pool_cleanup_interval: int
    max_idle_time: int
    unreachable_threshold: int
    default_ssh_port: int
    # PRA-313: per-host transport circuit-breaker tunables.
    transport_failure_threshold: int
    transport_cooldown_seconds: int

    class Config:
        from_attributes = True


class ConnectionSettingsUpdate(BaseModel):
    connection_timeout: int
    max_pool_size: int
    pool_cleanup_interval: int
    max_idle_time: int
    unreachable_threshold: int
    default_ssh_port: int
    # PRA-313: per-host transport circuit-breaker tunables.
    transport_failure_threshold: int
    transport_cooldown_seconds: int

    @validator("connection_timeout")
    def validate_connection_timeout(cls, v):
        if not 1 <= v <= 120:
            raise ValueError("Connection timeout must be between 1 and 120 seconds")
        return v

    @validator("max_pool_size")
    def validate_max_pool_size(cls, v):
        if not 1 <= v <= 500:
            raise ValueError("Max pool size must be between 1 and 500")
        return v

    @validator("pool_cleanup_interval")
    def validate_pool_cleanup_interval(cls, v):
        if not 30 <= v <= 3600:
            raise ValueError(
                "Pool cleanup interval must be between 30 and 3600 seconds"
            )
        return v

    @validator("max_idle_time")
    def validate_max_idle_time(cls, v):
        if not 60 <= v <= 7200:
            raise ValueError("Max idle time must be between 60 and 7200 seconds")
        return v

    @validator("unreachable_threshold")
    def validate_unreachable_threshold(cls, v):
        if not 1 <= v <= 100:
            raise ValueError("Unreachable threshold must be between 1 and 100")
        return v

    @validator("default_ssh_port")
    def validate_default_ssh_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError("SSH port must be between 1 and 65535")
        return v

    @validator("transport_failure_threshold")
    def validate_transport_failure_threshold(cls, v):
        if not 1 <= v <= 20:
            raise ValueError(
                "Transport failure threshold must be between 1 and 20 failures"
            )
        return v

    @validator("transport_cooldown_seconds")
    def validate_transport_cooldown_seconds(cls, v):
        if not 5 <= v <= 3600:
            raise ValueError("Transport cooldown must be between 5 and 3600 seconds")
        return v


def _get_settings(db: Session) -> GlobalConnectionSettings:
    """Return the singleton settings row, creating it if missing."""
    settings = db.query(GlobalConnectionSettings).first()
    if not settings:
        settings = GlobalConnectionSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.get("", response_model=ConnectionSettingsResponse)
async def get_connection_settings(
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Return the current global connection settings."""
    return _get_settings(db)


@router.put("", response_model=ConnectionSettingsResponse)
async def update_connection_settings(
    payload: ConnectionSettingsUpdate,
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Update global connection settings. Admin only."""
    settings = _get_settings(db)
    for field, value in payload.dict().items():
        setattr(settings, field, value)
    db.commit()
    db.refresh(settings)
    return settings
