"""API routes for application-wide settings (PRA-85)."""

from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import AppSettings, User
from ...db.session import get_db

router = APIRouter(redirect_slashes=False)

VALID_KEYS = {
    "app_name",
    "timezone",
    "date_format",
    "time_format",
    # PRA-149: days between scheduled access reviews (integer string)
    "access_review.cadence_days",
    # PRA-180 / PRA-216: admin-controlled self-registration switch.
    # Stored as "true"/"false". Absent => disabled (the 1.0 default is NOT
    # unconditional open signup).
    "auth.self_registration_enabled",
}

# PRA-216: key + default for the self-registration switch. Kept as module
# constants so the auth routes and the public status endpoint agree.
SELF_REGISTRATION_KEY = "auth.self_registration_enabled"
SELF_REGISTRATION_DEFAULT = False

# Online license refresh: AppSettings keys that hold SECRET material and must
# never be returned by the settings API. GET /app-settings dumps every row, so
# without this filter the stored refresh token would leak to any authenticated
# user. These are written/read only through app.services.license_service.
SECRET_SETTING_KEYS = {
    "license.refresh",  # {"instance_id": ..., "token": ...} — the refresh token
}

_TRUE_VALUES = {"1", "true", "yes", "on"}


def get_bool_setting(db: Session, key: str, default: bool = False) -> bool:
    """Read a persisted AppSettings value as a boolean.

    Returns ``default`` when the key is absent or unparseable. Truthy values
    are ``1/true/yes/on`` (case-insensitive); everything else is false.
    """
    row = db.query(AppSettings).filter(AppSettings.setting_key == key).first()
    if row is None or row.setting_value is None:
        return default
    return row.setting_value.strip().lower() in _TRUE_VALUES


def is_self_registration_enabled(db: Session) -> bool:
    """Whether admin-controlled self-registration is currently enabled."""
    return get_bool_setting(db, SELF_REGISTRATION_KEY, SELF_REGISTRATION_DEFAULT)


class SettingResponse(BaseModel):
    setting_key: str
    setting_value: str

    class Config:
        from_attributes = True


class SettingUpdate(BaseModel):
    setting_value: str


class BulkSettingsUpdate(BaseModel):
    settings: Dict[str, str]


def _public_settings(db: Session) -> List[AppSettings]:
    """All settings rows EXCEPT secret ones (e.g. the online-refresh token).
    Shared by every endpoint that returns the full settings list so no response
    path can leak a secret value."""
    return [
        s
        for s in db.query(AppSettings).all()
        if s.setting_key not in SECRET_SETTING_KEYS
    ]


@router.get("", response_model=List[SettingResponse])
async def get_all_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # PRA-180 AUTH-02
):  # pylint: disable=unused-argument
    return _public_settings(db)


@router.get("/{key}", response_model=SettingResponse)
async def get_setting(
    key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # PRA-180 AUTH-02
):  # pylint: disable=unused-argument
    # A secret key is treated as non-existent by the settings API.
    if key in SECRET_SETTING_KEYS:
        raise HTTPException(status_code=404, detail=f"Setting '{key}' not found")
    setting = db.query(AppSettings).filter(AppSettings.setting_key == key).first()
    if not setting:
        raise HTTPException(status_code=404, detail=f"Setting '{key}' not found")
    return setting


@router.put("/{key}", response_model=SettingResponse)
async def upsert_setting(
    key: str,
    body: SettingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    if key not in VALID_KEYS:
        raise HTTPException(status_code=400, detail=f"Invalid setting key: {key}")
    setting = db.query(AppSettings).filter(AppSettings.setting_key == key).first()
    if setting:
        setting.setting_value = body.setting_value
    else:
        setting = AppSettings(setting_key=key, setting_value=body.setting_value)
        db.add(setting)
    db.commit()
    db.refresh(setting)
    return setting


@router.put("", response_model=List[SettingResponse])
async def bulk_update_settings(
    body: BulkSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    invalid_keys = set(body.settings.keys()) - VALID_KEYS
    if invalid_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid setting keys: {', '.join(invalid_keys)}",
        )
    for key, value in body.settings.items():
        setting = db.query(AppSettings).filter(AppSettings.setting_key == key).first()
        if setting:
            setting.setting_value = value
        else:
            db.add(AppSettings(setting_key=key, setting_value=value))
    db.commit()
    # Filter secrets from the response (same as GET all) so the bulk PUT reply
    # can't leak license.refresh even though it isn't a writable key.
    return _public_settings(db)
