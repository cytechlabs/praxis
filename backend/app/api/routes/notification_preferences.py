"""
API routes for per-user notification preferences (PRA-100).
"""

import json

from fastapi import APIRouter, Depends
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from ...core.auth import get_current_user
from ...db.models import NotificationPreference, User
from ...db.session import get_db

router = APIRouter(redirect_slashes=False)

ALL_EVENT_TYPES = [
    "job_completed",
    "job_failed",
    "job_cancelled",
    "job_rollback",
    "system_unreachable",
    "system_recovered",
    "security_updates",
    # PRA-156 #3e-b: lifecycle event types replace the vestigial
    # ``eol_warning`` slot. See alert_service.SUPPORTED_EVENT_TYPES.
    "host_eol_approaching",
    "host_eol_reached",
    "package_scan_complete",
    "credential_change",
    "host_key_changed",
    "system_added",
    "system_removed",
    "bulk_operation_complete",
    # PRA-178 Slice 3: patch / compliance / remediation lifecycle
    # notifications. Mirrors ``alert_service.SUPPORTED_EVENT_TYPES``
    # so per-user preferences and the alert delivery allowlist agree
    # on the same vocabulary. Emission lives in
    # ``app.services.notification_events`` and is wired beside the
    # existing audit emits at each service's natural state transition.
    "patch.executed",
    "patch.reboot_required",
    "patch.reboot_completed",
    "patch.rollback_started",
    "patch.rollback_completed",
    "compliance.evaluated",
    "remediation.requested",
    "remediation.ready",
    "remediation.executed",
    "remediation.failed",
]


class NotificationPreferencesResponse(BaseModel):
    disabled_types: list[str]
    all_types: list[str]


class NotificationPreferencesUpdate(BaseModel):
    disabled_types: list[str]

    @validator("disabled_types", each_item=True)
    def validate_type(cls, v):
        if v not in ALL_EVENT_TYPES:
            raise ValueError(f"Unknown event type: {v}")
        return v


def _get_or_create_prefs(db: Session, user_id: int) -> NotificationPreference:
    prefs = (
        db.query(NotificationPreference)
        .filter(NotificationPreference.user_id == user_id)
        .first()
    )
    if not prefs:
        prefs = NotificationPreference(user_id=user_id, disabled_types="[]")
        db.add(prefs)
        db.commit()
        db.refresh(prefs)
    return prefs


@router.get("", response_model=NotificationPreferencesResponse)
async def get_notification_preferences(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the current user's notification preferences."""
    prefs = _get_or_create_prefs(db, current_user.id)
    return {
        "disabled_types": json.loads(prefs.disabled_types),
        "all_types": ALL_EVENT_TYPES,
    }


@router.put("", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    payload: NotificationPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update the current user's notification preferences."""
    prefs = _get_or_create_prefs(db, current_user.id)
    prefs.disabled_types = json.dumps(sorted(set(payload.disabled_types)))
    db.commit()
    db.refresh(prefs)
    return {
        "disabled_types": json.loads(prefs.disabled_types),
        "all_types": ALL_EVENT_TYPES,
    }
