"""
API routes for alert configuration and history (PRA-41).
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import AlertConfig, AlertHistory, User
from ...db.session import get_db
from ...services import outbound_http_guard
from ...services.alert_service import (
    SUPPORTED_EVENT_TYPES,
    force_retry,
    send_test_alert,
)

router = APIRouter(redirect_slashes=False)


def _validate_destination(destination: str) -> None:
    """SSRF guard: reject alert webhook destinations that resolve to
    loopback/private/link-local/metadata addresses. Runs at create/update (and
    delivery revalidates independently). Internal targets are blocked unless the
    dedicated ``ALERT_ALLOW_PRIVATE_TARGETS`` escape hatch is set — the audit-sink
    override does not apply here."""
    try:
        outbound_http_guard.validate_target(
            destination,
            allow_private=outbound_http_guard.alert_allow_private_targets(),
        )
    except outbound_http_guard.SsrfBlocked as exc:
        raise HTTPException(
            status_code=400, detail=f"alert destination not allowed: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class AlertConfigCreate(BaseModel):
    name: str = Field(..., max_length=100)
    alert_type: str = Field(..., max_length=50)  # slack, webhook
    destination: str
    events: list = Field(default_factory=list)
    enabled: bool = True
    secret: Optional[str] = Field(None, max_length=255)
    scope_smart_group_id: Optional[int] = None


class AlertConfigUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    alert_type: Optional[str] = Field(None, max_length=50)
    destination: Optional[str] = None
    events: Optional[list] = None
    enabled: Optional[bool] = None
    secret: Optional[str] = Field(None, max_length=255)
    clear_secret: Optional[bool] = False
    scope_smart_group_id: Optional[int] = None
    clear_scope: Optional[bool] = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_iso(dt):
    if dt is None:
        return None
    return dt.isoformat() + "Z"


def _config_to_dict(c: AlertConfig) -> Dict[str, Any]:
    try:
        events = json.loads(c.events)
    except (json.JSONDecodeError, TypeError):
        events = []
    return {
        "id": c.id,
        "name": c.name,
        "alert_type": c.alert_type,
        "destination": c.destination,
        "events": events,
        "enabled": c.enabled,
        "has_secret": bool(c.secret),
        "scope_smart_group_id": c.scope_smart_group_id,
        "created_by": c.created_by,
        "created_at": _utc_iso(c.created_at),
        "updated_at": _utc_iso(c.updated_at),
    }


def _history_to_dict(h: AlertHistory) -> Dict[str, Any]:
    return {
        "id": h.id,
        "alert_config_id": h.alert_config_id,
        "event_type": h.event_type,
        "message": h.message,
        "sent_at": _utc_iso(h.sent_at),
        "status": h.status,
        "error_message": h.error_message,
        "response_code": h.response_code,
        "attempt_count": h.attempt_count,
        "next_retry_at": _utc_iso(h.next_retry_at),
        "last_attempted_at": _utc_iso(h.last_attempted_at),
        "created_at": _utc_iso(h.created_at),
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=Dict[str, Any])
async def list_alert_configs(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """List all alert configurations."""
    configs = db.query(AlertConfig).order_by(AlertConfig.id).all()
    return {
        "status": "success",
        "configs": [_config_to_dict(c) for c in configs],
    }


@router.post("", response_model=Dict[str, Any])
async def create_alert_config(
    payload: AlertConfigCreate,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create a new alert configuration."""
    if payload.alert_type not in ("slack", "webhook"):
        raise HTTPException(
            status_code=400,
            detail="alert_type must be 'slack' or 'webhook'",
        )
    _validate_destination(payload.destination)

    config = AlertConfig(
        name=payload.name,
        alert_type=payload.alert_type,
        destination=payload.destination,
        events=json.dumps(payload.events),
        enabled=payload.enabled,
        secret=payload.secret or None,
        scope_smart_group_id=payload.scope_smart_group_id,
        created_by=current_user.id,
    )
    db.add(config)
    db.commit()
    db.refresh(config)

    return {"status": "success", "config": _config_to_dict(config)}


@router.put("/{config_id}", response_model=Dict[str, Any])
async def update_alert_config(
    config_id: int = Path(...),
    payload: AlertConfigUpdate = None,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Update an existing alert configuration."""
    config = db.query(AlertConfig).filter(AlertConfig.id == config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Alert config not found")

    if payload.name is not None:
        config.name = payload.name
    if payload.alert_type is not None:
        if payload.alert_type not in ("slack", "webhook"):
            raise HTTPException(
                status_code=400,
                detail="alert_type must be 'slack' or 'webhook'",
            )
        config.alert_type = payload.alert_type
    if payload.destination is not None:
        _validate_destination(payload.destination)
        config.destination = payload.destination
    if payload.events is not None:
        config.events = json.dumps(payload.events)
    if payload.enabled is not None:
        config.enabled = payload.enabled
    if payload.clear_secret:
        config.secret = None
    elif payload.secret is not None and payload.secret != "":
        config.secret = payload.secret
    if payload.clear_scope:
        config.scope_smart_group_id = None
    elif payload.scope_smart_group_id is not None:
        config.scope_smart_group_id = payload.scope_smart_group_id

    db.commit()
    db.refresh(config)

    return {"status": "success", "config": _config_to_dict(config)}


@router.delete("/{config_id}", response_model=Dict[str, Any])
async def delete_alert_config(
    config_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Delete an alert configuration."""
    config = db.query(AlertConfig).filter(AlertConfig.id == config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Alert config not found")

    db.delete(config)
    db.commit()

    return {"status": "success", "message": f"Alert config '{config.name}' deleted"}


@router.post("/{config_id}/test", response_model=Dict[str, Any])
async def test_alert_config(
    config_id: int = Path(...),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Send a test alert to verify webhook URL works."""
    result = send_test_alert(db, config_id)
    if result["status"] == "error":
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@router.get("/history", response_model=Dict[str, Any])
async def list_alert_history(
    alert_config_id: Optional[int] = Query(None),
    event_type: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Paginated alert history with filters."""
    query = db.query(AlertHistory)

    if alert_config_id is not None:
        query = query.filter(AlertHistory.alert_config_id == alert_config_id)
    if event_type:
        query = query.filter(AlertHistory.event_type == event_type)
    if status_filter:
        query = query.filter(AlertHistory.status == status_filter)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            query = query.filter(AlertHistory.sent_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            query = query.filter(AlertHistory.sent_at <= dt_to)
        except ValueError:
            pass

    total = query.count()
    records = (
        query.order_by(AlertHistory.sent_at.desc()).offset(offset).limit(limit).all()
    )

    return {
        "status": "success",
        "total": total,
        "limit": limit,
        "offset": offset,
        "history": [_history_to_dict(h) for h in records],
    }


@router.get("/event-types", response_model=Dict[str, Any])
async def list_event_types(
    current_user: User = Depends(get_current_user),
):
    """Return list of all supported event types for the UI dropdown."""
    return {"status": "success", "event_types": SUPPORTED_EVENT_TYPES}


@router.post("/{config_id}/history/{history_id}/retry", response_model=Dict[str, Any])
async def retry_delivery(
    config_id: int = Path(...),
    history_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Force a manual retry of a failed or dead-lettered delivery (PRA-125)."""
    record = (
        db.query(AlertHistory)
        .filter(
            AlertHistory.id == history_id,
            AlertHistory.alert_config_id == config_id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Delivery record not found")

    result = force_retry(db, history_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message"))
    db.refresh(record)
    return {"status": "success", "delivery": _history_to_dict(record)}
