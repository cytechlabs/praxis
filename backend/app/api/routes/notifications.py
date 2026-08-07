"""
API routes for in-app notifications (PRA-78, PRA-100).
"""

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ...core.auth import get_current_user
from ...db.models import Notification, NotificationPreference, User
from ...db.session import get_db

router = APIRouter(redirect_slashes=False)


def _get_disabled_types(db: Session, user_id: int) -> list[str]:
    """Return the list of event types the user has disabled."""
    prefs = (
        db.query(NotificationPreference)
        .filter(NotificationPreference.user_id == user_id)
        .first()
    )
    if not prefs:
        return []
    return json.loads(prefs.disabled_types)


def _utc_iso(dt):
    """Format a datetime as ISO string with Z suffix for UTC."""
    if dt is None:
        return None
    return dt.isoformat() + "Z"


def _notification_to_dict(n: Notification) -> Dict[str, Any]:
    """Convert a Notification model to a dictionary."""
    return {
        "id": n.id,
        "type": n.type,
        "title": n.title,
        "message": n.message,
        "severity": n.severity,
        "is_read": n.is_read,
        "user_id": n.user_id,
        "related_job_id": n.related_job_id,
        "created_at": _utc_iso(n.created_at),
    }


@router.get("", response_model=Dict[str, Any])
async def list_notifications(
    is_read: Optional[bool] = Query(None, description="Filter by read status"),
    limit: int = Query(50, ge=1, le=200, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List notifications for the current user (unread first, newest first)."""
    try:
        query = db.query(Notification).filter(
            or_(
                Notification.user_id == current_user.id,
                Notification.user_id.is_(None),
            )
        )

        # PRA-100: exclude event types the user has disabled
        disabled = _get_disabled_types(db, current_user.id)
        if disabled:
            query = query.filter(Notification.type.notin_(disabled))

        if is_read is not None:
            query = query.filter(Notification.is_read == is_read)

        total = query.count()
        notifications = (
            query.order_by(
                Notification.is_read.asc(),
                Notification.created_at.desc(),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "notifications": [_notification_to_dict(n) for n in notifications],
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error listing notifications: {str(e)}",
        ) from e


@router.get("/unread-count", response_model=Dict[str, Any])
async def get_unread_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get count of unread notifications for the current user."""
    try:
        query = db.query(Notification).filter(
            or_(
                Notification.user_id == current_user.id,
                Notification.user_id.is_(None),
            ),
            Notification.is_read == False,  # noqa: E712
        )

        # PRA-100: exclude disabled types from count
        disabled = _get_disabled_types(db, current_user.id)
        if disabled:
            query = query.filter(Notification.type.notin_(disabled))

        count = query.count()
        return {"status": "success", "unread_count": count}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error getting unread count: {str(e)}",
        ) from e


@router.put("/read-all", response_model=Dict[str, Any])
async def mark_all_as_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark all notifications as read for the current user."""
    try:
        updated = (
            db.query(Notification)
            .filter(
                or_(
                    Notification.user_id == current_user.id,
                    Notification.user_id.is_(None),
                ),
                Notification.is_read == False,  # noqa: E712
            )
            .update({"is_read": True}, synchronize_session="fetch")
        )
        db.commit()

        return {
            "status": "success",
            "message": f"{updated} notifications marked as read",
            "updated_count": updated,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error marking all as read: {str(e)}",
        ) from e


@router.put("/{notification_id}/read", response_model=Dict[str, Any])
async def mark_as_read(
    notification_id: int = Path(..., description="The notification ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark a notification as read."""
    try:
        notification = (
            db.query(Notification)
            .filter(
                Notification.id == notification_id,
                or_(
                    Notification.user_id == current_user.id,
                    Notification.user_id.is_(None),
                ),
            )
            .first()
        )
        if not notification:
            raise HTTPException(status_code=404, detail="Notification not found")

        notification.is_read = True
        db.commit()
        db.refresh(notification)

        return {
            "status": "success",
            "notification": _notification_to_dict(notification),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error marking notification as read: {str(e)}",
        ) from e
