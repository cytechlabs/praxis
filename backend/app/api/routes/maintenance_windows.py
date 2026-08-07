"""
API routes for maintenance windows (PRA-79).
"""

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role, require_system_access
from ...db.models import Group, MaintenanceWindow, System, User
from ...db.session import get_db
from ...services.access_authorization_service import scoped_system_ids
from ...services.maintenance_window_service import (
    get_upcoming_windows,
    is_in_maintenance_window,
    window_target_system_ids,
    window_visible_to_scope,
)

router = APIRouter(redirect_slashes=False)


def _enforce_window_target_scope(
    db: Session, current_user: User, target_type: str, target_id: Optional[int]
) -> None:
    """PRA-281: a scoped caller may only create/point a window at a target fully
    within fleet scope. ``all`` is tenant-wide → rejected; an out-of-scope
    ``system`` target → non-disclosing 404; a ``group`` not entirely in scope (or
    with no active members) → generic 400. No-op for admins."""
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        return
    if target_type == "all":
        raise HTTPException(
            status_code=403,
            detail="tenant-wide maintenance windows require tenant-wide admin access",
        )
    if target_type == "system":
        if target_id is None or target_id not in scope:
            raise HTTPException(status_code=404, detail="System not found")
        return
    # group (or any other resolvable target): require a non-empty, fully-in-scope
    # active target set.
    probe = MaintenanceWindow(target_type=target_type, target_id=target_id)
    ids = window_target_system_ids(db, probe)
    if ids is None or not ids or not ids.issubset(scope):
        raise HTTPException(
            status_code=400,
            detail="target group must resolve to systems within your access scope",
        )


class MaintenanceWindowCreate(BaseModel):
    """Request body for creating a maintenance window."""

    name: str
    target_type: str  # system, group, all
    target_id: Optional[int] = None
    schedule: Dict[
        str, Any
    ]  # {day_of_week: [], start_time: "", end_time: "", timezone: ""}
    enabled: bool = True


class MaintenanceWindowUpdate(BaseModel):
    """Request body for updating a maintenance window."""

    name: Optional[str] = None
    target_type: Optional[str] = None
    target_id: Optional[int] = None
    schedule: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


def _window_to_dict(window: MaintenanceWindow, db: Session) -> Dict[str, Any]:
    """Convert a MaintenanceWindow model to a dictionary."""
    schedule = {}
    try:
        schedule = (
            json.loads(window.schedule)
            if isinstance(window.schedule, str)
            else window.schedule or {}
        )
    except (json.JSONDecodeError, TypeError):
        pass

    # Resolve target name
    target_name = "All Systems"
    if window.target_type == "system" and window.target_id:
        system = db.query(System).filter(System.id == window.target_id).first()
        target_name = system.hostname if system else f"System #{window.target_id}"
    elif window.target_type == "group" and window.target_id:
        group = db.query(Group).filter(Group.id == window.target_id).first()
        target_name = group.name if group else f"Group #{window.target_id}"

    return {
        "id": window.id,
        "name": window.name,
        "target_type": window.target_type,
        "target_id": window.target_id,
        "target_name": target_name,
        "schedule": schedule,
        "enabled": window.enabled,
        "created_by": window.created_by,
        "created_at": window.created_at.isoformat() + "Z"
        if window.created_at
        else None,
        "updated_at": window.updated_at.isoformat() + "Z"
        if window.updated_at
        else None,
    }


@router.get("", response_model=Dict[str, Any])
async def list_maintenance_windows(
    current_user: User = Depends(get_current_user),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """List all maintenance windows."""
    try:
        windows = db.query(MaintenanceWindow).order_by(MaintenanceWindow.name).all()
        # PRA-281: filter to windows visible in scope BEFORE _window_to_dict, so
        # out-of-scope target system/group names are never resolved.
        scope = scoped_system_ids(db, current_user)
        if scope is not None:
            windows = [w for w in windows if window_visible_to_scope(db, w, scope)]
        return {
            "status": "success",
            "windows": [_window_to_dict(w, db) for w in windows],
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error listing maintenance windows: {str(e)}",
        ) from e


@router.post("", response_model=Dict[str, Any])
async def create_maintenance_window(
    body: MaintenanceWindowCreate,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Create a maintenance window."""
    try:
        valid_targets = {"system", "group", "all"}
        if body.target_type not in valid_targets:
            raise ValueError(
                f"Invalid target_type. Must be one of: {', '.join(sorted(valid_targets))}"
            )

        if body.target_type != "all" and not body.target_id:
            raise ValueError("target_id is required when target_type is not 'all'")

        # PRA-281: a scoped caller may not create a window that could pause
        # out-of-scope systems (before any DB write).
        _enforce_window_target_scope(db, current_user, body.target_type, body.target_id)

        # Validate schedule structure
        schedule = body.schedule
        if (
            "day_of_week" not in schedule
            or "start_time" not in schedule
            or "end_time" not in schedule
        ):
            raise ValueError(
                "Schedule must include day_of_week, start_time, and end_time"
            )

        window = MaintenanceWindow(
            name=body.name,
            target_type=body.target_type,
            target_id=body.target_id if body.target_type != "all" else None,
            schedule=json.dumps(schedule),
            enabled=body.enabled,
            created_by=current_user.id,
        )
        db.add(window)
        db.commit()
        db.refresh(window)

        return {
            "status": "success",
            "message": f"Maintenance window '{window.name}' created",
            "window": _window_to_dict(window, db),
        }
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error creating maintenance window: {str(e)}",
        ) from e


@router.put("/{window_id}", response_model=Dict[str, Any])
async def update_maintenance_window(
    body: MaintenanceWindowUpdate,
    window_id: int = Path(..., description="The ID of the maintenance window"),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Update a maintenance window."""
    try:
        window = (
            db.query(MaintenanceWindow)
            .filter(MaintenanceWindow.id == window_id)
            .first()
        )
        if not window:
            raise ValueError("Maintenance window not found")

        # PRA-281: the caller must already see this window (else non-disclosing
        # 404), and the RESULTING target must stay fully in scope.
        scope = scoped_system_ids(db, current_user)
        if scope is not None:
            if not window_visible_to_scope(db, window, scope):
                raise HTTPException(
                    status_code=404, detail="Maintenance window not found"
                )
            eff_type = (
                body.target_type if body.target_type is not None else window.target_type
            )
            eff_id = body.target_id if body.target_id is not None else window.target_id
            _enforce_window_target_scope(db, current_user, eff_type, eff_id)

        if body.name is not None:
            window.name = body.name
        if body.target_type is not None:
            valid_targets = {"system", "group", "all"}
            if body.target_type not in valid_targets:
                raise ValueError(
                    f"Invalid target_type. Must be one of: {', '.join(sorted(valid_targets))}"
                )
            window.target_type = body.target_type
        if body.target_id is not None:
            window.target_id = body.target_id
        if body.schedule is not None:
            schedule = body.schedule
            if (
                "day_of_week" not in schedule
                or "start_time" not in schedule
                or "end_time" not in schedule
            ):
                raise ValueError(
                    "Schedule must include day_of_week, start_time, and end_time"
                )
            window.schedule = json.dumps(schedule)
        if body.enabled is not None:
            window.enabled = body.enabled

        db.commit()
        db.refresh(window)

        return {
            "status": "success",
            "message": f"Maintenance window '{window.name}' updated",
            "window": _window_to_dict(window, db),
        }
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error updating maintenance window: {str(e)}",
        ) from e


@router.delete("/{window_id}", response_model=Dict[str, Any])
async def delete_maintenance_window(
    window_id: int = Path(..., description="The ID of the maintenance window"),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Delete a maintenance window."""
    try:
        window = (
            db.query(MaintenanceWindow)
            .filter(MaintenanceWindow.id == window_id)
            .first()
        )
        if not window:
            raise ValueError("Maintenance window not found")

        # PRA-281: non-disclosing 404 for a window not fully in the caller's scope
        # (out-of-scope/mixed/tenant-wide) before the delete.
        scope = scoped_system_ids(db, current_user)
        if scope is not None and not window_visible_to_scope(db, window, scope):
            raise ValueError("Maintenance window not found")

        window_name = window.name
        db.delete(window)
        db.commit()

        return {
            "status": "success",
            "message": f"Maintenance window '{window_name}' deleted",
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error deleting maintenance window: {str(e)}",
        ) from e


@router.get(
    "/check/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
async def check_system_window(
    system_id: int = Path(..., description="System ID to check"),
    current_user: User = Depends(get_current_user),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Check if a system is currently in a maintenance window."""
    try:
        in_window, details = is_in_maintenance_window(db, system_id)
        return {
            "status": "success",
            "system_id": system_id,
            "in_maintenance_window": in_window,
            "window_details": details,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error checking maintenance window: {str(e)}",
        ) from e


@router.get("/schedule", response_model=Dict[str, Any])
async def get_upcoming_schedule(
    days: int = Query(7, ge=1, le=30, description="Number of days to look ahead"),
    current_user: User = Depends(get_current_user),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Show upcoming maintenance windows for the next N days."""
    try:
        # PRA-281: only windows visible in the caller's fleet scope.
        upcoming = get_upcoming_windows(
            db, days=days, scope_system_ids=scoped_system_ids(db, current_user)
        )
        return {
            "status": "success",
            "days": days,
            "upcoming": upcoming,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching upcoming schedule: {str(e)}",
        ) from e
