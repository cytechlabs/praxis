"""
API routes for saved filter views (PRA-114).
"""

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...core.api_errors import internal_error
from ...core.auth import get_current_user
from ...db.models import SavedView, User
from ...db.session import get_db
from ...services.access_authorization_service import scoped_system_ids

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


def _view_hidden_for_scope(db: Session, current_user: User, view: SavedView) -> bool:
    """PRA-281: a saved view's ``filters`` blob can encode system/group/tag ids
    that reveal hidden inventory. Since arbitrary filter JSON cannot be safely
    scrubbed, a scoped caller may only see/operate their OWN views — shared/global
    views (typically admin-authored) are hidden. Admin (tenant-wide) sees all."""
    if scoped_system_ids(db, current_user) is None:
        return False
    return view.user_id != current_user.id


class SavedViewCreate(BaseModel):
    """Request body for creating a saved view."""

    name: str
    filters: Dict[str, Any]
    is_default: bool = False
    is_shared: bool = False


class SavedViewUpdate(BaseModel):
    """Request body for updating a saved view."""

    name: Optional[str] = None
    filters: Optional[Dict[str, Any]] = None
    is_default: Optional[bool] = None
    is_shared: Optional[bool] = None


def _view_to_dict(view: SavedView) -> Dict[str, Any]:
    """Convert a SavedView model to a dictionary."""
    return {
        "id": view.id,
        "name": view.name,
        "user_id": view.user_id,
        "filters": (
            json.loads(view.filters) if isinstance(view.filters, str) else view.filters
        ),
        "is_default": view.is_default,
        "is_shared": view.is_shared,
        "created_at": view.created_at.isoformat() + "Z" if view.created_at else None,
        "updated_at": view.updated_at.isoformat() + "Z" if view.updated_at else None,
    }


@router.get("", response_model=Dict[str, Any])
async def list_views(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List saved views for current user (own + shared)."""
    try:
        from sqlalchemy import or_

        # PRA-281: scoped callers only see their OWN views (shared/global views may
        # encode hidden system/group/tag ids in their filters). Admins see own +
        # shared as before.
        if scoped_system_ids(db, current_user) is not None:
            view_filter = SavedView.user_id == current_user.id
        else:
            view_filter = or_(
                SavedView.user_id == current_user.id,
                SavedView.is_shared.is_(True),
            )
        views = db.query(SavedView).filter(view_filter).order_by(SavedView.name).all()
        return {
            "status": "success",
            "views": [_view_to_dict(v) for v in views],
        }
    except Exception as e:
        raise internal_error(e, context="listing views", logger=logger) from e


@router.post("", response_model=Dict[str, Any])
async def create_view(
    body: SavedViewCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a saved view."""
    try:
        # Only admins can create shared views
        if body.is_shared:
            user_roles = (
                [r.name for r in current_user.roles] if current_user.roles else []
            )
            if "admin" not in user_roles:
                raise ValueError("Only admins can create shared views")

        # If setting as default, unset any existing defaults for this user
        if body.is_default:
            existing_defaults = (
                db.query(SavedView)
                .filter(
                    SavedView.user_id == current_user.id,
                    SavedView.is_default.is_(True),
                )
                .all()
            )
            for v in existing_defaults:
                v.is_default = False

        view = SavedView(
            name=body.name,
            user_id=current_user.id,
            filters=json.dumps(body.filters),
            is_default=body.is_default,
            is_shared=body.is_shared,
        )
        db.add(view)
        db.commit()
        db.refresh(view)

        return {
            "status": "success",
            "message": f"View '{view.name}' created",
            "view": _view_to_dict(view),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="creating view", logger=logger) from e


@router.put("/{view_id}", response_model=Dict[str, Any])
async def update_view(
    body: SavedViewUpdate,
    view_id: int = Path(..., description="The ID of the view"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update a saved view. Only owner or admin for shared views."""
    try:
        view = db.query(SavedView).filter(SavedView.id == view_id).first()
        if not view:
            raise ValueError("View not found")
        # PRA-281: non-disclosing 404 for a shared/non-owned view (a scoped caller
        # must not see or mutate views whose filters may reference hidden inventory).
        if _view_hidden_for_scope(db, current_user, view):
            raise ValueError("View not found")

        user_roles = [r.name for r in current_user.roles] if current_user.roles else []
        is_admin = "admin" in user_roles
        if view.user_id != current_user.id and not is_admin:
            raise ValueError("You can only edit your own views")

        if body.name is not None:
            view.name = body.name
        if body.filters is not None:
            view.filters = json.dumps(body.filters)
        if body.is_shared is not None:
            if body.is_shared and not is_admin:
                raise ValueError("Only admins can create shared views")
            view.is_shared = body.is_shared
        if body.is_default is not None:
            if body.is_default:
                # Unset other defaults
                existing_defaults = (
                    db.query(SavedView)
                    .filter(
                        SavedView.user_id == current_user.id,
                        SavedView.is_default.is_(True),
                        SavedView.id != view_id,
                    )
                    .all()
                )
                for v in existing_defaults:
                    v.is_default = False
            view.is_default = body.is_default

        db.commit()
        db.refresh(view)

        return {
            "status": "success",
            "message": f"View '{view.name}' updated",
            "view": _view_to_dict(view),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="updating view", logger=logger) from e


@router.delete("/{view_id}", response_model=Dict[str, Any])
async def delete_view(
    view_id: int = Path(..., description="The ID of the view"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a saved view. Only owner or admin."""
    try:
        view = db.query(SavedView).filter(SavedView.id == view_id).first()
        if not view:
            raise ValueError("View not found")
        # PRA-281: non-disclosing 404 for a shared/non-owned view.
        if _view_hidden_for_scope(db, current_user, view):
            raise ValueError("View not found")

        user_roles = [r.name for r in current_user.roles] if current_user.roles else []
        is_admin = "admin" in user_roles
        if view.user_id != current_user.id and not is_admin:
            raise ValueError("You can only delete your own views")

        view_name = view.name
        db.delete(view)
        db.commit()

        return {
            "status": "success",
            "message": f"View '{view_name}' deleted",
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="deleting view", logger=logger) from e


@router.put("/{view_id}/default", response_model=Dict[str, Any])
async def set_default_view(
    view_id: int = Path(..., description="The ID of the view"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Set a view as the default for the current user."""
    try:
        view = db.query(SavedView).filter(SavedView.id == view_id).first()
        if not view:
            raise ValueError("View not found")
        # PRA-281: a scoped caller may not set a shared/non-owned view as default
        # (the response returns the view's filters). Non-disclosing 404.
        if _view_hidden_for_scope(db, current_user, view):
            raise ValueError("View not found")

        # Must be owner or it must be a shared view
        if view.user_id != current_user.id and not view.is_shared:
            raise ValueError("View not accessible")

        # Unset any existing defaults for this user
        existing_defaults = (
            db.query(SavedView)
            .filter(
                SavedView.user_id == current_user.id,
                SavedView.is_default.is_(True),
            )
            .all()
        )
        for v in existing_defaults:
            v.is_default = False

        view.is_default = True
        db.commit()
        db.refresh(view)

        return {
            "status": "success",
            "message": f"View '{view.name}' set as default",
            "view": _view_to_dict(view),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="setting default view", logger=logger) from e
