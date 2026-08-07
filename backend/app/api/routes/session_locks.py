"""Session lock endpoints (PRA-146).

Operator-only emergency cut-off. Admin or maintainer can create a lock
that immediately closes every live session belonging to the subject and
blocks all gated actions for them until released.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ...core.auth import get_current_user
from ...db.access_models import SessionLock
from ...db.models import Role, User
from ...db.session import get_db
from ...services import session_lock_service
from ...services.access_authorization_service import scoped_system_ids

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


def _is_tenant_wide(db, user: User) -> bool:
    """PRA-281: a session lock's subject (a user or an app role) can have live
    sessions on ANY system now OR in the future, so a lock's affected set is
    inherently unbounded and can never be proven fully within a scoped caller's
    fleet scope over time. Per the slice brief we therefore fail closed: session
    locks are operable ONLY by tenant-wide admins (``scoped_system_ids`` is
    ``None``). A scoped maintainer keeps its role but sees/creates/releases no
    lock — this prevents a scoped caller from closing out-of-scope (present or
    future) live sessions via a broad subject lock."""
    return scoped_system_ids(db, user) is None


def _is_admin_or_maintainer(user: User) -> bool:
    if user.is_admin:
        return True
    return any(r.name == "maintainer" for r in (user.roles or []))


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _row_to_dict(
    lock: SessionLock,
    *,
    subject_user: Optional[str] = None,
    subject_role: Optional[str] = None,
    creator_username: Optional[str] = None,
    releaser_username: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "id": lock.id,
        "subject_user_id": lock.subject_user_id,
        "subject_username": subject_user,
        "subject_app_role_id": lock.subject_app_role_id,
        "subject_role_name": subject_role,
        "reason": lock.reason,
        "created_by": lock.created_by,
        "created_by_username": creator_username,
        "created_at": _iso(lock.created_at),
        "released_at": _iso(lock.released_at),
        "released_by": lock.released_by,
        "released_by_username": releaser_username,
        "active": lock.released_at is None,
    }


def _enrich_many(db: DbSession, locks: List[SessionLock]) -> List[Dict[str, Any]]:
    if not locks:
        return []
    user_ids = {lock.subject_user_id for lock in locks if lock.subject_user_id}
    user_ids.update(lock.created_by for lock in locks if lock.created_by)
    user_ids.update(lock.released_by for lock in locks if lock.released_by)
    role_ids = {lock.subject_app_role_id for lock in locks if lock.subject_app_role_id}
    user_map = (
        {
            u.id: u.username
            for u in db.query(User.id, User.username)
            .filter(User.id.in_(user_ids))
            .all()
        }
        if user_ids
        else {}
    )
    role_map = (
        {
            r.id: r.name
            for r in db.query(Role.id, Role.name).filter(Role.id.in_(role_ids)).all()
        }
        if role_ids
        else {}
    )
    return [
        _row_to_dict(
            lock,
            subject_user=user_map.get(lock.subject_user_id),
            subject_role=role_map.get(lock.subject_app_role_id),
            creator_username=user_map.get(lock.created_by),
            releaser_username=user_map.get(lock.released_by),
        )
        for lock in locks
    ]


# ------------------------------------------------------------------ schemas


class CreateLockBody(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)
    subject_user_id: Optional[int] = None
    subject_username: Optional[str] = Field(None, max_length=100)
    subject_app_role_id: Optional[int] = None
    subject_role_name: Optional[str] = Field(None, max_length=100)


# ------------------------------------------------------------------ routes


@router.get("", response_model=Dict[str, Any])
async def list_locks(
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
    active_only: bool = Query(False),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    # PRA-281: fail closed for scoped callers — locks are tenant-wide-admin only.
    if not _is_tenant_wide(db, current_user):
        return {"status": "success", "locks": []}
    locks = session_lock_service.list_locks(db, active_only=active_only)
    return {"status": "success", "locks": _enrich_many(db, locks)}


@router.post("", response_model=Dict[str, Any])
async def create_lock(
    payload: CreateLockBody,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    # PRA-281: a scoped caller must not create a lock that could close out-of-scope
    # (present or future) live sessions for the subject. Restrict creation to
    # tenant-wide admin — checked BEFORE any session is closed.
    if not _is_tenant_wide(db, current_user):
        raise HTTPException(
            status_code=403,
            detail="session locks require tenant-wide admin access",
        )

    # Resolve username / role name to ids so the service sees a uniform shape.
    subject_user_id = payload.subject_user_id
    if subject_user_id is None and payload.subject_username:
        u = db.query(User).filter(User.username == payload.subject_username).first()
        if u is None:
            raise HTTPException(
                status_code=400, detail=f"user {payload.subject_username!r} not found"
            )
        subject_user_id = u.id
    subject_role_id = payload.subject_app_role_id
    if subject_role_id is None and payload.subject_role_name:
        r = db.query(Role).filter(Role.name == payload.subject_role_name).first()
        if r is None:
            raise HTTPException(
                status_code=400, detail=f"role {payload.subject_role_name!r} not found"
            )
        subject_role_id = r.id

    try:
        lock = session_lock_service.create_lock(
            db,
            creator=current_user,
            reason=payload.reason,
            subject_user_id=subject_user_id,
            subject_app_role_id=subject_role_id,
            actor_ip=http_request.client.host if http_request.client else None,
        )
    except session_lock_service.LockError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "success", "lock": _enrich_many(db, [lock])[0]}


@router.post("/{lock_id}/release", response_model=Dict[str, Any])
async def release_lock(
    http_request: Request,
    lock_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    # PRA-281: scoped callers cannot see any lock (fail closed), so a release
    # attempt is a non-disclosing 404 BEFORE any mutation/audit.
    if not _is_tenant_wide(db, current_user):
        raise HTTPException(status_code=404, detail="session lock not found")
    try:
        lock = session_lock_service.release_lock(
            db,
            lock_id=lock_id,
            releaser=current_user,
            actor_ip=http_request.client.host if http_request.client else None,
        )
    except session_lock_service.LockError as e:
        msg = str(e)
        status = 404 if "not found" in msg else 409 if "already" in msg else 400
        raise HTTPException(status_code=status, detail=msg) from e
    return {"status": "success", "lock": _enrich_many(db, [lock])[0]}
