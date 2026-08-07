"""Session approval endpoints (PRA-147).

GET list (operators see all; requesters see only their own), grant, deny.
The actual approval *create* path is implicit — ``open_session`` creates
the pending row when a fleet role requires approval. This module covers
the operator queue and the requester's polling endpoint.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ...core.auth import get_current_user
from ...db.access_models import FleetRole, SessionApproval
from ...db.models import System, User
from ...db.session import get_db
from ...services import session_approval_service
from ...services.access_authorization_service import scoped_system_ids

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


def _scope_approvals(query, current_user: User, db: DbSession):
    """PRA-281: restrict a SessionApproval query to the caller's fleet scope.

    Approval rows are host-derived (``SessionApproval.system_id``), so a scoped
    caller never sees an approval id, requester/approver username, hostname, role
    name, login, reason, decision reason, or state for an out-of-scope system.
    Admin (scope ``None``) is unchanged; an empty scope yields nothing.
    """
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        return query
    if not scope:
        from sqlalchemy import false

        return query.filter(false())
    return query.filter(SessionApproval.system_id.in_(scope))


def _enforce_approval_scope(
    db: DbSession, current_user: User, approval_id: int
) -> None:
    """PRA-281: before enrichment or any grant/deny mutation/audit, a scoped
    caller may only touch an approval whose system is in scope. Out-of-scope (or
    missing) approvals get a non-disclosing 404. Admins are unaffected (existing
    service not-found handling is preserved)."""
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        return
    row = db.query(SessionApproval).filter(SessionApproval.id == approval_id).first()
    if row is None or row.system_id not in scope:
        raise HTTPException(status_code=404, detail="approval not found")


def _is_admin_or_maintainer(user: User) -> bool:
    if user.is_admin:
        return True
    return any(r.name == "maintainer" for r in (user.roles or []))


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _row_to_dict(
    row: SessionApproval,
    *,
    requester_username: Optional[str] = None,
    approver_username: Optional[str] = None,
    hostname: Optional[str] = None,
    fleet_role_name: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "id": row.id,
        "requester_id": row.requester_id,
        "requester_username": requester_username,
        "system_id": row.system_id,
        "hostname": hostname,
        "fleet_role_id": row.fleet_role_id,
        "fleet_role_name": fleet_role_name,
        "login": row.login,
        "reason": row.reason,
        "state": row.state,
        "approver_id": row.approver_id,
        "approver_username": approver_username,
        "decision_reason": row.decision_reason,
        "decided_at": _iso(row.decided_at),
        "expires_at": _iso(row.expires_at),
        "created_at": _iso(row.created_at),
    }


def _enrich(db: DbSession, rows: List[SessionApproval]) -> List[Dict[str, Any]]:
    if not rows:
        return []
    user_ids = {r.requester_id for r in rows}
    user_ids.update(r.approver_id for r in rows if r.approver_id)
    sys_ids = {r.system_id for r in rows}
    role_ids = {r.fleet_role_id for r in rows}
    user_map = {
        u.id: u.username
        for u in db.query(User.id, User.username).filter(User.id.in_(user_ids)).all()
    }
    sys_map = {
        s.id: s.hostname
        for s in db.query(System.id, System.hostname)
        .filter(System.id.in_(sys_ids))
        .all()
    }
    role_map = {
        r.id: r.name
        for r in db.query(FleetRole.id, FleetRole.name)
        .filter(FleetRole.id.in_(role_ids))
        .all()
    }
    return [
        _row_to_dict(
            r,
            requester_username=user_map.get(r.requester_id),
            approver_username=user_map.get(r.approver_id),
            hostname=sys_map.get(r.system_id),
            fleet_role_name=role_map.get(r.fleet_role_id),
        )
        for r in rows
    ]


# ----------------------------------------------------------- schemas


class DecisionBody(BaseModel):
    reason: Optional[str] = Field(None, max_length=1000)


# ----------------------------------------------------------- routes


@router.get("", response_model=Dict[str, Any])
async def list_approvals(
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
    state: Optional[str] = Query(None),
    mine_only: bool = Query(False),
):
    q = db.query(SessionApproval)
    if mine_only or not _is_admin_or_maintainer(current_user):
        q = q.filter(SessionApproval.requester_id == current_user.id)
    if state:
        q = q.filter(SessionApproval.state == state)
    # PRA-281: additionally fleet-scope every row before enrichment so hidden
    # requester/host/role/login metadata is never looked up.
    q = _scope_approvals(q, current_user, db)
    rows = q.order_by(SessionApproval.id.desc()).limit(200).all()
    return {"status": "success", "approvals": _enrich(db, rows)}


@router.get("/{approval_id}", response_model=Dict[str, Any])
async def get_approval(
    approval_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    row = db.query(SessionApproval).filter(SessionApproval.id == approval_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="approval not found")
    # PRA-281: out-of-scope approval -> non-disclosing 404 BEFORE the ownership
    # check / metadata enrichment (own-but-out-of-scope is 404, not 403).
    scope = scoped_system_ids(db, current_user)
    if scope is not None and row.system_id not in scope:
        raise HTTPException(status_code=404, detail="approval not found")
    if row.requester_id != current_user.id and not _is_admin_or_maintainer(
        current_user
    ):
        raise HTTPException(status_code=403, detail="not your approval")
    return {"status": "success", "approval": _enrich(db, [row])[0]}


@router.post("/{approval_id}/grant", response_model=Dict[str, Any])
async def grant_approval(
    payload: DecisionBody,
    http_request: Request,
    approval_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    _enforce_approval_scope(db, current_user, approval_id)
    try:
        row = session_approval_service.grant(
            db,
            approval_id=approval_id,
            approver=current_user,
            decision_reason=payload.reason,
            actor_ip=http_request.client.host if http_request.client else None,
        )
    except session_approval_service.ApprovalError as e:
        status = (
            404 if e.code == "not_found" else 409 if e.code == "invalid_state" else 400
        )
        raise HTTPException(status_code=status, detail=str(e)) from e
    return {"status": "success", "approval": _enrich(db, [row])[0]}


@router.post("/{approval_id}/deny", response_model=Dict[str, Any])
async def deny_approval(
    payload: DecisionBody,
    http_request: Request,
    approval_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    _enforce_approval_scope(db, current_user, approval_id)
    try:
        row = session_approval_service.deny(
            db,
            approval_id=approval_id,
            approver=current_user,
            decision_reason=payload.reason,
            actor_ip=http_request.client.host if http_request.client else None,
        )
    except session_approval_service.ApprovalError as e:
        status = (
            404 if e.code == "not_found" else 409 if e.code == "invalid_state" else 400
        )
        raise HTTPException(status_code=status, detail=str(e)) from e
    return {"status": "success", "approval": _enrich(db, [row])[0]}
