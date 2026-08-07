"""Just-in-time access request endpoints (PRA-139)."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.access_models import AccessRequest
from ...db.models import User
from ...db.session import get_db
from ...services import access_request_service as ar_svc
from ...services.access_request_service import AccessRequestError

router = APIRouter(redirect_slashes=False)


class AccessRequestCreate(BaseModel):
    fleet_role_id: int
    scope_group_id: Optional[int] = None
    scope_smart_group_id: Optional[int] = None
    justification: Optional[str] = Field(None, max_length=4000)
    duration_seconds: int = Field(3600, ge=300, le=60 * 60 * 24 * 7)

    @validator("scope_smart_group_id", always=True)
    def _scope_xor(v, values):  # noqa: N805
        group_set = values.get("scope_group_id") is not None
        sg_set = v is not None
        if group_set == sg_set:
            raise ValueError(
                "exactly one of scope_group_id / scope_smart_group_id must be set"
            )
        return v


class DecisionBody(BaseModel):
    comment: Optional[str] = Field(None, max_length=4000)


def _iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _to_dict(r: AccessRequest) -> Dict[str, Any]:
    return {
        "id": r.id,
        "requested_by": r.requested_by,
        "fleet_role_id": r.fleet_role_id,
        "scope_group_id": r.scope_group_id,
        "scope_smart_group_id": r.scope_smart_group_id,
        "justification": r.justification,
        "duration_seconds": r.duration_seconds,
        "status": r.status,
        "decided_by": r.decided_by,
        "decided_at": _iso(r.decided_at),
        "decision_comment": r.decision_comment,
        "resulting_binding_id": r.resulting_binding_id,
        "requested_at": _iso(r.requested_at),
    }


@router.get("", response_model=Dict[str, Any])
async def list_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    mine_only: bool = Query(True),
    status: Optional[str] = Query(None),
):
    """List access requests. Non-admins always get ``mine_only=True``."""
    if current_user.is_admin and not mine_only:
        rows = ar_svc.list_all(db, status=status)
    else:
        rows = ar_svc.list_for_user(db, current_user.id)
        if status is not None:
            rows = [r for r in rows if r.status == status]
    return {"status": "success", "requests": [_to_dict(r) for r in rows]}


@router.post("", response_model=Dict[str, Any])
async def create_request(
    payload: AccessRequestCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        req = ar_svc.create_request(
            db,
            requested_by=current_user.id,
            fleet_role_id=payload.fleet_role_id,
            scope_group_id=payload.scope_group_id,
            scope_smart_group_id=payload.scope_smart_group_id,
            justification=payload.justification,
            duration_seconds=payload.duration_seconds,
        )
    except AccessRequestError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "success", "request": _to_dict(req)}


@router.post("/{request_id}/approve", response_model=Dict[str, Any])
async def approve_request(
    request_id: int = Path(...),
    payload: DecisionBody = DecisionBody(),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    try:
        req = ar_svc.approve(
            db, request_id, decider_id=current_user.id, comment=payload.comment
        )
    except AccessRequestError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "success", "request": _to_dict(req)}


@router.post("/{request_id}/reject", response_model=Dict[str, Any])
async def reject_request(
    request_id: int = Path(...),
    payload: DecisionBody = DecisionBody(),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    try:
        req = ar_svc.reject(
            db, request_id, decider_id=current_user.id, comment=payload.comment
        )
    except AccessRequestError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "success", "request": _to_dict(req)}


@router.post("/{request_id}/revoke", response_model=Dict[str, Any])
async def revoke_request(
    request_id: int = Path(...),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    try:
        req = ar_svc.revoke(db, request_id, revoker_id=current_user.id)
    except AccessRequestError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "success", "request": _to_dict(req)}
