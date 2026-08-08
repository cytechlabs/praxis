"""
API routes for command approval workflows (PRA-80).
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import CommandApproval, CommandApprovalVote, System, User
from ...db.session import get_db
from ...services.access_authorization_service import scoped_system_ids
from ...services.command_approval_service import ApprovalVoteError, record_vote

router = APIRouter(redirect_slashes=False)


def _scoped_approvals(query, current_user: User, db: Session):
    """PRA-281: restrict a CommandApproval query to the caller's fleet scope.

    Approval rows are host-derived (``CommandApproval.system_id``), so a scoped
    caller must never see approvals — ids, hostnames, command text, requester/
    decider/vote metadata, or counts — for systems outside their scope. Admin
    (scope ``None``) is unchanged; an empty scope yields nothing.
    """
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        return query
    if not scope:
        from sqlalchemy import false

        return query.filter(false())
    return query.filter(CommandApproval.system_id.in_(scope))


def _enforce_approval_scope(db: Session, current_user: User, approval_id: int) -> None:
    """PRA-281: before any vote/approve/reject side effect, a scoped caller may
    only act on an approval whose system is in scope. Out-of-scope (or missing)
    approvals get a non-disclosing 404 with no state change. Admins
    (tenant-wide) are unaffected, so existing admin behavior (missing → the
    service's 400) is preserved."""
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        return
    approval = (
        db.query(CommandApproval).filter(CommandApproval.id == approval_id).first()
    )
    if approval is None or approval.system_id not in scope:
        raise HTTPException(status_code=404, detail="Approval request not found")


def _utc_iso(dt):
    if dt is None:
        return None
    return dt.isoformat() + "Z"


def _serialize_approval(a: CommandApproval, db: Session) -> Dict[str, Any]:
    requester = db.query(User).filter(User.id == a.requested_by).first()
    decider = (
        db.query(User).filter(User.id == a.decided_by).first() if a.decided_by else None
    )
    system = db.query(System).filter(System.id == a.system_id).first()
    votes = (
        db.query(CommandApprovalVote)
        .filter(CommandApprovalVote.approval_id == a.id)
        .all()
    )
    approves = sum(1 for v in votes if v.decision == "approve")
    return {
        "id": a.id,
        "command": a.command,
        "system_id": a.system_id,
        "system_hostname": system.hostname if system else None,
        "whitelist_entry_id": a.whitelist_entry_id,
        "requested_by": a.requested_by,
        "requester_username": requester.username if requester else None,
        "decided_by": a.decided_by,
        "decider_username": decider.username if decider else None,
        "status": a.status,
        "comment": a.comment,
        "timeout_seconds": a.timeout_seconds,
        "expires_at": _utc_iso(a.expires_at),
        "required_approvals": a.required_approvals or 1,
        "approves_received": approves,
        "votes": [
            {
                "user_id": v.user_id,
                "decision": v.decision,
                "comment": v.comment,
                "created_at": _utc_iso(v.created_at),
            }
            for v in votes
        ],
        "requested_at": _utc_iso(a.requested_at),
        "decided_at": _utc_iso(a.decided_at),
    }


class ApprovalDecisionIn(BaseModel):
    comment: Optional[str] = None


class VoteIn(BaseModel):
    decision: str  # "approve" or "reject"
    comment: Optional[str] = None


@router.get("", response_model=Dict[str, Any])
def list_approvals(
    status: Optional[str] = Query(
        None, description="Filter: pending, approved, rejected"
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List approval requests. Admins see all; others see only their own."""
    query = db.query(CommandApproval)
    if status:
        query = query.filter(CommandApproval.status == status)
    if not current_user.is_admin:
        query = query.filter(CommandApproval.requested_by == current_user.id)
    # PRA-281: additionally restrict to the caller's fleet scope (own-semantics
    # above are preserved and now further narrowed by scope).
    query = _scoped_approvals(query, current_user, db)
    approvals = query.order_by(CommandApproval.requested_at.desc()).limit(100).all()
    return {"approvals": [_serialize_approval(a, db) for a in approvals]}


def _vote_response(approval_id: int, db: Session) -> Dict[str, Any]:
    approval = (
        db.query(CommandApproval).filter(CommandApproval.id == approval_id).first()
    )
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return _serialize_approval(approval, db)


@router.post("/{approval_id}/vote", response_model=Dict[str, Any])
def vote_on_approval(
    approval_id: int = Path(...),
    payload: VoteIn = None,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Record a vote on a pending approval (PRA-129).

    decision = "approve" | "reject". Rejection is immediate; approvals
    accumulate until required_approvals is reached.
    """
    _enforce_approval_scope(db, current_user, approval_id)
    try:
        record_vote(
            db,
            approval_id,
            current_user.id,
            payload.decision,
            payload.comment,
        )
    except ApprovalVoteError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _vote_response(approval_id, db)


@router.post("/{approval_id}/approve", response_model=Dict[str, Any])
def approve_command(
    approval_id: int = Path(...),
    payload: ApprovalDecisionIn = ApprovalDecisionIn(),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Approve a pending command — backwards-compat wrapper around /vote."""
    _enforce_approval_scope(db, current_user, approval_id)
    try:
        record_vote(db, approval_id, current_user.id, "approve", payload.comment)
    except ApprovalVoteError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _vote_response(approval_id, db)


@router.post("/{approval_id}/reject", response_model=Dict[str, Any])
def reject_command(
    approval_id: int = Path(...),
    payload: ApprovalDecisionIn = ApprovalDecisionIn(),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Reject a pending command — backwards-compat wrapper around /vote."""
    _enforce_approval_scope(db, current_user, approval_id)
    try:
        record_vote(db, approval_id, current_user.id, "reject", payload.comment)
    except ApprovalVoteError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _vote_response(approval_id, db)


@router.get("/pending-count", response_model=Dict[str, Any])
def pending_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get count of pending approvals (admin sees all, others see own)."""
    query = db.query(CommandApproval).filter(CommandApproval.status == "pending")
    if not current_user.is_admin:
        query = query.filter(CommandApproval.requested_by == current_user.id)
    query = _scoped_approvals(query, current_user, db)
    return {"pending_count": query.count()}
