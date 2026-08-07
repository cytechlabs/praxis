"""Patch-scoped approval voting + expiration service (PRA-161 slice 1a).

Sister to :mod:`command_approval_service` but deliberately decoupled.
The two services share semantic shape (multi-distinct-vote spine,
reject-shorts, sweeper) but **must not share code or exception
types**: command approvals auto-execute on threshold, patch
approvals never do. Mixing the two would make ``record_vote``'s
post-approval contract ambiguous, which is exactly what M16 design
locks forbid.

Caller contract:

* ``request_approval`` creates a pending row.
* ``record_vote`` records one vote and may flip status to
  ``approved`` / ``rejected``. It returns the new status; it does
  **not** dispatch any work.
* The caller polls :func:`get_approval_status` (or queries the
  ORM directly) and decides whether to proceed with the
  underlying patch action.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from ..db.models import PatchApproval, PatchApprovalVote, User

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local exception type — DO NOT replace with a shared base class. Keeping
# this local prevents accidental coupling back to command_approval_service.
# ---------------------------------------------------------------------------


class PatchApprovalVoteError(Exception):
    """Raised when a patch-approval vote cannot be recorded."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_SUBJECT_KINDS = frozenset({"policy", "plan", "rollback"})
ALLOWED_DECISIONS = frozenset({"approve", "reject"})
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def request_approval(
    db: Session,
    *,
    subject_kind: str,
    subject_id: int,
    requested_by: int,
    required_approvals: int = 1,
    expires_at: Optional[datetime] = None,
    comment: Optional[str] = None,
) -> PatchApproval:
    """Create a pending patch-approval row.

    Validations are explicit and loud — every layer rejects
    bad input rather than letting it reach the DB CHECK
    constraints.
    """
    if subject_kind not in ALLOWED_SUBJECT_KINDS:
        raise PatchApprovalVoteError(
            f"subject_kind must be one of {sorted(ALLOWED_SUBJECT_KINDS)}"
        )
    if (
        not isinstance(subject_id, int)
        or isinstance(subject_id, bool)
        or subject_id <= 0
    ):
        raise PatchApprovalVoteError("subject_id must be a positive integer")
    # Bool-as-int trap: bool is a subclass of int in Python, so ``isinstance(v, int)``
    # admits ``True`` / ``False``. Reject explicitly.
    if (
        isinstance(required_approvals, bool)
        or not isinstance(required_approvals, int)
        or required_approvals < 1
    ):
        raise PatchApprovalVoteError("required_approvals must be an integer >= 1")
    if expires_at is not None and not isinstance(expires_at, datetime):
        raise PatchApprovalVoteError("expires_at must be a datetime or None")

    approval = PatchApproval(
        subject_kind=subject_kind,
        subject_id=subject_id,
        status=STATUS_PENDING,
        required_approvals=required_approvals,
        expires_at=expires_at,
        requested_by=requested_by,
        comment=comment,
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval


def record_vote(
    db: Session,
    approval_id: int,
    user_id: int,
    decision: str,
    comment: Optional[str] = None,
) -> Dict[str, Any]:
    """Record a vote and flip status if threshold reached.

    Rules mirror command-approval semantics (reject short-circuits,
    one vote per user, expired requests are sealed on access) but
    **no work is dispatched** when status flips to ``approved``.
    """
    if decision not in ALLOWED_DECISIONS:
        raise PatchApprovalVoteError("decision must be 'approve' or 'reject'")

    approval = db.query(PatchApproval).filter(PatchApproval.id == approval_id).first()
    if not approval:
        raise PatchApprovalVoteError("Approval not found")
    if approval.status != STATUS_PENDING:
        raise PatchApprovalVoteError(f"Already {approval.status}")
    if approval.expires_at and approval.expires_at < datetime.utcnow():
        _expire(db, approval)
        raise PatchApprovalVoteError("Request has expired")

    existing = (
        db.query(PatchApprovalVote)
        .filter(
            PatchApprovalVote.approval_id == approval_id,
            PatchApprovalVote.user_id == user_id,
        )
        .first()
    )
    if existing:
        raise PatchApprovalVoteError("You have already voted on this request")

    vote = PatchApprovalVote(
        approval_id=approval_id,
        user_id=user_id,
        decision=decision,
        comment=comment,
    )
    db.add(vote)
    db.flush()

    if decision == "reject":
        approval.status = STATUS_REJECTED
        approval.decided_by = user_id
        approval.decided_at = datetime.utcnow()
        approval.comment = comment
        db.commit()
        _notify(db, approval, "patch_approval_rejected", user_id, comment)
        return {"status": STATUS_REJECTED, "approval_id": approval.id}

    approve_count = (
        db.query(PatchApprovalVote)
        .filter(
            PatchApprovalVote.approval_id == approval_id,
            PatchApprovalVote.decision == "approve",
        )
        .count()
    )
    required = approval.required_approvals or 1

    if approve_count >= required:
        approval.status = STATUS_APPROVED
        approval.decided_by = user_id
        approval.decided_at = datetime.utcnow()
        approval.comment = comment
        db.commit()
        _notify(db, approval, "patch_approval_approved", user_id, comment)
        # Intentionally NO _execute_in_background. Caller polls status.
        return {
            "status": STATUS_APPROVED,
            "approval_id": approval.id,
            "approves": approve_count,
            "required": required,
        }

    db.commit()
    return {
        "status": STATUS_PENDING,
        "approval_id": approval.id,
        "approves": approve_count,
        "required": required,
    }


def get_approval_status(
    db: Session,
    *,
    subject_kind: str,
    subject_id: int,
) -> Optional[Dict[str, Any]]:
    """Return the most recent approval row for a subject, or None.

    Patch surfaces ask "is this policy/plan/rollback approved right
    now?" — they do not paginate approval history. Service returns
    the newest row by ``created_at`` and lets the caller decide.
    """
    if subject_kind not in ALLOWED_SUBJECT_KINDS:
        raise PatchApprovalVoteError(
            f"subject_kind must be one of {sorted(ALLOWED_SUBJECT_KINDS)}"
        )

    approval = (
        db.query(PatchApproval)
        .filter(
            PatchApproval.subject_kind == subject_kind,
            PatchApproval.subject_id == subject_id,
        )
        .order_by(PatchApproval.created_at.desc())
        .first()
    )
    if not approval:
        return None

    if (
        approval.status == STATUS_PENDING
        and approval.expires_at
        and approval.expires_at < datetime.utcnow()
    ):
        _expire(db, approval)

    return {
        "approval_id": approval.id,
        "subject_kind": approval.subject_kind,
        "subject_id": approval.subject_id,
        "status": approval.status,
        "required_approvals": approval.required_approvals,
        "expires_at": approval.expires_at,
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at,
    }


# ---------------------------------------------------------------------------
# Sweeper
# ---------------------------------------------------------------------------


def expire_stale(db: Session) -> int:
    """Find pending approvals past their ``expires_at`` and mark expired."""
    now = datetime.utcnow()
    stale = (
        db.query(PatchApproval)
        .filter(
            PatchApproval.status == STATUS_PENDING,
            PatchApproval.expires_at.isnot(None),
            PatchApproval.expires_at < now,
        )
        .all()
    )
    for a in stale:
        _expire(db, a)
    return len(stale)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _expire(db: Session, approval: PatchApproval) -> None:
    approval.status = STATUS_EXPIRED
    approval.decided_at = datetime.utcnow()
    db.commit()


def _notify(
    db: Session,
    approval: PatchApproval,
    event: str,
    actor_id: int,
    comment: Optional[str],
) -> None:
    try:
        from .notification_service import create_notification

        actor = db.query(User).filter(User.id == actor_id).first()
        actor_name = actor.username if actor else f"User {actor_id}"
        verb = "approved" if event == "patch_approval_approved" else "rejected"
        msg = (
            f"Your patch {approval.subject_kind} approval was {verb} "
            f"by {actor_name}"
        )
        if comment:
            msg += f" — {comment}"
        create_notification(
            db,
            type=event,
            title=f"Patch {approval.subject_kind} {verb}",
            message=msg,
            severity="info" if event == "patch_approval_approved" else "warning",
            user_id=approval.requested_by,
        )
    except Exception as e:  # pylint: disable=broad-except
        logger.error("patch approval notification failed: %s", e)
