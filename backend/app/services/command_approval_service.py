"""Command approval voting + expiration service (PRA-129)."""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from ..db.models import CommandApproval, CommandApprovalVote, User
from ..db.session import SessionLocal

logger = logging.getLogger(__name__)


class ApprovalVoteError(Exception):
    """Raised when a vote cannot be recorded (already expired, duplicate, etc.)."""


def record_vote(
    db: Session,
    approval_id: int,
    user_id: int,
    decision: str,
    comment: Optional[str] = None,
) -> Dict[str, Any]:
    """Record a vote and, if threshold met, mark the approval executed/rejected.

    Rules:
      - decision must be "approve" or "reject"
      - a user may vote at most once on a given approval
      - a reject vote immediately rejects the request (short-circuit)
      - an approve vote counts toward required_approvals; when N distinct
        approves are recorded, the approval flips to approved
    """
    if decision not in ("approve", "reject"):
        raise ApprovalVoteError("decision must be 'approve' or 'reject'")

    approval = (
        db.query(CommandApproval).filter(CommandApproval.id == approval_id).first()
    )
    if not approval:
        raise ApprovalVoteError("Approval not found")
    if approval.status != "pending":
        raise ApprovalVoteError(f"Already {approval.status}")
    if approval.expires_at and approval.expires_at < datetime.utcnow():
        _expire(db, approval)
        raise ApprovalVoteError("Request has expired")

    existing = (
        db.query(CommandApprovalVote)
        .filter(
            CommandApprovalVote.approval_id == approval_id,
            CommandApprovalVote.user_id == user_id,
        )
        .first()
    )
    if existing:
        raise ApprovalVoteError("You have already voted on this request")

    vote = CommandApprovalVote(
        approval_id=approval_id,
        user_id=user_id,
        decision=decision,
        comment=comment,
    )
    db.add(vote)
    db.flush()

    if decision == "reject":
        approval.status = "rejected"
        approval.decided_by = user_id
        approval.decided_at = datetime.utcnow()
        approval.comment = comment
        db.commit()
        _notify(db, approval, "command_rejected", user_id, comment)
        return {"status": "rejected", "approval_id": approval.id}

    # Count distinct approves
    approve_count = (
        db.query(CommandApprovalVote)
        .filter(
            CommandApprovalVote.approval_id == approval_id,
            CommandApprovalVote.decision == "approve",
        )
        .count()
    )
    required = approval.required_approvals or 1

    if approve_count >= required:
        approval.status = "approved"
        approval.decided_by = user_id
        approval.decided_at = datetime.utcnow()
        approval.comment = comment
        db.commit()
        _notify(db, approval, "command_approved", user_id, comment)
        _execute_in_background(approval.id)
        return {
            "status": "approved",
            "approval_id": approval.id,
            "approves": approve_count,
            "required": required,
        }

    db.commit()
    return {
        "status": "pending",
        "approval_id": approval.id,
        "approves": approve_count,
        "required": required,
    }


def _notify(
    db: Session,
    approval: CommandApproval,
    event: str,
    actor_id: int,
    comment: Optional[str],
) -> None:
    try:
        from .notification_service import create_notification

        actor = db.query(User).filter(User.id == actor_id).first()
        actor_name = actor.username if actor else f"User {actor_id}"
        verb = "approved" if event == "command_approved" else "rejected"
        msg = f"Your command was {verb} by {actor_name}: {approval.command}"
        if comment:
            msg += f" — {comment}"
        create_notification(
            db,
            type=event,
            title=f"Command {verb}",
            message=msg,
            severity="info" if event == "command_approved" else "warning",
            user_id=approval.requested_by,
        )
    except Exception as e:  # pylint: disable=broad-except
        logger.error("approval notification failed: %s", e)


def _execute_in_background(approval_id: int) -> None:
    """Run the approved command in a background thread."""

    def _run():
        from .command_execution_service import CommandExecutionService

        bg_db = SessionLocal()
        try:
            approval = (
                bg_db.query(CommandApproval)
                .filter(CommandApproval.id == approval_id)
                .first()
            )
            if not approval:
                return
            CommandExecutionService(bg_db).execute_command(
                system_id=approval.system_id,
                user_id=approval.requested_by,
                command=approval.command,
                timeout_seconds=approval.timeout_seconds or 30,
                bypass_validation=True,
                execution_context={"approval_id": approval.id},
            )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Approved command execution failed: %s", e)
        finally:
            bg_db.close()

    threading.Thread(target=_run, daemon=True).start()


# ---------------------------------------------------------------------------
# Expiration sweeper
# ---------------------------------------------------------------------------


def _expire(db: Session, approval: CommandApproval) -> None:
    approval.status = "expired"
    approval.decided_at = datetime.utcnow()
    db.commit()
    try:
        from .notification_service import create_notification

        create_notification(
            db,
            type="command_expired",
            title="Command approval expired",
            message=f"Your approval request expired without decision: {approval.command}",
            severity="warning",
            user_id=approval.requested_by,
        )
    except Exception as e:  # pylint: disable=broad-except
        logger.error("approval expiration notification failed: %s", e)


def expire_stale(db: Session) -> int:
    """Find pending approvals past their expires_at and mark expired."""
    now = datetime.utcnow()
    stale = (
        db.query(CommandApproval)
        .filter(
            CommandApproval.status == "pending",
            CommandApproval.expires_at.isnot(None),
            CommandApproval.expires_at < now,
        )
        .all()
    )
    for a in stale:
        _expire(db, a)
    return len(stale)
