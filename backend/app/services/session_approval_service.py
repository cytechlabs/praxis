"""Session approval workflow (PRA-147).

When a fleet role has ``session_requires_approval=True``, ``open_session``
calls into this module. It looks up a usable grant matching the
(requester, system, fleet_role, login) tuple and atomically consumes it.
On miss, it creates a ``pending`` row, emits an audit event, and returns
the row so the API layer can tell the requester to wait.

Operators (admin/maintainer) call ``grant`` or ``deny``. Grants get a
short ``expires_at`` (default 5 min, per Teleport-style single-use
ergonomics) so an unused approval doesn't sit around as a latent
authorization. The scheduler runs ``sweep_expired`` every 60s.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session as DbSession

from ..db.access_models import SessionApproval
from ..db.models import User
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)

GRANT_TTL_SECONDS = 300  # 5 minutes — Teleport-style single-use window


class ApprovalError(Exception):
    """Raised when an approval mutation can't proceed (state mismatch, etc.)."""

    def __init__(self, reason: str, code: str = "invalid"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


# ----------------------------------------------------------------- queries


def find_usable_grant(
    db: DbSession,
    *,
    requester_id: int,
    system_id: int,
    fleet_role_id: int,
    login: str,
) -> Optional[SessionApproval]:
    """Return a granted, unexpired, unconsumed approval matching the tuple.

    Match key includes ``login`` per the PRA-147 design — a granted
    approval for ``alice as developer`` must not let her in as ``dba``.
    """
    now = datetime.utcnow()
    return (
        db.query(SessionApproval)
        .filter(
            SessionApproval.requester_id == requester_id,
            SessionApproval.system_id == system_id,
            SessionApproval.fleet_role_id == fleet_role_id,
            SessionApproval.login == login,
            SessionApproval.state == "granted",
            SessionApproval.expires_at > now,
        )
        .order_by(SessionApproval.id.desc())
        .first()
    )


# ----------------------------------------------------------------- mutations


def request_approval(
    db: DbSession,
    *,
    requester: User,
    system_id: int,
    fleet_role_id: int,
    login: str,
    reason: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> SessionApproval:
    """Persist a pending approval and emit ``session.approval_request``."""
    row = SessionApproval(
        requester_id=requester.id,
        system_id=system_id,
        fleet_role_id=fleet_role_id,
        login=login,
        reason=(reason or None),
        state="pending",
        created_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    safe_emit(
        db=db,
        action="session.approval_request",
        actor_user_id=requester.id,
        actor_username=requester.username,
        actor_ip=actor_ip,
        target_system_id=system_id,
        target_kind="session_approval",
        target_id=str(row.id),
        context={
            "fleet_role_id": fleet_role_id,
            "login": login,
            "reason": reason,
        },
    )
    return row


def grant(
    db: DbSession,
    *,
    approval_id: int,
    approver: User,
    decision_reason: Optional[str] = None,
    actor_ip: Optional[str] = None,
    ttl_seconds: int = GRANT_TTL_SECONDS,
) -> SessionApproval:
    row = _load_pending(db, approval_id)
    row.state = "granted"
    row.approver_id = approver.id
    row.decision_reason = decision_reason
    row.decided_at = datetime.utcnow()
    row.expires_at = row.decided_at + timedelta(seconds=ttl_seconds)
    db.commit()
    db.refresh(row)
    safe_emit(
        db=db,
        action="session.approval_grant",
        actor_user_id=approver.id,
        actor_username=approver.username,
        actor_ip=actor_ip,
        target_system_id=row.system_id,
        target_kind="session_approval",
        target_id=str(row.id),
        context={
            "requester_id": row.requester_id,
            "fleet_role_id": row.fleet_role_id,
            "login": row.login,
            "expires_at": row.expires_at.isoformat() + "Z",
        },
    )
    return row


def deny(
    db: DbSession,
    *,
    approval_id: int,
    approver: User,
    decision_reason: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> SessionApproval:
    row = _load_pending(db, approval_id)
    row.state = "denied"
    row.approver_id = approver.id
    row.decision_reason = decision_reason
    row.decided_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    safe_emit(
        db=db,
        action="session.approval_deny",
        actor_user_id=approver.id,
        actor_username=approver.username,
        actor_ip=actor_ip,
        target_system_id=row.system_id,
        target_kind="session_approval",
        target_id=str(row.id),
        context={
            "requester_id": row.requester_id,
            "fleet_role_id": row.fleet_role_id,
            "login": row.login,
            "decision_reason": decision_reason,
        },
    )
    return row


def consume(db: DbSession, *, approval: SessionApproval) -> SessionApproval:
    """Flip granted -> consumed. Caller already verified usability."""
    if approval.state != "granted":
        raise ApprovalError(
            f"approval {approval.id} not granted (state={approval.state})",
            code="invalid_state",
        )
    if approval.expires_at and approval.expires_at <= datetime.utcnow():
        raise ApprovalError(f"approval {approval.id} expired", code="expired")
    approval.state = "consumed"
    db.commit()
    db.refresh(approval)
    safe_emit(
        db=db,
        action="session.approval_consumed",
        actor_user_id=approval.requester_id,
        target_system_id=approval.system_id,
        target_kind="session_approval",
        target_id=str(approval.id),
        context={
            "fleet_role_id": approval.fleet_role_id,
            "login": approval.login,
        },
    )
    return approval


def sweep_expired(db: Optional[DbSession] = None) -> int:
    """Mark granted-but-unused approvals past expires_at as ``expired``."""
    own = db is None
    if own:
        from ..db.session import SessionLocal

        db = SessionLocal()
    try:
        now = datetime.utcnow()
        rows = (
            db.query(SessionApproval)
            .filter(
                SessionApproval.state == "granted",
                SessionApproval.expires_at <= now,
            )
            .all()
        )
        for row in rows:
            row.state = "expired"
        if rows:
            db.commit()
            for row in rows:
                safe_emit(
                    db=db,
                    action="session.approval_expire",
                    actor_user_id=None,
                    target_system_id=row.system_id,
                    target_kind="session_approval",
                    target_id=str(row.id),
                    context={
                        "requester_id": row.requester_id,
                        "fleet_role_id": row.fleet_role_id,
                        "login": row.login,
                    },
                )
        return len(rows)
    finally:
        if own:
            db.close()


# ----------------------------------------------------------------- helpers


def _load_pending(db: DbSession, approval_id: int) -> SessionApproval:
    row = db.query(SessionApproval).filter(SessionApproval.id == approval_id).first()
    if row is None:
        raise ApprovalError(f"approval {approval_id} not found", code="not_found")
    if row.state != "pending":
        raise ApprovalError(
            f"approval {approval_id} not pending (state={row.state})",
            code="invalid_state",
        )
    return row
