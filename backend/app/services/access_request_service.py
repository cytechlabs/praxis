"""Just-in-time access request service (PRA-139).

Flow:
    1. A user submits an AccessRequest specifying fleet_role + scope +
       duration + justification.
    2. An admin approves or rejects.
    3. On approval: a time-bound AccessBinding is created (subject = the
       requester, expires_at = now + duration). The request row stores the
       resulting binding ID so the UI can show 'access active until…'.
    4. The normal expired-binding sweep in ``access_binding_service`` drops
       the binding when the window closes.

The approval uses simple single-decider semantics for 1.0 — the M10 multi-vote
spine can be layered in later if a fleet calls for it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy.orm import Session

from ..db.access_models import AccessBinding, AccessRequest, FleetRole
from ..db.models import Group, SmartGroup
from . import access_binding_service as abs_svc

logger = logging.getLogger(__name__)

VALID_STATUSES = {"pending", "approved", "rejected", "expired", "revoked"}
MIN_DURATION_S = 300  # 5 min
MAX_DURATION_S = 60 * 60 * 24 * 7  # 7 days


class AccessRequestError(ValueError):
    """Raised on bad payload or state transitions."""


# ------------------------------------------------------------- validation


def _validate_scope(
    scope_group_id: Optional[int], scope_smart_group_id: Optional[int]
) -> None:
    set_count = sum(1 for v in (scope_group_id, scope_smart_group_id) if v is not None)
    if set_count != 1:
        raise AccessRequestError(
            "exactly one of scope_group_id / scope_smart_group_id must be set"
        )


def _validate_duration(seconds: int) -> None:
    if not (MIN_DURATION_S <= seconds <= MAX_DURATION_S):
        raise AccessRequestError(
            f"duration_seconds must be between {MIN_DURATION_S} and {MAX_DURATION_S}"
        )


# --------------------------------------------------------------- lifecycle


def create_request(
    db: Session,
    *,
    requested_by: int,
    fleet_role_id: int,
    scope_group_id: Optional[int] = None,
    scope_smart_group_id: Optional[int] = None,
    justification: Optional[str] = None,
    duration_seconds: int = 3600,
) -> AccessRequest:
    _validate_scope(scope_group_id, scope_smart_group_id)
    _validate_duration(duration_seconds)
    if db.query(FleetRole).filter(FleetRole.id == fleet_role_id).first() is None:
        raise AccessRequestError(f"fleet role {fleet_role_id} not found")
    if (
        scope_group_id is not None
        and db.query(Group).filter(Group.id == scope_group_id).first() is None
    ):
        raise AccessRequestError(f"group {scope_group_id} not found")
    if (
        scope_smart_group_id is not None
        and db.query(SmartGroup).filter(SmartGroup.id == scope_smart_group_id).first()
        is None
    ):
        raise AccessRequestError(f"smart group {scope_smart_group_id} not found")

    req = AccessRequest(
        requested_by=requested_by,
        fleet_role_id=fleet_role_id,
        scope_group_id=scope_group_id,
        scope_smart_group_id=scope_smart_group_id,
        justification=justification,
        duration_seconds=duration_seconds,
        status="pending",
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    try:
        from .audit_event_service import safe_emit

        safe_emit(
            db=db,
            action="access_request.create",
            actor_user_id=requested_by,
            target_kind="access_request",
            target_id=str(req.id),
            context={
                "fleet_role_id": fleet_role_id,
                "scope_group_id": scope_group_id,
                "scope_smart_group_id": scope_smart_group_id,
                "duration_seconds": duration_seconds,
                "justification": justification,
            },
        )
    except Exception:  # pylint: disable=broad-except
        pass
    return req


def approve(
    db: Session,
    request_id: int,
    *,
    decider_id: int,
    comment: Optional[str] = None,
) -> AccessRequest:
    req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if req is None:
        raise AccessRequestError(f"access request {request_id} not found")
    if req.status != "pending":
        raise AccessRequestError(f"cannot approve request in state {req.status!r}")

    binding = abs_svc.create_binding(
        db,
        fleet_role_id=req.fleet_role_id,
        subject_user_id=req.requested_by,
        scope_group_id=req.scope_group_id,
        scope_smart_group_id=req.scope_smart_group_id,
        enabled=True,
        expires_at=datetime.utcnow() + timedelta(seconds=req.duration_seconds),
        created_by=decider_id,
    )

    req.status = "approved"
    req.decided_by = decider_id
    req.decided_at = datetime.utcnow()
    req.decision_comment = comment
    req.resulting_binding_id = binding.id
    db.commit()
    db.refresh(req)
    logger.info(
        "access request %d approved by user %d -> binding %d",
        request_id,
        decider_id,
        binding.id,
    )
    try:
        from .audit_event_service import safe_emit

        safe_emit(
            db=db,
            action="access_request.approve",
            actor_user_id=decider_id,
            target_kind="access_request",
            target_id=str(req.id),
            context={
                "requested_by": req.requested_by,
                "fleet_role_id": req.fleet_role_id,
                "resulting_binding_id": binding.id,
                "duration_seconds": req.duration_seconds,
                "comment": comment,
            },
        )
    except Exception:  # pylint: disable=broad-except
        pass
    return req


def reject(
    db: Session,
    request_id: int,
    *,
    decider_id: int,
    comment: Optional[str] = None,
) -> AccessRequest:
    req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if req is None:
        raise AccessRequestError(f"access request {request_id} not found")
    if req.status != "pending":
        raise AccessRequestError(f"cannot reject request in state {req.status!r}")

    req.status = "rejected"
    req.decided_by = decider_id
    req.decided_at = datetime.utcnow()
    req.decision_comment = comment
    db.commit()
    db.refresh(req)
    try:
        from .audit_event_service import safe_emit

        safe_emit(
            db=db,
            action="access_request.reject",
            actor_user_id=decider_id,
            target_kind="access_request",
            target_id=str(req.id),
            context={"requested_by": req.requested_by, "comment": comment},
        )
    except Exception:  # pylint: disable=broad-except
        pass
    return req


def revoke(db: Session, request_id: int, revoker_id: int) -> AccessRequest:
    """Force-close an approved request early. Disables the binding."""
    req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if req is None:
        raise AccessRequestError(f"access request {request_id} not found")
    if req.status != "approved":
        raise AccessRequestError(f"cannot revoke request in state {req.status!r}")

    if req.resulting_binding_id is not None:
        # PRA-285: delete_binding recomputes grants (the common revocation choke
        # point) which enqueues host reconcile work; carry the JIT reason for audit.
        abs_svc.delete_binding(
            db,
            req.resulting_binding_id,
            reason="jit_revoke",
            source=f"access_request:{req.id}",
        )

    req.status = "revoked"
    req.decision_comment = (
        (req.decision_comment or "") + f"\n[revoked by user {revoker_id}]"
    ).strip()
    db.commit()
    db.refresh(req)
    return req


def expire_past_due(db: Session) -> int:
    """Mark approved requests whose binding has expired. Returns row count."""
    now = datetime.utcnow()
    approved = db.query(AccessRequest).filter(AccessRequest.status == "approved").all()
    changed = 0
    for req in approved:
        if req.resulting_binding_id is None:
            continue
        binding = (
            db.query(AccessBinding)
            .filter(AccessBinding.id == req.resulting_binding_id)
            .first()
        )
        if binding is None or (
            binding.expires_at is not None and binding.expires_at <= now
        ):
            req.status = "expired"
            changed += 1
    if changed:
        db.commit()
    return changed


# ------------------------------------------------------------------ query


def list_for_user(db: Session, user_id: int) -> List[AccessRequest]:
    return (
        db.query(AccessRequest)
        .filter(AccessRequest.requested_by == user_id)
        .order_by(AccessRequest.id.desc())
        .all()
    )


def list_pending(db: Session) -> List[AccessRequest]:
    return (
        db.query(AccessRequest)
        .filter(AccessRequest.status == "pending")
        .order_by(AccessRequest.id.asc())
        .all()
    )


def list_all(
    db: Session, status: Optional[str] = None, limit: int = 200
) -> List[AccessRequest]:
    q = db.query(AccessRequest)
    if status is not None:
        q = q.filter(AccessRequest.status == status)
    return q.order_by(AccessRequest.id.desc()).limit(limit).all()
