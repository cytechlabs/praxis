"""Access reviews (PRA-149).

Periodic "who has what binding, are they still authorized?" sweep that
closes the SOC 2 / ISO access-review control without third-party tooling.

Lifecycle:
    create_review(scope) -> pending review + one item per matching enabled
                            AccessBinding (frozen snapshot)
    attest|revoke|extend item-by-item; revoke disables the live binding,
    extend bumps its expires_at.
    complete_review once every item is decided.
    sweep_overdue marks past-due pending reviews as expired.

Cadence is operator-configurable via the ``access_review.cadence_days``
key in ``app_settings`` (default 90 days).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy.orm import Session as DbSession

from ..db.access_models import AccessBinding, AccessReview, AccessReviewItem
from ..db.models import AppSettings, User
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)

DEFAULT_CADENCE_DAYS = 90
DEFAULT_DUE_IN_DAYS = 14
DEFAULT_EXTEND_DAYS = 90
CADENCE_SETTING_KEY = "access_review.cadence_days"


class ReviewError(Exception):
    """Raised when a review mutation can't proceed."""

    def __init__(self, reason: str, code: str = "invalid"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


# ----------------------------------------------------------- cadence cfg


def get_cadence_days(db: DbSession) -> int:
    """Operator-configured days between scheduled reviews. Default 90."""
    row = (
        db.query(AppSettings)
        .filter(AppSettings.setting_key == CADENCE_SETTING_KEY)
        .first()
    )
    if row is None:
        return DEFAULT_CADENCE_DAYS
    try:
        n = int(row.setting_value)
        return max(1, n)
    except (TypeError, ValueError):
        return DEFAULT_CADENCE_DAYS


# ----------------------------------------------------------- snapshots


def _snapshot_binding(b: AccessBinding) -> dict:
    """Frozen view of a binding so the review row stays meaningful even
    after the live binding is later revoked / deleted."""
    return {
        "binding_id": b.id,
        "subject_user_id": b.subject_user_id,
        "subject_app_role_id": b.subject_app_role_id,
        "scope_group_id": b.scope_group_id,
        "scope_smart_group_id": b.scope_smart_group_id,
        "fleet_role_id": b.fleet_role_id,
        "enabled": bool(b.enabled),
        "expires_at": b.expires_at.isoformat() + "Z" if b.expires_at else None,
        "created_at": b.created_at.isoformat() + "Z",
    }


def _bindings_in_scope(
    db: DbSession, scope: str, scope_ref_id: Optional[int]
) -> List[AccessBinding]:
    """Resolve a scope spec to the matching enabled bindings.

    PRA-149 spec answer: ``all`` covers only ``enabled=True`` bindings.
    Disabled bindings are noise — the operator already revoked them.
    """
    q = db.query(AccessBinding).filter(AccessBinding.enabled.is_(True))
    if scope == "all":
        pass
    elif scope == "binding":
        if scope_ref_id is None:
            raise ReviewError("binding scope requires scope_ref_id")
        q = q.filter(AccessBinding.id == scope_ref_id)
    elif scope == "user":
        if scope_ref_id is None:
            raise ReviewError("user scope requires scope_ref_id")
        q = q.filter(AccessBinding.subject_user_id == scope_ref_id)
    elif scope == "role":
        if scope_ref_id is None:
            raise ReviewError("role scope requires scope_ref_id")
        q = q.filter(AccessBinding.fleet_role_id == scope_ref_id)
    else:
        raise ReviewError(f"unknown scope {scope!r}")
    return q.order_by(AccessBinding.id.asc()).all()


# ----------------------------------------------------------- mutations


def create_review(
    db: DbSession,
    *,
    creator: Optional[User],
    scope: str = "all",
    scope_ref_id: Optional[int] = None,
    due_in_days: int = DEFAULT_DUE_IN_DAYS,
    actor_ip: Optional[str] = None,
) -> AccessReview:
    bindings = _bindings_in_scope(db, scope, scope_ref_id)
    review = AccessReview(
        scope=scope,
        scope_ref_id=scope_ref_id,
        state="pending",
        due_at=datetime.utcnow() + timedelta(days=max(1, due_in_days)),
        created_by=creator.id if creator is not None else None,
        created_at=datetime.utcnow(),
    )
    db.add(review)
    db.flush()
    for b in bindings:
        item = AccessReviewItem(
            review_id=review.id,
            binding_id=b.id,
            binding_snapshot_json=json.dumps(_snapshot_binding(b)),
            action="pending",
        )
        db.add(item)
    db.commit()
    db.refresh(review)
    safe_emit(
        db=db,
        action="review.create",
        actor_user_id=creator.id if creator is not None else None,
        actor_username=creator.username if creator is not None else None,
        actor_ip=actor_ip,
        target_kind="access_review",
        target_id=str(review.id),
        context={
            "scope": scope,
            "scope_ref_id": scope_ref_id,
            "item_count": len(bindings),
        },
    )
    logger.info(
        "access review %d created (scope=%s ref=%s items=%d)",
        review.id,
        scope,
        scope_ref_id,
        len(bindings),
    )
    return review


def _load_pending_item(db: DbSession, item_id: int) -> AccessReviewItem:
    item = db.query(AccessReviewItem).filter(AccessReviewItem.id == item_id).first()
    if item is None:
        raise ReviewError(f"item {item_id} not found", code="not_found")
    if item.action != "pending":
        raise ReviewError(
            f"item {item_id} already decided ({item.action})",
            code="invalid_state",
        )
    return item


def attest_item(
    db: DbSession,
    *,
    item_id: int,
    reviewer: User,
    notes: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> AccessReviewItem:
    item = _load_pending_item(db, item_id)
    item.action = "attest"
    item.decided_at = datetime.utcnow()
    item.decided_by = reviewer.id
    item.notes = notes
    db.commit()
    db.refresh(item)
    safe_emit(
        db=db,
        action="review.attest",
        actor_user_id=reviewer.id,
        actor_username=reviewer.username,
        actor_ip=actor_ip,
        target_kind="access_review_item",
        target_id=str(item.id),
        context={"review_id": item.review_id, "binding_id": item.binding_id},
    )
    return item


def revoke_item(
    db: DbSession,
    *,
    item_id: int,
    reviewer: User,
    notes: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> AccessReviewItem:
    item = _load_pending_item(db, item_id)
    # Disable the live binding (if it still exists).
    revoked_binding = False
    if item.binding_id is not None:
        binding = (
            db.query(AccessBinding).filter(AccessBinding.id == item.binding_id).first()
        )
        if binding is not None:
            binding.enabled = False
            revoked_binding = True
    item.action = "revoke"
    item.decided_at = datetime.utcnow()
    item.decided_by = reviewer.id
    item.notes = notes
    # PRA-285 fix-pass: FLUSH (not commit), then recompute in the SAME transaction
    # so the review-item decision + binding disable + grant rebuild + RevocationWork
    # outbox commit ATOMICALLY. A recompute failure rolls it all back — the item is
    # not marked revoked with stale grants and no outbox. Route through the common
    # path explicitly (the after-commit hook is disabled under tests).
    db.flush()
    if revoked_binding:
        from .access_binding_service import recompute_grants

        recompute_grants(
            db, reason="access_review_revoke", source=f"review_item:{item.id}"
        )
    else:
        db.commit()
    db.refresh(item)
    safe_emit(
        db=db,
        action="review.revoke",
        actor_user_id=reviewer.id,
        actor_username=reviewer.username,
        actor_ip=actor_ip,
        target_kind="access_review_item",
        target_id=str(item.id),
        context={
            "review_id": item.review_id,
            "binding_id": item.binding_id,
            "notes": notes,
        },
    )
    return item


def extend_item(
    db: DbSession,
    *,
    item_id: int,
    reviewer: User,
    days: int = DEFAULT_EXTEND_DAYS,
    notes: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> AccessReviewItem:
    item = _load_pending_item(db, item_id)
    if item.binding_id is None:
        raise ReviewError(
            "cannot extend a binding that no longer exists", code="invalid_state"
        )
    binding = (
        db.query(AccessBinding).filter(AccessBinding.id == item.binding_id).first()
    )
    if binding is None:
        raise ReviewError(
            "cannot extend a binding that no longer exists", code="invalid_state"
        )
    base = binding.expires_at or datetime.utcnow()
    binding.expires_at = base + timedelta(days=max(1, days))
    item.action = "extend"
    item.decided_at = datetime.utcnow()
    item.decided_by = reviewer.id
    item.notes = notes
    db.commit()
    db.refresh(item)
    safe_emit(
        db=db,
        action="review.extend",
        actor_user_id=reviewer.id,
        actor_username=reviewer.username,
        actor_ip=actor_ip,
        target_kind="access_review_item",
        target_id=str(item.id),
        context={
            "review_id": item.review_id,
            "binding_id": item.binding_id,
            "days": days,
            "new_expires_at": binding.expires_at.isoformat() + "Z",
        },
    )
    return item


def complete_review(
    db: DbSession,
    *,
    review_id: int,
    reviewer: User,
    summary: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> AccessReview:
    review = db.query(AccessReview).filter(AccessReview.id == review_id).first()
    if review is None:
        raise ReviewError(f"review {review_id} not found", code="not_found")
    if review.state != "pending":
        raise ReviewError(
            f"review {review_id} not pending ({review.state})", code="invalid_state"
        )
    undecided = (
        db.query(AccessReviewItem)
        .filter(
            AccessReviewItem.review_id == review_id,
            AccessReviewItem.action == "pending",
        )
        .count()
    )
    if undecided > 0:
        raise ReviewError(f"{undecided} items still need a decision", code="undecided")
    review.state = "completed"
    review.completed_at = datetime.utcnow()
    review.reviewer_id = reviewer.id
    review.summary = summary
    db.commit()
    db.refresh(review)
    safe_emit(
        db=db,
        action="review.complete",
        actor_user_id=reviewer.id,
        actor_username=reviewer.username,
        actor_ip=actor_ip,
        target_kind="access_review",
        target_id=str(review.id),
        context={"summary": summary},
    )
    return review


# ----------------------------------------------------------- sweep


def sweep_overdue(db: Optional[DbSession] = None) -> int:
    """Mark past-due pending reviews as ``expired`` and audit each."""
    own = db is None
    if own:
        from ..db.session import SessionLocal

        db = SessionLocal()
    try:
        now = datetime.utcnow()
        rows = (
            db.query(AccessReview)
            .filter(
                AccessReview.state == "pending",
                AccessReview.due_at <= now,
            )
            .all()
        )
        for r in rows:
            r.state = "expired"
        if rows:
            db.commit()
            for r in rows:
                safe_emit(
                    db=db,
                    action="review.expire",
                    target_kind="access_review",
                    target_id=str(r.id),
                    context={"scope": r.scope, "due_at": r.due_at.isoformat() + "Z"},
                )
        return len(rows)
    finally:
        if own:
            db.close()


def maybe_create_scheduled_review(db: Optional[DbSession] = None) -> Optional[int]:
    """Create a new "all" review when the cadence window has elapsed.

    Cadence is read from app_settings (key access_review.cadence_days).
    Skips if a pending all-scope review already exists, or the most recent
    completed review is younger than the cadence.
    """
    own = db is None
    if own:
        from ..db.session import SessionLocal

        db = SessionLocal()
    try:
        existing_pending = (
            db.query(AccessReview)
            .filter(
                AccessReview.scope == "all",
                AccessReview.state == "pending",
            )
            .first()
        )
        if existing_pending is not None:
            return None
        last_completed = (
            db.query(AccessReview)
            .filter(
                AccessReview.scope == "all",
                AccessReview.state == "completed",
            )
            .order_by(AccessReview.completed_at.desc())
            .first()
        )
        cadence = get_cadence_days(db)
        if last_completed is not None and last_completed.completed_at is not None:
            elapsed = datetime.utcnow() - last_completed.completed_at
            if elapsed.days < cadence:
                return None
        review = create_review(db, creator=None, scope="all")
        return review.id
    finally:
        if own:
            db.close()
