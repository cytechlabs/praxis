"""Access review endpoints (PRA-149).

Operator-facing review queue plus per-item attest/revoke/extend and
review-completion. Includes a CSV evidence export for compliance
packages.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from ...core.auth import get_current_user
from ...db.access_models import AccessReview, AccessReviewItem
from ...db.models import User
from ...db.session import get_db
from ...services import access_review_service

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


def _is_admin_or_maintainer(user: User) -> bool:
    if user.is_admin:
        return True
    return any(r.name == "maintainer" for r in (user.roles or []))


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _review_to_dict(r: AccessReview, *, item_count: int = 0) -> Dict[str, Any]:
    return {
        "id": r.id,
        "scope": r.scope,
        "scope_ref_id": r.scope_ref_id,
        "state": r.state,
        "due_at": _iso(r.due_at),
        "completed_at": _iso(r.completed_at),
        "reviewer_id": r.reviewer_id,
        "summary": r.summary,
        "created_by": r.created_by,
        "created_at": _iso(r.created_at),
        "item_count": item_count,
    }


def _item_to_dict(item: AccessReviewItem) -> Dict[str, Any]:
    try:
        snapshot = json.loads(item.binding_snapshot_json)
    except (TypeError, ValueError):
        snapshot = {}
    return {
        "id": item.id,
        "review_id": item.review_id,
        "binding_id": item.binding_id,
        "binding_snapshot": snapshot,
        "action": item.action,
        "decided_at": _iso(item.decided_at),
        "decided_by": item.decided_by,
        "notes": item.notes,
    }


# ----------------------------------------------------------- schemas


class CreateReviewBody(BaseModel):
    scope: str = Field("all", pattern="^(all|binding|user|role)$")
    scope_ref_id: Optional[int] = None
    due_in_days: int = Field(14, ge=1, le=365)


class ItemDecisionBody(BaseModel):
    notes: Optional[str] = Field(None, max_length=2000)
    days: Optional[int] = Field(None, ge=1, le=730)  # only for extend


class CompleteBody(BaseModel):
    summary: Optional[str] = Field(None, max_length=4000)


# ----------------------------------------------------------- routes


@router.get("", response_model=Dict[str, Any])
async def list_reviews(
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    reviews = db.query(AccessReview).order_by(AccessReview.id.desc()).limit(200).all()
    if not reviews:
        return {"status": "success", "reviews": []}
    review_ids = [r.id for r in reviews]
    counts: Dict[int, int] = {rid: 0 for rid in review_ids}
    for row in (
        db.query(AccessReviewItem.review_id, AccessReviewItem.id)
        .filter(AccessReviewItem.review_id.in_(review_ids))
        .all()
    ):
        counts[row[0]] = counts.get(row[0], 0) + 1
    return {
        "status": "success",
        "reviews": [
            _review_to_dict(r, item_count=counts.get(r.id, 0)) for r in reviews
        ],
    }


@router.post("", response_model=Dict[str, Any])
async def create_review(
    payload: CreateReviewBody,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="admin required")
    try:
        review = access_review_service.create_review(
            db,
            creator=current_user,
            scope=payload.scope,
            scope_ref_id=payload.scope_ref_id,
            due_in_days=payload.due_in_days,
            actor_ip=http_request.client.host if http_request.client else None,
        )
    except access_review_service.ReviewError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    item_count = (
        db.query(AccessReviewItem)
        .filter(AccessReviewItem.review_id == review.id)
        .count()
    )
    return {
        "status": "success",
        "review": _review_to_dict(review, item_count=item_count),
    }


@router.get("/{review_id}", response_model=Dict[str, Any])
async def get_review(
    review_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    review = db.query(AccessReview).filter(AccessReview.id == review_id).first()
    if review is None:
        raise HTTPException(status_code=404, detail="review not found")
    items = (
        db.query(AccessReviewItem)
        .filter(AccessReviewItem.review_id == review_id)
        .order_by(AccessReviewItem.id.asc())
        .all()
    )
    return {
        "status": "success",
        "review": _review_to_dict(review, item_count=len(items)),
        "items": [_item_to_dict(i) for i in items],
    }


def _decide(
    db: DbSession,
    *,
    review_id: int,
    item_id: int,
    decision: str,
    payload: ItemDecisionBody,
    user: User,
    http_request: Request,
) -> Dict[str, Any]:
    item = (
        db.query(AccessReviewItem)
        .filter(
            AccessReviewItem.id == item_id,
            AccessReviewItem.review_id == review_id,
        )
        .first()
    )
    if item is None:
        raise HTTPException(status_code=404, detail="item not found")
    actor_ip = http_request.client.host if http_request.client else None
    try:
        if decision == "attest":
            item = access_review_service.attest_item(
                db,
                item_id=item_id,
                reviewer=user,
                notes=payload.notes,
                actor_ip=actor_ip,
            )
        elif decision == "revoke":
            item = access_review_service.revoke_item(
                db,
                item_id=item_id,
                reviewer=user,
                notes=payload.notes,
                actor_ip=actor_ip,
            )
        elif decision == "extend":
            item = access_review_service.extend_item(
                db,
                item_id=item_id,
                reviewer=user,
                days=payload.days or access_review_service.DEFAULT_EXTEND_DAYS,
                notes=payload.notes,
                actor_ip=actor_ip,
            )
        else:  # pragma: no cover
            raise HTTPException(status_code=400, detail="bad decision")
    except access_review_service.ReviewError as e:
        status = (
            404 if e.code == "not_found" else 409 if e.code == "invalid_state" else 400
        )
        raise HTTPException(status_code=status, detail=str(e)) from e
    return {"status": "success", "item": _item_to_dict(item)}


@router.post("/{review_id}/items/{item_id}/attest", response_model=Dict[str, Any])
async def attest_item(
    payload: ItemDecisionBody,
    http_request: Request,
    review_id: int = Path(...),
    item_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    return _decide(
        db,
        review_id=review_id,
        item_id=item_id,
        decision="attest",
        payload=payload,
        user=current_user,
        http_request=http_request,
    )


@router.post("/{review_id}/items/{item_id}/revoke", response_model=Dict[str, Any])
async def revoke_item(
    payload: ItemDecisionBody,
    http_request: Request,
    review_id: int = Path(...),
    item_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    return _decide(
        db,
        review_id=review_id,
        item_id=item_id,
        decision="revoke",
        payload=payload,
        user=current_user,
        http_request=http_request,
    )


@router.post("/{review_id}/items/{item_id}/extend", response_model=Dict[str, Any])
async def extend_item(
    payload: ItemDecisionBody,
    http_request: Request,
    review_id: int = Path(...),
    item_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    return _decide(
        db,
        review_id=review_id,
        item_id=item_id,
        decision="extend",
        payload=payload,
        user=current_user,
        http_request=http_request,
    )


@router.post("/{review_id}/complete", response_model=Dict[str, Any])
async def complete_review(
    payload: CompleteBody,
    http_request: Request,
    review_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    try:
        review = access_review_service.complete_review(
            db,
            review_id=review_id,
            reviewer=current_user,
            summary=payload.summary,
            actor_ip=http_request.client.host if http_request.client else None,
        )
    except access_review_service.ReviewError as e:
        status = (
            404
            if e.code == "not_found"
            else 409 if e.code in ("invalid_state", "undecided") else 400
        )
        raise HTTPException(status_code=status, detail=str(e)) from e
    item_count = (
        db.query(AccessReviewItem)
        .filter(AccessReviewItem.review_id == review.id)
        .count()
    )
    return {
        "status": "success",
        "review": _review_to_dict(review, item_count=item_count),
    }


@router.get("/{review_id}/export.csv")
async def export_review_csv(
    review_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    """Compliance evidence CSV — one row per review item with decision."""
    if not _is_admin_or_maintainer(current_user):
        raise HTTPException(status_code=403, detail="admin or maintainer required")
    review = db.query(AccessReview).filter(AccessReview.id == review_id).first()
    if review is None:
        raise HTTPException(status_code=404, detail="review not found")
    items = (
        db.query(AccessReviewItem)
        .filter(AccessReviewItem.review_id == review_id)
        .order_by(AccessReviewItem.id.asc())
        .all()
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "review_id",
            "review_state",
            "review_scope",
            "review_completed_at",
            "review_summary",
            "item_id",
            "binding_id",
            "subject_user_id",
            "subject_app_role_id",
            "scope_group_id",
            "scope_smart_group_id",
            "fleet_role_id",
            "binding_enabled_at_snapshot",
            "binding_expires_at_snapshot",
            "decision",
            "decided_at",
            "decided_by",
            "notes",
        ]
    )
    for item in items:
        try:
            snap = json.loads(item.binding_snapshot_json)
        except (TypeError, ValueError):
            snap = {}
        writer.writerow(
            [
                review.id,
                review.state,
                review.scope,
                _iso(review.completed_at) or "",
                review.summary or "",
                item.id,
                item.binding_id or "",
                snap.get("subject_user_id") or "",
                snap.get("subject_app_role_id") or "",
                snap.get("scope_group_id") or "",
                snap.get("scope_smart_group_id") or "",
                snap.get("fleet_role_id") or "",
                snap.get("enabled"),
                snap.get("expires_at") or "",
                item.action,
                _iso(item.decided_at) or "",
                item.decided_by or "",
                item.notes or "",
            ]
        )
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="access-review-{review_id}.csv"',
        },
    )
