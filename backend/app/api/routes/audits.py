"""
System audit API routes (PRA-14).

Exposes read-only access to the SystemAudit log.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session, joinedload

from ...core.auth import require_role
from ...core.timeutil import utc_iso
from ...db.models import System, SystemAudit, User
from ...db.session import get_db
from ...services.access_authorization_service import (
    scope_query_by_system,
    scoped_system_ids,
    user_can_access_system,
)

router = APIRouter(redirect_slashes=False)


def _serialize_audit(audit: SystemAudit) -> Dict[str, Any]:
    return {
        "id": audit.id,
        "system_id": audit.system_id,
        "system_hostname": audit.system.hostname if audit.system else None,
        "audit_type": audit.audit_type,
        "operation": audit.operation,
        "changed_by": audit.changed_by,
        "changed_by_username": (
            audit.changed_by_user.username
            if getattr(audit, "changed_by_user", None)
            else None
        ),
        "changed_at": utc_iso(audit.changed_at),
        "old_value": audit.old_value,
        "new_value": audit.new_value,
        "created_at": utc_iso(audit.created_at),
    }


def _apply_filters(
    query,
    system_id: Optional[int],
    user_id: Optional[int],
    audit_type: Optional[str],
    operation: Optional[str],
    from_date: Optional[datetime],
    to_date: Optional[datetime],
):
    if system_id is not None:
        query = query.filter(SystemAudit.system_id == system_id)
    if user_id is not None:
        query = query.filter(SystemAudit.changed_by == user_id)
    if audit_type:
        query = query.filter(SystemAudit.audit_type == audit_type)
    if operation:
        query = query.filter(SystemAudit.operation == operation)
    if from_date:
        query = query.filter(SystemAudit.changed_at >= from_date)
    if to_date:
        query = query.filter(SystemAudit.changed_at <= to_date)
    return query


def _serialize_with_user(
    audit: SystemAudit, user_map: Dict[int, str]
) -> Dict[str, Any]:
    return {
        "id": audit.id,
        "system_id": audit.system_id,
        "system_hostname": audit.system.hostname if audit.system else None,
        "audit_type": audit.audit_type,
        "operation": audit.operation,
        "changed_by": audit.changed_by,
        "changed_by_username": user_map.get(audit.changed_by),
        "changed_at": utc_iso(audit.changed_at),
        "old_value": audit.old_value,
        "new_value": audit.new_value,
        "created_at": utc_iso(audit.created_at),
    }


@router.get("")
async def list_audits(
    system_id: Optional[int] = Query(None),
    user_id: Optional[int] = Query(None),
    audit_type: Optional[str] = Query(None),
    operation: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    current_user: User = Depends(require_role("admin", "auditor")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Paginated list of SystemAudit entries with filters."""
    # PRA-281: an explicit out-of-scope system_id filter is a non-disclosing 404
    # (indistinguishable from a nonexistent system), before any query runs.
    if (
        system_id is not None
        and scoped_system_ids(db, current_user) is not None
        and not user_can_access_system(db, current_user, system_id)
    ):
        raise HTTPException(status_code=404, detail="System not found")

    query = db.query(SystemAudit).options(joinedload(SystemAudit.system))
    query = _apply_filters(
        query, system_id, user_id, audit_type, operation, from_date, to_date
    )
    # PRA-281: rows AND total are scoped by SystemAudit.system_id (audits with a
    # NULL/out-of-scope system are excluded for scoped callers; empty scope → 0).
    query = scope_query_by_system(query, db, current_user, SystemAudit.system_id)
    total = query.count()
    items = (
        query.order_by(SystemAudit.changed_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    user_ids = {a.changed_by for a in items if a.changed_by is not None}
    user_map: Dict[int, str] = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        user_map = {u.id: u.username for u in users}

    return {
        "items": [_serialize_with_user(a, user_map) for a in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.get("/filters/options")
async def get_filter_options(
    current_user: User = Depends(require_role("admin", "auditor")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return distinct values for filter dropdowns on the frontend."""
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        audit_types = [
            row[0]
            for row in db.query(SystemAudit.audit_type).distinct().all()
            if row[0]
        ]
        operations = [
            row[0] for row in db.query(SystemAudit.operation).distinct().all() if row[0]
        ]
        systems = [
            {"id": s.id, "hostname": s.hostname}
            for s in db.query(System).order_by(System.hostname).all()
        ]
        users = [
            {"id": u.id, "username": u.username}
            for u in db.query(User).order_by(User.username).all()
        ]
        return {
            "audit_types": sorted(audit_types),
            "operations": sorted(operations),
            "systems": systems,
            "users": users,
        }

    # PRA-281: a scoped caller's filter vocabulary is derived only from the audit
    # rows visible to them (in-scope system_id), so no out-of-scope audit type,
    # operation, system hostname, or actor username leaks. Empty scope → empty.
    base = scope_query_by_system(
        db.query(SystemAudit), db, current_user, SystemAudit.system_id
    )
    audit_types = sorted(
        {
            row[0]
            for row in base.with_entities(SystemAudit.audit_type).distinct()
            if row[0]
        }
    )
    operations = sorted(
        {
            row[0]
            for row in base.with_entities(SystemAudit.operation).distinct()
            if row[0]
        }
    )
    system_ids = {
        row[0]
        for row in base.with_entities(SystemAudit.system_id).distinct()
        if row[0] is not None
    }
    systems = [
        {"id": s.id, "hostname": s.hostname}
        for s in db.query(System)
        .filter(System.id.in_(system_ids))
        .order_by(System.hostname)
        .all()
    ]
    user_ids = {
        row[0]
        for row in base.with_entities(SystemAudit.changed_by).distinct()
        if row[0] is not None
    }
    users = [
        {"id": u.id, "username": u.username}
        for u in db.query(User)
        .filter(User.id.in_(user_ids))
        .order_by(User.username)
        .all()
    ]
    return {
        "audit_types": audit_types,
        "operations": operations,
        "systems": systems,
        "users": users,
    }


@router.get("/{system_id}")
async def list_audits_for_system(
    system_id: int = Path(..., ge=1),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    current_user: User = Depends(require_role("admin", "auditor")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Paginated audits for a single system."""
    # PRA-281: non-disclosing 404 for an out-of-scope (or empty-scope) system id,
    # before the system hostname or any audit row is returned.
    if scoped_system_ids(db, current_user) is not None and not user_can_access_system(
        db, current_user, system_id
    ):
        raise HTTPException(status_code=404, detail="System not found")

    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    query = (
        db.query(SystemAudit)
        .options(joinedload(SystemAudit.system))
        .filter(SystemAudit.system_id == system_id)
    )
    if from_date:
        query = query.filter(SystemAudit.changed_at >= from_date)
    if to_date:
        query = query.filter(SystemAudit.changed_at <= to_date)

    total = query.count()
    items = (
        query.order_by(SystemAudit.changed_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    user_ids = {a.changed_by for a in items if a.changed_by is not None}
    user_map: Dict[int, str] = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        user_map = {u.id: u.username for u in users}

    return {
        "system": {"id": system.id, "hostname": system.hostname},
        "items": [_serialize_with_user(a, user_map) for a in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
    }
