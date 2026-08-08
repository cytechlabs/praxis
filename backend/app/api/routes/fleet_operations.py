"""
Fleet operations audit trail routes (PRA-115).

Read-only endpoints that expose the FleetOperation + FleetOperationResult
audit tables written by bulk action handlers.
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session, joinedload

from ...core.auth import get_current_user
from ...core.timeutil import utc_iso
from ...db.models import FleetOperation, FleetOperationResult, User
from ...db.session import get_db
from ...services.access_authorization_service import scoped_system_ids

router = APIRouter(redirect_slashes=False)


def _operation_result_system_ids(db: Session, op_ids) -> Dict[int, set]:
    """Map each operation id -> the set of non-null result system ids.

    PRA-281: a fleet operation is host-derived through its
    ``FleetOperationResult`` rows. A result row with a NULL ``system_id`` cannot
    be attributed to a system, so it does not count toward the in-scope set.
    """
    out: Dict[int, set] = {oid: set() for oid in op_ids}
    if not op_ids:
        return out
    rows = (
        db.query(
            FleetOperationResult.fleet_operation_id,
            FleetOperationResult.system_id,
        )
        .filter(FleetOperationResult.fleet_operation_id.in_(op_ids))
        .all()
    )
    for op_id, sys_id in rows:
        if sys_id is not None:
            out.setdefault(op_id, set()).add(sys_id)
    return out


def _operation_visible_to_scope(members: set, scope) -> bool:
    """Admin (scope ``None``) sees all. A scoped caller may see an operation only
    when its resolved result systems are non-empty AND entirely in scope — empty,
    mixed, and out-of-scope-only operations are hidden (fail closed), so no
    out-of-scope hostname/error/count leaks."""
    if scope is None:
        return True
    return bool(members) and members.issubset(scope)


def _parse_parameters(raw: Optional[str]) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw


def _serialize_operation(op: FleetOperation, username: Optional[str]) -> Dict[str, Any]:
    return {
        "id": op.id,
        "operation_type": op.operation_type,
        "user_id": op.user_id,
        "username": username,
        "target_count": op.target_count,
        "success_count": op.success_count,
        "failure_count": op.failure_count,
        "status": op.status,
        "parameters": _parse_parameters(op.parameters),
        "created_at": utc_iso(op.created_at),
        "completed_at": utc_iso(op.completed_at),
    }


@router.get("")
async def list_fleet_operations(
    operation_type: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    current_user: User = Depends(get_current_user),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Paginated fleet-operations audit trail list."""
    query = db.query(FleetOperation)
    if operation_type:
        query = query.filter(FleetOperation.operation_type == operation_type)
    if user_id is not None:
        query = query.filter(FleetOperation.user_id == user_id)
    if status_filter:
        query = query.filter(FleetOperation.status == status_filter)
    if from_date:
        query = query.filter(FleetOperation.created_at >= from_date)
    if to_date:
        query = query.filter(FleetOperation.created_at <= to_date)

    # PRA-281: admins page efficiently in SQL; a scoped caller must filter by
    # per-operation result-system visibility, so we resolve the filtered set,
    # keep only fully-in-scope operations, then paginate in Python — the total
    # reflects the visible set (out-of-scope/mixed operations never leak).
    scope = scoped_system_ids(db, current_user)
    ordered = query.order_by(FleetOperation.created_at.desc())
    if scope is None:
        total = query.count()
        items = ordered.offset((page - 1) * page_size).limit(page_size).all()
    else:
        all_ops = ordered.all()
        sys_map = _operation_result_system_ids(db, [o.id for o in all_ops])
        visible = [
            o
            for o in all_ops
            if _operation_visible_to_scope(sys_map.get(o.id, set()), scope)
        ]
        total = len(visible)
        items = visible[(page - 1) * page_size : page * page_size]

    user_ids = {o.user_id for o in items if o.user_id is not None}
    user_map: Dict[int, str] = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        user_map = {u.id: u.username for u in users}

    return {
        "items": [_serialize_operation(o, user_map.get(o.user_id)) for o in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.get("/filters/options")
async def get_filter_options(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return distinct operation_types/statuses + user list for filter UI."""
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        operation_types = [
            row[0]
            for row in db.query(FleetOperation.operation_type).distinct().all()
            if row[0]
        ]
        statuses = [
            row[0] for row in db.query(FleetOperation.status).distinct().all() if row[0]
        ]
        users = [
            {"id": u.id, "username": u.username}
            for u in db.query(User).order_by(User.username).all()
        ]
        return {
            "operation_types": sorted(operation_types),
            "statuses": sorted(statuses),
            "users": users,
        }

    # PRA-281: a scoped caller's filter vocabulary is derived only from the
    # operations VISIBLE to them (result systems non-empty AND fully in scope),
    # so no out-of-scope operation type, status, or operator username leaks.
    # Empty scope → empty option lists.
    all_ops = db.query(FleetOperation).all()
    sys_map = _operation_result_system_ids(db, [o.id for o in all_ops])
    visible = [
        o
        for o in all_ops
        if _operation_visible_to_scope(sys_map.get(o.id, set()), scope)
    ]
    operation_types = sorted({o.operation_type for o in visible if o.operation_type})
    statuses = sorted({o.status for o in visible if o.status})
    user_ids = {o.user_id for o in visible if o.user_id is not None}
    users = [
        {"id": u.id, "username": u.username}
        for u in db.query(User)
        .filter(User.id.in_(user_ids))
        .order_by(User.username)
        .all()
    ]
    return {
        "operation_types": operation_types,
        "statuses": statuses,
        "users": users,
    }


@router.get("/{operation_id}")
async def get_fleet_operation(
    operation_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Fetch a single FleetOperation with its per-system result rows."""
    op = db.query(FleetOperation).filter(FleetOperation.id == operation_id).first()
    if not op:
        raise HTTPException(status_code=404, detail="Fleet operation not found")

    # PRA-281: non-disclosing 404 for an operation not fully in scope, BEFORE any
    # operation parameters, counts, username, result hostname, or error message is
    # returned. Hidden/mixed/out-of-scope-only/empty operations are indistinct
    # from nonexistent.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        members = _operation_result_system_ids(db, [op.id]).get(op.id, set())
        if not _operation_visible_to_scope(members, scope):
            raise HTTPException(status_code=404, detail="Fleet operation not found")

    username = None
    if op.user_id:
        user = db.query(User).filter(User.id == op.user_id).first()
        username = user.username if user else None

    results = (
        db.query(FleetOperationResult)
        .options(joinedload(FleetOperationResult.system))
        .filter(FleetOperationResult.fleet_operation_id == operation_id)
        .order_by(FleetOperationResult.id.asc())
        .all()
    )

    result_rows = [
        {
            "id": r.id,
            "system_id": r.system_id,
            "system_hostname": r.system.hostname if r.system else None,
            "status": r.status,
            "error_message": r.error_message,
            "created_at": utc_iso(r.created_at),
        }
        for r in results
    ]

    return {
        "operation": _serialize_operation(op, username),
        "results": result_rows,
    }
