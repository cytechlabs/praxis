"""
Activity feed API routes (PRA-18).

Unified chronological feed from multiple data sources.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, get_user_roles
from ...core.timeutil import utc_iso
from ...db.models import (
    FleetOperation,
    JobHistory,
    Notification,
    Package,
    PackageHistory,
    System,
    SystemAudit,
    User,
)
from ...db.session import get_db
from ...services.access_authorization_service import scoped_system_ids

router = APIRouter(redirect_slashes=False)

SOURCES = ["audit", "fleet_op", "job", "package", "notification"]

# PRA-180 AUDIT-05: the "audit" source surfaces SystemAudit old/new values,
# actor usernames, and fleet-wide system context. Only the audit-read roles may
# see it, matching the unified ``/audit/events`` posture.
AUDIT_READ_ROLES = {"admin", "auditor"}


def _safe_json(raw: Optional[str]) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw


def _build_feed_items(
    db: Session,
    source: Optional[str],
    system_id: Optional[int],
    user_id: Optional[int],
    from_date: Optional[datetime],
    to_date: Optional[datetime],
    fetch_limit: int,
    include_audit: bool,
    allowed_system_ids: Optional[set],
) -> List[Dict[str, Any]]:
    """Query each source table and normalize into feed items.

    PRA-281: ``allowed_system_ids`` is the caller's fleet scope — ``None`` for a
    tenant-wide admin (no restriction), otherwise the set of grantable system ids
    (possibly empty). The ``package`` source is host-attributed operational data
    (system_id + hostname + package/version detail) and is restricted to that
    set. The ``audit`` source is intentionally tenant-wide for audit-read roles
    (see below). The remaining sources (``fleet_op``, ``job``, ``notification``)
    are not per-host attributed (``system_id`` is always ``None`` on their items).
    """
    items: List[Dict[str, Any]] = []

    user_map: Dict[int, str] = {}

    def _username(uid: Optional[int]) -> Optional[str]:
        if uid is None:
            return None
        if uid not in user_map:
            u = db.query(User).filter(User.id == uid).first()
            user_map[uid] = u.username if u else None
        return user_map.get(uid)

    # --- SystemAudit ---
    # PRA-180 AUDIT-05: only emit audit rows for audit-read roles. Lower-privilege
    # callers still get the rest of the mixed feed, just without audit detail.
    if (source is None or source == "audit") and include_audit:
        # PRA-281 / PRA-221: the audit source is intentionally tenant-wide for the
        # audit-read roles (admin/auditor) — it mirrors ``/audit/events``, the
        # canonical compliance audit trail. It is NOT fleet-scoped; the role gate
        # in the route is its access control. Only the ``package`` source below,
        # which has no tenant-wide-reader design, is restricted to fleet scope.
        q = db.query(SystemAudit)
        if system_id is not None:
            q = q.filter(SystemAudit.system_id == system_id)
        if user_id is not None:
            q = q.filter(SystemAudit.changed_by == user_id)
        if from_date:
            q = q.filter(SystemAudit.changed_at >= from_date)
        if to_date:
            q = q.filter(SystemAudit.changed_at <= to_date)
        audits = q.order_by(SystemAudit.changed_at.desc()).limit(fetch_limit).all()
        for a in audits:
            sys = (
                db.query(System).filter(System.id == a.system_id).first()
                if a.system_id
                else None
            )
            items.append(
                {
                    "id": f"audit-{a.id}",
                    "source": "audit",
                    "event_type": a.audit_type,
                    "description": f"{a.operation}: {a.audit_type}",
                    "user_id": a.changed_by,
                    "username": _username(a.changed_by),
                    "system_id": a.system_id,
                    "system_hostname": sys.hostname if sys else None,
                    "timestamp": utc_iso(a.changed_at),
                    "details": {"old_value": a.old_value, "new_value": a.new_value},
                }
            )

    # --- FleetOperation ---
    if source is None or source == "fleet_op":
        q = db.query(FleetOperation)
        if user_id is not None:
            q = q.filter(FleetOperation.user_id == user_id)
        if from_date:
            q = q.filter(FleetOperation.created_at >= from_date)
        if to_date:
            q = q.filter(FleetOperation.created_at <= to_date)
        # fleet ops don't have a single system_id, skip filter if system_id set
        if system_id is not None:
            q = q.filter(False)  # exclude fleet ops when filtering by system
        ops = q.order_by(FleetOperation.created_at.desc()).limit(fetch_limit).all()
        for o in ops:
            items.append(
                {
                    "id": f"fleet_op-{o.id}",
                    "source": "fleet_op",
                    "event_type": o.operation_type,
                    "description": f"Fleet operation: {o.operation_type} ({o.target_count} targets, {o.status})",
                    "user_id": o.user_id,
                    "username": _username(o.user_id),
                    "system_id": None,
                    "system_hostname": None,
                    "timestamp": utc_iso(o.created_at),
                    "details": {
                        "status": o.status,
                        "target_count": o.target_count,
                        "success_count": o.success_count,
                        "failure_count": o.failure_count,
                        "parameters": _safe_json(o.parameters),
                    },
                }
            )

    # --- JobHistory ---
    if source is None or source == "job":
        q = db.query(JobHistory)
        if from_date:
            q = q.filter(JobHistory.start_time >= from_date)
        if to_date:
            q = q.filter(JobHistory.start_time <= to_date)
        if system_id is not None or user_id is not None:
            q = q.filter(False)  # jobs don't have direct system/user FK
        jobs = q.order_by(JobHistory.start_time.desc()).limit(fetch_limit).all()
        for j in jobs:
            items.append(
                {
                    "id": f"job-{j.id}",
                    "source": "job",
                    "event_type": j.status,
                    "description": f"Job #{j.job_id} {j.status} ({j.systems_targeted} targeted, {j.systems_completed} completed)",
                    "user_id": None,
                    "username": None,
                    "system_id": None,
                    "system_hostname": None,
                    "timestamp": utc_iso(j.start_time),
                    "details": {
                        "job_id": j.job_id,
                        "status": j.status,
                        "systems_targeted": j.systems_targeted,
                        "systems_completed": j.systems_completed,
                        "systems_failed": j.systems_failed,
                        "error_message": j.error_message,
                    },
                }
            )

    # --- PackageHistory ---
    if source is None or source == "package":
        q = db.query(PackageHistory)
        if allowed_system_ids is not None:
            q = q.filter(PackageHistory.system_id.in_(allowed_system_ids))
        if system_id is not None:
            q = q.filter(PackageHistory.system_id == system_id)
        if user_id is not None:
            q = q.filter(PackageHistory.performed_by == user_id)
        if from_date:
            q = q.filter(PackageHistory.performed_at >= from_date)
        if to_date:
            q = q.filter(PackageHistory.performed_at <= to_date)
        pkg_hist = (
            q.order_by(PackageHistory.performed_at.desc()).limit(fetch_limit).all()
        )
        for ph in pkg_hist:
            pkg = db.query(Package).filter(Package.id == ph.package_id).first()
            sys = (
                db.query(System).filter(System.id == ph.system_id).first()
                if ph.system_id
                else None
            )
            pkg_name = pkg.name if pkg else f"pkg#{ph.package_id}"
            items.append(
                {
                    "id": f"package-{ph.id}",
                    "source": "package",
                    "event_type": ph.operation,
                    "description": f"Package {ph.operation}: {pkg_name} ({ph.old_version or '?'} -> {ph.new_version or '?'})",
                    "user_id": ph.performed_by,
                    "username": _username(ph.performed_by),
                    "system_id": ph.system_id,
                    "system_hostname": sys.hostname if sys else None,
                    "timestamp": utc_iso(ph.performed_at),
                    "details": {
                        "package_name": pkg_name,
                        "old_version": ph.old_version,
                        "new_version": ph.new_version,
                        "status": ph.status,
                    },
                }
            )

    # --- Notification ---
    if source is None or source == "notification":
        q = db.query(Notification)
        if user_id is not None:
            q = q.filter(
                (Notification.user_id == user_id) | (Notification.user_id.is_(None))
            )
        if from_date:
            q = q.filter(Notification.created_at >= from_date)
        if to_date:
            q = q.filter(Notification.created_at <= to_date)
        if system_id is not None:
            q = q.filter(False)  # notifications don't have system_id
        notifs = q.order_by(Notification.created_at.desc()).limit(fetch_limit).all()
        for n in notifs:
            items.append(
                {
                    "id": f"notification-{n.id}",
                    "source": "notification",
                    "event_type": n.type,
                    "description": n.title,
                    "user_id": n.user_id,
                    "username": _username(n.user_id),
                    "system_id": None,
                    "system_hostname": None,
                    "timestamp": utc_iso(n.created_at),
                    "details": {
                        "message": n.message,
                        "severity": n.severity,
                        "is_read": n.is_read,
                    },
                }
            )

    return items


@router.get("/feed")
async def activity_feed(
    source: Optional[str] = Query(None),
    system_id: Optional[int] = Query(None),
    user_id: Optional[int] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Unified chronological activity feed."""
    # PRA-180 AUDIT-05: the audit source is restricted to admin/auditor. An
    # explicit ``source=audit`` request from a lower-privilege role is denied;
    # the unfiltered ("all sources") feed still works for them but drops audit
    # rows instead of leaking fleet-wide audit detail.
    can_read_audit = bool(set(get_user_roles(current_user)) & AUDIT_READ_ROLES)
    if source == "audit" and not can_read_audit:
        raise HTTPException(
            status_code=403,
            detail="Audit activity requires the admin or auditor role",
        )

    # PRA-281: the host-attributed ``package`` source is restricted to the
    # caller's fleet scope (``None`` = tenant-wide admin, unchanged). A scoped
    # caller who filters by an out-of-scope ``system_id`` simply gets no package
    # rows — the scope filter intersects the explicit id, so nothing leaks — while
    # the tenant-wide ``audit`` source (audit-read roles only) is unaffected, per
    # the PRA-221 audit posture.
    allowed_system_ids = scoped_system_ids(db, current_user)

    fetch_limit = page_size * 3  # over-fetch from each source

    items = _build_feed_items(
        db,
        source,
        system_id,
        user_id,
        from_date,
        to_date,
        fetch_limit,
        include_audit=can_read_audit,
        allowed_system_ids=allowed_system_ids,
    )

    # Sort by timestamp descending
    items.sort(key=lambda x: x["timestamp"] or "", reverse=True)

    # Paginate
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]

    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.get("/feed/sources")
async def feed_sources(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Available source types for filter dropdown."""
    return {
        "sources": [
            {"value": "audit", "label": "System Changes"},
            {"value": "fleet_op", "label": "Bulk Operations"},
            {"value": "job", "label": "Jobs"},
            {"value": "package", "label": "Packages"},
            {"value": "notification", "label": "Notifications"},
        ]
    }
