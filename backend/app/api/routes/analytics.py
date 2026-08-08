"""
Analytics API routes (PRA-19).

System health trends, compliance trends, top active systems, common failures.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Set

from fastapi import APIRouter, Depends, Query
from sqlalchemy import false, func
from sqlalchemy.orm import Session

from ...core.auth import get_current_user
from ...db.models import (
    FleetOperation,
    FleetOperationResult,
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


def _scope(query, column, system_ids: Optional[Set[int]]):
    """PRA-281: constrain an analytics query to the caller's fleet scope.

    ``system_ids is None`` = tenant-wide (admin), no filter. An explicit set is an
    allow-list; an empty set yields zero rows. Applied to every analytics source
    table that carries (or joins to) ``system_id`` so no row, count, or grouping
    includes or reveals an inaccessible system.
    """
    if system_ids is None:
        return query
    if not system_ids:
        return query.filter(false())
    return query.filter(column.in_(system_ids))


@router.get("/system-health-trends")
async def system_health_trends(
    days: int = Query(30, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Daily system status counts derived from audit entries + current snapshot."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    scope = scoped_system_ids(db, current_user)

    # Get current snapshot
    current_counts = (
        _scope(db.query(System.status, func.count(System.id)), System.id, scope)
        .group_by(System.status)
        .all()
    )
    current_snapshot = {status: count for status, count in current_counts}

    # Try to derive historical from status_change audit entries. Scoped by
    # SystemAudit.system_id, so audits for out-of-scope (or system-less) rows are
    # excluded for a scoped caller.
    status_changes = (
        _scope(
            db.query(
                func.date(SystemAudit.changed_at).label("date"),
                func.count(SystemAudit.id).label("change_count"),
            ),
            SystemAudit.system_id,
            scope,
        )
        .filter(
            SystemAudit.audit_type == "status_change",
            SystemAudit.changed_at >= cutoff,
        )
        .group_by(func.date(SystemAudit.changed_at))
        .order_by(func.date(SystemAudit.changed_at))
        .all()
    )

    daily_data = []
    if status_changes:
        for row in status_changes:
            daily_data.append(
                {
                    "date": str(row.date),
                    "changes": row.change_count,
                }
            )

    return {
        "current_snapshot": current_snapshot,
        "daily_changes": daily_data,
        "days": days,
        "note": (
            "Historical data derived from audit entries. Current snapshot shows live status."
            if not daily_data
            else None
        ),
    }


@router.get("/update-compliance-trend")
async def update_compliance_trend(
    days: int = Query(30, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Daily update compliance derived from PackageHistory operations."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    scope = scoped_system_ids(db, current_user)

    daily_ops = (
        _scope(
            db.query(
                func.date(PackageHistory.performed_at).label("date"),
                PackageHistory.operation,
                func.count(PackageHistory.id).label("count"),
            ),
            PackageHistory.system_id,
            scope,
        )
        .filter(PackageHistory.performed_at >= cutoff)
        .group_by(
            func.date(PackageHistory.performed_at),
            PackageHistory.operation,
        )
        .order_by(func.date(PackageHistory.performed_at))
        .all()
    )

    date_map: Dict[str, Dict[str, int]] = {}
    for row in daily_ops:
        d = str(row.date)
        if d not in date_map:
            date_map[d] = {}
        date_map[d][row.operation] = row.count

    trend = [{"date": d, "operations": ops} for d, ops in sorted(date_map.items())]

    return {
        "trend": trend,
        "days": days,
        "note": (
            "Sparse data is expected if few package operations occurred."
            if not trend
            else None
        ),
    }


@router.get("/top-active-systems")
async def top_active_systems(
    days: int = Query(30, ge=1, le=90),
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Top systems by activity count in the given period."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    scope = scoped_system_ids(db, current_user)

    # Count audit entries per system
    audit_counts = (
        _scope(
            db.query(
                SystemAudit.system_id,
                func.count(SystemAudit.id).label("audit_count"),
            ),
            SystemAudit.system_id,
            scope,
        )
        .filter(SystemAudit.changed_at >= cutoff, SystemAudit.system_id.isnot(None))
        .group_by(SystemAudit.system_id)
        .all()
    )

    # Count package operations per system
    pkg_counts = (
        _scope(
            db.query(
                PackageHistory.system_id,
                func.count(PackageHistory.id).label("pkg_count"),
            ),
            PackageHistory.system_id,
            scope,
        )
        .filter(PackageHistory.performed_at >= cutoff)
        .group_by(PackageHistory.system_id)
        .all()
    )

    # Merge counts
    system_activity: Dict[int, int] = {}
    for sid, cnt in audit_counts:
        system_activity[sid] = system_activity.get(sid, 0) + cnt
    for sid, cnt in pkg_counts:
        system_activity[sid] = system_activity.get(sid, 0) + cnt

    # Sort and take top N
    top_ids = sorted(system_activity.items(), key=lambda x: x[1], reverse=True)[:limit]

    results = []
    for sid, count in top_ids:
        sys = db.query(System).filter(System.id == sid).first()
        results.append(
            {
                "system_id": sid,
                "hostname": sys.hostname if sys else f"#{sid}",
                "activity_count": count,
            }
        )

    return {"systems": results, "days": days}


@router.get("/common-failures")
async def common_failures(
    days: int = Query(30, ge=1, le=90),
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Top failure reasons from jobs and fleet operations."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    scope = scoped_system_ids(db, current_user)

    failures: Dict[str, int] = {}

    # JobHistory failures. JobHistory has no direct system_id, so for a scoped
    # caller we attribute a job to systems via its PackageHistory rows (the only
    # per-system link) and keep only failures of jobs that touched an in-scope
    # system — error messages can embed hostnames, so job failures that cannot be
    # tied to an in-scope system are not surfaced. Admins (scope=None) see all.
    if scope is None:
        job_fails = (
            db.query(JobHistory.error_message, func.count(JobHistory.id))
            .filter(
                JobHistory.status == "failed",
                JobHistory.start_time >= cutoff,
                JobHistory.error_message.isnot(None),
            )
            .group_by(JobHistory.error_message)
            .all()
        )
    elif not scope:
        job_fails = []
    else:
        job_fails = (
            db.query(
                JobHistory.error_message,
                func.count(func.distinct(JobHistory.id)),
            )
            .join(PackageHistory, PackageHistory.job_history_id == JobHistory.id)
            .filter(
                JobHistory.status == "failed",
                JobHistory.start_time >= cutoff,
                JobHistory.error_message.isnot(None),
                PackageHistory.system_id.in_(scope),
            )
            .group_by(JobHistory.error_message)
            .all()
        )
    for msg, cnt in job_fails:
        key = (msg or "Unknown error")[:200]
        failures[key] = failures.get(key, 0) + cnt

    # FleetOperationResult failures — scoped by the per-system result's system_id.
    fleet_fails = (
        _scope(
            db.query(
                FleetOperationResult.error_message,
                func.count(FleetOperationResult.id),
            ),
            FleetOperationResult.system_id,
            scope,
        )
        .filter(
            FleetOperationResult.status == "failure",
            FleetOperationResult.created_at >= cutoff,
            FleetOperationResult.error_message.isnot(None),
        )
        .group_by(FleetOperationResult.error_message)
        .all()
    )
    for msg, cnt in fleet_fails:
        key = (msg or "Unknown error")[:200]
        failures[key] = failures.get(key, 0) + cnt

    sorted_failures = sorted(failures.items(), key=lambda x: x[1], reverse=True)[:limit]

    return {
        "failures": [{"error": err, "count": cnt} for err, cnt in sorted_failures],
        "days": days,
    }


@router.get("/overview-stats")
async def overview_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Quick overview statistics."""
    cutoff_30d = datetime.utcnow() - timedelta(days=30)
    scope = scoped_system_ids(db, current_user)

    total_systems = (
        _scope(db.query(func.count(System.id)), System.id, scope).scalar() or 0
    )
    total_packages = (
        _scope(db.query(func.count(Package.id)), Package.system_id, scope).scalar() or 0
    )

    # total_jobs_30d / total_bulk_ops: the base rows (JobHistory / FleetOperation)
    # carry no direct system_id. For a scoped caller we count only executions that
    # touched an in-scope system via their per-system child rows (PackageHistory /
    # FleetOperationResult); jobs/ops with no in-scope system target are excluded.
    if scope is None:
        total_jobs_30d = (
            db.query(func.count(JobHistory.id))
            .filter(JobHistory.start_time >= cutoff_30d)
            .scalar()
            or 0
        )
        total_bulk_ops = (
            db.query(func.count(FleetOperation.id))
            .filter(FleetOperation.created_at >= cutoff_30d)
            .scalar()
            or 0
        )
    elif not scope:
        total_jobs_30d = 0
        total_bulk_ops = 0
    else:
        total_jobs_30d = (
            db.query(func.count(func.distinct(JobHistory.id)))
            .join(PackageHistory, PackageHistory.job_history_id == JobHistory.id)
            .filter(
                JobHistory.start_time >= cutoff_30d,
                PackageHistory.system_id.in_(scope),
            )
            .scalar()
            or 0
        )
        total_bulk_ops = (
            db.query(func.count(func.distinct(FleetOperation.id)))
            .join(
                FleetOperationResult,
                FleetOperationResult.fleet_operation_id == FleetOperation.id,
            )
            .filter(
                FleetOperation.created_at >= cutoff_30d,
                FleetOperationResult.system_id.in_(scope),
            )
            .scalar()
            or 0
        )

    # active_alerts: unread in-app notifications. Notifications carry no system_id
    # (they are job/user-scoped) and a bare unread count cannot reveal system or
    # fleet inventory, so it stays global per the PRA-281 inventory's documented
    # non-system-count exception.
    active_alerts = (
        db.query(func.count(Notification.id))
        .filter(Notification.is_read.is_(False))
        .scalar()
        or 0
    )

    return {
        "total_systems": total_systems,
        "total_jobs_30d": total_jobs_30d,
        "total_packages": total_packages,
        "total_bulk_ops": total_bulk_ops,
        "active_alerts": active_alerts,
    }
