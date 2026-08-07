"""
System status monitoring routes - PRA-15.

Exposes fleet health dashboard data and per-system status information.
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_system_access
from ...db.models import Distro, Group, System, SystemMetadata, User
from ...db.session import get_db
from ...services.access_authorization_service import (
    scope_query_by_system,
    scoped_system_ids,
)
from ...services.health_service import HealthService

router = APIRouter(redirect_slashes=False)


@router.get("/overview")
async def get_system_status_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fleet-wide system status overview combining health dashboard with status counts."""
    # PRA-281: every count below is constrained to the caller's fleet scope
    # (None = tenant-wide admin), so an out-of-scope system never contributes to
    # a total or is revealed by a status rollup.
    scope = scoped_system_ids(db, current_user)

    health_svc = HealthService(db)
    dashboard = health_svc.get_fleet_dashboard(system_ids=scope)

    # Systems by connection_status
    conn_rows = (
        scope_query_by_system(
            db.query(SystemMetadata.connection_status, func.count(SystemMetadata.id)),
            db,
            current_user,
            SystemMetadata.system_id,
        )
        .group_by(SystemMetadata.connection_status)
        .all()
    )
    connection_counts = {
        (status or "never_checked"): count for status, count in conn_rows
    }

    # Systems with no metadata at all count as never_checked
    systems_with_meta = (
        scope_query_by_system(
            db.query(func.count(SystemMetadata.id)),
            db,
            current_user,
            SystemMetadata.system_id,
        ).scalar()
        or 0
    )
    total_systems = (
        scope_query_by_system(
            db.query(func.count(System.id)), db, current_user, System.id
        ).scalar()
        or 0
    )
    no_meta = total_systems - systems_with_meta
    if no_meta > 0:
        connection_counts["never_checked"] = (
            connection_counts.get("never_checked", 0) + no_meta
        )

    # Systems with stale scans (last_audited > 7 days ago or NULL)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    stale_scan_count = (
        scope_query_by_system(
            db.query(func.count(System.id)).filter(
                (System.last_audited.is_(None)) | (System.last_audited < seven_days_ago)
            ),
            db,
            current_user,
            System.id,
        ).scalar()
        or 0
    )

    # Average consecutive_failures across unreachable systems
    avg_failures = scope_query_by_system(
        db.query(func.avg(SystemMetadata.consecutive_failures))
        .join(System, System.id == SystemMetadata.system_id)
        .filter(System.status == "Unreachable"),
        db,
        current_user,
        System.id,
    ).scalar()

    return {
        **dashboard,
        "connection_counts": connection_counts,
        "stale_scan_count": stale_scan_count,
        "avg_consecutive_failures_unreachable": (
            round(float(avg_failures), 2) if avg_failures else 0
        ),
    }


@router.get("/systems")
async def get_system_status_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: Optional[str] = Query(None),
    connection_status: Optional[str] = Query(None),
    group_id: Optional[int] = Query(None),
    sort_by: Optional[str] = Query("hostname"),
    sort_dir: Optional[str] = Query("asc"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Paginated list of all systems with health info."""
    query = (
        db.query(System)
        .outerjoin(SystemMetadata, SystemMetadata.system_id == System.id)
        .outerjoin(Distro, Distro.id == System.distro_id)
        .outerjoin(Group, Group.id == System.group_id)
    )
    # PRA-281: only systems inside the caller's fleet scope are listed or counted.
    query = scope_query_by_system(query, db, current_user, System.id)

    if status:
        query = query.filter(System.status == status)
    if connection_status:
        if connection_status == "never_checked":
            query = query.filter(
                (SystemMetadata.connection_status.is_(None))
                | (SystemMetadata.id.is_(None))
            )
        else:
            query = query.filter(SystemMetadata.connection_status == connection_status)
    if group_id:
        query = query.filter(System.group_id == group_id)

    # Sorting
    sort_column = {
        "hostname": System.hostname,
        "status": System.status,
        "last_connection": SystemMetadata.last_connection,
    }.get(sort_by, System.hostname)

    if sort_dir == "desc":
        query = query.order_by(sort_column.desc().nullslast())
    else:
        query = query.order_by(sort_column.asc().nullsfirst())

    total = query.count()
    systems = query.offset((page - 1) * page_size).limit(page_size).all()

    items = []
    for s in systems:
        meta = s.system_metadata
        distro = s.distro
        group = s.group
        items.append(
            {
                "id": s.id,
                "hostname": s.hostname,
                "ip_address": str(s.ip_address),
                "status": s.status,
                "connection_status": (
                    meta.connection_status if meta else "never_checked"
                ),
                "last_connection": (
                    meta.last_connection.isoformat() + "Z"
                    if meta and meta.last_connection
                    else None
                ),
                "consecutive_failures": (meta.consecutive_failures if meta else 0),
                "last_audited": (
                    s.last_audited.isoformat() + "Z" if s.last_audited else None
                ),
                "distro_name": distro.name if distro else None,
                "group_name": group.name if group else None,
                "group_id": s.group_id,
            }
        )

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, -(-total // page_size)),
    }


@router.get(
    "/systems/{system_id}/history",
    dependencies=[Depends(require_system_access())],
)
async def get_system_status_history(
    system_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Current state snapshot for a system (no history table exists)."""
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="System not found")

    meta = system.system_metadata
    distro = system.distro
    group = system.group

    return {
        "system_id": system.id,
        "hostname": system.hostname,
        "ip_address": str(system.ip_address),
        "status": system.status,
        "connection_status": meta.connection_status if meta else "never_checked",
        "last_connection": (
            meta.last_connection.isoformat() + "Z"
            if meta and meta.last_connection
            else None
        ),
        "consecutive_failures": meta.consecutive_failures if meta else 0,
        "last_audited": (
            system.last_audited.isoformat() + "Z" if system.last_audited else None
        ),
        "distro_name": distro.name if distro else None,
        "distro_version": distro.version if distro else None,
        "group_name": group.name if group else None,
        "registered_at": (
            system.registered_at.isoformat() + "Z" if system.registered_at else None
        ),
        "metadata": (
            {
                "cpu_arch": meta.cpu_arch,
                "cpu_cores": meta.cpu_cores,
                "memory_total": meta.memory_total,
                "disk_total": meta.disk_total,
                "environment_type": meta.environment_type,
                "maintenance_window": meta.maintenance_window,
                "ssh_port": meta.ssh_port,
            }
            if meta
            else None
        ),
        "note": "History tracking is not yet implemented. This is a current state snapshot.",
    }
