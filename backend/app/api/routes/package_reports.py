"""
Package reports API routes (PRA-17).

Fleet-wide package summary, outdated packages, and compliance reporting.

PRA-358: the two tabular sections (outdated + compliance) also expose on-demand
CSV/JSON exports that record a durable ``report_runs`` row through the shared
report-kind contract, so Package Reports is a first-class reporting domain (not
just a dashboard) and its exports show up in Recent Reports / are schedulable.
"""

import csv
import io
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import Package, PackageUpdate, SmartGroupMembership, System, User
from ...db.session import get_db
from ...services import (
    _export_helpers,
    package_reports_export_service,
    report_run_service,
)
from ...services.access_authorization_service import scoped_system_ids

router = APIRouter(redirect_slashes=False)


def _actor_ip(request: Request) -> Optional[str]:
    return request.client.host if request and request.client else None


def _export_response(
    rows: List[Dict[str, Any]],
    columns: Sequence[str],
    fmt: str,
    filename_base: str,
) -> Any:
    """Serialize export rows to a downloadable CSV or JSON attachment with a
    consistent Content-Disposition filename."""
    if fmt == "json":
        return JSONResponse(
            content=rows,
            headers={
                "Content-Disposition": f"attachment; filename={filename_base}.json"
            },
        )
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename_base}.csv"},
    )


def _effective_system_ids(
    db: Session, current_user: User, smart_group_id: Optional[int]
) -> Optional[list]:
    """PRA-281: resolve the effective system-id filter for a package report,
    combining the caller's FLEET SCOPE with the optional ``smart_group_id``.

    Returns ``None`` ONLY for a tenant-wide admin with no ``smart_group_id``
    (truly fleet-wide, unchanged). Otherwise a concrete list (possibly empty):

    * no ``smart_group_id`` → a scoped caller sees only their fleet scope;
    * with ``smart_group_id`` → the smart-group membership INTERSECTED with the
      caller's fleet scope (empty intersection → empty/zero reports, never global,
      so hidden membership is not leaked).

    Empty scope (scoped caller with no grants) → empty list → zeroed reports.
    """
    caller = scoped_system_ids(db, current_user)  # None = admin; else a set
    if smart_group_id is None:
        return None if caller is None else list(caller)
    members = {
        r[0]
        for r in db.query(SmartGroupMembership.system_id)
        .filter(SmartGroupMembership.smart_group_id == smart_group_id)
        .all()
    }
    return list(members) if caller is None else list(members & caller)


@router.get("/summary")
async def package_summary(
    smart_group_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Fleet-wide package summary statistics (optionally scoped to a smart group)."""
    scoped_ids = _effective_system_ids(db, current_user, smart_group_id)

    pkg_q = db.query(func.count(Package.id))
    pkg_distinct_q = db.query(func.count(func.distinct(Package.name)))
    sec_q = db.query(func.count(Package.id)).filter(
        Package.is_security_critical.is_(True)
    )
    held_q = db.query(func.count(Package.id)).filter(Package.is_held.is_(True))
    upd_q = db.query(func.count(func.distinct(PackageUpdate.package_id)))
    sys_q = db.query(func.count(System.id))

    if scoped_ids is not None:
        if not scoped_ids:
            return {
                "total_packages": 0,
                "total_installed": 0,
                "security_critical_count": 0,
                "held_count": 0,
                "updates_available_count": 0,
                "systems_with_stale_scans": 0,
                "packages_per_system_avg": 0,
                "system_count": 0,
            }
        pkg_q = pkg_q.filter(Package.system_id.in_(scoped_ids))
        pkg_distinct_q = pkg_distinct_q.filter(Package.system_id.in_(scoped_ids))
        sec_q = sec_q.filter(Package.system_id.in_(scoped_ids))
        held_q = held_q.filter(Package.system_id.in_(scoped_ids))
        upd_q = upd_q.join(Package, PackageUpdate.package_id == Package.id).filter(
            Package.system_id.in_(scoped_ids)
        )
        sys_q = sys_q.filter(System.id.in_(scoped_ids))

    total_installed = pkg_q.scalar() or 0
    total_packages = pkg_distinct_q.scalar() or 0
    security_critical_count = sec_q.scalar() or 0
    held_count = held_q.scalar() or 0
    updates_available_count = upd_q.scalar() or 0

    stale_threshold = datetime.utcnow() - timedelta(days=7)
    stale_q = db.query(func.count(System.id)).filter(
        (System.last_audited < stale_threshold) | (System.last_audited.is_(None))
    )
    if scoped_ids is not None:
        stale_q = stale_q.filter(System.id.in_(scoped_ids))
    systems_with_stale_scans = stale_q.scalar() or 0

    system_count = sys_q.scalar() or 0
    packages_per_system_avg = (
        round(total_installed / system_count, 1) if system_count else 0
    )

    return {
        "total_packages": total_packages,
        "total_installed": total_installed,
        "security_critical_count": security_critical_count,
        "held_count": held_count,
        "updates_available_count": updates_available_count,
        "systems_with_stale_scans": systems_with_stale_scans,
        "packages_per_system_avg": packages_per_system_avg,
        "system_count": system_count,
    }


@router.get("/outdated")
async def outdated_packages(
    security_only: bool = Query(False),
    system_id: Optional[int] = Query(None),
    smart_group_id: Optional[int] = Query(None),
    name_filter: Optional[str] = Query(None),
    sort_by: str = Query("name", regex="^(name|system)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Paginated list of packages with available updates fleet-wide."""
    # PRA-281: an explicit out-of-scope system_id is a non-disclosing 404 before
    # any package row / hostname is queried.
    caller_scope = scoped_system_ids(db, current_user)
    if (
        system_id is not None
        and caller_scope is not None
        and system_id not in caller_scope
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
        )

    query = (
        db.query(Package, PackageUpdate, System)
        .join(PackageUpdate, PackageUpdate.package_id == Package.id)
        .join(System, System.id == Package.system_id)
    )

    if security_only:
        query = query.filter(Package.is_security_critical.is_(True))
    if system_id is not None:
        query = query.filter(Package.system_id == system_id)
    scoped_ids = _effective_system_ids(db, current_user, smart_group_id)
    if scoped_ids is not None:
        if not scoped_ids:
            return {
                "items": [],
                "total": 0,
                "page": page,
                "page_size": page_size,
                "total_pages": 0,
            }
        query = query.filter(Package.system_id.in_(scoped_ids))
    if name_filter:
        query = query.filter(Package.name.ilike(f"%{name_filter}%"))

    total = query.count()

    if sort_by == "system":
        query = query.order_by(System.hostname, Package.name)
    else:
        query = query.order_by(Package.name, System.hostname)

    items = query.offset((page - 1) * page_size).limit(page_size).all()

    rows = []
    for pkg, upd, sys in items:
        rows.append(
            {
                "package_name": pkg.name,
                "installed_version": pkg.installed_version,
                "available_version": upd.available_version,
                "system_id": sys.id,
                "system_hostname": sys.hostname,
                "is_security_critical": pkg.is_security_critical,
            }
        )

    return {
        "items": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.get("/compliance")
async def update_compliance(
    smart_group_id: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Update compliance per system + fleet average."""
    systems_q = db.query(System)
    scoped_ids = _effective_system_ids(db, current_user, smart_group_id)
    if scoped_ids is not None:
        if not scoped_ids:
            return {"systems": [], "fleet_average_compliance": 100.0}
        systems_q = systems_q.filter(System.id.in_(scoped_ids))
    systems = systems_q.order_by(System.hostname).all()

    compliance_rows = []
    total_compliance = 0.0

    for sys in systems:
        total_pkgs = (
            db.query(func.count(Package.id))
            .filter(Package.system_id == sys.id)
            .scalar()
            or 0
        )
        outdated_count = (
            db.query(func.count(func.distinct(PackageUpdate.package_id)))
            .filter(PackageUpdate.system_id == sys.id)
            .scalar()
            or 0
        )
        held_count = (
            db.query(func.count(Package.id))
            .filter(Package.system_id == sys.id, Package.is_held.is_(True))
            .scalar()
            or 0
        )
        up_to_date_count = total_pkgs - outdated_count
        compliance_pct = (
            round((up_to_date_count / total_pkgs) * 100, 1) if total_pkgs else 100.0
        )
        total_compliance += compliance_pct

        compliance_rows.append(
            {
                "system_id": sys.id,
                "hostname": sys.hostname,
                "total_packages": total_pkgs,
                "up_to_date_count": up_to_date_count,
                "outdated_count": outdated_count,
                "held_count": held_count,
                "compliance_percentage": compliance_pct,
            }
        )

    fleet_average = round(total_compliance / len(systems), 1) if systems else 100.0

    return {
        "systems": compliance_rows,
        "fleet_average_compliance": fleet_average,
    }


# ---------------------------------------------------------------------------
# PRA-358: on-demand exports recorded as report_runs
# ---------------------------------------------------------------------------


@router.get("/outdated/export", response_class=StreamingResponse)
def export_outdated_packages(
    request: Request,
    format: str = Query("csv"),
    security_only: bool = Query(False),
    system_id: Optional[int] = Query(None, ge=1),
    smart_group_id: Optional[int] = Query(None),
    name_filter: Optional[str] = Query(None),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
) -> Any:
    """Export the outdated-packages report (CSV/JSON) and record a report_run.

    Fleet-scoped: an explicit out-of-scope ``system_id`` is a non-disclosing 404
    before any package row is read; a scoped caller only ever sees in-scope
    systems; an empty scope yields an empty export.
    """
    caller_scope = scoped_system_ids(db, current_user)
    if (
        system_id is not None
        and caller_scope is not None
        and system_id not in caller_scope
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
        )
    try:
        fmt = package_reports_export_service.validate_format(format)
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    effective = _effective_system_ids(db, current_user, smart_group_id)
    if system_id is not None:
        # Intersect the explicit system with the effective scope set.
        system_ids: Optional[Sequence[int]] = (
            [system_id] if (effective is None or system_id in effective) else []
        )
    else:
        system_ids = effective

    try:
        rows = package_reports_export_service.collect_outdated_export_rows(
            db,
            security_only=security_only,
            name_filter=name_filter,
            system_ids=system_ids,
        )
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    filters = package_reports_export_service.outdated_filters_for_audit(
        security_only=security_only,
        name_filter=name_filter,
        smart_group_id=smart_group_id,
        system_id=system_id,
    )
    _export_helpers.emit_export_requested(
        action=package_reports_export_service.AUDIT_PACKAGE_OUTDATED_EXPORT_REQUESTED,
        target_kind="package_outdated_export",
        actor_user_id=current_user.id,
        actor_username=getattr(current_user, "username", None),
        actor_ip=_actor_ip(request),
        export_format=fmt,
        filters=filters,
        row_count=len(rows),
    )
    report_run_service.safe_record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PACKAGE_OUTDATED,
        triggered_by=report_run_service.TRIGGERED_BY_USER,
        triggered_by_user_id=current_user.id,
        triggered_by_username=getattr(current_user, "username", None),
        format=fmt,
        filters_snapshot=filters,
        row_count=len(rows),
    )
    return _export_response(
        rows,
        package_reports_export_service.OUTDATED_CSV_COLUMNS,
        fmt,
        "outdated-packages-export",
    )


@router.get("/compliance/export", response_class=StreamingResponse)
def export_update_compliance(
    request: Request,
    format: str = Query("csv"),
    smart_group_id: Optional[int] = Query(None),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
) -> Any:
    """Export the update-compliance report (CSV/JSON) and record a report_run.

    Fleet-scoped via ``_effective_system_ids``: a scoped caller only sees
    in-scope systems; an empty scope yields an empty export.
    """
    try:
        fmt = package_reports_export_service.validate_format(format)
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    system_ids = _effective_system_ids(db, current_user, smart_group_id)
    try:
        rows = package_reports_export_service.collect_compliance_export_rows(
            db, system_ids=system_ids
        )
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    filters = package_reports_export_service.compliance_filters_for_audit(
        smart_group_id=smart_group_id,
    )
    _export_helpers.emit_export_requested(
        action=package_reports_export_service.AUDIT_PACKAGE_COMPLIANCE_EXPORT_REQUESTED,
        target_kind="package_compliance_export",
        actor_user_id=current_user.id,
        actor_username=getattr(current_user, "username", None),
        actor_ip=_actor_ip(request),
        export_format=fmt,
        filters=filters,
        row_count=len(rows),
    )
    report_run_service.safe_record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PACKAGE_COMPLIANCE,
        triggered_by=report_run_service.TRIGGERED_BY_USER,
        triggered_by_user_id=current_user.id,
        triggered_by_username=getattr(current_user, "username", None),
        format=fmt,
        filters_snapshot=filters,
        row_count=len(rows),
    )
    return _export_response(
        rows,
        package_reports_export_service.COMPLIANCE_CSV_COLUMNS,
        fmt,
        "update-compliance-export",
    )
