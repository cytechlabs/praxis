"""
Data export API routes (PRA-45).

CSV and JSON exports for systems, packages, audits, and jobs.
"""

import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import Group, Job, JobHistory, Package, System, SystemAudit, User
from ...db.session import get_db
from ...services.access_authorization_service import (
    scope_query_by_system,
    scoped_system_ids,
)
from ...services.job_service import JobService

router = APIRouter(redirect_slashes=False)


def _csv_response(output: io.StringIO, filename: str) -> StreamingResponse:
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _json_response(data: List[Dict[str, Any]], filename: str) -> StreamingResponse:
    content = json.dumps(data, default=str, indent=2)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/systems")
async def export_systems(
    format: str = Query("csv", regex="^(csv|json)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export system inventory."""
    # PRA-281: export only systems in the caller's fleet scope (admin unchanged;
    # empty scope → valid empty export). Group names are resolved only for the
    # exported (in-scope) systems, so no hidden hostname/IP/OS/status/group/
    # timestamp leaks.
    systems = (
        scope_query_by_system(db.query(System), db, current_user, System.id)
        .order_by(System.hostname)
        .all()
    )

    group_ids = {s.group_id for s in systems if s.group_id}
    group_map: Dict[int, str] = {}
    if group_ids:
        groups = db.query(Group).filter(Group.id.in_(group_ids)).all()
        group_map = {g.id: g.name for g in groups}

    rows = []
    for s in systems:
        rows.append(
            {
                "hostname": s.hostname,
                "ip_address": str(s.ip_address),
                "os_version": s.os_version,
                "status": s.status,
                "group": group_map.get(s.group_id, ""),
                "registered_at": s.registered_at.isoformat() if s.registered_at else "",
                "last_audited": s.last_audited.isoformat() if s.last_audited else "",
            }
        )

    if format == "json":
        return _json_response(rows, "systems-export.json")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "hostname",
            "ip_address",
            "os_version",
            "status",
            "group",
            "registered_at",
            "last_audited",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r["hostname"],
                r["ip_address"],
                r["os_version"],
                r["status"],
                r["group"],
                r["registered_at"],
                r["last_audited"],
            ]
        )
    return _csv_response(output, "systems-export.csv")


@router.get("/packages")
async def export_packages(
    system_id: int = Query(...),
    format: str = Query("csv", regex="^(csv|json)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export package inventory for a system."""
    # PRA-281: a direct out-of-scope (or empty-scope) system id is a
    # non-disclosing 404 — identical to a nonexistent host — BEFORE any package
    # is queried or a system-id-bearing filename/body is serialized.
    scope = scoped_system_ids(db, current_user)
    if scope is not None and system_id not in scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
        )

    packages = (
        db.query(Package)
        .filter(Package.system_id == system_id)
        .order_by(Package.name)
        .all()
    )

    rows = []
    for p in packages:
        rows.append(
            {
                "name": p.name,
                "version": p.installed_version,
                "type": p.package_type or "",
                "is_held": p.is_held,
                "is_security_critical": p.is_security_critical,
                "last_audited": p.last_audited.isoformat() if p.last_audited else "",
            }
        )

    if format == "json":
        return _json_response(rows, f"packages-system-{system_id}.json")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["name", "version", "type", "is_held", "is_security_critical", "last_audited"]
    )
    for r in rows:
        writer.writerow(
            [
                r["name"],
                r["version"],
                r["type"],
                r["is_held"],
                r["is_security_critical"],
                r["last_audited"],
            ]
        )
    return _csv_response(output, f"packages-system-{system_id}.csv")


@router.get("/audits")
async def export_audits(
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    format: str = Query("csv", regex="^(csv|json)$"),
    current_user: User = Depends(  # pylint: disable=unused-argument
        require_role("admin", "auditor")
    ),
    db: Session = Depends(get_db),
):
    """Export audit log with optional date range filter.

    PRA-180 AUDIT-05: audit export returns SystemAudit old/new values across the
    fleet, so it is gated to the audit-read roles (admin/auditor) to match the
    unified ``/audit/events`` posture rather than any authenticated user.
    """
    query = db.query(SystemAudit).order_by(SystemAudit.changed_at.desc())
    if from_date:
        query = query.filter(SystemAudit.changed_at >= from_date)
    if to_date:
        query = query.filter(SystemAudit.changed_at <= to_date)
    # PRA-281: export only in-scope audit rows (admin unchanged; empty scope →
    # empty export). Scoping by SystemAudit.system_id excludes rows with a
    # NULL/out-of-scope system for scoped callers — a NULL-system audit cannot be
    # attributed to a host, so it is not surfaced to a scoped caller. The
    # user/hostname maps below are built only from the exported rows, so no hidden
    # username, hostname, or old/new value is ever resolved.
    query = scope_query_by_system(query, db, current_user, SystemAudit.system_id)
    audits = query.limit(10000).all()

    # Build user map
    user_ids = {a.changed_by for a in audits if a.changed_by}
    user_map: Dict[int, str] = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        user_map = {u.id: u.username for u in users}

    # Build system map
    sys_ids = {a.system_id for a in audits if a.system_id}
    sys_map: Dict[int, str] = {}
    if sys_ids:
        systems = db.query(System).filter(System.id.in_(sys_ids)).all()
        sys_map = {s.id: s.hostname for s in systems}

    rows = []
    for a in audits:
        rows.append(
            {
                "id": a.id,
                "system_hostname": sys_map.get(a.system_id, ""),
                "audit_type": a.audit_type,
                "operation": a.operation,
                "changed_by": user_map.get(a.changed_by, ""),
                "changed_at": a.changed_at.isoformat() if a.changed_at else "",
                "old_value": a.old_value or "",
                "new_value": a.new_value or "",
            }
        )

    if format == "json":
        return _json_response(rows, "audits-export.json")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "system_hostname",
            "audit_type",
            "operation",
            "changed_by",
            "changed_at",
            "old_value",
            "new_value",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r["id"],
                r["system_hostname"],
                r["audit_type"],
                r["operation"],
                r["changed_by"],
                r["changed_at"],
                r["old_value"],
                r["new_value"],
            ]
        )
    return _csv_response(output, "audits-export.csv")


@router.get("/jobs")
async def export_jobs(
    format: str = Query("csv", regex="^(csv|json)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export job history."""
    jobs = (
        db.query(JobHistory).order_by(JobHistory.start_time.desc()).limit(10000).all()
    )

    # PRA-281: reuse the accepted Slice 4 job-visibility model — a JobHistory row
    # is exported to a scoped caller only when its job's whole resolved target set
    # is in scope (fail closed for out-of-scope/mixed/orphaned). Admin (scope
    # None) is unchanged; empty scope → empty export. No hidden job id, status,
    # target count, timing, or error message leaks.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        svc = JobService(db, scope=scope)
        job_ids = {j.job_id for j in jobs if j.job_id is not None}
        job_map = (
            {j.id: j for j in db.query(Job).filter(Job.id.in_(job_ids)).all()}
            if job_ids
            else {}
        )
        jobs = [
            h
            for h in jobs
            if h.job_id in job_map and svc.is_job_visible(job_map[h.job_id])
        ]

    rows = []
    for j in jobs:
        rows.append(
            {
                "id": j.id,
                "job_id": j.job_id,
                "start_time": j.start_time.isoformat() if j.start_time else "",
                "end_time": j.end_time.isoformat() if j.end_time else "",
                "status": j.status,
                "systems_targeted": j.systems_targeted,
                "systems_completed": j.systems_completed,
                "systems_failed": j.systems_failed,
                "error_message": j.error_message or "",
            }
        )

    if format == "json":
        return _json_response(rows, "jobs-export.json")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "job_id",
            "start_time",
            "end_time",
            "status",
            "systems_targeted",
            "systems_completed",
            "systems_failed",
            "error_message",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r["id"],
                r["job_id"],
                r["start_time"],
                r["end_time"],
                r["status"],
                r["systems_targeted"],
                r["systems_completed"],
                r["systems_failed"],
                r["error_message"],
            ]
        )
    return _csv_response(output, "jobs-export.csv")
