"""
System comparison & drift detection routes - PRA-113.

Compare packages across selected systems to find version drift and missing packages.
"""

import csv
import io
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ...core.auth import get_current_user
from ...db.models import Package, System, User
from ...db.session import get_db
from ...services.access_authorization_service import user_can_access_system

router = APIRouter(redirect_slashes=False)


def _enforce_scope(db: Session, user: User, system_ids: list) -> None:
    """PRA-281: every requested comparison id must be in the caller's fleet scope.

    A single out-of-scope id fails the whole request with a NON-DISCLOSING 404 —
    the response never reveals which id was out of scope, and we never silently
    drop it (dropping would change comparison semantics and leak by omission).
    Admins (tenant-wide scope) pass. Runs before any comparison/export is built.
    """
    for sid in system_ids:
        if not user_can_access_system(db, user, sid):
            raise HTTPException(status_code=404, detail="System not found")


def _build_comparison(
    db: Session, system_ids: list, security_only: bool, name_filter: Optional[str]
):
    """Build the package comparison data structure."""
    systems = db.query(System).filter(System.id.in_(system_ids)).all()
    if len(systems) < 2:
        raise HTTPException(
            status_code=400, detail="At least 2 valid systems required for comparison"
        )
    if len(systems) > 10:
        raise HTTPException(
            status_code=400, detail="Maximum 10 systems can be compared at once"
        )

    system_map = {s.id: s for s in systems}
    system_info = [{"id": s.id, "hostname": s.hostname} for s in systems]
    valid_ids = [s.id for s in systems]

    # Query all packages for selected systems
    pkg_query = db.query(Package).filter(Package.system_id.in_(valid_ids))
    if security_only:
        pkg_query = pkg_query.filter(Package.is_security_critical.is_(True))
    if name_filter:
        pkg_query = pkg_query.filter(Package.name.ilike(f"%{name_filter}%"))

    packages = pkg_query.all()

    # Group packages by name -> {system_id: version}
    pkg_map = defaultdict(dict)
    for p in packages:
        pkg_map[p.name][p.system_id] = p.installed_version

    common_packages = []
    missing_packages = []
    version_drift_count = 0
    missing_count = 0

    for pkg_name, versions_by_system in sorted(pkg_map.items()):
        present_on = set(versions_by_system.keys())
        all_systems = set(valid_ids)

        versions_list = {str(sid): versions_by_system.get(sid) for sid in valid_ids}

        if present_on == all_systems:
            # Present on all systems
            unique_versions = set(versions_by_system.values())
            has_drift = len(unique_versions) > 1
            if has_drift:
                version_drift_count += 1
            common_packages.append(
                {
                    "name": pkg_name,
                    "versions": versions_list,
                    "has_drift": has_drift,
                }
            )
        else:
            # Missing from some systems
            missing_count += 1
            missing_from = [
                {"id": sid, "hostname": system_map[sid].hostname}
                for sid in valid_ids
                if sid not in present_on
            ]
            present_versions = set(v for v in versions_by_system.values())
            has_drift = len(present_versions) > 1
            if has_drift:
                version_drift_count += 1
            missing_packages.append(
                {
                    "name": pkg_name,
                    "versions": versions_list,
                    "missing_from": missing_from,
                    "has_drift": has_drift,
                }
            )

    return {
        "systems": system_info,
        "common_packages": common_packages,
        "missing_packages": missing_packages,
        "drift_summary": {
            "total_packages": len(pkg_map),
            "common_count": len(common_packages),
            "missing_count": missing_count,
            "version_drift_count": version_drift_count,
        },
    }


@router.get("/compare")
async def compare_systems(
    system_ids: str = Query(..., description="Comma-separated system IDs (2-10)"),
    security_only: bool = Query(False),
    name_filter: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Compare packages across selected systems."""
    try:
        ids = [int(x.strip()) for x in system_ids.split(",") if x.strip()]
    except ValueError:
        raise HTTPException(
            status_code=400, detail="system_ids must be comma-separated integers"
        )

    _enforce_scope(db, current_user, ids)
    return _build_comparison(db, ids, security_only, name_filter)


@router.get("/compare/export")
async def export_comparison(
    system_ids: str = Query(..., description="Comma-separated system IDs (2-10)"),
    format: str = Query("csv", description="Export format: csv or json"),
    security_only: bool = Query(False),
    name_filter: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export system comparison as CSV or JSON."""
    try:
        ids = [int(x.strip()) for x in system_ids.split(",") if x.strip()]
    except ValueError:
        raise HTTPException(
            status_code=400, detail="system_ids must be comma-separated integers"
        )

    _enforce_scope(db, current_user, ids)
    data = _build_comparison(db, ids, security_only, name_filter)

    if format == "json":
        return data

    # CSV export
    output = io.StringIO()
    writer = csv.writer(output)

    system_names = [s["hostname"] for s in data["systems"]]
    header = ["Package"] + system_names + ["Status"]
    writer.writerow(header)

    for pkg in data["common_packages"]:
        row = [pkg["name"]]
        for s in data["systems"]:
            row.append(pkg["versions"].get(str(s["id"]), ""))
        row.append("drift" if pkg["has_drift"] else "ok")
        writer.writerow(row)

    for pkg in data["missing_packages"]:
        row = [pkg["name"]]
        for s in data["systems"]:
            v = pkg["versions"].get(str(s["id"]))
            row.append(v if v else "(missing)")
        row.append("missing")
        writer.writerow(row)

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=system-comparison.csv"},
    )
