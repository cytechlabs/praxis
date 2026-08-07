"""PRA-358 — package posture exports (outdated packages + update compliance).

Promotes the two tabular Package Reports sections (``/package-reports/outdated``
and ``/package-reports/compliance``) into the PRA-178 report-kind contract so an
operator can generate them on demand, get a downloadable CSV/JSON, and have the
run recorded in ``report_runs`` (and, via the same contract, scheduled).

Row shapes mirror the live dashboard endpoints exactly so the export and the
on-screen table stay in lockstep. Fleet scope is applied by the ROUTE (which
passes an already-resolved ``system_ids`` list); this module is scope-agnostic
beyond honoring that list. The shared ``_export_helpers`` row cap keeps a
misclicked unbounded GET from dumping the whole fleet.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db.models import Package, PackageUpdate, System
from . import _export_helpers

# Reused by the route layer for a consistent 422 on a bad ?format=.
validate_format = _export_helpers.validate_format

AUDIT_PACKAGE_OUTDATED_EXPORT_REQUESTED = "package_outdated_export.requested"
AUDIT_PACKAGE_COMPLIANCE_EXPORT_REQUESTED = "package_compliance_export.requested"

# Pinned CSV column order (stable for auditor scripts). Mirrors the dashboard
# row keys so the export and the on-screen table match column-for-column.
OUTDATED_CSV_COLUMNS = (
    "package_name",
    "installed_version",
    "available_version",
    "system_id",
    "system_hostname",
    "is_security_critical",
)
COMPLIANCE_CSV_COLUMNS = (
    "system_id",
    "hostname",
    "total_packages",
    "up_to_date_count",
    "outdated_count",
    "held_count",
    "compliance_percentage",
)


def collect_outdated_export_rows(
    db: Session,
    *,
    security_only: bool = False,
    name_filter: Optional[str] = None,
    system_ids: Optional[Sequence[int]] = None,
) -> List[Dict[str, Any]]:
    """Every package with an available update (fleet-wide by default).

    ``system_ids`` is the route-resolved fleet-scope/​smart-group filter:
    ``None`` = tenant-wide (admin, no group); an empty sequence = a scoped
    caller with no visible systems → no rows (never global).
    """
    if system_ids is not None and not system_ids:
        return []

    query = (
        db.query(Package, PackageUpdate, System)
        .join(PackageUpdate, PackageUpdate.package_id == Package.id)
        .join(System, System.id == Package.system_id)
    )
    if security_only:
        query = query.filter(Package.is_security_critical.is_(True))
    if system_ids is not None:
        query = query.filter(Package.system_id.in_(list(system_ids)))
    if name_filter:
        query = query.filter(Package.name.ilike(f"%{name_filter}%"))
    query = query.order_by(Package.name, System.hostname)

    out: List[Dict[str, Any]] = []
    for pkg, upd, sys in query.yield_per(_export_helpers.EXPORT_STREAM_CHUNK):
        out.append(
            {
                "package_name": pkg.name,
                "installed_version": pkg.installed_version,
                "available_version": upd.available_version,
                "system_id": sys.id,
                "system_hostname": sys.hostname,
                "is_security_critical": pkg.is_security_critical,
            }
        )
        _export_helpers.assert_row_cap(len(out), label="package outdated")
    return out


def collect_compliance_export_rows(
    db: Session,
    *,
    system_ids: Optional[Sequence[int]] = None,
) -> List[Dict[str, Any]]:
    """Per-system update-compliance rows (one row per visible system).

    Same computation the ``/package-reports/compliance`` dashboard uses:
    ``compliance_percentage`` = up-to-date / total installed. ``system_ids``
    semantics match :func:`collect_outdated_export_rows`.
    """
    if system_ids is not None and not system_ids:
        return []

    systems_q = db.query(System)
    if system_ids is not None:
        systems_q = systems_q.filter(System.id.in_(list(system_ids)))
    systems = systems_q.order_by(System.hostname).all()

    out: List[Dict[str, Any]] = []
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
        out.append(
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
        _export_helpers.assert_row_cap(len(out), label="package compliance")
    return out


def outdated_filters_for_audit(
    *,
    security_only: bool,
    name_filter: Optional[str],
    smart_group_id: Optional[int],
    system_id: Optional[int],
) -> Dict[str, Any]:
    return _export_helpers.filters_snapshot(
        security_only=security_only,
        name_filter=name_filter,
        smart_group_id=smart_group_id,
        system_id=system_id,
    )


def compliance_filters_for_audit(*, smart_group_id: Optional[int]) -> Dict[str, Any]:
    return _export_helpers.filters_snapshot(smart_group_id=smart_group_id)
