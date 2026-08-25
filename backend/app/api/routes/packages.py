"""
API routes for package management (PRA-2).
"""

import logging
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from ...core.api_errors import internal_error
from ...core.auth import get_current_user, require_role, require_system_access
from ...db.models import System, User
from ...db.session import get_db
from ...services import fleet_operation_service
from ...services.access_authorization_service import (
    resolve_package_scope_ids,
    user_can_access_system,
)
from ...services.package_service import PackageService
from ...services.security_scan_status_service import (
    RESULT_FAILURE,
    RESULT_SKIPPED,
    SECURITY_SCAN_OPERATION_COHORT,
    SECURITY_SCAN_OPERATION_SINGLE,
    redact_result_message,
    result_status_for_scan,
)
from ...services.ssh_service import SSHConnectionError

logger = logging.getLogger(__name__)

router = APIRouter()


def _resolve_scope(
    db: Session,
    user: User,
    scope_type: Optional[str],
    scope_id: Optional[int],
):
    """Resolve optional ``scope_type``/``scope_id`` query params to the
    effective system-id set for a scoped package view, translating a bad selector
    to a 400. Returns ``None`` (tenant-wide admin, ``all``) or a set (possibly
    empty → zero rows, never a global fallback)."""
    try:
        return resolve_package_scope_ids(db, user, scope_type, scope_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


# Strict regex for package names: alphanumeric, dots, dashes, plus, colons (arch)
PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.+\-:~]+$")


def _enforce_bulk_scope(db: Session, user: User, system_ids: List[int]) -> None:
    """PRA-281: every requested system must be in the caller's fleet scope.

    A single out-of-scope id fails the whole request with a NON-DISCLOSING 404 —
    the response never reveals which ids exist or are in scope. Admins (tenant-wide
    scope) pass here; per-id existence is validated separately after this gate.
    """
    for sid in system_ids:
        if not user_can_access_system(db, user, sid):
            raise HTTPException(status_code=404, detail="System not found")


def _validate_package_names(names: List[str]) -> List[str]:
    for name in names:
        if not PACKAGE_NAME_RE.match(name):
            raise ValueError(
                f"Invalid package name '{name}': "
                "only alphanumeric, dots, dashes, plus, colons, tildes allowed"
            )
        if len(name) > 256:
            raise ValueError(f"Package name too long: '{name[:50]}...'")
    return names


class UpdateRequest(BaseModel):
    """Request body for applying package updates."""

    package_names: Optional[List[str]] = None

    @validator("package_names", pre=True)
    def validate_names(cls, v):  # pylint: disable=no-self-argument
        if v is not None:
            return _validate_package_names(v)
        return v


class HoldRequest(BaseModel):
    package_names: List[str]

    @validator("package_names")
    def validate_names(cls, v):  # pylint: disable=no-self-argument
        return _validate_package_names(v)


class BulkUpdateRequest(BaseModel):
    """Request body for bulk package updates across systems."""

    system_ids: List[int]
    package_names: Optional[List[str]] = None

    @validator("package_names", pre=True)
    def validate_names(cls, v):  # pylint: disable=no-self-argument
        if v is not None:
            return _validate_package_names(v)
        return v


class BulkHoldRequest(BaseModel):
    """Request body for bulk hold/unhold across systems."""

    system_ids: List[int]
    package_names: List[str]

    @validator("package_names")
    def validate_names(cls, v):  # pylint: disable=no-self-argument
        return _validate_package_names(v)


@router.get("/search", response_model=Dict[str, Any])
def search_fleet_packages(
    name: str = Query(..., min_length=1, description="Package name to search for"),
    version: Optional[str] = Query(None, description="Filter by version"),
    is_held: Optional[bool] = Query(None, description="Filter by held status"),
    has_update: Optional[bool] = Query(
        None, description="Filter by update availability"
    ),
    limit: int = Query(50, ge=1, le=500, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    scope_type: Optional[str] = Query(
        None, description="Cohort scope: all|system|group|smart_group"
    ),
    scope_id: Optional[int] = Query(
        None, description="Scope target id for group/smart_group/system scopes"
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Search packages across systems in the caller's fleet scope, optionally
    narrowed to a static group or smart group."""
    system_ids = _resolve_scope(db, current_user, scope_type, scope_id)
    try:
        service = PackageService(db)
        return service.search_fleet_packages(
            name=name,
            version=version,
            is_held=is_held,
            has_update=has_update,
            limit=limit,
            offset=offset,
            system_ids=system_ids,
        )
    except Exception as e:
        raise internal_error(e, context="searching packages", logger=logger) from e


@router.post("/bulk/update", response_model=Dict[str, Any])
def bulk_update_packages(
    body: BulkUpdateRequest,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Apply package updates across multiple systems."""
    if not body.system_ids:
        raise HTTPException(
            status_code=400, detail="At least one system ID is required"
        )
    _enforce_bulk_scope(db, current_user, body.system_ids)

    # Validate all system IDs exist
    systems = db.query(System).filter(System.id.in_(body.system_ids)).all()
    found_ids = {s.id for s in systems}
    missing = set(body.system_ids) - found_ids
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"Systems not found: {sorted(missing)}",
        )

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type="bulk_package_update",
        user_id=current_user.id,
        target_count=len(body.system_ids),
        parameters={
            "system_ids": body.system_ids,
            "package_names": body.package_names,
        },
    )
    try:
        service = PackageService(db)
        result = service.bulk_update_packages(
            system_ids=body.system_ids,
            package_names=body.package_names,
            user_id=current_user.id,
        )
        success = int(result.get("success_count", 0)) if isinstance(result, dict) else 0
        failure = int(result.get("failure_count", 0)) if isinstance(result, dict) else 0
        if success == 0 and failure == 0:
            success = len(body.system_ids)
        for sid in body.system_ids:
            fleet_operation_service.record_result(fleet_op_id, sid, "success")
        fleet_operation_service.complete_operation(fleet_op_id, success, failure)
        if isinstance(result, dict):
            result["fleet_operation_id"] = fleet_op_id
        return result
    except Exception as e:
        fleet_operation_service.complete_operation(
            fleet_op_id, 0, len(body.system_ids), status="failed"
        )
        raise internal_error(e, context="bulk updating packages", logger=logger) from e


@router.post("/bulk/hold", response_model=Dict[str, Any])
def bulk_hold_packages(
    body: BulkHoldRequest,
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Hold packages across multiple systems."""
    if not body.system_ids:
        raise HTTPException(
            status_code=400, detail="At least one system ID is required"
        )
    if not body.package_names:
        raise HTTPException(
            status_code=400, detail="At least one package name is required"
        )
    _enforce_bulk_scope(db, current_user, body.system_ids)

    systems = db.query(System).filter(System.id.in_(body.system_ids)).all()
    found_ids = {s.id for s in systems}
    missing = set(body.system_ids) - found_ids
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"Systems not found: {sorted(missing)}",
        )

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type="bulk_package_hold",
        user_id=current_user.id,
        target_count=len(body.system_ids),
        parameters={
            "system_ids": body.system_ids,
            "package_names": body.package_names,
        },
    )
    try:
        service = PackageService(db)
        result = service.bulk_hold_packages(
            system_ids=body.system_ids,
            package_names=body.package_names,
        )
        for sid in body.system_ids:
            fleet_operation_service.record_result(fleet_op_id, sid, "success")
        fleet_operation_service.complete_operation(fleet_op_id, len(body.system_ids), 0)
        if isinstance(result, dict):
            result["fleet_operation_id"] = fleet_op_id
        return result
    except Exception as e:
        fleet_operation_service.complete_operation(
            fleet_op_id, 0, len(body.system_ids), status="failed"
        )
        raise internal_error(e, context="bulk holding packages", logger=logger) from e


@router.post("/bulk/unhold", response_model=Dict[str, Any])
def bulk_unhold_packages(
    body: BulkHoldRequest,
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Unhold packages across multiple systems."""
    if not body.system_ids:
        raise HTTPException(
            status_code=400, detail="At least one system ID is required"
        )
    if not body.package_names:
        raise HTTPException(
            status_code=400, detail="At least one package name is required"
        )
    _enforce_bulk_scope(db, current_user, body.system_ids)

    systems = db.query(System).filter(System.id.in_(body.system_ids)).all()
    found_ids = {s.id for s in systems}
    missing = set(body.system_ids) - found_ids
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"Systems not found: {sorted(missing)}",
        )

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type="bulk_package_unhold",
        user_id=current_user.id,
        target_count=len(body.system_ids),
        parameters={
            "system_ids": body.system_ids,
            "package_names": body.package_names,
        },
    )
    try:
        service = PackageService(db)
        result = service.bulk_unhold_packages(
            system_ids=body.system_ids,
            package_names=body.package_names,
        )
        for sid in body.system_ids:
            fleet_operation_service.record_result(fleet_op_id, sid, "success")
        fleet_operation_service.complete_operation(fleet_op_id, len(body.system_ids), 0)
        if isinstance(result, dict):
            result["fleet_operation_id"] = fleet_op_id
        return result
    except Exception as e:
        fleet_operation_service.complete_operation(
            fleet_op_id, 0, len(body.system_ids), status="failed"
        )
        raise internal_error(e, context="bulk unholding packages", logger=logger) from e


class CohortScanRequest(BaseModel):
    """Request body for a cohort package/security refresh scan."""

    scope_type: str
    scope_id: Optional[int] = None
    security: bool = False


@router.post("/scope/scan", response_model=Dict[str, Any])
def scan_scope_packages(
    body: CohortScanRequest,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Scan package (or security) inventory across a resolved cohort.

    Resolves the scope to its in-scope system ids (an incomplete cohort is a 400;
    an empty intersection scans nothing, never the whole fleet), snapshots the
    resolved targets on a FleetOperation, then runs the per-host scan. Partial
    failure is reported per host; no updates are applied.
    """
    scoped = _resolve_scope(db, current_user, body.scope_type, body.scope_id)
    # ``None`` = tenant-wide admin under an ``all`` scope: expand to concrete ids
    # so a scan always targets an explicit, snapshotted host list.
    if scoped is None:
        ids = [row[0] for row in db.query(System.id).all()]
    else:
        ids = sorted(scoped)

    base = {
        "scope_type": body.scope_type,
        "scope_id": body.scope_id,
        "security": body.security,
    }
    if not ids:
        # Empty/disjoint cohort → operate on nothing, never a global fallback.
        return {
            **base,
            "total": 0,
            "success_count": 0,
            "failure_count": 0,
            "skipped_count": 0,
            "results": [],
            "fleet_operation_id": None,
        }

    systems = db.query(System).filter(System.id.in_(ids)).all()
    targets = [(s.id, s.hostname) for s in systems]

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type=(
            SECURITY_SCAN_OPERATION_COHORT if body.security else "cohort_package_scan"
        ),
        user_id=current_user.id,
        target_count=len(targets),
        parameters={
            "scope_type": body.scope_type,
            "scope_id": body.scope_id,
            "security": body.security,
            "system_ids": [t[0] for t in targets],
            "hostnames": [t[1] for t in targets],
        },
    )
    try:
        service = PackageService(db)
        result = service.scan_scope(targets, security=body.security)
        for row in result["results"]:
            # A security scan that could not read or store part of its result is
            # recorded as partial, so the host is not counted as covered by a
            # trustworthy scan even though the host itself did not fail. Its
            # message can be a remote failure string, so it is redacted before
            # it is persisted.
            message = row.get("message")
            fleet_operation_service.record_result(
                fleet_op_id,
                row["system_id"],
                result_status_for_scan(row),
                error_message=(
                    redact_result_message(message) if body.security else message
                ),
            )
        # Skipped (single-flight already-running) hosts are not failures — the
        # operation's failure_count reflects real failures only.
        fleet_operation_service.complete_operation(
            fleet_op_id,
            result["success_count"],
            result["failure_count"],
        )
        result.update(base)
        result["fleet_operation_id"] = fleet_op_id
        return result
    except Exception as e:
        fleet_operation_service.complete_operation(
            fleet_op_id, 0, len(targets), status="failed"
        )
        raise internal_error(e, context="cohort package scan", logger=logger) from e


@router.get("/security/all", response_model=List[Dict[str, Any]])
def list_all_security_updates(
    scope_type: Optional[str] = Query(
        None, description="Cohort scope: all|system|group|smart_group"
    ),
    scope_id: Optional[int] = Query(
        None, description="Scope target id for group/smart_group/system scopes"
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    system_ids = _resolve_scope(db, current_user, scope_type, scope_id)
    try:
        service = PackageService(db)
        return service.get_security_updates(system_ids=system_ids)
    except Exception as e:
        raise internal_error(
            e, context="listing security updates", logger=logger
        ) from e


@router.get(
    "/security/{system_id}",
    response_model=List[Dict[str, Any]],
    dependencies=[Depends(require_system_access())],
)
def list_system_security_updates(
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(get_current_user),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.get_security_updates(system_id=system_id)
    except Exception as e:
        raise internal_error(
            e, context="listing security updates", logger=logger
        ) from e


def _record_single_host_scan_failure(
    fleet_op_id: int, system_id: int, message: str
) -> None:
    """Record a security scan that raised before returning a per-host result."""
    fleet_operation_service.record_result(
        fleet_op_id,
        system_id,
        RESULT_FAILURE,
        error_message=redact_result_message(message),
    )
    fleet_operation_service.complete_operation(fleet_op_id, 0, 1, status="failed")


@router.post(
    "/{system_id}/scan-security",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def scan_security_updates(
    system_id: int = Path(..., description="The ID of the system to scan"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Scan one host for security updates and record the scan itself.

    The outcome is recorded per host so fleet security state can tell a host
    that was scanned apart from one that was never asked the question. A scan
    that never produced a usable result is recorded as a failure rather than
    leaving the host looking clean.
    """
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    fleet_op_id = fleet_operation_service.start_operation(
        operation_type=SECURITY_SCAN_OPERATION_SINGLE,
        user_id=current_user.id,
        target_count=1,
        parameters={
            "system_ids": [system.id],
            "hostnames": [system.hostname],
        },
    )
    try:
        service = PackageService(db)
        result = service.scan_security_updates(system_id)
    except (SSHConnectionError, ValueError) as e:
        _record_single_host_scan_failure(fleet_op_id, system_id, str(e))
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        _record_single_host_scan_failure(fleet_op_id, system_id, "Security scan failed")
        raise internal_error(
            e, context="scanning security updates", logger=logger
        ) from e

    outcome = result_status_for_scan(result)
    fleet_operation_service.record_result(
        fleet_op_id,
        system_id,
        outcome,
        error_message=redact_result_message(result.get("message")),
    )
    if outcome == RESULT_FAILURE:
        success_count, failure_count = 0, 1
    elif outcome == RESULT_SKIPPED:
        # Another package operation held the host, so no scan ran for it.
        success_count, failure_count = 0, 0
    else:
        success_count, failure_count = 1, 0
    fleet_operation_service.complete_operation(
        fleet_op_id, success_count, failure_count
    )
    result["fleet_operation_id"] = fleet_op_id
    return result


@router.post(
    "/{system_id}/update-security",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def apply_security_updates(
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.apply_security_updates(
            system_id,
            user_id=current_user.id,
        )
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(
            e, context="applying security updates", logger=logger
        ) from e


@router.post(
    "/{system_id}/hold",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def hold_packages(
    body: HoldRequest,
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.hold_packages(system_id, body.package_names)
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="holding packages", logger=logger) from e


@router.post(
    "/{system_id}/unhold",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def unhold_packages(
    body: HoldRequest,
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.unhold_packages(system_id, body.package_names)
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="unholding packages", logger=logger) from e


@router.post(
    "/{system_id}/remove",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def remove_packages(
    body: HoldRequest,
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.remove_packages(
            system_id, body.package_names, user_id=current_user.id
        )
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="removing packages", logger=logger) from e


@router.get("/inventory", response_model=Dict[str, Any])
def list_scoped_packages(
    search: Optional[str] = Query(None, description="Search packages by name"),
    limit: int = Query(100, ge=1, le=500, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    scope_type: Optional[str] = Query(
        None, description="Cohort scope: all|system|group|smart_group"
    ),
    scope_id: Optional[int] = Query(
        None, description="Scope target id for group/smart_group/system scopes"
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Aggregate installed-package inventory across a cohort.

    Unlike ``GET /{system_id}`` this spans a scope — fleet, a static group, or a
    smart group — and every row carries its ``hostname`` so an operator can see
    which host each package is installed on. Empty/disjoint cohorts return zero
    rows, never a global fallback.
    """
    system_ids = _resolve_scope(db, current_user, scope_type, scope_id)
    try:
        service = PackageService(db)
        return service.get_packages_for_scope(
            system_ids=system_ids, search=search, limit=limit, offset=offset
        )
    except Exception as e:
        raise internal_error(e, context="listing scoped packages", logger=logger) from e


@router.get(
    "/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def list_packages(
    system_id: int = Path(..., description="The ID of the system"),
    search: Optional[str] = Query(None, description="Search packages by name"),
    limit: int = Query(100, ge=1, le=500, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    current_user: User = Depends(get_current_user),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """List installed packages on a system."""
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.get_packages(
            system_id, search=search, limit=limit, offset=offset
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="listing packages", logger=logger) from e


@router.post(
    "/{system_id}/scan",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def scan_packages(
    system_id: int = Path(..., description="The ID of the system to scan"),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Trigger a package scan on a system via SSH."""
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.scan_packages(system_id)
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="scanning packages", logger=logger) from e


@router.get("/updates/all", response_model=List[Dict[str, Any]])
def list_all_updates(
    scope_type: Optional[str] = Query(
        None, description="Cohort scope: all|system|group|smart_group"
    ),
    scope_id: Optional[int] = Query(
        None, description="Scope target id for group/smart_group/system scopes"
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List available updates across the caller's fleet scope, optionally narrowed
    to a static group or smart group."""
    system_ids = _resolve_scope(db, current_user, scope_type, scope_id)
    try:
        service = PackageService(db)
        return service.get_updates(system_ids=system_ids)
    except Exception as e:
        raise internal_error(e, context="listing updates", logger=logger) from e


@router.get(
    "/updates/{system_id}",
    response_model=List[Dict[str, Any]],
    dependencies=[Depends(require_system_access())],
)
def list_system_updates(
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(get_current_user),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """List available updates for a specific system."""
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.get_updates(system_id=system_id)
    except Exception as e:
        raise internal_error(e, context="listing updates", logger=logger) from e


@router.post(
    "/{system_id}/update",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def apply_updates(
    system_id: int = Path(..., description="The ID of the system"),
    body: Optional[UpdateRequest] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Apply package updates on a system."""
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        package_names = body.package_names if body else None
        return service.apply_updates(
            system_id,
            package_names=package_names,
            user_id=current_user.id,
        )
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="applying updates", logger=logger) from e


@router.get("/history/all", response_model=Dict[str, Any])
def list_all_history(
    limit: int = Query(50, ge=1, le=200, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    scope_type: Optional[str] = Query(
        None, description="Cohort scope: all|system|group|smart_group"
    ),
    scope_id: Optional[int] = Query(
        None, description="Scope target id for group/smart_group/system scopes"
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List package operation history across the caller's fleet scope, optionally
    narrowed to a static group or smart group."""
    system_ids = _resolve_scope(db, current_user, scope_type, scope_id)
    try:
        service = PackageService(db)
        return service.get_history(
            limit=limit,
            offset=offset,
            system_ids=system_ids,
        )
    except Exception as e:
        raise internal_error(e, context="listing history", logger=logger) from e


@router.get(
    "/history/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access())],
)
def list_system_history(
    system_id: int = Path(..., description="The ID of the system"),
    limit: int = Query(50, ge=1, le=200, description="Results per page"),
    offset: int = Query(0, ge=0, description="Results offset"),
    current_user: User = Depends(get_current_user),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """List package operation history for a specific system."""
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = PackageService(db)
        return service.get_history(system_id=system_id, limit=limit, offset=offset)
    except Exception as e:
        raise internal_error(e, context="listing history", logger=logger) from e
