"""Patch advisory list / detail / fleet-counts / import routes.

Operator surface over native distribution advisories:

* ``GET ""`` — list with optional filters.
* ``GET "/counts"`` — fleet roll-up of ``applicable`` advisory rows
  by severity and advisory_class for the dashboard tile. Declared
  BEFORE ``/{advisory_id}`` per ``feedback_fastapi_route_ordering.md``.
* ``GET "/imports"`` — recent import-run history (status + counts).
* ``POST "/imports"`` — admin/maintainer-triggered import of raw native
  advisory payloads (Ubuntu USN / Debian security / Red Hat updateinfo).
  Normalizes then delegates to the shared ``import_advisories()`` path,
  which records the run, audits, and recomputes host applicability.
  Both ``/imports`` routes are declared BEFORE ``/{advisory_id}`` so the
  literal segment is not parsed as an advisory id.
* ``GET "/{advisory_id}"`` — single advisory + its fixed-package
  targets.

Mounted at ``/patch/advisories`` from ``app/api/main.py``.
``redirect_slashes=False`` is set globally; collection root uses the
empty-string path per ``feedback_trailing_slash.md``.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.schemas.patch_advisories import (
    AdvisoryImportRequest,
    AdvisoryImportResponse,
    FleetAdvisoryCountsRead,
    PatchAdvisoryDetailRead,
    PatchAdvisoryFixedPackageRead,
    PatchAdvisoryImportRunRead,
    PatchAdvisoryRead,
)
from app.core.auth import get_current_user, require_role
from app.db.models import PatchAdvisory
from app.db.session import get_db
from app.services import patch_advisory_service
from app.services.access_authorization_service import scoped_system_ids
from app.services.patch_advisory_service import (
    VALID_ADVISORY_CLASSES,
    VALID_DISTRO_FAMILIES,
    VALID_SEVERITIES,
    VALID_SOURCE_KINDS,
    PatchAdvisoryError,
    normalize_debian_security,
    normalize_redhat_updateinfo,
    normalize_ubuntu_usn,
)

# PRA-239: raw native payload -> canonical normalizer per source kind.
_NORMALIZERS = {
    "ubuntu_usn": normalize_ubuntu_usn,
    "debian_security": normalize_debian_security,
    "redhat_updateinfo": normalize_redhat_updateinfo,
}

logger = logging.getLogger(__name__)

router = APIRouter(tags=["patch-advisories"])


def _advisory_to_read(advisory: PatchAdvisory) -> dict:
    return {
        "id": advisory.id,
        "source_kind": advisory.source_kind,
        "source_advisory_id": advisory.source_advisory_id,
        "advisory_class": advisory.advisory_class,
        "severity": advisory.severity,
        "title": advisory.title,
        "summary": advisory.summary,
        "distro_family": advisory.distro_family,
        "published_at": advisory.published_at,
        "source_updated_at": advisory.source_updated_at,
        "cve_ids": list(advisory.cve_ids or []) or None,
        "external_refs": list(advisory.external_refs or []) or None,
        "raw": advisory.raw,
        "digest": advisory.digest,
        "created_at": advisory.created_at,
        "updated_at": advisory.updated_at,
    }


def _fixed_package_to_read(fp) -> dict:
    return {
        "id": fp.id,
        "advisory_id": fp.advisory_id,
        "distro_id": fp.distro_id,
        "distro_release": fp.distro_release,
        "package_name": fp.package_name,
        "fixed_version": fp.fixed_version,
        "created_at": fp.created_at,
        "updated_at": fp.updated_at,
    }


def _import_run_to_read(run) -> dict:
    return {
        "id": run.id,
        "source_kind": run.source_kind,
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "imported_count": run.imported_count,
        "refreshed_count": run.refreshed_count,
        "unchanged_count": run.unchanged_count,
        "error_count": run.error_count,
        "error_details": run.error_details,
        "created_by": run.created_by,
        "created_at": run.created_at,
    }


def _outcome_to_read(o) -> dict:
    return {
        "source_advisory_id": o.source_advisory_id,
        "action": o.action,
        "advisory_id": o.advisory_id,
        "error": o.error,
    }


def _actor_ip(request: Optional[Request]) -> Optional[str]:
    if request is None or request.client is None:
        return None
    return request.client.host


# ---------------------------------------------------------------------------
# List + filters
# ---------------------------------------------------------------------------


@router.get("", response_model=List[PatchAdvisoryRead])
def list_patch_advisories(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    source_kind: Optional[str] = None,
    advisory_class: Optional[str] = None,
    severity: Optional[str] = None,
    distro_family: Optional[str] = None,
    offset: int = 0,
    limit: int = 100,
) -> Any:
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="offset must be >= 0",
        )
    if not (1 <= limit <= 500):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be 1..500",
        )
    if source_kind is not None and source_kind not in VALID_SOURCE_KINDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"source_kind must be one of {sorted(VALID_SOURCE_KINDS)}",
        )
    if advisory_class is not None and advisory_class not in VALID_ADVISORY_CLASSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"advisory_class must be one of {sorted(VALID_ADVISORY_CLASSES)}",
        )
    if severity is not None and severity not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"severity must be one of {sorted(VALID_SEVERITIES)}",
        )
    if distro_family is not None and distro_family not in VALID_DISTRO_FAMILIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"distro_family must be one of {sorted(VALID_DISTRO_FAMILIES)}",
        )

    rows = patch_advisory_service.list_advisories(
        db,
        source_kind=source_kind,
        advisory_class=advisory_class,
        severity=severity,
        distro_family=distro_family,
        limit=limit,
        offset=offset,
    )
    return [_advisory_to_read(a) for a in rows]


# ---------------------------------------------------------------------------
# Fleet counts — declared BEFORE /{advisory_id} per
# feedback_fastapi_route_ordering.md
# ---------------------------------------------------------------------------


@router.get("/counts", response_model=FleetAdvisoryCountsRead)
def get_fleet_advisory_counts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    # PRA-281: scope the fleet applicability roll-up to the caller's fleet scope
    # (None = tenant-wide admin; empty scope → zeroed counts) so an out-of-scope
    # host's applicable advisories never contribute to the dashboard tile.
    return patch_advisory_service.count_fleet_applicable_by_severity(
        db, scope_system_ids=scoped_system_ids(db, current_user)
    )


# ---------------------------------------------------------------------------
# Import runs + operator-triggered import (PRA-239)
#
# Both declared BEFORE /{advisory_id} so FastAPI matches the literal
# "imports" segment to these handlers rather than parsing it as an
# advisory id (per feedback_fastapi_route_ordering.md).
# ---------------------------------------------------------------------------


@router.get("/imports", response_model=List[PatchAdvisoryImportRunRead])
def list_patch_advisory_import_runs(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    source_kind: Optional[str] = None,
    limit: int = 50,
) -> Any:
    """Recent advisory import-run history, newest first, optionally
    filtered by ``source_kind``."""
    if source_kind is not None and source_kind not in VALID_SOURCE_KINDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"source_kind must be one of {sorted(VALID_SOURCE_KINDS)}",
        )
    if not (1 <= limit <= 200):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be 1..200",
        )
    runs = patch_advisory_service.list_import_runs(
        db, source_kind=source_kind, limit=limit
    )
    return [_import_run_to_read(r) for r in runs]


@router.post(
    "/imports",
    response_model=AdvisoryImportResponse,
    status_code=status.HTTP_201_CREATED,
)
def import_patch_advisories(
    body: AdvisoryImportRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Admin/maintainer-triggered import of native advisory payloads.

    Validates ``source_kind``, normalizes each raw payload with the
    matching source-specific normalizer, then delegates to the existing
    ``import_advisories()`` — the single storage/audit/applicability-
    recompute path. Malformed payloads are rejected up front (422) so a
    recorded import run only ever reflects real import attempts.
    """
    if body.source_kind not in VALID_SOURCE_KINDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"source_kind must be one of {sorted(VALID_SOURCE_KINDS)}",
        )
    normalizer = _NORMALIZERS[body.source_kind]

    canonical = []
    for i, raw in enumerate(body.payloads or []):
        try:
            canonical.append(normalizer(raw))
        except PatchAdvisoryError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"payload[{i}] failed to normalize: {exc}",
            ) from exc

    try:
        run, outcomes = patch_advisory_service.import_advisories(
            db,
            source_kind=body.source_kind,
            payloads=canonical,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
        )
    except PatchAdvisoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    return {
        "run": _import_run_to_read(run),
        "outcomes": [_outcome_to_read(o) for o in outcomes],
    }


# ---------------------------------------------------------------------------
# Detail
# ---------------------------------------------------------------------------


@router.get("/{advisory_id}", response_model=PatchAdvisoryDetailRead)
def get_patch_advisory(
    advisory_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    advisory = patch_advisory_service.get_advisory(db, advisory_id)
    if advisory is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch advisory id={advisory_id} not found",
        )
    fixed = patch_advisory_service.list_fixed_packages(db, advisory_id)
    body = _advisory_to_read(advisory)
    body["fixed_packages"] = [_fixed_package_to_read(fp) for fp in fixed]
    return body
