"""Per-host advisory routes (PRA-163 slice 4).

Mounted at ``/systems`` to mirror the URL shape of
``system_patch_policy.py`` / ``system_patch_ring.py`` /
``lifecycle.py``. Three endpoints:

* ``GET /{system_id}/patch-advisories`` — joined applicability rows
  for the host with optional ``state`` filter.
* ``GET /{system_id}/patch-advisories/counts`` — per-host counts
  by state, always returning all four state keys (zero-default).
* ``POST /{system_id}/patch-advisories/recompute`` — operator-
  triggered manual recompute. Wraps Slice 2
  ``compute_host_applicability`` and surfaces the
  :class:`ApplicabilityResult` summary inline so the UI can render
  the row delta. Audit fires through the existing
  ``patch_advisory.applicable_recomputed`` event — no new audit
  event is added.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.schemas.patch_advisories import (
    ApplicabilityResultRead,
    HostAdvisoryCountsRead,
    HostAdvisoryRowRead,
    PatchAdvisoryRead,
)
from app.core.auth import get_current_user, require_role, require_system_access
from app.db.models import HostFacts, PatchAdvisory, System
from app.db.session import get_db
from app.services import patch_advisory_service
from app.services.patch_advisory_service import (
    VALID_APPLICABILITY_STATES,
    PatchAdvisoryError,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system-patch-advisories"])


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


def _row_to_read(row, advisory: PatchAdvisory) -> dict:
    return {
        "id": row.id,
        "system_id": row.system_id,
        "advisory_id": row.advisory_id,
        "fixed_package_id": row.fixed_package_id,
        "package_name": row.package_name,
        "installed_version": row.installed_version,
        "required_version": row.required_version,
        "state": row.state,
        "reason": row.reason,
        "evaluated_at": row.evaluated_at,
        "advisory": _advisory_to_read(advisory),
    }


def _actor_ip(request: Optional[Request]) -> Optional[str]:
    if request is None or request.client is None:
        return None
    return request.client.host


def _require_system(db: Session, system_id: int) -> System:
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system id={system_id} not found",
        )
    return system


def _host_facts_missing(db: Session, system_id: int) -> bool:
    """Slice 4-a: mirror the Slice 2 resolver's "no usable facts"
    predicate so the per-host card can render the callout on initial
    load (before any operator-triggered recompute).

    A host has usable facts iff ``HostFacts`` exists for the
    ``system_id`` AND both ``distro_id_facts`` and ``distro_release``
    are non-empty strings — same condition gating the
    ``compute_host_applicability`` short-circuit branch.
    """
    facts = db.query(HostFacts).filter(HostFacts.system_id == system_id).one_or_none()
    return facts is None or not facts.distro_id_facts or not facts.distro_release


# ---------------------------------------------------------------------------
# Per-host counts — declared BEFORE the bare list endpoint (FastAPI
# matches in registration order; the more specific path first means
# /counts never collides with the list).
# ---------------------------------------------------------------------------


@router.get(
    "/{system_id}/patch-advisories/counts",
    response_model=HostAdvisoryCountsRead,
    dependencies=[Depends(require_system_access())],
)
def get_host_advisory_counts(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    _require_system(db, system_id)
    counts = patch_advisory_service.count_host_advisories_by_state(db, system_id)
    return {
        "system_id": system_id,
        "counts": counts,
        "host_facts_missing": _host_facts_missing(db, system_id),
    }


# ---------------------------------------------------------------------------
# Per-host list with optional state filter
# ---------------------------------------------------------------------------


@router.get(
    "/{system_id}/patch-advisories",
    response_model=List[HostAdvisoryRowRead],
    dependencies=[Depends(require_system_access())],
)
def list_host_advisories(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    state: Optional[str] = None,
    offset: int = 0,
    limit: int = 200,
) -> Any:
    _require_system(db, system_id)
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="offset must be >= 0",
        )
    if not (1 <= limit <= 1000):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be 1..1000",
        )
    if state is not None and state not in VALID_APPLICABILITY_STATES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"state must be one of {sorted(VALID_APPLICABILITY_STATES)}",
        )

    try:
        rows = patch_advisory_service.list_host_advisories(
            db,
            system_id,
            state=state,
            limit=limit,
            offset=offset,
        )
    except PatchAdvisoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    if not rows:
        return []
    advisory_ids = {r.advisory_id for r in rows}
    advisories = {
        a.id: a
        for a in db.query(PatchAdvisory)
        .filter(PatchAdvisory.id.in_(advisory_ids))
        .all()
    }
    out = []
    for r in rows:
        adv = advisories.get(r.advisory_id)
        if adv is None:
            # Defensive: applicability row references a missing
            # advisory (CASCADE would normally remove it; surfaces
            # only in race conditions). Skip rather than 500.
            continue
        out.append(_row_to_read(r, adv))
    return out


# ---------------------------------------------------------------------------
# Manual recompute trigger
# ---------------------------------------------------------------------------


@router.post(
    "/{system_id}/patch-advisories/recompute",
    response_model=ApplicabilityResultRead,
    dependencies=[Depends(require_system_access("admin", "maintainer"))],
)
def recompute_host_advisories(
    system_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _require_system(db, system_id)
    try:
        result = patch_advisory_service.compute_host_applicability(
            db,
            system_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
        )
    except PatchAdvisoryError as exc:
        # The resolver should not raise for a system that passed
        # _require_system, but be defensive.
        if "not found" in str(exc) or "not reference" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    return {
        "system_id": result.system_id,
        "counts": result.counts,
        "rows_added": result.rows_added,
        "rows_updated": result.rows_updated,
        "rows_removed": result.rows_removed,
        "advisories_touched": result.advisories_touched,
        "host_facts_missing": result.host_facts_missing,
        "changed": result.changed,
    }
