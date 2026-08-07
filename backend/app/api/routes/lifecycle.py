"""PRA-156 #3b + #3d: lifecycle read endpoints.

Two routers live in this module — both consume the same
``LifecycleService`` and ``smart_group_service.evaluate`` paths so the
per-host read, the fleet aggregate, and the bucket member list all
agree on the verdict by construction.

``router`` (mounted under ``/systems`` in ``api/main.py``)
    ``GET /systems/{id}/lifecycle`` — per-host verdict (#3b).

``fleet_router`` (mounted at root in ``api/main.py``)
    ``GET /lifecycle/summary``       — fleet bucket counts (#3d).
    ``GET /lifecycle/systems``       — system IDs in one bucket (#3d).

Response shape for the per-host endpoint (locked):

    {
      "system_id": int,
      "freshness": "missing" | "stale" | "fresh",
      "status": "supported" | "approaching-eol" | "unsupported" | "unknown",
      "days_to_eol": int | null,
      "eol_date": "YYYY-MM-DD" | null,
      "support_kind": "standard" | "esm" | "extended" | null,
      "source": str | null,
      "unknown_reason": str | null,
      "staleness_threshold_seconds": int,
    }

Locked behavior:

  * Missing ``host_facts`` row → 200 with ``freshness="missing"`` and
    ``status="unknown"`` (NOT 404 — first-collect is a normal state,
    same lock as PRA-155 #2c facts read).
  * Stale facts → ``freshness="stale"``, ``status="unknown"``. The
    saved-view filter for unknown hosts must match these.
  * 404 only when the system itself doesn't exist.
  * Read MUST NOT trigger collection or mutate ``host_facts`` — test
    required.
  * API is raw: ISO date, integer days. UI does human formatting
    (PRA-155 read-API contract).

The fleet aggregate ``GET /lifecycle/systems`` rides the smart-group
predicate compile path (PRA-156 #3d lock). Frontend filter chips and
saved-view filters MUST consume this endpoint rather than implementing
a parallel client-side lifecycle filter — fleet-list truth must not
diverge from smart-group truth.

NOTE: the legacy ``GET /systems/eol-status`` (PRA-43) lives in
``app/api/routes/systems.py`` and is unrelated to this module. It is
keyed off ``systems.distro_id`` (registration-time, may be stale)
rather than the host-fact strings PRA-155 normalizes. PRA-156 does
not migrate it; that's a separate compatibility slice.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_system_access
from ...db.models import HostFacts, SmartGroupMembership, System, User
from ...db.session import get_db
from ...services import lifecycle_service, smart_group_service
from ...services.access_authorization_service import scoped_system_ids
from ...services.facts_freshness import STALENESS_THRESHOLD_SECONDS, freshness_of

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)
fleet_router = APIRouter(redirect_slashes=False)


# Mapping between the canonical hyphenated lifecycle.status values
# (used everywhere the verdict is the truth: smart-group predicates,
# the per-host read response, the smart-group compile path) and the
# Python-friendly underscore keys used in the summary response. The
# wire-side query param ``?status=approaching-eol`` matches the
# canonical form; only the JSON dict key in the summary swaps in the
# underscore.
_SUMMARY_KEY_FOR_STATUS = {
    "supported": "supported",
    "approaching-eol": "approaching_eol",
    "unsupported": "unsupported",
    "unknown": "unknown",
}


@router.get(
    "/{system_id}/lifecycle",
    dependencies=[Depends(require_system_access())],
)
async def get_lifecycle(
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),  # noqa: ARG001
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return the lifecycle verdict for ``system_id``.

    Authenticated-readable. The refresh path that re-runs collection
    is the existing ``POST /systems/{id}/facts/refresh`` (admin-only)
    — there is intentionally no ``/lifecycle/refresh`` because
    lifecycle is computed on the fly from the most recent
    ``host_facts`` row.
    """
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise HTTPException(status_code=404, detail=f"system {system_id} not found")

    row = db.query(HostFacts).filter(HostFacts.system_id == system_id).one_or_none()
    freshness = freshness_of(row.collected_at if row else None)

    # PRA-156 #3e-a: pass the host's smart-group memberships so
    # compute() consults distro_lifecycle_override rows scoped to
    # any of those groups. The bulk path
    # (``compute_for_all_systems``) loads memberships in one query
    # for the whole fleet; the per-host path makes one targeted
    # query for THIS system. Empty list collapses to no override
    # lookup, matching the standard-row-only behavior.
    membership_ids = [
        sgm.smart_group_id
        for sgm in db.query(SmartGroupMembership.smart_group_id)
        .filter(SmartGroupMembership.system_id == system_id)
        .all()
    ]
    verdict = lifecycle_service.compute(
        db,
        distro_id_facts=row.distro_id_facts if row is not None else None,
        distro_release=row.distro_release if row is not None else None,
        today=datetime.utcnow().date(),
        freshness=freshness,
        smart_group_ids=membership_ids or None,
    )

    return {
        "system_id": system_id,
        "freshness": freshness,
        "status": verdict.status,
        "days_to_eol": verdict.days_to_eol,
        "eol_date": verdict.eol_date.isoformat() if verdict.eol_date else None,
        "support_kind": verdict.support_kind,
        "source": verdict.source,
        "unknown_reason": verdict.unknown_reason,
        "staleness_threshold_seconds": STALENESS_THRESHOLD_SECONDS,
    }


# ---------------------------------------------------------------- fleet


@fleet_router.get("/lifecycle/summary")
async def get_lifecycle_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return ``{supported, approaching_eol, unsupported, unknown}``
    counts across the entire fleet.

    Computed live from ``compute_for_all_systems`` so the values can
    never drift from the per-host read or the smart-group predicate
    membership. Authenticated read; no admin requirement.

    Note the response key spelling: hyphenated ``approaching-eol`` is
    the canonical lifecycle.status value (predicates, per-host read,
    URL query params), but Python dict keys use the underscore form
    ``approaching_eol``. Frontend code that maps a bucket card to a
    URL filter must translate.
    """
    index = lifecycle_service.compute_for_all_systems(db)
    # PRA-281: count only systems in the caller's fleet scope (None = tenant-wide
    # admin). Empty scope collapses to all-zero counts with no hidden totals.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        index = {sid: v for sid, v in index.items() if sid in scope}
    counts: Dict[str, int] = {key: 0 for key in _SUMMARY_KEY_FOR_STATUS.values()}
    # PRA-240: aggregate WHY hosts are unknown so the dashboard can turn an
    # otherwise-opaque "all unknown" tile into an actionable diagnostic. Keys are
    # seeded at zero so the frontend always has stable fields to render; ``other``
    # is a defensive bucket for any unknown verdict without a recognized reason.
    unknown_reasons: Dict[str, int] = {
        lifecycle_service.UNKNOWN_REASON_FRESHNESS: 0,
        lifecycle_service.UNKNOWN_REASON_MISSING_DISTRO_FACTS: 0,
        lifecycle_service.UNKNOWN_REASON_NO_LIFECYCLE_ROW: 0,
        "other": 0,
    }
    for verdict in index.values():
        key = _SUMMARY_KEY_FOR_STATUS.get(verdict.status)
        if key is not None:
            counts[key] += 1
        if verdict.status == "unknown":
            reason = verdict.unknown_reason
            if reason in unknown_reasons:
                unknown_reasons[reason] += 1
            else:
                unknown_reasons["other"] += 1
    return {
        "counts": counts,
        # sum(unknown_reasons.values()) == counts["unknown"] by construction.
        "unknown_reasons": unknown_reasons,
        "total": len(index),
        # Echo the staleness threshold so the UI can show "Lifecycle
        # bucket counts include hosts with stale facts as 'unknown'"
        # without hardcoding 24h.
        "staleness_threshold_seconds": STALENESS_THRESHOLD_SECONDS,
    }


@fleet_router.get("/lifecycle/systems")
async def get_lifecycle_systems(
    status: str = Query(..., description="Lifecycle status to filter by"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return the system IDs in one lifecycle bucket.

    Locked behavior (PRA-156 #3d): the truth source is the smart-group
    predicate compile path, NOT a parallel computation. The frontend
    filter chip and saved-view filter ride this endpoint so
    fleet-list truth cannot diverge from smart-group truth.

    Returns ``{status, system_ids}``. The ``status`` echoes the
    request value verbatim (canonical hyphenated form).
    """
    if status not in lifecycle_service.LIFECYCLE_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"status must be one of "
                f"{sorted(lifecycle_service.LIFECYCLE_STATUSES)}; got {status!r}"
            ),
        )
    rule = {"field": "lifecycle.status", "op": "in", "value": [status]}
    system_ids: List[int] = smart_group_service.evaluate(rule, db)
    # PRA-281: restrict the bucket members to the caller's fleet scope so the
    # smart-group predicate path cannot surface out-of-scope system ids. Empty
    # scope yields an empty list.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        system_ids = [sid for sid in system_ids if sid in scope]
    return {"status": status, "system_ids": system_ids}
