"""GET ``/systems/{system_id}/patch-ring`` (PRA-162 slice 2).

Effective-ring read endpoint. Walks direct host > static group >
smart group ring bindings and returns a structured payload with one
of three statuses:

* ``"no_ring"``   — no enabled candidate at any tier
* ``"resolved"``  — exactly one distinct enabled ring at the winning tier
* ``"conflict"``  — same-tier overlap of distinct enabled rings

Conflict is exposed as a *state* in the 200 response (with candidate
ring summaries) rather than HTTP 409. This matches the conflict-as-state
pattern PRA-161 slice 1e established for ``patch.*`` predicates and
keeps the operator UI on a single render path. The route 404s only
when the host itself does not exist.

Mounted under ``/systems`` to mirror the shape of ``system_patch_policy``
without crowding the systems router with patch-specific concerns.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.schemas.patch_rings import EffectiveRingRead
from app.core.auth import get_current_user, require_system_access
from app.db.session import get_db
from app.services import patch_ring_service
from app.services.patch_ring_service import PatchRingError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system-patch-ring"])


def _ring_to_read(ring) -> dict:
    return {
        "id": ring.id,
        "slug": ring.slug,
        "name": ring.name,
        "description": ring.description,
        "sort_order": ring.sort_order,
        "enabled": ring.enabled,
        "created_by": ring.created_by,
        "created_at": ring.created_at,
        "updated_at": ring.updated_at,
    }


@router.get(
    "/{system_id}/patch-ring",
    response_model=EffectiveRingRead,
    dependencies=[Depends(require_system_access())],
)
def get_effective_patch_ring(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> dict:
    try:
        result = patch_ring_service.resolve_effective_ring(db, system_id)
    except PatchRingError as exc:
        # _require_target / host-lookup is the only path that can fire
        # PatchRingError from this endpoint. Worded "host id=N not
        # found" to map cleanly to 404.
        if "not found" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    return {
        "system_id": result.system_id,
        "status": result.status,
        "source_tier": result.source_tier,
        "ring": _ring_to_read(result.ring) if result.ring is not None else None,
        "candidates": [_ring_to_read(r) for r in result.candidates],
        "message": result.message,
    }
