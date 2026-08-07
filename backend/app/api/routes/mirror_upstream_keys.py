"""Upstream-trust-anchor CRUD routes (PRA-158 #4a).

Top-level prefix ``/mirror-upstream-keys`` — these are Praxis-wide
trust anchors, not per-mirror. Slice #4b's pre-sync verify gate
reads the table to build a transient gpg keyring for verifying
upstream Release.gpg / repomd.xml.asc.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.schemas.mirror_upstream_keys import (
    MirrorUpstreamKeyCreate,
    MirrorUpstreamKeyList,
    MirrorUpstreamKeyRead,
)
from app.core.auth import get_current_user, require_role
from app.db.models import MirrorUpstreamKey
from app.db.session import get_db
from app.services.mirror_upstream_key_service import (
    MirrorUpstreamKeyError,
    MirrorUpstreamKeyService,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mirror-upstream-keys"])


def _to_read(row: MirrorUpstreamKey) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "gpg_fingerprint": row.gpg_fingerprint,
        "armored_public_key": row.armored_public_key,
        "notes": row.notes,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


@router.get("", response_model=MirrorUpstreamKeyList)
async def list_upstream_keys(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """List Praxis-wide upstream trust anchors.

    Read-open to any authenticated user — public material; the
    fingerprint set is operationally useful for any operator
    inspecting trust state.
    """
    service = MirrorUpstreamKeyService(db)
    return {"keys": [_to_read(k) for k in service.list_keys()]}


@router.post(
    "",
    response_model=MirrorUpstreamKeyRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_upstream_key(
    body: MirrorUpstreamKeyCreate,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Import an armored upstream public key.

    Fingerprint is derived server-side from the armored body. 400 on
    malformed/empty input, 409 if a key with the same fingerprint
    already exists.
    """
    service = MirrorUpstreamKeyService(db)
    try:
        row = service.create_from_armored(
            name=body.name,
            armored_public_key=body.armored_public_key,
            notes=body.notes,
        )
    except MirrorUpstreamKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An upstream key with this fingerprint is already imported.",
        ) from exc
    return _to_read(row)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_upstream_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Response:
    service = MirrorUpstreamKeyService(db)
    if not service.delete(key_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Upstream key {key_id} not found",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
