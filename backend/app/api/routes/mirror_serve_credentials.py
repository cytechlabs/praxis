"""Per-host bearer credential management for the mirror serve
endpoint (PRA-159 slice #2).

Mounted under ``/systems/{system_id}/mirror-serve-credentials``.
v1 surface:

  * ``POST   /systems/{id}/mirror-serve-credentials`` — issue
    (admin/maintainer). Returns the plaintext bearer ONCE; revokes
    any prior active credential for the same ``(host, mirror)``.
  * ``GET    /systems/{id}/mirror-serve-credentials`` — list
    metadata (no plaintext, no hash). Default lists active only;
    ``?include_revoked=true`` returns history.
  * ``DELETE /systems/{id}/mirror-serve-credentials/{cred_id}`` —
    revoke (admin/maintainer). 404 if missing or already revoked.

Slice #3's apply orchestrator will issue credentials automatically
as part of ``apply_content_profile_to_host``; this surface exists
for manual ops and for slice #2 testing.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.schemas.content_serve import (
    MirrorServeCredentialIssueRequest,
    MirrorServeCredentialIssueResponse,
    MirrorServeCredentialRead,
)
from app.core.auth import get_current_user, require_role
from app.db.models import HostMirrorServeCredential, MirrorRepo, System
from app.db.session import get_db
from app.services import audit_event_service
from app.services.access_authorization_service import scoped_system_ids
from app.services.mirror_serve_credential_service import (
    MirrorServeCredentialError,
    MirrorServeCredentialService,
)

logger = logging.getLogger(__name__)

# Mounted at /systems by main.py so paths land at
# /systems/{system_id}/mirror-serve-credentials/...
router = APIRouter(tags=["mirror-serve-credentials"])


def _scope_gate(db: Session, current_user, system_id: int) -> None:
    """PRA-281: a direct out-of-scope (or empty-scope) or nonexistent system id is
    a non-disclosing 404 — identical either way — placed BEFORE ``_system_or_404``,
    ``MirrorServeCredentialService``, the ``MirrorRepo`` lookup, plaintext token
    issue, credential list/history retrieval, revoke, audit emission, or any
    credential/mirror error text. So ``mirror_id`` never becomes a mirror-inventory
    probe, ``include_revoked=true`` never leaks hidden host history, and a
    credential id on a hidden host is never probeable. Tenant-wide admins (scope
    ``None``) are unchanged.
    """
    scope = scoped_system_ids(db, current_user)
    if scope is not None and system_id not in scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found",
        )


def _system_or_404(db: Session, system_id: int) -> System:
    system = db.query(System).filter(System.id == system_id).one_or_none()
    if system is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found",
        )
    return system


def _to_read(cred: HostMirrorServeCredential, mirror_slug: str) -> dict:
    return {
        "id": cred.id,
        "host_id": cred.host_id,
        "mirror_id": cred.mirror_id,
        "mirror_slug": mirror_slug,
        "issued_at": cred.issued_at,
        "expires_at": cred.expires_at,
        "last_used_at": cred.last_used_at,
        "revoked_at": cred.revoked_at,
    }


def _actor_id(current_user) -> Optional[int]:
    return getattr(current_user, "id", None) if current_user is not None else None


@router.post(
    "/{system_id}/mirror-serve-credentials",
    response_model=MirrorServeCredentialIssueResponse,
    status_code=status.HTTP_201_CREATED,
)
async def issue_credential(
    system_id: int,
    body: MirrorServeCredentialIssueRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Issue a bearer credential for ``(system, mirror)``.

    Returns the plaintext token ONCE. Revokes any prior active
    credential for the same ``(host, mirror)`` in the same
    transaction.
    """
    _scope_gate(db, current_user, system_id)
    _system_or_404(db, system_id)
    service = MirrorServeCredentialService(db)
    try:
        result = service.issue(
            host_id=system_id,
            mirror_id=body.mirror_id,
            ttl_days=body.ttl_days,
        )
    except MirrorServeCredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    audit_event_service.emit(
        db,
        action="mirror_serve_credential.issued",
        target_kind="system",
        target_id=str(system_id),
        context={
            "credential_id": result.credential_id,
            "mirror_id": result.mirror_id,
            "ttl_days": body.ttl_days,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return {
        "credential_id": result.credential_id,
        "host_id": result.host_id,
        "mirror_id": result.mirror_id,
        "plaintext": result.plaintext,
        "issued_at": result.issued_at,
        "expires_at": result.expires_at,
    }


@router.get(
    "/{system_id}/mirror-serve-credentials",
    response_model=List[MirrorServeCredentialRead],
)
async def list_credentials(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    include_revoked: bool = False,
) -> Any:
    """List metadata for the host's serve credentials.

    Plaintext is NEVER returned (it doesn't exist post-issue —
    storage is hash-only). Default lists active rows; pass
    ``?include_revoked=true`` for history.
    """
    _scope_gate(db, current_user, system_id)
    _system_or_404(db, system_id)
    service = MirrorServeCredentialService(db)
    rows = service.list_for_host(system_id, include_revoked=include_revoked)
    # Bulk-fetch mirror slugs for the read shape (one query, not N).
    mirror_ids = {r.mirror_id for r in rows}
    slug_map: dict[int, str] = {}
    if mirror_ids:
        for mirror in db.query(MirrorRepo).filter(MirrorRepo.id.in_(mirror_ids)).all():
            slug_map[mirror.id] = mirror.slug
    return [_to_read(r, slug_map.get(r.mirror_id, "")) for r in rows]


@router.delete(
    "/{system_id}/mirror-serve-credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_credential(
    system_id: int,
    credential_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    # PRA-281: scope-gate the system BEFORE service.get, so a credential id on a
    # hidden system is never probeable via this delete route.
    _scope_gate(db, current_user, system_id)
    _system_or_404(db, system_id)
    service = MirrorServeCredentialService(db)
    cred = service.get(credential_id)
    if cred is None or cred.host_id != system_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(f"Credential {credential_id} not found for system {system_id}"),
        )
    if not service.revoke(credential_id):
        # Already revoked — surface as 404 so revoking twice is idempotent
        # from the operator's perspective without misleading 200/204.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Credential {credential_id} already revoked",
        )
    audit_event_service.emit(
        db,
        action="mirror_serve_credential.revoked",
        target_kind="system",
        target_id=str(system_id),
        context={
            "credential_id": credential_id,
            "mirror_id": cred.mirror_id,
            "actor_user_id": _actor_id(current_user),
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
