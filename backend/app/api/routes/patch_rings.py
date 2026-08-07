"""Patch ring CRUD + membership routes (PRA-162 slice 1).

Mounted at ``/patch/rings``. Mirrors the PRA-161 patch-policy router
shape (literal sub-routes declared before the wildcard ``/{ring_id}``
detail route per ``feedback_fastapi_route_ordering.md``).

PatchRingError → HTTP 422, except missing-ring → HTTP 404 disambiguated
by the same wording convention PRA-161 slice 1c-a locked in:
``"... not found"`` → 404, ``"... does not exist"`` → 422.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.schemas.patch_rings import (
    PatchRingBindingsList,
    PatchRingCreate,
    PatchRingGateDefinitionCreate,
    PatchRingGateDefinitionRead,
    PatchRingGateDefinitionUpdate,
    PatchRingGateSignalCreate,
    PatchRingGateSignalRead,
    PatchRingGroupBindingCreate,
    PatchRingGroupBindingRead,
    PatchRingHostBindingCreate,
    PatchRingHostBindingRead,
    PatchRingPromotionReadiness,
    PatchRingRead,
    PatchRingSeedDefaultsResult,
    PatchRingSmartGroupBindingCreate,
    PatchRingSmartGroupBindingRead,
    PatchRingUpdate,
)
from app.core.auth import get_current_user, require_role
from app.db.models import PatchRing
from app.db.session import get_db
from app.services import patch_ring_service
from app.services.access_authorization_service import scoped_system_ids
from app.services.patch_ring_service import PatchRingError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["patch-rings"])


def _scope_gate_host(db: Session, current_user, host_id: int) -> None:
    """PRA-281: a patch-ring host binding is host-derived. A direct out-of-scope
    (or empty-scope) or nonexistent host id is a non-disclosing 404 — identical
    either way — placed BEFORE ``patch_ring_service.bind_host`` / ``unbind_host``
    (which look up the ring + host, insert/delete the binding, and emit audit). So
    a scoped caller cannot bind/unbind an out-of-scope host, nor probe ring/host/
    binding existence or conflict details. Tenant-wide admins (scope ``None``) are
    unchanged.
    """
    scope = scoped_system_ids(db, current_user)
    if scope is not None and host_id not in scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
        )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _to_read(ring: PatchRing) -> dict:
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


def _ring_error_to_http(exc: PatchRingError) -> HTTPException:
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


# ---------------------------------------------------------------------------
# CRUD — list / create at the collection root
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=PatchRingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_patch_ring(
    body: PatchRingCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        ring = patch_ring_service.create_ring(
            db,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            slug=body.slug,
            name=body.name,
            description=body.description,
            sort_order=body.sort_order,
            enabled=body.enabled,
        )
    except PatchRingError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    logger.info("created patch ring %s (id=%d)", ring.slug, ring.id)
    return _to_read(ring)


@router.get("", response_model=List[PatchRingRead])
def list_patch_rings(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    enabled_only: bool = False,
) -> Any:
    rows = patch_ring_service.list_rings(db, enabled_only=enabled_only)
    return [_to_read(r) for r in rows]


# ---------------------------------------------------------------------------
# Default ring seed (idempotent canary → pilot → prod)
# ---------------------------------------------------------------------------


@router.post(
    "/seed-defaults",
    response_model=PatchRingSeedDefaultsResult,
)
def seed_default_rings(
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        result = patch_ring_service.seed_default_rings(
            db,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return {
        "created": result["created"],
        "existing": result["existing"],
        "rings": [_to_read(r) for r in result["rings"]],
    }


# ---------------------------------------------------------------------------
# Lookup by slug — declared BEFORE /{ring_id} (route-ordering rule)
# ---------------------------------------------------------------------------


@router.get("/by-slug/{slug}", response_model=PatchRingRead)
def get_patch_ring_by_slug(
    slug: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    ring = patch_ring_service.get_ring_by_slug(db, slug)
    if ring is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch ring slug={slug!r} not found",
        )
    return _to_read(ring)


# ---------------------------------------------------------------------------
# Per-ring detail / update / delete
# ---------------------------------------------------------------------------


@router.get("/{ring_id}", response_model=PatchRingRead)
def get_patch_ring(
    ring_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    ring = patch_ring_service.get_ring(db, ring_id)
    if ring is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch ring {ring_id} not found",
        )
    return _to_read(ring)


@router.patch("/{ring_id}", response_model=PatchRingRead)
def update_patch_ring(
    ring_id: int,
    body: PatchRingUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    updates = body.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="no fields to update",
        )
    try:
        ring = patch_ring_service.update_ring(
            db,
            ring_id,
            updates,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return _to_read(ring)


@router.delete("/{ring_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_patch_ring(
    ring_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    try:
        patch_ring_service.delete_ring(
            db,
            ring_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------


@router.get(
    "/{ring_id}/bindings",
    response_model=PatchRingBindingsList,
)
def list_patch_ring_bindings(
    ring_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        return patch_ring_service.list_bindings(db, ring_id)
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc


@router.post(
    "/{ring_id}/bindings/hosts",
    response_model=PatchRingHostBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def bind_patch_ring_host(
    ring_id: int,
    body: PatchRingHostBindingCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _scope_gate_host(db, current_user, body.host_id)
    try:
        binding = patch_ring_service.bind_host(
            db,
            ring_id=ring_id,
            system_id=body.host_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return binding


@router.delete(
    "/{ring_id}/bindings/hosts/{host_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unbind_patch_ring_host(
    ring_id: int,
    host_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    _scope_gate_host(db, current_user, host_id)
    try:
        patch_ring_service.unbind_host(
            db,
            ring_id=ring_id,
            system_id=host_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{ring_id}/bindings/groups",
    response_model=PatchRingGroupBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def bind_patch_ring_group(
    ring_id: int,
    body: PatchRingGroupBindingCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        binding = patch_ring_service.bind_group(
            db,
            ring_id=ring_id,
            group_id=body.group_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return binding


@router.delete(
    "/{ring_id}/bindings/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unbind_patch_ring_group(
    ring_id: int,
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    try:
        patch_ring_service.unbind_group(
            db,
            ring_id=ring_id,
            group_id=group_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{ring_id}/bindings/smart-groups",
    response_model=PatchRingSmartGroupBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def bind_patch_ring_smart_group(
    ring_id: int,
    body: PatchRingSmartGroupBindingCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        binding = patch_ring_service.bind_smart_group(
            db,
            ring_id=ring_id,
            smart_group_id=body.smart_group_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return binding


@router.delete(
    "/{ring_id}/bindings/smart-groups/{smart_group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unbind_patch_ring_smart_group(
    ring_id: int,
    smart_group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    try:
        patch_ring_service.unbind_smart_group(
            db,
            ring_id=ring_id,
            smart_group_id=smart_group_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Gate definitions + stored signals + promotion readiness — slice 4
# ---------------------------------------------------------------------------
#
# Sub-routes live under /patch/rings/{ring_id}/gates/, /gate-signals/,
# and /promotion-readiness. The literal sub-paths sort before the
# /{ring_id} detail route per feedback_fastapi_route_ordering.md.
# Auth mirrors the existing membership routes: GET requires any
# authenticated user; mutating verbs require admin or maintainer.


def _gate_to_read(gate) -> dict:
    return {
        "id": gate.id,
        "ring_id": gate.ring_id,
        "signal_key": gate.signal_key,
        "name": gate.name,
        "description": gate.description,
        "gate_kind": gate.gate_kind,
        "comparator": gate.comparator,
        "parameters": gate.parameters,
        "required": gate.required,
        "enabled": gate.enabled,
        "created_by": gate.created_by,
        "created_at": gate.created_at,
        "updated_at": gate.updated_at,
    }


def _signal_to_read(signal) -> dict:
    return {
        "id": signal.id,
        "ring_id": signal.ring_id,
        "gate_definition_id": signal.gate_definition_id,
        "signal_key": signal.signal_key,
        "status": signal.status,
        "value": signal.value,
        "details": signal.details,
        "source_kind": signal.source_kind,
        "source_ref_kind": signal.source_ref_kind,
        "source_ref_id": signal.source_ref_id,
        "observed_at": signal.observed_at,
        "expires_at": signal.expires_at,
        "created_by": signal.created_by,
        "created_at": signal.created_at,
        "updated_at": signal.updated_at,
    }


@router.get(
    "/{ring_id}/gates",
    response_model=List[PatchRingGateDefinitionRead],
)
def list_patch_ring_gates(
    ring_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        gates = patch_ring_service.list_gates(db, ring_id)
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return [_gate_to_read(g) for g in gates]


@router.post(
    "/{ring_id}/gates",
    response_model=PatchRingGateDefinitionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_patch_ring_gate(
    ring_id: int,
    body: PatchRingGateDefinitionCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        gate = patch_ring_service.create_gate(
            db,
            ring_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            signal_key=body.signal_key,
            name=body.name,
            description=body.description,
            gate_kind=body.gate_kind,
            comparator=body.comparator,
            parameters=body.parameters,
            required=body.required,
            enabled=body.enabled,
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return _gate_to_read(gate)


@router.patch(
    "/{ring_id}/gates/{gate_id}",
    response_model=PatchRingGateDefinitionRead,
)
def update_patch_ring_gate(
    ring_id: int,
    gate_id: int,
    body: PatchRingGateDefinitionUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    updates = body.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="no updatable fields provided",
        )
    try:
        gate = patch_ring_service.update_gate(
            db,
            ring_id,
            gate_id,
            updates,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return _gate_to_read(gate)


@router.delete(
    "/{ring_id}/gates/{gate_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_patch_ring_gate(
    ring_id: int,
    gate_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    try:
        patch_ring_service.delete_gate(
            db,
            ring_id,
            gate_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{ring_id}/gate-signals",
    response_model=List[PatchRingGateSignalRead],
)
def list_patch_ring_gate_signals(
    ring_id: int,
    signal_key: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        signals = patch_ring_service.list_gate_signals(
            db, ring_id, signal_key=signal_key, limit=limit
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return [_signal_to_read(s) for s in signals]


@router.post(
    "/{ring_id}/gate-signals",
    response_model=PatchRingGateSignalRead,
    status_code=status.HTTP_201_CREATED,
)
def record_patch_ring_gate_signal(
    ring_id: int,
    body: PatchRingGateSignalCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        signal = patch_ring_service.record_gate_signal(
            db,
            ring_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            signal_key=body.signal_key,
            status=body.status,
            value=body.value,
            details=body.details,
            source_kind=body.source_kind,
            source_ref_kind=body.source_ref_kind,
            source_ref_id=body.source_ref_id,
            observed_at=body.observed_at,
            expires_at=body.expires_at,
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return _signal_to_read(signal)


@router.delete(
    "/{ring_id}/gate-signals/{signal_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_patch_ring_gate_signal(
    ring_id: int,
    signal_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    try:
        patch_ring_service.delete_gate_signal(
            db,
            ring_id,
            signal_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{ring_id}/promotion-readiness",
    response_model=PatchRingPromotionReadiness,
)
def get_patch_ring_promotion_readiness(
    ring_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        result = patch_ring_service.evaluate_promotion_readiness(db, ring_id)
    except PatchRingError as exc:
        raise _ring_error_to_http(exc) from exc
    # Convert per-gate signal ORM objects to read-shape dicts.
    gates = []
    for g in result.get("gates", []):
        signal = g.get("signal")
        gates.append(
            {
                **g,
                "signal": _signal_to_read(signal) if signal is not None else None,
            }
        )
    return {**result, "gates": gates}
