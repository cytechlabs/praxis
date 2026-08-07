"""Patch policy CRUD routes (PRA-161 slice 1b).

Mounted at ``/patch/policies``. CRUD only — no bindings, no
resolver, no apply path. Slice 1c will add the binding sub-resource.

Conventions:

* ``APIRouter()`` is used; the FastAPI app already has
  ``redirect_slashes=False`` set globally, and we use empty-string
  paths for the collection root per
  ``feedback_trailing_slash.md``.
* Service-level :class:`PatchPolicyError` is mapped to HTTP 422 so
  bad bind-time MW references / scope-kind / slug-conflict failures
  surface as structured validation errors rather than 500s.
* Audit emission for ``patch_policy.created`` happens inside the
  service after its own commit (see service docstring).
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.schemas.patch_policies import (
    PatchPolicyBindingsList,
    PatchPolicyCreate,
    PatchPolicyGroupBindingCreate,
    PatchPolicyGroupBindingRead,
    PatchPolicyHostBindingCreate,
    PatchPolicyHostBindingRead,
    PatchPolicyRead,
    PatchPolicyRingBindingCreate,
    PatchPolicyRingBindingRead,
    PatchPolicyRingSetList,
    PatchPolicySmartGroupBindingCreate,
    PatchPolicySmartGroupBindingRead,
    PatchPolicyStagedReadiness,
    PatchPolicyUpdate,
)
from app.core.auth import get_current_user, require_role
from app.db.models import PatchPolicy
from app.db.session import get_db
from app.services import patch_policy_service
from app.services.access_authorization_service import scoped_system_ids
from app.services.patch_policy_service import PatchPolicyError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["patch-policies"])


def _scope_gate_host(db: Session, current_user, host_id: int) -> None:
    """PRA-281: a patch-policy host binding is host-derived. A direct out-of-scope
    (or empty-scope) or nonexistent host id is a non-disclosing 404 — identical
    either way — placed BEFORE ``patch_policy_service.bind_host`` / ``unbind_host``
    (which look up the policy + host, insert/delete the binding, and emit audit).
    So a scoped caller cannot bind/unbind an out-of-scope host, nor probe policy/
    host/binding existence or conflict details. Tenant-wide admins (scope ``None``)
    are unchanged.
    """
    scope = scoped_system_ids(db, current_user)
    if scope is not None and host_id not in scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
        )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _to_read(policy: PatchPolicy) -> dict:
    return {
        "id": policy.id,
        "slug": policy.slug,
        "name": policy.name,
        "description": policy.description,
        "scope_kind": policy.scope_kind,
        "scope_packages": list(policy.scope_packages or []),
        "reboot_policy": policy.reboot_policy,
        "reboot_window_id": policy.reboot_window_id,
        "maintenance_window_id": policy.maintenance_window_id,
        "requires_approval": policy.requires_approval,
        "required_approvals": policy.required_approvals,
        "rollout_cadence": policy.rollout_cadence,
        "failure_policy": policy.failure_policy,
        "enabled": policy.enabled,
        "is_fleet_default": policy.is_fleet_default,
        "created_by": policy.created_by,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }


def _actor_ip(request) -> Optional[str]:
    if request is None or request.client is None:
        return None
    return request.client.host


# ---------------------------------------------------------------------------
# CRUD — list / create at the collection root
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=PatchPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_patch_policy(
    body: PatchPolicyCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        policy = patch_policy_service.create_policy(
            db,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            slug=body.slug,
            name=body.name,
            description=body.description,
            scope_kind=body.scope_kind,
            scope_packages=body.scope_packages or [],
            reboot_policy=body.reboot_policy,
            reboot_window_id=body.reboot_window_id,
            maintenance_window_id=body.maintenance_window_id,
            requires_approval=body.requires_approval,
            required_approvals=body.required_approvals,
            rollout_cadence=body.rollout_cadence,
            failure_policy=body.failure_policy,
            enabled=body.enabled,
        )
    except PatchPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    logger.info("created patch policy %s (id=%d)", policy.slug, policy.id)
    return _to_read(policy)


@router.get("", response_model=List[PatchPolicyRead])
def list_patch_policies(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    enabled_only: bool = False,
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
    rows, _total = patch_policy_service.list_policies(
        db, enabled_only=enabled_only, offset=offset, limit=limit
    )
    return [_to_read(p) for p in rows]


# ---------------------------------------------------------------------------
# Lookup by slug — declared BEFORE /{policy_id} per
# feedback_fastapi_route_ordering.md
# ---------------------------------------------------------------------------


@router.get("/by-slug/{slug}", response_model=PatchPolicyRead)
def get_patch_policy_by_slug(
    slug: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    policy = patch_policy_service.get_policy_by_slug(db, slug)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch policy slug={slug!r} not found",
        )
    return _to_read(policy)


# ---------------------------------------------------------------------------
# Per-policy detail / update / delete
# ---------------------------------------------------------------------------


@router.get("/{policy_id}", response_model=PatchPolicyRead)
def get_patch_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    policy = patch_policy_service.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch policy {policy_id} not found",
        )
    return _to_read(policy)


@router.patch("/{policy_id}", response_model=PatchPolicyRead)
def update_patch_policy(
    policy_id: int,
    body: PatchPolicyUpdate,
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
        policy = patch_policy_service.update_policy(
            db, policy_id, updates, actor_user_id=current_user.id
        )
    except PatchPolicyError as exc:
        # 404 if unknown id, otherwise 422 for validation. Service raises
        # the same exception type for both — disambiguate by message.
        msg = str(exc)
        if "not found" in msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=msg
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg
        ) from exc
    return _to_read(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_patch_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),  # pylint: disable=unused-argument
):
    try:
        patch_policy_service.delete_policy(db, policy_id)
    except PatchPolicyError as exc:
        if "not found" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Fleet default — slice 1d
# ---------------------------------------------------------------------------


@router.post(
    "/{policy_id}/fleet-default",
    response_model=PatchPolicyRead,
)
def set_patch_policy_fleet_default(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        policy = patch_policy_service.set_fleet_default(
            db,
            policy_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        if "not found" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return _to_read(policy)


@router.delete(
    "/{policy_id}/fleet-default",
    response_model=PatchPolicyRead,
)
def clear_patch_policy_fleet_default(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        policy = patch_policy_service.clear_fleet_default(
            db,
            policy_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        if "not found" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return _to_read(policy)


# ---------------------------------------------------------------------------
# Bindings — slice 1c
#
# Sub-routes are mounted under /patch/policies/{policy_id}/bindings/. The
# literal /bindings segment guarantees no shadowing of the /{policy_id}
# detail route, so the feedback_fastapi_route_ordering rule is satisfied
# without any special declaration order.
# ---------------------------------------------------------------------------


def _bindings_error_to_http(exc: PatchPolicyError) -> HTTPException:
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


@router.get(
    "/{policy_id}/bindings",
    response_model=PatchPolicyBindingsList,
)
def list_patch_policy_bindings(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        return patch_policy_service.list_bindings(db, policy_id)
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc


@router.post(
    "/{policy_id}/bindings/hosts",
    response_model=PatchPolicyHostBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def bind_patch_policy_host(
    policy_id: int,
    body: PatchPolicyHostBindingCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _scope_gate_host(db, current_user, body.host_id)
    try:
        binding = patch_policy_service.bind_host(
            db,
            policy_id=policy_id,
            system_id=body.host_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return binding


@router.delete(
    "/{policy_id}/bindings/hosts/{host_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unbind_patch_policy_host(
    policy_id: int,
    host_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    _scope_gate_host(db, current_user, host_id)
    try:
        patch_policy_service.unbind_host(
            db,
            policy_id=policy_id,
            system_id=host_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{policy_id}/bindings/groups",
    response_model=PatchPolicyGroupBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def bind_patch_policy_group(
    policy_id: int,
    body: PatchPolicyGroupBindingCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        binding = patch_policy_service.bind_group(
            db,
            policy_id=policy_id,
            group_id=body.group_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return binding


@router.delete(
    "/{policy_id}/bindings/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unbind_patch_policy_group(
    policy_id: int,
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    try:
        patch_policy_service.unbind_group(
            db,
            policy_id=policy_id,
            group_id=group_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{policy_id}/bindings/smart-groups",
    response_model=PatchPolicySmartGroupBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def bind_patch_policy_smart_group(
    policy_id: int,
    body: PatchPolicySmartGroupBindingCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        binding = patch_policy_service.bind_smart_group(
            db,
            policy_id=policy_id,
            smart_group_id=body.smart_group_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return binding


@router.delete(
    "/{policy_id}/bindings/smart-groups/{smart_group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unbind_patch_policy_smart_group(
    policy_id: int,
    smart_group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    try:
        patch_policy_service.unbind_smart_group(
            db,
            policy_id=policy_id,
            smart_group_id=smart_group_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Ring-set binding + staged-readiness — slice 3
# ---------------------------------------------------------------------------
#
# Sub-routes live under /patch/policies/{policy_id}/rings/. The literal
# /rings segment guarantees no shadowing of /{policy_id} or
# /{policy_id}/bindings/* (FastAPI route-ordering rule). Auth mirrors
# the bindings sub-resource: GET requires any authenticated user;
# mutating verbs require admin or maintainer.


def _policy_ring_to_read(binding, ring) -> dict:
    """Inline ring metadata so the operator UI can spot stale or
    disabled bindings without a follow-up call."""
    return {
        "id": binding.id,
        "policy_id": binding.policy_id,
        "ring_id": binding.ring_id,
        "ring_slug": ring.slug,
        "ring_name": ring.name,
        "ring_sort_order": ring.sort_order,
        "ring_enabled": ring.enabled,
        "created_by": binding.created_by,
        "created_at": binding.created_at,
        "updated_at": binding.updated_at,
    }


@router.get(
    "/{policy_id}/rings",
    response_model=PatchPolicyRingSetList,
)
def list_patch_policy_rings(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        rows = patch_policy_service.list_policy_rings(db, policy_id)
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return {
        "policy_id": policy_id,
        "rings": [_policy_ring_to_read(b, r) for b, r in rows],
    }


@router.post(
    "/{policy_id}/rings",
    response_model=PatchPolicyRingBindingRead,
    status_code=status.HTTP_201_CREATED,
)
def bind_patch_policy_ring(
    policy_id: int,
    body: PatchPolicyRingBindingCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        binding = patch_policy_service.bind_policy_ring(
            db,
            policy_id=policy_id,
            ring_id=body.ring_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return _policy_ring_to_read(binding, binding.ring)


@router.delete(
    "/{policy_id}/rings/{ring_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unbind_patch_policy_ring(
    policy_id: int,
    ring_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    try:
        patch_policy_service.unbind_policy_ring(
            db,
            policy_id=policy_id,
            ring_id=ring_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{policy_id}/staged-readiness",
    response_model=PatchPolicyStagedReadiness,
)
def get_patch_policy_staged_readiness(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        return patch_policy_service.get_staged_readiness(db, policy_id)
    except PatchPolicyError as exc:
        raise _bindings_error_to_http(exc) from exc
