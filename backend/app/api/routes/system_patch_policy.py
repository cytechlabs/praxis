"""GET ``/systems/{system_id}/patch-policy/effective`` (PRA-161 slice 1d).

Resolver-facing endpoint. Returns the effective patch policy for a
host plus a ``resolution_kind`` describing which precedence tier
matched. When no tier matches and there is no enabled fleet default,
returns 200 with ``{policy: null, resolution_kind: "no_policy"}``.

Conflict semantics: if multiple distinct enabled policies are bound
at the same precedence tier, the resolver raises
:class:`EffectivePolicyConflict` and the route translates it to
HTTP 409 Conflict with structured detail naming the tier and the
conflicting ``(policy_id, slug)`` pairs so an operator can fix the
duplicate-binding state.

Mounted as a separate router under ``/systems`` to mirror the shape
of ``lifecycle.py``'s ``/systems/{id}/lifecycle`` endpoint without
crowding the systems router with patch-specific concerns.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.schemas.patch_policies import EffectivePolicyRead, PatchPolicyRead
from app.core.auth import get_current_user, require_system_access
from app.db.session import get_db
from app.services import patch_policy_service
from app.services.patch_policy_service import EffectivePolicyConflict, PatchPolicyError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system-patch-policy"])


def _policy_to_read(policy) -> dict:
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


@router.get(
    "/{system_id}/patch-policy/effective",
    response_model=EffectivePolicyRead,
    dependencies=[Depends(require_system_access())],
)
def get_effective_patch_policy(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        policy, kind = patch_policy_service.resolve_effective_policy(db, system_id)
    except EffectivePolicyConflict as exc:
        # 409 Conflict — the resolver cannot pick a single effective
        # policy because the binding layer has duplicate enabled
        # policies at the same tier. Detail names the tier and the
        # conflicting policies so the operator can fix it.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "effective_policy_conflict",
                "tier": exc.tier,
                "policies": [{"id": pid, "slug": slug} for pid, slug in exc.policies],
                "message": str(exc),
            },
        ) from exc
    except PatchPolicyError as exc:
        # Currently this only fires for "host id=N not found".
        if "not found" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    return {
        "system_id": system_id,
        "resolution_kind": kind,
        "policy": _policy_to_read(policy) if policy is not None else None,
    }
