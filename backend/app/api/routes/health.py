"""
Fleet health and dashboard routes (PRA-112, PRA-103).
"""

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...core.api_errors import internal_error
from ...core.auth import get_current_user, require_role, require_system_access
from ...db.models import User
from ...db.session import get_db
from ...services.access_authorization_service import (
    scoped_system_ids,
    user_can_access_system,
)
from ...services.health_service import HealthService

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


def _enforce_bulk_scope(db: Session, user: User, system_ids: List[int]) -> None:
    """PRA-281: every requested system must be in the caller's fleet scope.

    A single out-of-scope id fails the whole request with a NON-DISCLOSING 404 —
    the response never reveals which ids exist or are in scope. Admins (tenant-wide
    scope) pass here; per-id validity is handled by the check itself afterward.
    """
    for sid in system_ids:
        if not user_can_access_system(db, user, sid):
            raise HTTPException(status_code=404, detail="System not found")


class BulkCheckRequest(BaseModel):
    """Request body for bulk system check."""

    system_ids: List[int]


@router.get("/health", response_model=Dict[str, Any])
def fleet_health(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get fleet connectivity health summary."""
    try:
        service = HealthService(db)
        return service.get_fleet_health(system_ids=scoped_system_ids(db, current_user))
    except Exception as e:
        raise internal_error(e, context="getting fleet health", logger=logger) from e


@router.get("/dashboard", response_model=Dict[str, Any])
def fleet_dashboard(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get fleet operations dashboard data."""
    try:
        service = HealthService(db)
        return service.get_fleet_dashboard(
            system_ids=scoped_system_ids(db, current_user)
        )
    except Exception as e:
        raise internal_error(e, context="getting fleet dashboard", logger=logger) from e


@router.post(
    "/check/{system_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(require_system_access("admin", "maintainer"))],
)
def check_system_health(
    system_id: int = Path(..., description="System ID to check"),
    current_user: User = Depends(
        require_role("admin", "maintainer")
    ),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Trigger an on-demand connectivity check for a single system."""
    try:
        service = HealthService(db)
        # PRA-313: a single on-demand check is an explicit operator recheck, so it
        # bypasses the transport cooldown to actually retry (and recover) the host.
        return service.check_system(system_id, bypass_cooldown=True)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise internal_error(e, context="checking system health", logger=logger) from e


@router.post("/bulk/check", response_model=Dict[str, Any])
def bulk_check_systems(
    body: BulkCheckRequest,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Trigger health checks on multiple systems."""
    if not body.system_ids:
        raise HTTPException(status_code=400, detail="At least one system ID required")
    # PRA-281: reject the whole request if any requested id is out of the caller's
    # fleet scope, without disclosing which id failed.
    _enforce_bulk_scope(db, current_user, body.system_ids)
    try:
        service = HealthService(db)
        # PRA-313: an explicitly-selected bulk check is an operator recheck — retry
        # cooling-down hosts rather than fast-fail them.
        return service.check_systems(body.system_ids, bypass_cooldown=True)
    except Exception as e:
        raise internal_error(e, context="bulk health check", logger=logger) from e


@router.post("/check-all", response_model=Dict[str, Any])
def check_all_systems(
    force: bool = Query(
        False,
        description="Retry hosts currently in transport cooldown (bypass the "
        "circuit breaker). Default skips cooling-down hosts so one bad host does "
        "not make the whole sweep wait on its SSH timeout.",
    ),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Trigger health checks on all active systems (in the caller's fleet scope).

    PRA-313: by default this skips hosts in transport cooldown; pass ``force=true``
    to retry them (explicit operator recovery).
    """
    try:
        service = HealthService(db)
        return service.check_all_systems(
            scope_system_ids=scoped_system_ids(db, current_user), force=force
        )
    except Exception as e:
        raise internal_error(e, context="check-all systems", logger=logger) from e
