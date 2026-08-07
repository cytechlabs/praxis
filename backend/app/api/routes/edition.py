"""Edition / entitlement / license surface (PRA-132, PRA-133).

``GET /edition`` returns the current edition, entitlement map, host cap + usage,
and license status (any authenticated user). ``POST/DELETE /edition/license``
apply or remove an offline license (admin only). Enforcement is server-side;
this surface drives the frontend locked/upgrade and License settings UI.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...core.support_logging import log_support_event
from ...db.models import User
from ...db.session import get_db
from ...services import license_service
from ...services.license_service import LicenseError

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


class LicenseApplyRequest(BaseModel):
    token: str
    # Optional online-refresh material. When present AND the license validates, it
    # is stored server-side (bound to this install's instance_id) so the license
    # can later be refreshed automatically after a Paddle renewal. Offline/manual
    # apply is unchanged when omitted. Never echoed back in any response.
    refresh_token: Optional[str] = None


@router.get("")
def get_edition(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    """Current edition, entitlements, host cap/usage, and license status."""
    return license_service.license_status(db)


@router.get("/buy-url")
def get_buy_url(
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    """The Praxis website buy page with this install's instance_id prefilled. The
    website is the buy surface; the app never starts checkout or holds price IDs."""
    return {"buy_url": license_service.buy_license_url(db)}


@router.post("/license")
def apply_license(
    body: LicenseApplyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Apply an offline license token. Admin only. Returns the updated status.

    If ``refresh_token`` is supplied and the license is valid, the token is stored
    server-side (bound to this install's instance_id) to enable online refresh; an
    invalid license stores nothing."""
    try:
        result = license_service.apply_license(
            db,
            body.token,
            actor_user_id=current_user.id,
            refresh_token=body.refresh_token,
        )
        log_support_event(
            logger, "license.apply", outcome="success", actor_user_id=current_user.id
        )
        return result
    except LicenseError as exc:
        log_support_event(
            logger,
            "license.apply",
            level=logging.WARNING,
            outcome="failure",
            error_category=exc.state,
            actor_user_id=current_user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"state": exc.state, "message": exc.message},
        ) from exc


@router.post("/license/refresh")
def refresh_license(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Refresh the applied license online via the EE bridge. Admin only.

    Uses this install's server-owned instance_id + the stored refresh token. If
    refresh is not configured, EE is unavailable, or EE declines, the current
    license is left untouched. Returns the refresh result plus the updated edition
    status (the response never contains the refresh token)."""
    return license_service.refresh_license(db, actor_user_id=current_user.id)


@router.delete("/license")
def remove_license(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Remove the applied license -> free edition. Admin only. Existing hosts are
    never disabled."""
    return license_service.remove_license(db, actor_user_id=current_user.id)
