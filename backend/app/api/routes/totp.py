"""TOTP enrollment + step-up endpoints (PRA-139)."""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.auth import get_current_user
from ...db.models import User
from ...db.session import get_db
from ...services import totp_service
from ...services.totp_service import TotpError

router = APIRouter(redirect_slashes=False)


class CodeBody(BaseModel):
    code: str = Field(..., min_length=6, max_length=32)


@router.get("/status", response_model=Dict[str, Any])
async def totp_status(
    current_user: User = Depends(get_current_user),
):
    """Return the caller's TOTP enrollment state."""
    return {
        "enrolled": totp_service.is_enrolled(current_user),
        "enrolled_at": (
            current_user.totp_enrolled_at.isoformat() + "Z"
            if current_user.totp_enrolled_at
            else None
        ),
        "recovery_codes_remaining": totp_service.remaining_recovery_codes(current_user),
    }


@router.post("/enroll-begin", response_model=Dict[str, Any])
async def enroll_begin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a fresh TOTP secret and otpauth URI for the caller."""
    secret, uri = totp_service.begin_enrollment(db, current_user)
    return {"secret": secret, "uri": uri}


@router.post("/enroll-verify", response_model=Dict[str, Any])
async def enroll_verify(
    payload: CodeBody,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Confirm the first TOTP code; returns one-time recovery codes."""
    try:
        codes = totp_service.verify_enrollment(db, current_user, payload.code)
    except TotpError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"recovery_codes": codes}


@router.post("/step-up", response_model=Dict[str, Any])
async def step_up(
    payload: CodeBody,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify a TOTP or recovery code and mint a fresh-TOTP challenge."""
    try:
        ok = totp_service.verify_step_up(db, current_user, payload.code)
    except TotpError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if not ok:
        raise HTTPException(status_code=400, detail="invalid code")
    return {"status": "ok"}


@router.post("/disable", response_model=Dict[str, Any])
async def disable(
    payload: CodeBody,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable TOTP after confirming the current code (belt-and-suspenders)."""
    if not totp_service.verify_current_code(current_user, payload.code):
        raise HTTPException(status_code=400, detail="invalid code")
    totp_service.disable(db, current_user)
    return {"status": "disabled"}


@router.post("/recovery-codes/regenerate", response_model=Dict[str, Any])
async def regenerate_recovery_codes(
    payload: CodeBody,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Rotate recovery codes after verifying the current TOTP code."""
    if not totp_service.verify_current_code(current_user, payload.code):
        raise HTTPException(status_code=400, detail="invalid code")
    try:
        codes = totp_service.generate_fresh_recovery_codes(db, current_user)
    except TotpError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"recovery_codes": codes}
