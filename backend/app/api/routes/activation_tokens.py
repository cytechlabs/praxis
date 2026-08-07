"""PRA-154 slice #1b: admin CRUD endpoints for activation tokens.

Mounted at ``/agent/activation-tokens``. All endpoints require admin
role; an operator authoring an enrollment token is functionally
authorizing identity issuance, so the gate matches.

The plaintext token is returned exactly once on create. List and
detail responses surface the prefix, expiry, uses, status, and
placement scope, but never the hash or the plaintext.

Bootstrap-side redemption (``POST /agent/enroll``) lives in slice #1c.
"""

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from ...core.auth import require_role
from ...db.models import ActivationToken, Group, System, Tag, User
from ...db.session import get_db
from ...services import activation_token_service as svc

router = APIRouter(redirect_slashes=False)


# ----------------------------------------------------------- request models


class ActivationTokenCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    default_group_id: int = Field(..., ge=1)
    target_system_id: int = Field(..., ge=1)
    default_tag_ids: List[int] = Field(default_factory=list)
    ttl_seconds: int = Field(..., ge=60, le=60 * 60 * 24 * 30)
    # Forced to 1 while link-only redemption is the only path: the
    # (token_id, system_id) ledger unique already caps real
    # redemptions at 1. The column is kept on the schema for the
    # eventual create-on-redemption slice that re-enables bulk
    # enrollment.
    max_uses: int = Field(1, ge=1, le=1)

    @validator("default_tag_ids")
    def _no_duplicate_tags(v):  # noqa: N805
        if len(set(v)) != len(v):
            raise ValueError("default_tag_ids must not contain duplicates")
        return v


# ----------------------------------------------------------- response models


class ActivationTokenView(BaseModel):
    """Listing/detail shape — no plaintext, no hash."""

    id: int
    name: str
    token_prefix: str
    default_group_id: int
    target_system_id: int
    target_system_hostname: Optional[str]
    default_tag_ids: List[int]
    ttl_expires_at: str
    max_uses: int
    uses_count: int
    revoked_at: Optional[str]
    revoked_by_user_id: Optional[int]
    created_by_user_id: int
    created_at: str
    updated_at: str
    status: str  # "active" | "expired" | "exhausted" | "revoked"


class ActivationTokenCreated(ActivationTokenView):
    """Create response — plaintext is included exactly once and must
    not be persisted by the caller."""

    plaintext: str
    # One-line operator command. ``None`` when ``PRAXIS_PUBLIC_URL``
    # is not configured on the control plane; the token itself is
    # still valid and can be used by hand. UI should surface
    # ``bootstrap_command_unavailable_reason`` when this is null.
    bootstrap_command: Optional[str]
    bootstrap_command_unavailable_reason: Optional[str]


# ---------------------------------------------------------------- helpers


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.isoformat() + "Z"


def _status(token: ActivationToken, *, now: Optional[datetime] = None) -> str:
    now = now or datetime.utcnow()
    if token.revoked_at is not None:
        return "revoked"
    if token.ttl_expires_at <= now:
        return "expired"
    if token.uses_count >= token.max_uses:
        return "exhausted"
    return "active"


def _to_view(token: ActivationToken) -> Dict[str, Any]:
    target_hostname = (
        token.target_system.hostname if token.target_system is not None else None
    )
    return {
        "id": token.id,
        "name": token.name,
        "token_prefix": token.token_prefix,
        "default_group_id": token.default_group_id,
        "target_system_id": token.target_system_id,
        "target_system_hostname": target_hostname,
        "default_tag_ids": list(token.default_tag_ids or []),
        "ttl_expires_at": _iso(token.ttl_expires_at),
        "max_uses": token.max_uses,
        "uses_count": token.uses_count,
        "revoked_at": _iso(token.revoked_at),
        "revoked_by_user_id": token.revoked_by_user_id,
        "created_by_user_id": token.created_by_user_id,
        "created_at": _iso(token.created_at),
        "updated_at": _iso(token.updated_at),
        "status": _status(token),
    }


def _bootstrap_command(
    plaintext: str, system_id: int
) -> tuple[Optional[str], Optional[str]]:
    """Return ``(command, unavailable_reason)``.

    Command is None when ``PRAXIS_PUBLIC_URL`` is not configured. The
    token is still functionally valid; the UI should surface the
    reason rather than silently hide the convenience copy."""
    public_url = os.getenv("PRAXIS_PUBLIC_URL")
    if not public_url:
        return None, "PRAXIS_PUBLIC_URL unset"
    cmd = (
        f"curl -fsSL {public_url}/agent/bootstrap.sh | "
        f"sudo PRAXIS_URL='{public_url}' "
        f"PRAXIS_ACTIVATION_TOKEN='{plaintext}' "
        f"PRAXIS_SYSTEM_ID='{system_id}' bash"
    )
    return cmd, None


def _validate_placement(db: Session, group_id: int, tag_ids: List[int]) -> None:
    """Reject creation against a missing group or unknown tags. The
    target system existence + group-match check stays in the service
    so future callers cannot bypass it."""
    if db.query(Group).filter(Group.id == group_id).first() is None:
        raise HTTPException(
            status_code=400, detail=f"default_group_id {group_id} not found"
        )
    if tag_ids:
        found = {t.id for t in db.query(Tag).filter(Tag.id.in_(tag_ids)).all()}
        missing = sorted(set(tag_ids) - found)
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"default_tag_ids not found: {missing}",
            )


def _load_or_404(db: Session, token_id: int) -> ActivationToken:
    tok = db.query(ActivationToken).filter(ActivationToken.id == token_id).first()
    if tok is None:
        raise HTTPException(
            status_code=404, detail=f"activation token {token_id} not found"
        )
    return tok


# ---------------------------------------------------------------- routes


@router.post("", response_model=ActivationTokenCreated, status_code=201)
def create_activation_token(
    body: ActivationTokenCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
) -> Dict[str, Any]:
    _validate_placement(db, body.default_group_id, body.default_tag_ids)
    expires_at = datetime.utcnow() + timedelta(seconds=body.ttl_seconds)

    try:
        issued = svc.issue_token(
            db,
            name=body.name,
            default_group_id=body.default_group_id,
            target_system_id=body.target_system_id,
            default_tag_ids=body.default_tag_ids,
            ttl_expires_at=expires_at,
            max_uses=body.max_uses,
            created_by_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.commit()
    db.refresh(issued.token)
    # Emit post-commit so audit_event_service.emit's internal commit
    # cannot land the token mutation before the route is ready, and
    # so a later route failure cannot leave a token committed without
    # the rest of the work. See svc.emit_audit docstring.
    svc.emit_audit(
        db,
        action="activation_token.create",
        token=issued.token,
        actor_user_id=current_user.id,
    )
    payload = _to_view(issued.token)
    payload["plaintext"] = issued.plaintext
    cmd, reason = _bootstrap_command(issued.plaintext, body.target_system_id)
    payload["bootstrap_command"] = cmd
    payload["bootstrap_command_unavailable_reason"] = reason
    return payload


@router.get("", response_model=List[ActivationTokenView])
def list_activation_tokens(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> List[Dict[str, Any]]:
    tokens = db.query(ActivationToken).order_by(ActivationToken.id.desc()).all()
    return [_to_view(t) for t in tokens]


@router.post("/{token_id}/revoke", response_model=ActivationTokenView)
def revoke_activation_token(
    token_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
) -> Dict[str, Any]:
    tok = _load_or_404(db, token_id)
    was_already_revoked = tok.revoked_at is not None
    svc.revoke_token(db, tok, revoked_by_user_id=current_user.id)
    db.commit()
    db.refresh(tok)
    # Idempotent re-revoke is a no-op in the service; only emit on the
    # transition that actually flipped state.
    if not was_already_revoked:
        svc.emit_audit(
            db,
            action="activation_token.revoke",
            token=tok,
            actor_user_id=current_user.id,
        )
    return _to_view(tok)


@router.get("/{token_id}", response_model=ActivationTokenView)
def get_activation_token(
    token_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> Dict[str, Any]:
    tok = _load_or_404(db, token_id)
    return _to_view(tok)
