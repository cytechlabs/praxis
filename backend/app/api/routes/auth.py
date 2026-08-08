"""
Authentication routes module.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import (  # pylint: disable=wrong-import-order
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from fastapi.security import (  # pylint: disable=wrong-import-order
    OAuth2PasswordRequestForm,
)
from sqlalchemy import or_, update  # pylint: disable=wrong-import-order
from sqlalchemy.orm import Session  # pylint: disable=wrong-import-order

from app.api.routes.app_settings import is_self_registration_enabled
from app.api.schemas.auth import (
    PasswordChange,
    Token,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from app.core.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    authenticate_user,
    create_access_token,
    create_refresh_token,
    get_current_user,
    get_password_hash,
    verify_password,
    verify_refresh_token,
)
from app.core.rate_limit import limiter
from app.core.support_logging import log_support_event
from app.db.models import RefreshToken, Role, User
from app.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])


def user_to_response(user: User) -> Dict:
    """Convert User model to response dict with role names."""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_active": user.is_active,
        "roles": [role.name for role in user.roles],
    }


@router.get("/registration-status")
async def registration_status(db: Session = Depends(get_db)) -> Any:
    """Public: whether self-registration is currently enabled.

    Used by the login UI so it does not advertise signup when an administrator
    has disabled it. Anonymous (allow-listed in the JWT middleware) like the
    OIDC status endpoint.
    """
    return {"enabled": is_self_registration_enabled(db)}


@router.post("/register", response_model=UserResponse)
@limiter.limit("3/hour")
async def register(
    request: Request, user_data: UserCreate, db: Session = Depends(get_db)
) -> Any:
    """Register a new user.

    PRA-216: self-registration is gated behind an admin-controlled setting and
    is disabled by default for 1.0. When disabled the endpoint refuses with a
    clear, non-sensitive 403 rather than silently creating accounts.
    """
    if not is_self_registration_enabled(db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-registration is disabled. Contact an administrator.",
        )

    if (
        db.query(User)
        .filter(or_(User.username == user_data.username, User.email == user_data.email))
        .first()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        is_active=True,
    )

    viewer_role = db.query(Role).filter(Role.name == "viewer").first()
    if viewer_role:
        user.roles.append(viewer_role)

    db.add(user)
    db.commit()
    db.refresh(user)
    return user_to_response(user)


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> Any:
    """Login user and return tokens."""
    try:
        user = authenticate_user(db, form_data.username, form_data.password)
    except HTTPException:
        # Supportability: record the failure without the attempted credentials.
        log_support_event(
            logger, "auth.login", level=logging.WARNING, outcome="failure"
        )
        raise
    log_support_event(logger, "auth.login", outcome="success", actor_user_id=user.id)

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    token_refresh = create_refresh_token(
        data={"sub": user.username},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    # Store refresh token
    db_refresh_token = RefreshToken(
        token=token_refresh,
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        is_valid=True,
    )
    db.add(db_refresh_token)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": token_refresh,
        "token_type": "bearer",
    }


@router.post("/change-password")
@limiter.limit("5/minute")
async def change_password(
    request: Request,
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Change user's password."""
    # Verify current password
    if not verify_password(
        password_data.current_password, current_user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Verify new passwords match
    try:
        password_data.validate_passwords_match()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    # Update password
    current_user.hashed_password = get_password_hash(password_data.new_password)

    # PRA-180 AUTH-04: invalidate all of the user's existing refresh tokens so a
    # password change (incl. a suspected-compromise rotation) kicks out other
    # sessions. Access tokens are short-lived (30 min) and expire on their own.
    revoked = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.user_id == current_user.id,
            RefreshToken.is_valid.is_(True),
        )
        .update({RefreshToken.is_valid: False}, synchronize_session=False)
    )
    db.commit()

    return {
        "message": "Password updated successfully",
        "sessions_revoked": int(revoked or 0),
    }


def claim_refresh_token(db: Session, token_refresh: str, now: datetime):
    """PRA-252: atomically claim (single-use) the presented refresh-token row.

    A single conditional ``UPDATE ... WHERE token=:t AND is_valid AND
    expires_at>:now SET is_valid=false RETURNING id, user_id`` both flips the row
    to invalid AND reports whether THIS transaction won. Under concurrent replay
    Postgres row-locks the matching row: exactly one transaction updates the
    still-valid row and gets the RETURNING payload; the others re-evaluate the
    predicate after the lock releases, match zero rows, and get nothing. Returns
    the claimed ``(id, user_id)`` row on success, or ``None`` when the token is
    unknown/expired/already claimed. Does not commit — the caller commits once
    after minting the successor so the invalidation and the new row are one unit.
    """
    stmt = (
        update(RefreshToken)
        .where(
            RefreshToken.token == token_refresh,
            RefreshToken.is_valid.is_(True),
            RefreshToken.expires_at > now,
        )
        .values(is_valid=False)
        .returning(RefreshToken.id, RefreshToken.user_id)
        .execution_options(synchronize_session=False)
    )
    return db.execute(stmt).first()


@router.post("/refresh", response_model=Token)
@limiter.limit("10/minute")
async def refresh_access_token(
    request: Request, token_refresh: str, db: Session = Depends(get_db)
) -> Any:
    """Get new access token using refresh token."""
    payload = verify_refresh_token(token_refresh)
    username = payload.get("sub")
    now = datetime.utcnow()

    # PRA-252: atomically claim the old row BEFORE minting a successor so a
    # concurrent replay cannot mint two valid sessions. Only the request that
    # wins the claim proceeds; losers fall through to the same 401 as a replay.
    claimed = claim_refresh_token(db, token_refresh, now)
    if claimed is None:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # PRA-290: never mint a successor for a deactivated user. Deactivation already
    # invalidates refresh tokens, but this is fail-closed defense-in-depth. Keep the
    # claimed (now-consumed) row invalidated — commit the claim, mint nothing.
    refresh_user = db.query(User).filter(User.id == claimed.user_id).first()
    if refresh_user is None or not refresh_user.is_active:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    new_access_token = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    new_refresh_token = create_refresh_token(
        data={"sub": username},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    db.add(
        RefreshToken(
            token=new_refresh_token,
            user_id=claimed.user_id,
            expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            is_valid=True,
        )
    )
    db.commit()

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


@router.post("/logout")
async def logout(
    token_refresh: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Any:
    """Logout by revoking the presented refresh token.

    Deliberately does NOT require a valid access token: an explicit logout must
    kill the server-side session even when the caller's access token is expired
    or missing, otherwise a stolen refresh token would stay usable after the user
    logs out. Revocation is scoped to the exact refresh-token value — itself a
    bearer secret — so it only ever invalidates the presenting token's own row and
    never an unrelated session.

    Idempotent by design: an unknown, bogus, already-revoked, or entirely absent
    token is a constant-response no-op (no user/token existence signal), so a
    caller can always complete logout without a server-side error.
    """
    if token_refresh:
        db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.token == token_refresh,
                RefreshToken.is_valid.is_(True),
            )
            .values(is_valid=False)
            .execution_options(synchronize_session=False)
        )
        db.commit()

    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def read_current_user(current_user: User = Depends(get_current_user)) -> Any:
    """Get current user information."""
    return user_to_response(current_user)


@router.put("/me", response_model=UserResponse)
async def update_current_user(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Update current user information."""
    if user_data.email and user_data.email != current_user.email:
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )
        current_user.email = user_data.email

    db.commit()
    db.refresh(current_user)
    return user_to_response(current_user)
