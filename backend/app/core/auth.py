"""
Authentication core functionality module.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import (  # pylint: disable=wrong-import-order
    Depends,
    HTTPException,
    Path,
    status,
)
from fastapi.security import OAuth2PasswordBearer  # pylint: disable=wrong-import-order
from sqlalchemy.orm import Session  # pylint: disable=wrong-import-order

from app.core.security import pwd_context, verify_password
from app.db.models import User
from app.db.session import get_db

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable is required. "
        "Set it in your .env file or environment."
    )

# Reject known-weak secret values
_WEAK_SECRETS = {
    "dev_secret_change_in_production",
    "your-secret-key-here",
    "change-me-to-a-random-string",
    "secret",
    "changeme",
}
# PRA-180 AUTH-06: minimum SECRET_KEY length enforced in production so a short,
# low-entropy (but non-blacklisted) key can't weaken every HS256 JWT.
_MIN_PROD_SECRET_KEY_LEN = 32


def validate_secret_key(secret_key: str, environment: str) -> None:
    """Validate SECRET_KEY strength. Raises ``RuntimeError`` in production for a
    known-weak value or a too-short key; warns (does not raise) outside
    production. Pure + side-effect-light so it is unit-testable (PRA-180)."""
    is_weak = secret_key.lower() in _WEAK_SECRETS or secret_key.startswith("change-me")
    if is_weak:
        if environment == "production":
            raise RuntimeError(
                "SECRET_KEY is set to a known-weak value. "
                "Generate a secure random key for production."
            )
        logging.getLogger(__name__).warning(
            "SECRET_KEY is set to a known-weak value. "
            "This is acceptable for development but must be changed for production."
        )
    if environment == "production" and len(secret_key) < _MIN_PROD_SECRET_KEY_LEN:
        raise RuntimeError(
            "SECRET_KEY must be at least "
            f"{_MIN_PROD_SECRET_KEY_LEN} characters in production. "
            "Generate a 256-bit random key, e.g. `openssl rand -hex 32`."
        )


_environment = os.getenv("ENVIRONMENT", "development")
validate_secret_key(SECRET_KEY, _environment)

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """
    Authenticate a user by username and password.

    Args:
        db: Database session
        username: Username to authenticate
        password: Password to verify

    Returns:
        User object if authentication successful

    Raises:
        HTTPException: If authentication fails
    """
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "token_type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT refresh token.

    Includes a random jti (JWT ID) claim so two tokens minted in the same
    second for the same user hash to distinct strings — required for rotation
    since the refresh_tokens table has a unique index on the token value.
    """
    import uuid

    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode.update({"exp": expire, "token_type": "refresh", "jti": uuid.uuid4().hex})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode + validate an access JWT.

    Single source of truth for access-token validation, used by both the
    per-route ``get_current_user`` dependency and the app-wide
    ``JWTAuthMiddleware`` fail-closed gate (PRA-180 AUTH-01). Raises
    ``jwt.PyJWTError`` on a bad/expired signature, a missing ``sub``, or a
    refresh token presented as an access token.
    """
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload.get("sub") is None:
        raise jwt.InvalidTokenError("token missing subject")
    if payload.get("token_type") == "refresh":
        raise jwt.InvalidTokenError("refresh token used as access token")
    return payload


def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> User:
    """Get current user from token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        username: str = payload.get("sub")
    except jwt.PyJWTError as exc:
        raise credentials_exception from exc

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def verify_refresh_token(token: str) -> dict:
    """Verify JWT refresh token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_user_roles(user: User) -> list[str]:
    """Get list of role names for a user."""
    return [role.name for role in user.roles]


def verify_admin(current_user: User = Depends(get_current_user)) -> User:
    """Verify if user has admin privileges."""
    if "admin" not in get_user_roles(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def require_role(*allowed_roles: str):
    """
    Dependency factory that checks if the current user has one of the allowed roles.

    Usage:
        @router.post("/systems", dependencies=[Depends(require_role("admin", "maintainer"))])
        def create_system(...):
    """

    def checker(current_user: User = Depends(get_current_user)) -> User:
        user_roles = get_user_roles(current_user)
        if not any(role in allowed_roles for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(allowed_roles)}",
            )
        return current_user

    return checker


def require_system_access(*allowed_roles: str):
    """PRA-281: dependency enforcing fleet scope on a route with a ``system_id``
    path parameter.

    The caller must have fleet scope on the path's ``system_id`` (an
    ``AccessGrant``, or tenant-wide app-admin scope) and, when ``allowed_roles``
    is given, one of those global app roles. A caller outside their fleet scope —
    or targeting a system that does not exist — receives a NON-DISCLOSING 404, so
    system existence is never leaked across a scope boundary. Admins pass via the
    policy engine's tenant-wide scope, not a route-level bypass
    (``access_authorization_service.user_can_access_system``).

    The role gate (403) runs before the scope gate (404): lacking the global role
    is not system-specific and does not disclose anything about a particular host.
    """

    def checker(
        system_id: int = Path(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        if allowed_roles and not any(
            role in allowed_roles for role in get_user_roles(current_user)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(allowed_roles)}",
            )
        # Lazy import avoids a module-load cycle (the service imports db models).
        from app.services.access_authorization_service import user_can_access_system

        if not user_can_access_system(db, current_user, system_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="System not found"
            )
        return current_user

    return checker


# Role definitions:
# admin      - full access to everything
# maintainer - manage systems, credentials, packages, jobs, SSH, vault. No user management.
# auditor    - read-only access to everything. No create, edit, delete, execute.


def get_password_hash(password: str) -> str:
    """Create password hash."""
    return pwd_context.hash(password)
