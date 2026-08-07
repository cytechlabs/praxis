"""
User management routes module.
"""

# pylint: disable=unused-argument

from typing import Any, List

from fastapi import (  # pylint: disable=wrong-import-order
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from sqlalchemy.orm import Session  # pylint: disable=wrong-import-order

from app.api.schemas.auth import (
    PasswordChange,
    RoleAssignment,
    UserCreate,
    UserResponse,
)
from app.core.auth import get_current_user, get_password_hash, verify_admin
from app.core.rate_limit import limiter
from app.db.models import Role, User
from app.db.session import get_db
from app.services import identity_access_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/roles", response_model=List[str])
async def get_available_roles(
    current_user: User = Depends(get_current_user),  # pylint: disable=unused-argument
    is_admin: bool = Depends(verify_admin),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
) -> Any:
    """
    Get all available roles in the system.
    Only administrators can access this endpoint.
    """
    roles = db.query(Role.name).all()
    return [role[0] for role in roles]


@router.get("", response_model=List[UserResponse])
async def get_users(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, le=100),
    current_user: User = Depends(get_current_user),  # pylint: disable=unused-argument
    is_admin: bool = Depends(verify_admin),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
) -> Any:
    """
    Only administrators can access this endpoint.

    Parameters:
    - skip: Number of users to skip (pagination offset)
    - limit: Maximum number of users to return
    """
    users = db.query(User).offset(skip).limit(limit).all()
    return [UserResponse.from_orm(user) for user in users]


@router.patch("/{user_id}/toggle-active", response_model=UserResponse)
async def toggle_user_active(
    user_id: int,
    current_user: User = Depends(get_current_user),
    is_admin: bool = Depends(verify_admin),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
) -> Any:
    """
    Toggle a user's active status.
    Only administrators can access this endpoint.

    Parameters:
    - user_id: ID of the user to toggle active status
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent self-deactivation
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot toggle your own active status",
        )

    # PRA-290: route (de)activation through the single identity-access path so it
    # denies new auth, invalidates refresh tokens, recomputes grants + host desired
    # state, and invokes the session-impact hook (deactivate) — or restores grants
    # and releases the auto-lock (activate). Failures surface as a 5xx rather than
    # committing a half-applied state.
    identity_access_service.set_user_active(
        db, user, active=not user.is_active, actor=current_user
    )
    db.refresh(user)
    return UserResponse.from_orm(user)


@router.put("/{user_id}/roles", response_model=UserResponse)
async def update_user_roles(
    user_id: int,
    role_assignment: RoleAssignment,
    current_user: User = Depends(get_current_user),
    is_admin: bool = Depends(verify_admin),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
) -> Any:
    """
    Update a user's roles.
    Only administrators can access this endpoint.

    Parameters:
    - user_id: ID of the user to update roles
    - role_assignment: List of role names to assign
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent self-role modification
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify your own roles",
        )

    # Verify all roles exist
    roles = []
    for role_name in role_assignment.roles:
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role {role_name} does not exist",
            )
        roles.append(role)

    # PRA-290: route the role change through the single identity-access path so
    # grants are atomically recomputed (PRA-289). Admin removal drops implicit
    # all-system grants promptly; a recompute failure surfaces instead of
    # committing stale authorization.
    identity_access_service.apply_role_assignment(db, user, roles)
    db.refresh(user)
    return UserResponse.from_orm(user)


@router.post("", response_model=UserResponse)
@limiter.limit("10/minute")
async def create_user(
    request: Request,
    user_data: UserCreate,
    current_user: User = Depends(get_current_user),  # pylint: disable=unused-argument
    is_admin: bool = Depends(verify_admin),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
) -> Any:
    """
    Create a new user.
    Only administrators can access this endpoint.

    Parameters:
    - user_data: User creation data including username, email, and password
    """
    # Check if username or email already exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Create new user
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        is_active=True,
    )

    # Assign default viewer role
    viewer_role = db.query(Role).filter(Role.name == "viewer").first()
    if viewer_role:
        user.roles.append(viewer_role)

    db.add(user)
    db.commit()
    db.refresh(user)
    return UserResponse.from_orm(user)


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    is_admin: bool = Depends(verify_admin),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
) -> Any:
    """
    Delete a user.
    Only administrators can access this endpoint.

    Parameters:
    - user_id: ID of the user to delete
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent self-deletion
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}


@router.put("/{user_id}/password")
async def admin_change_user_password(
    user_id: int,
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),  # pylint: disable=unused-argument
    is_admin: bool = Depends(verify_admin),  # pylint: disable=unused-argument
    db: Session = Depends(get_db),
) -> Any:
    """
    Change a user's password (admin only).
    Only administrators can access this endpoint.

    Parameters:
    - user_id: ID of the user whose password to change
    - password_data: New password data
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
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
    user.hashed_password = get_password_hash(password_data.new_password)
    db.commit()

    return {"message": "Password updated successfully"}
