"""Authentication and user management schemas for Praxis."""

from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, constr


class Token(BaseModel):
    """Schema for authentication token response."""

    access_token: str
    token_type: str
    refresh_token: str


class TokenData(BaseModel):
    """Schema for token payload data."""

    username: Optional[str] = None


class UserBase(BaseModel):
    """Base schema for user data.

    PRA-179 Slice 5: ``email`` is intentionally a plain ``str`` on
    base/response models, not ``EmailStr``. ``email-validator`` (which
    ``EmailStr`` requires) rejects RFC 2606 reserved TLDs such as
    ``.invalid`` and ``.test``. An operator setting
    ``ADMIN_EMAIL=admin@somecorp.invalid`` (a perfectly defensible
    choice for an internal-only deployment) would otherwise see every
    endpoint that serializes ``UserResponse`` 500 with a Pydantic
    ``ValidationError`` at response-model validation time. Input-side
    schemas (``UserCreate`` / ``UserUpdate``) keep ``EmailStr`` so
    self-service signup/edit still validates; the stored value is
    trusted at serialization time.
    """

    email: str


class UserCreate(UserBase):
    """Schema for creating a new user."""

    username: str
    password: constr(min_length=8)  # Ensure password is at least 8 chars
    email: EmailStr


class UserUpdate(UserBase):
    """Schema for updating user information."""

    email: Optional[EmailStr] = None


class UserResponse(UserBase):
    """Schema for user data in API responses.

    See ``UserBase`` docstring for the rationale on ``email: str`` vs
    ``email: EmailStr`` (RFC 2606 reserved-TLD compatibility for
    already-stored values).
    """

    id: int
    username: str
    email: str
    is_active: bool
    roles: List[str] = Field(default_factory=list)

    class Config:  # pylint: disable=too-few-public-methods
        """Pydantic configuration for ORM mode."""

        orm_mode = True

    @classmethod
    def from_orm(cls, obj):
        """Convert ORM model instance to Pydantic model.

        Args:
            obj: SQLAlchemy ORM model instance

        Returns:
            UserResponse: Pydantic model instance with role names extracted
        """
        # Create a new dict with base fields
        obj_dict = {
            "id": obj.id,
            "username": obj.username,
            "email": obj.email,
            "is_active": obj.is_active,
            # Extract role names from Role objects
            "roles": [role.name for role in obj.roles] if obj.roles else [],
        }
        return cls(**obj_dict)


class UserList(BaseModel):
    """Schema for paginated list of users."""

    total: int
    items: List[UserResponse]

    class Config:  # pylint: disable=too-few-public-methods
        """Pydantic configuration for ORM mode."""

        orm_mode = True


class PasswordChange(BaseModel):
    """Schema for password change request."""

    current_password: str
    new_password: constr(min_length=8)
    confirm_password: str

    def validate_passwords_match(self):
        """Validate that new password and confirm password match."""
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match")


class RoleAssignment(BaseModel):
    """Schema for assigning roles to a user."""

    roles: List[str]  # List of role names to assign
