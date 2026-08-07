"""
Security module for handling password hashing and verification.
"""

from passlib.context import CryptContext

# Create a CryptContext object for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)
