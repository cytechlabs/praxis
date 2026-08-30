"""
Security module for handling password hashing and verification.
"""

from passlib.context import CryptContext
from passlib.exc import PasswordSizeError

# Create a CryptContext object for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password.

    Passlib rejects a candidate longer than its maximum secret size by raising
    instead of returning a result, and it raises before any comparison work. A
    candidate that large cannot match a stored hash, so it is a failed
    comparison rather than a server fault, and the callers that gate login and
    password change treat it exactly like any other wrong password. Only that
    one exception is absorbed; anything else still propagates. The candidate is
    not truncated, retried, recorded, or carried into the return value.
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except PasswordSizeError:
        return False
