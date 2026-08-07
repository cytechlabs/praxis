"""PRA-179 Slice 5: regression test for the EmailStr / RFC 2606 bug
surfaced during Slice 2.

Before the fix, ``UserResponse.email`` was ``EmailStr`` (which depends
on ``email-validator``). RFC 2606 reserved TLDs such as ``.invalid``
and ``.test`` are rejected by ``email-validator``, so an admin user
created with ``ADMIN_EMAIL=admin@somecorp.invalid`` (a defensible
choice for internal-only deployments) made every endpoint that
returned ``UserResponse`` 500 with a Pydantic ``ValidationError`` at
response-model serialization time — including ``/auth/me`` and
``GET /users``.

The fix is in ``backend/app/api/schemas/auth.py``: input schemas
(``UserCreate``, ``UserUpdate``) still use ``EmailStr`` so signup
validation stays strict; response schemas (``UserBase``,
``UserResponse``) use plain ``str`` so already-stored values
serialize cleanly.

This test creates an admin-like user whose email is in a reserved
TLD, then hits ``/auth/me`` and asserts a 200 + the email value
round-trips.
"""

from __future__ import annotations

import pytest

from app.core.auth import get_password_hash
from app.db.models import Role, User

# Reserved TLD per RFC 2606 §2. Pre-fix, ``EmailStr`` validation
# raised ``value is not a valid email address: The part after the
# @-sign is a special-use or reserved name``.
RESERVED_TLD_EMAIL = "admin-reserved@example.invalid"


@pytest.fixture
def reserved_tld_admin(db) -> User:
    """An admin user whose email lives in an RFC 2606 reserved TLD."""
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if admin_role is None:
        admin_role = Role(name="admin", description="Administrator")
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)

    user = User(
        username="pra179_reserved_tld_admin",
        email=RESERVED_TLD_EMAIL,
        hashed_password=get_password_hash("strong-password-1234"),
        is_active=True,
        roles=[admin_role],
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_auth_me_serializes_user_with_reserved_tld_email(
    client, reserved_tld_admin
) -> None:
    """The fix: ``/auth/me`` must return 200 and the email must
    round-trip unchanged even though it would have failed
    ``EmailStr`` validation pre-fix."""
    # Log in to get a token.
    login = client.post(
        "/auth/login",
        data={
            "username": reserved_tld_admin.username,
            "password": "strong-password-1234",
        },
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    body = me.json()
    assert body["username"] == reserved_tld_admin.username
    assert body["email"] == RESERVED_TLD_EMAIL
    assert "admin" in body["roles"]


def test_users_list_serializes_reserved_tld_email(
    authed_client, reserved_tld_admin
) -> None:
    """Defense in depth: the admin-only ``GET /users`` listing is the
    other endpoint that historically 500'd on the reserved-TLD email,
    because it iterates ``UserResponse`` over every row."""
    resp = authed_client.get("/users")
    assert resp.status_code == 200, resp.text
    emails = [row["email"] for row in resp.json()]
    assert RESERVED_TLD_EMAIL in emails
