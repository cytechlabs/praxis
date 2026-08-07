"""PRA-180 P2 Remediation (PRA-220): auth/session authorization hardening.

Covers:
- AUTH-01: the JWT middleware fails closed (a non-public route requires a VALID
  access token, not merely a non-empty Authorization header) + an invariant
  that every non-public route declares an auth dependency.
- AUTH-02: /app-settings read endpoints require authentication.
- AUTH-04: password change revokes the user's existing refresh tokens.
- AUTH-06: production SECRET_KEY strength validation.
"""

import pytest
from fastapi.routing import APIRoute

from app.api.main import app, is_public_path
from app.core.auth import decode_access_token, get_current_user, validate_secret_key
from app.db.models import RefreshToken

BOGUS = {"Authorization": "Bearer not-a-real-jwt"}


# ── AUTH-02: /app-settings reads require auth ──────────────────────────────


def test_app_settings_list_requires_auth(client):
    assert client.get("/app-settings").status_code == 401
    assert client.get("/app-settings", headers=BOGUS).status_code == 401


def test_app_settings_get_one_requires_auth(client):
    assert client.get("/app-settings/timezone").status_code == 401
    assert client.get("/app-settings/timezone", headers=BOGUS).status_code == 401


def test_app_settings_list_ok_with_valid_token(authed_client):
    res = authed_client.get("/app-settings")
    assert res.status_code == 200, res.text


# ── AUTH-01: middleware fails closed (valid token required) ────────────────


def test_middleware_rejects_invalid_token_on_protected_route(client):
    """A non-empty but INVALID bearer must be rejected centrally — previously
    the middleware only checked header presence and let it through."""
    # /credentials requires auth; an invalid token must 401 at the middleware.
    assert client.get("/credentials", headers=BOGUS).status_code == 401
    # No header at all -> 401 too.
    assert client.get("/credentials").status_code == 401


def test_protected_route_ok_with_valid_token(authed_client):
    assert authed_client.get("/credentials").status_code == 200


def _all_dependency_calls(dependant):
    calls = []
    stack = [dependant]
    while stack:
        d = stack.pop()
        if getattr(d, "call", None) is not None:
            calls.append(d.call)
        stack.extend(getattr(d, "dependencies", []) or [])
    return calls


def test_every_non_public_route_requires_auth():
    """AUTH-01 invariant: every non-public HTTP route declares an auth
    dependency (get_current_user, directly or via require_role/verify_admin).
    The JWT middleware is the runtime floor; this catches a forgotten
    dependency at test time and proves no route is unintentionally open."""
    offenders = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue  # websocket/static handled separately
        methods = set(route.methods or [])
        if methods and methods <= {"OPTIONS", "HEAD"}:
            continue
        if is_public_path(route.path):
            continue
        if get_current_user not in _all_dependency_calls(route.dependant):
            offenders.append((sorted(methods), route.path))
    assert not offenders, f"non-public routes missing an auth dependency: {offenders}"


# ── AUTH-04: password change revokes refresh tokens ────────────────────────


def test_password_change_revokes_refresh_tokens(client, admin_user, db):
    # Log in to mint a refresh token.
    login = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "testpass123"},
    )
    assert login.status_code == 200, login.text
    body = login.json()
    access = body["access_token"]
    refresh = body["refresh_token"]

    # Change the password.
    res = client.post(
        "/auth/change-password",
        json={
            "current_password": "testpass123",
            "new_password": "brand-new-pass-123",
            "confirm_password": "brand-new-pass-123",
        },
        headers={"Authorization": f"Bearer {access}"},
    )
    assert res.status_code == 200, res.text
    assert res.json().get("sessions_revoked", 0) >= 1

    # The pre-change refresh token is now invalid in the DB...
    db.expire_all()
    row = db.query(RefreshToken).filter_by(token=refresh).one()
    assert row.is_valid is False

    # ...and can no longer be exchanged for a new access token.
    assert client.post(f"/auth/refresh?token_refresh={refresh}").status_code == 401


# ── AUTH-06: production SECRET_KEY strength ────────────────────────────────


def test_validate_secret_key_prod_rejects_short_key():
    with pytest.raises(RuntimeError, match="at least 32"):
        validate_secret_key("short-key", "production")


def test_validate_secret_key_prod_rejects_known_weak():
    with pytest.raises(RuntimeError, match="known-weak"):
        validate_secret_key("changeme", "production")


def test_validate_secret_key_prod_accepts_strong_key():
    validate_secret_key("x" * 48, "production")  # no raise


def test_validate_secret_key_dev_allows_short_key():
    validate_secret_key("short-dev-key", "development")  # warns, no raise


# ── decode_access_token sanity (shared helper) ─────────────────────────────


def test_decode_access_token_rejects_garbage():
    import jwt as pyjwt

    with pytest.raises(pyjwt.PyJWTError):
        decode_access_token("not-a-real-jwt")
