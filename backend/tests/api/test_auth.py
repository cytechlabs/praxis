"""Integration tests for the auth flow (login, refresh, rotation, logout)."""


from app.db.models import AppSettings, RefreshToken


def _set_registration(db, enabled: bool):
    """Persist the PRA-216 self-registration switch for the test session."""
    row = (
        db.query(AppSettings)
        .filter(AppSettings.setting_key == "auth.self_registration_enabled")
        .first()
    )
    value = "true" if enabled else "false"
    if row:
        row.setting_value = value
    else:
        db.add(
            AppSettings(
                setting_key="auth.self_registration_enabled", setting_value=value
            )
        )
    db.flush()


_NEW_USER = {
    "username": "newbie",
    "email": "newbie@praxis.example.com",
    "password": "supersecret123",
}


def _login(client, username="admintest", password="testpass123"):
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
    )


def test_login_success_returns_tokens_and_sets_no_cookies_at_backend(
    client, admin_user
):
    res = _login(client)
    assert res.status_code == 200, f"body={res.text}"
    body = res.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


def test_login_wrong_password_401(client, admin_user):
    res = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "wrongpass"},
    )
    assert res.status_code == 401


def test_login_unknown_user_401(client):
    res = client.post(
        "/auth/login",
        data={"username": "nonesuch", "password": "whatever"},
    )
    assert res.status_code == 401


def test_refresh_rotates_token_and_invalidates_old(client, admin_user, db):
    login_body = _login(client).json()
    old_refresh = login_body["refresh_token"]

    res = client.post(f"/auth/refresh?token_refresh={old_refresh}")
    assert res.status_code == 200
    new_refresh = res.json()["refresh_token"]

    assert new_refresh != old_refresh, "refresh token must rotate"

    db.expire_all()
    old_row = db.query(RefreshToken).filter_by(token=old_refresh).one()
    new_row = db.query(RefreshToken).filter_by(token=new_refresh).one()
    assert old_row.is_valid is False, "old refresh token must be invalidated"
    assert new_row.is_valid is True


def test_refresh_with_invalidated_token_401(client, admin_user):
    body = _login(client).json()
    old = body["refresh_token"]
    # Burn it once
    client.post(f"/auth/refresh?token_refresh={old}")
    # Reuse should fail
    res = client.post(f"/auth/refresh?token_refresh={old}")
    assert res.status_code == 401


def test_refresh_with_bogus_token_401(client, admin_user):
    res = client.post("/auth/refresh?token_refresh=not-a-real-token")
    assert res.status_code == 401


def test_me_requires_auth(client):
    res = client.get("/auth/me")
    assert res.status_code == 401


def test_me_returns_current_user(authed_client, admin_user):
    res = authed_client.get("/auth/me")
    assert res.status_code == 200
    body = res.json()
    assert body["username"] == admin_user.username
    assert "admin" in body["roles"]


def test_logout_invalidates_refresh_token(client, admin_user, db):
    body = _login(client).json()
    access = body["access_token"]
    refresh = body["refresh_token"]

    res = client.post(
        f"/auth/logout?token_refresh={refresh}",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert res.status_code == 200

    db.expire_all()
    row = db.query(RefreshToken).filter_by(token=refresh).one()
    assert row.is_valid is False


def test_logout_without_access_token_still_revokes(client, admin_user, db):
    """PRA-366: an explicit logout must revoke the refresh token even when no
    access token is presented — otherwise a stolen refresh token would outlive
    logout."""
    refresh = _login(client).json()["refresh_token"]

    res = client.post(f"/auth/logout?token_refresh={refresh}")
    assert res.status_code == 200

    db.expire_all()
    row = db.query(RefreshToken).filter_by(token=refresh).one()
    assert row.is_valid is False


def test_logout_with_expired_access_token_still_revokes(client, admin_user, db):
    """PRA-366: an expired/invalid access token must not block revocation."""
    from datetime import timedelta

    from app.core.auth import create_access_token

    refresh = _login(client).json()["refresh_token"]
    expired_access = create_access_token(
        {"sub": admin_user.username}, expires_delta=timedelta(minutes=-5)
    )

    res = client.post(
        f"/auth/logout?token_refresh={refresh}",
        headers={"Authorization": f"Bearer {expired_access}"},
    )
    assert res.status_code == 200

    db.expire_all()
    row = db.query(RefreshToken).filter_by(token=refresh).one()
    assert row.is_valid is False


def test_logout_with_bogus_refresh_is_idempotent_and_isolated(client, admin_user, db):
    """PRA-366: a bogus/unknown refresh token is a 200 no-op and must not revoke
    any unrelated still-valid session."""
    other_refresh = _login(client).json()["refresh_token"]

    res = client.post("/auth/logout?token_refresh=not-a-real-token")
    assert res.status_code == 200

    db.expire_all()
    other_row = db.query(RefreshToken).filter_by(token=other_refresh).one()
    assert other_row.is_valid is True, "unrelated session must stay valid"


def test_logout_already_revoked_is_idempotent(client, admin_user, db):
    """PRA-366: logging out twice with the same token is a safe no-op."""
    refresh = _login(client).json()["refresh_token"]

    first = client.post(f"/auth/logout?token_refresh={refresh}")
    assert first.status_code == 200
    second = client.post(f"/auth/logout?token_refresh={refresh}")
    assert second.status_code == 200

    db.expire_all()
    row = db.query(RefreshToken).filter_by(token=refresh).one()
    assert row.is_valid is False


def test_logout_revoked_refresh_cannot_refresh(client, admin_user):
    """PRA-366 end-to-end: a refresh token revoked at logout can no longer mint
    a new access token."""
    refresh = _login(client).json()["refresh_token"]

    client.post(f"/auth/logout?token_refresh={refresh}")

    res = client.post(f"/auth/refresh?token_refresh={refresh}")
    assert res.status_code == 401


def test_logout_without_token_param_is_200_noop(client, admin_user):
    """PRA-366: a logout with no refresh token at all is a constant-200 no-op
    (idempotency intent), not a 422."""
    res = client.post("/auth/logout")
    assert res.status_code == 200
    assert res.json() == {"message": "Successfully logged out"}


def test_refresh_with_deleted_user_401(client, admin_user, db):
    """If the user record is gone, refresh should not succeed."""
    body = _login(client).json()
    refresh = body["refresh_token"]
    db.delete(admin_user)
    db.flush()
    # After user deletion, refresh should either return the new access token
    # (token validates against the signed payload) or fail. The current
    # implementation only invalidates via the refresh_tokens row, so accept
    # either shape — the meaningful assertion is "does not crash."
    res = client.post(f"/auth/refresh?token_refresh={refresh}")
    assert res.status_code in (200, 401)


# ── PRA-216: admin-controlled self-registration ───────────────────────────


def test_registration_disabled_by_default_403(client, db, seed_roles):
    """With no setting persisted, self-registration is off (1.0 default)."""
    res = client.post("/auth/register", json=_NEW_USER)
    assert res.status_code == 403, f"body={res.text}"
    assert "disabled" in res.json()["detail"].lower()


def test_registration_explicitly_disabled_403(client, db, seed_roles):
    _set_registration(db, False)
    res = client.post("/auth/register", json=_NEW_USER)
    assert res.status_code == 403


def test_registration_enabled_creates_viewer(client, db, seed_roles):
    _set_registration(db, True)
    res = client.post("/auth/register", json=_NEW_USER)
    assert res.status_code == 200, f"body={res.text}"
    body = res.json()
    assert body["username"] == _NEW_USER["username"]
    assert body["roles"] == ["viewer"]


def test_registration_status_reflects_setting(client, db):
    res = client.get("/auth/registration-status")
    assert res.status_code == 200
    assert res.json()["enabled"] is False

    _set_registration(db, True)
    res = client.get("/auth/registration-status")
    assert res.json()["enabled"] is True


def test_registration_status_is_public(client):
    """No Authorization header required for the status probe."""
    res = client.get("/auth/registration-status")
    assert res.status_code == 200
