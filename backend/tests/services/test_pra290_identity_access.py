"""PRA-290: identity changes route through one explicit access path.

Proves app-role changes, user deactivation, and OIDC role sync all go through
``identity_access_service`` so they atomically recompute grants (PRA-289) and
invoke the session-impact hook — no stale authorization left behind.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.auth import get_password_hash
from app.db.access_models import AccessGrant, FleetRole
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, RefreshToken, System, User
from app.services import access_authorization_service as authz
from app.services import access_binding_service as abs_svc
from app.services import identity_access_service as ias
from app.services import session_lock_service

# --------------------------------------------------------------------- helpers


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra290-grp").first()
    if not g:
        g = Group(name="pra290-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra290-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.90.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _user(db, seed_roles, username, role_names, *, active=True):
    u = User(
        username=username,
        email=f"{username}@pra290.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=active,
    )
    for rn in role_names:
        u.roles.append(seed_roles[rn])
    db.add(u)
    db.flush()
    return u


def _grants_for(db, user_id):
    return db.query(AccessGrant).filter(AccessGrant.user_id == user_id).all()


# ------------------------------------------------------------------ role changes


def test_add_admin_role_materializes_grants_via_recompute(
    db, seed_roles, seed_distro, group, cred
):
    _system(db, seed_distro, group, cred, "p290-add")
    user = _user(db, seed_roles, "p290-add-user", ["viewer"])
    abs_svc.recompute_grants(db)
    assert not _grants_for(db, user.id), "no grants before the admin role"

    ias.apply_role_assignment(db, user, [seed_roles["admin"]])

    # Admin => implicit all-system grants materialized through the explicit path.
    assert _grants_for(db, user.id), "admin role must materialize grants"
    assert authz.scoped_system_ids(db, user) is None  # tenant-wide


def test_remove_admin_role_drops_implicit_grants_and_denies(
    db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p290-remove")
    user = _user(db, seed_roles, "p290-remove-user", ["admin"])
    abs_svc.recompute_grants(db)
    assert _grants_for(db, user.id), "admin should have implicit grants"

    ias.apply_role_assignment(db, user, [seed_roles["viewer"]])

    assert not _grants_for(db, user.id), "removing admin drops implicit grants"
    with pytest.raises(authz.PermissionDenied) as exc:
        authz.authorize_action(db, user, system, "session_open")
    assert exc.value.code == "forbidden"


def test_role_recompute_failure_surfaces_and_preserves_grants(
    db, seed_roles, seed_distro, group, cred, monkeypatch
):
    _system(db, seed_distro, group, cred, "p290-fail")
    user = _user(db, seed_roles, "p290-fail-user", ["admin"])
    abs_svc.recompute_grants(db)
    before = {g.id for g in _grants_for(db, user.id)}
    assert before

    def _boom(_db, *args, **kwargs):
        raise RuntimeError("recompute failed")

    monkeypatch.setattr(abs_svc, "recompute_grants", _boom)
    with pytest.raises(RuntimeError):
        ias.apply_role_assignment(db, user, [seed_roles["viewer"]])

    # The failure surfaced; the previously valid grants are untouched (not a
    # silent stale-authz commit).
    monkeypatch.undo()
    assert {g.id for g in _grants_for(db, user.id)} == before


# ------------------------------------------------------------- user deactivation


def test_deactivation_drops_grants_tokens_and_closes_sessions(
    db, seed_roles, admin_user, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p290-deact")
    user = _user(db, seed_roles, "p290-deact-user", ["admin"])
    abs_svc.recompute_grants(db)
    assert _grants_for(db, user.id)

    # A live refresh token and an active session for the user.
    token = RefreshToken(
        token="p290-rt",
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(days=7),
        is_valid=True,
    )
    db.add(token)
    fleet_admin = db.query(FleetRole).filter_by(name="admin").first()
    sess = SessionRow(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=fleet_admin.id,
        login=user.username,
        status="active",
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(sess)
    db.flush()

    ias.deactivate_user(db, user, actor=admin_user)

    db.refresh(user)
    assert user.is_active is False
    # Grants gone (inactive users don't materialize grants).
    assert not _grants_for(db, user.id)
    # Refresh tokens invalidated (bulk UPDATE — re-read from the DB, not the
    # stale identity-mapped object).
    db.refresh(token)
    assert token.is_valid is False
    # Session-impact hook fired: a deactivation lock exists + live session closed.
    lock = session_lock_service.is_user_locked(db, user)
    assert lock is not None and lock.reason == ias.DEACTIVATION_LOCK_REASON
    db.refresh(sess)
    assert sess.status == "closed"


def test_reactivation_restores_grants_and_releases_autolock(
    db, seed_roles, admin_user, seed_distro, group, cred
):
    _system(db, seed_distro, group, cred, "p290-react")
    user = _user(db, seed_roles, "p290-react-user", ["admin"])
    ias.deactivate_user(db, user, actor=admin_user)
    assert not _grants_for(db, user.id)
    assert session_lock_service.is_user_locked(db, user) is not None

    ias.activate_user(db, user, actor=admin_user)

    db.refresh(user)
    assert user.is_active is True
    assert _grants_for(db, user.id), "reactivation restores grants"
    # The auto-lock created at deactivation is released.
    assert session_lock_service.is_user_locked(db, user) is None


def test_deactivated_user_cannot_login_current_user_or_refresh(
    db, seed_roles, admin_user, client
):
    user = _user(db, seed_roles, "p290-auth-user", ["viewer"])
    db.commit()
    # Establish a session first.
    login = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert login.status_code == 200, login.text
    access = login.json()["access_token"]
    refresh = login.json()["refresh_token"]

    ias.deactivate_user(db, user, actor=admin_user)
    db.commit()

    # Login denied.
    relogin = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert relogin.status_code == 401
    # Current-user with the old access token denied.
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert me.status_code == 401
    # Refresh with the old (now-invalidated) refresh token denied — no successor.
    ref = client.post(f"/auth/refresh?token_refresh={refresh}")
    assert ref.status_code == 401


# ------------------------------------------------------------------- OIDC sync


def test_oidc_role_sync_uses_same_path_and_updates_grants(
    db, seed_roles, seed_distro, group, cred
):
    from app.services.oidc_service import OIDCService

    _system(db, seed_distro, group, cred, "p290-oidc")
    user = User(
        username="p290-oidc-user",
        email="p290-oidc@example.com",
        hashed_password=get_password_hash("x"),
        is_active=True,
        oidc_sub="sub-p290",
        oidc_issuer="https://idp.example.com",
    )
    user.roles.append(seed_roles["viewer"])
    db.add(user)
    db.flush()
    abs_svc.recompute_grants(db)
    assert not _grants_for(db, user.id)

    svc = OIDCService(db)
    # Federated sync maps this subject to admin -> same path -> grants recompute.
    svc._apply_oidc_roles(user, ["admin"])
    assert _grants_for(db, user.id), "OIDC role sync must recompute grants"

    # Syncing back to a non-admin role drops the implicit grants.
    svc._apply_oidc_roles(user, ["viewer"])
    assert not _grants_for(db, user.id)
