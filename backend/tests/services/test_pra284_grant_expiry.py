"""PRA-284: synchronous, fail-closed grant-expiry enforcement.

Proves ``AccessGrant.expires_at`` is materialized from the source binding and that
every authorization surface treats ``expires_at <= now`` as expired at the decision
boundary — a grant valid when materialized stops authorizing once time advances
past its expiry, with no recompute and no unrelated DB mutation.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.auth import get_password_hash
from app.db.access_models import AccessGrant, FleetRole
from app.db.models import Credential, Group, System, User
from app.services import access_authorization_service as authz
from app.services import access_binding_service as abs_svc

# --------------------------------------------------------------------- helpers


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra284-grp").first()
    if not g:
        g = Group(name="pra284-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra284-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.84.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _user(db, seed_roles, username, role_names):
    u = User(
        username=username,
        email=f"{username}@pra284.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    for rn in role_names:
        u.roles.append(seed_roles[rn])
    db.add(u)
    db.flush()
    return u


def _maintainer_fleet(db):
    return db.query(FleetRole).filter_by(name="maintainer").first()


def _bind(db, user, group, role, expires_at=None):
    return abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=user.id,
        scope_group_id=group.id,
        expires_at=expires_at,
    )


def _grant(db, user_id, system_id):
    return (
        db.query(AccessGrant)
        .filter(AccessGrant.user_id == user_id, AccessGrant.system_id == system_id)
        .first()
    )


# ---------------------------------------------------------- materialization


def test_recompute_materializes_expiry_from_binding(
    db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p284-mat")
    user = _user(db, seed_roles, "p284-mat-user", ["maintainer"])
    exp = datetime.utcnow() + timedelta(hours=1)
    _bind(db, user, group, _maintainer_fleet(db), expires_at=exp)

    grant = _grant(db, user.id, system.id)
    assert grant is not None
    assert grant.expires_at == exp


def test_already_expired_binding_materializes_no_grant(
    db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p284-exp")
    user = _user(db, seed_roles, "p284-exp-user", ["maintainer"])
    past = datetime.utcnow() - timedelta(minutes=1)
    _bind(db, user, group, _maintainer_fleet(db), expires_at=past)

    assert _grant(db, user.id, system.id) is None


def test_implicit_admin_grant_never_expires(db, seed_roles, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "p284-admin")
    user = _user(db, seed_roles, "p284-admin-user", ["admin"])
    abs_svc.recompute_grants(db)

    grant = _grant(db, user.id, system.id)
    assert grant is not None and grant.expires_at is None
    # Still authorized arbitrarily far in the future.
    result = authz.authorize_action(
        db, user, system, "session_open", now=datetime.utcnow() + timedelta(days=3650)
    )
    assert result.fleet_role.name == "admin"


def test_implicit_admin_wins_over_expiring_explicit_binding(
    db, seed_roles, seed_distro, group, cred
):
    """An app-admin's never-expiring implicit grant must not be shortened by an
    overlapping expiring admin binding on the same (system, login)."""
    system = _system(db, seed_distro, group, cred, "p284-merge")
    user = _user(db, seed_roles, "p284-merge-user", ["admin"])
    admin_fleet = db.query(FleetRole).filter_by(name="admin").first()
    _bind(
        db, user, group, admin_fleet, expires_at=datetime.utcnow() + timedelta(hours=1)
    )

    grant = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == user.id,
            AccessGrant.system_id == system.id,
            AccessGrant.fleet_role_id == admin_fleet.id,
        )
        .first()
    )
    assert grant is not None and grant.expires_at is None  # implicit NULL wins


# ------------------------------------------------- synchronous authz boundary


def test_grant_denied_after_time_advances_without_recompute(
    db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p284-adv")
    user = _user(db, seed_roles, "p284-adv-user", ["maintainer"])
    exp = datetime.utcnow() + timedelta(hours=1)
    _bind(db, user, group, _maintainer_fleet(db), expires_at=exp)

    # Valid right now (before expiry).
    authz.authorize_action(db, user, system, "command_exec")
    # Advance the clock past expiry — no recompute, no DB mutation.
    with pytest.raises(authz.PermissionDenied) as exc:
        authz.authorize_action(
            db, user, system, "command_exec", now=exp + timedelta(seconds=1)
        )
    assert exc.value.code == "forbidden"


def test_expiry_boundary_is_exact_at_now(db, seed_roles, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "p284-boundary")
    user = _user(db, seed_roles, "p284-boundary-user", ["maintainer"])
    exp = datetime.utcnow() + timedelta(hours=1)
    _bind(db, user, group, _maintainer_fleet(db), expires_at=exp)
    grant = _grant(db, user.id, system.id)

    # expires_at <= now is expired; strictly-before is active.
    assert authz.is_grant_active(grant, now=exp - timedelta(microseconds=1)) is True
    assert authz.is_grant_active(grant, now=exp) is False
    with pytest.raises(authz.PermissionDenied):
        authz.authorize_action(db, user, system, "session_open", now=exp)


def test_all_gated_actions_denied_when_expired(
    db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p284-actions")
    user = _user(db, seed_roles, "p284-actions-user", ["maintainer"])
    exp = datetime.utcnow() + timedelta(hours=1)
    _bind(db, user, group, _maintainer_fleet(db), expires_at=exp)
    after = exp + timedelta(seconds=1)
    for action in ("session_open", "command_exec", "file_transfer"):
        with pytest.raises(authz.PermissionDenied):
            authz.authorize_action(db, user, system, action, now=after)


def test_scope_helpers_omit_expired_grants(db, seed_roles, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "p284-scope")
    user = _user(db, seed_roles, "p284-scope-user", ["maintainer"])
    exp = datetime.utcnow() + timedelta(hours=1)
    _bind(db, user, group, _maintainer_fleet(db), expires_at=exp)
    after = exp + timedelta(seconds=1)

    assert authz.scoped_system_ids(db, user) == {system.id}  # active now
    assert authz.scoped_system_ids(db, user, now=after) == set()  # expired
    assert authz.user_can_access_system(db, user, system.id, now=after) is False


def test_desired_login_roles_omit_expired_grants(
    db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p284-desired")
    user = _user(db, seed_roles, "p284-desired-user", ["maintainer"])
    exp = datetime.utcnow() + timedelta(hours=1)
    _bind(db, user, group, _maintainer_fleet(db), expires_at=exp)
    after = exp + timedelta(seconds=1)

    assert user.username in authz.resolve_desired_login_roles(db, system.id)
    assert authz.resolve_desired_login_roles(db, system.id, now=after) == {}


# ---------------------------------------------------------------- scoped route


def test_scoped_api_route_hides_expired_system(
    client, db, seed_roles, seed_distro, group, cred
):
    system = _system(db, seed_distro, group, cred, "p284-route")
    user = _user(db, seed_roles, "p284-route-user", ["maintainer"])
    # Insert an ALREADY-expired grant directly (past expiry) to exercise the route
    # at real wall-clock time — the route filters it out via the shared helper.
    db.add(
        AccessGrant(
            user_id=user.id,
            system_id=system.id,
            fleet_role_id=_maintainer_fleet(db).id,
            login=user.username,
            is_implicit_admin=False,
            expires_at=datetime.utcnow() - timedelta(minutes=5),
        )
    )
    db.commit()

    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})
    # Expired grant => system not in scope => non-disclosing 404.
    assert client.get(f"/packages/{system.id}").status_code == 404
