"""PRA-303: read-only effective-access summary.

The summary is a projection of the CURRENT enforced state for one (user, system):
what the identity can do right now and why, built from the SAME production
authorization/resolution services live auth uses. These tests prove the endpoint
mirrors `authorize_action`, is scoped/audited like the other fleet views, and never
regresses PRA-284 expiry, PRA-287 conflict, or PRA-288 cert-principal semantics.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.db.access_models import (
    AccessGrant,
    AuditEvent,
    FleetRole,
    HostUserState,
    RevocationWork,
)
from app.db.models import Credential, Group, System, User
from app.services.access_authorization_service import cert_principal_for_user

# --------------------------------------------------------------------- helpers


@pytest.fixture
def grp(db):
    g = db.query(Group).filter_by(name="pra303-grp").first()
    if not g:
        g = Group(name="pra303-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra303-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, grp, cred, hostname, ip="10.33.0.1"):
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _user(db, username):
    from app.core.auth import get_password_hash

    u = User(
        username=username,
        email=f"{username}@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    db.add(u)
    db.flush()
    return u


def _role(
    db,
    name,
    *,
    actions=("session_open", "command_exec", "file_transfer"),
    login_mode="per_user",
    role_account_name=None,
    os_groups=(),
    approval=False,
    totp=False,
):
    r = FleetRole(
        name=name,
        login_mode=login_mode,
        role_account_name=role_account_name,
        allowed_actions_json=json.dumps(list(actions)),
        os_groups_json=json.dumps(list(os_groups)),
        session_requires_approval=approval,
        totp_required=totp,
    )
    db.add(r)
    db.flush()
    return r


def _grant(db, user, system, role, login, *, expires_at=None):
    g = AccessGrant(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=role.id,
        login=login,
        expires_at=expires_at,
    )
    db.add(g)
    db.flush()
    return g


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


def _get(client, user_id, system_id, login=None):
    qs = f"?user_id={user_id}&system_id={system_id}"
    if login is not None:
        qs += f"&login={login}"
    return client.get(f"/fleet/effective-access{qs}")


def _cap(summary, action, login=None):
    for c in summary["capabilities"]:
        if c["action"] == action and (login is None or c["requested_login"] == login):
            return c
    return None


# --------------------------------------------------------------- allow path


def test_in_scope_active_grant_matches_authorize_allow(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-allow")
    target = _user(db, "p303-alice")
    role = _role(db, "p303-role", approval=True, totp=True)
    _grant(db, target, s, role, target.username)
    db.commit()

    _login(client, admin_user)
    res = _get(client, target.id, s.id)
    assert res.status_code == 200, res.text
    summary = res.json()["summary"]

    assert summary["identity"]["user_id"] == target.id
    assert summary["identity"]["cert_principal"] == cert_principal_for_user(target)
    assert summary["scoped_api_access"]["allowed"] is True

    # session_open resolves to the per-user login + immutable cert principal, and
    # carries the live requirements (approval/TOTP) — matching authorize_action.
    so = _cap(summary, "session_open")
    assert so["allowed"] is True
    assert so["login"] == target.username
    assert so["cert_principal"] == cert_principal_for_user(target)
    assert so["login_mode"] == "per_user"
    assert so["requires_approval"] is True
    assert so["requires_totp"] is True
    assert _cap(summary, "command_exec")["allowed"] is True
    assert _cap(summary, "file_transfer")["allowed"] is True


def test_role_account_reports_shared_login_and_per_user_principal(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-ra")
    alice = _user(db, "p303-ra-alice")
    role = _role(db, "p303-ra-role", login_mode="role_account", role_account_name="svc")
    _grant(db, alice, s, role, "svc")
    db.commit()

    _login(client, admin_user)
    summary = _get(client, alice.id, s.id).json()["summary"]
    so = _cap(summary, "session_open")
    assert so["login"] == "svc"  # shared Linux login
    assert so["login_mode"] == "role_account"
    # PRA-288: principal is the immutable per-user value, NOT the shared login.
    assert so["cert_principal"] == cert_principal_for_user(alice)
    assert so["cert_principal"] != "svc"


# --------------------------------------------------------------- deny paths


def test_no_grant_denies_all_capabilities(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-nogrant")
    target = _user(db, "p303-nobody")
    db.commit()

    _login(client, admin_user)
    summary = _get(client, target.id, s.id).json()["summary"]
    assert summary["scoped_api_access"]["allowed"] is False
    assert summary["scoped_api_access"]["code"] == "out_of_scope"
    # command_exec/file_transfer denied with a forbidden code, no active grant.
    assert _cap(summary, "command_exec")["allowed"] is False
    assert _cap(summary, "command_exec")["code"] == "forbidden"
    assert _cap(summary, "file_transfer")["allowed"] is False
    assert summary["logins"] == []


def test_expired_grant_does_not_authorize_and_is_reported_expired(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-expired")
    target = _user(db, "p303-exp")
    role = _role(db, "p303-exp-role")
    _grant(
        db,
        target,
        s,
        role,
        target.username,
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )
    db.commit()

    _login(client, admin_user)
    summary = _get(client, target.id, s.id, login=target.username).json()["summary"]
    # Expired grant is not effective access...
    assert _cap(summary, "command_exec")["allowed"] is False
    detail = summary["logins"][0]
    assert detail["active_grants"] == []
    # ...but is surfaced as explanatory expired context.
    assert len(detail["expired_grants"]) == 1
    assert detail["expired_grants"][0]["expiry_state"] == "expired"
    assert detail["expiry_state"] == "expired"


def test_shared_login_conflict_fails_closed_with_login_conflict(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-conflict")
    alice = _user(db, "p303-c-alice")
    bob = _user(db, "p303-c-bob")
    # Same shared login, incompatible os_groups -> PRA-287 account-shape conflict.
    ra = _role(
        db,
        "p303-c-a",
        login_mode="role_account",
        role_account_name="svc",
        os_groups=["docker"],
    )
    rb = _role(
        db,
        "p303-c-b",
        login_mode="role_account",
        role_account_name="svc",
        os_groups=["wheel"],
    )
    _grant(db, alice, s, ra, "svc")
    _grant(db, bob, s, rb, "svc")
    db.commit()

    _login(client, admin_user)
    summary = _get(client, alice.id, s.id).json()["summary"]
    so = _cap(summary, "session_open")
    assert so["allowed"] is False
    assert so["code"] == "login_conflict"
    # The conflict detail is surfaced prominently.
    assert summary["conflicts"]
    assert summary["conflicts"][0]["login"] == "svc"
    assert "os_groups" in summary["conflicts"][0]["differing_fields"]
    assert summary["logins"][0]["conflict"] is not None


# --------------------------------------------------- host convergence + revocation


def test_host_convergence_and_revocation_surface(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-host")
    target = _user(db, "p303-host-user")
    role = _role(db, "p303-host-role")
    _grant(db, target, s, role, target.username)
    # Not-yet-converged host state + a pending revocation-reconcile work item.
    db.add(
        HostUserState(
            system_id=s.id,
            login=target.username,
            mode="per_user",
            state="error",
            last_error="ssh unreachable",
        )
    )
    db.add(
        RevocationWork(
            reason="binding_update",
            user_id=target.id,
            system_id=s.id,
            login=target.username,
            status="pending",
        )
    )
    db.commit()

    _login(client, admin_user)
    detail = _get(client, target.id, s.id).json()["summary"]["logins"][0]
    assert detail["host_state"]["state"] == "error"
    assert detail["host_state"]["converged"] is False
    assert detail["revocation"]["pending"] == 1


def test_missing_host_state_reports_not_provisioned(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-noprov")
    target = _user(db, "p303-noprov-user")
    role = _role(db, "p303-noprov-role")
    _grant(db, target, s, role, target.username)
    db.commit()

    _login(client, admin_user)
    detail = _get(client, target.id, s.id).json()["summary"]["logins"][0]
    assert detail["host_state"]["state"] == "not_provisioned"
    assert detail["host_state"]["converged"] is False


# --------------------------------------------------------------- scoping + audit


def test_out_of_scope_system_is_non_disclosing_404(
    db, client, maintainer_user, seed_roles, seed_distro, grp, cred
):
    # The maintainer holds no grant on this system -> out of scope.
    s = _system(db, seed_distro, grp, cred, "p303-hidden")
    target = _user(db, "p303-hidden-target")
    role = _role(db, "p303-hidden-role")
    _grant(db, target, s, role, target.username)
    db.commit()

    _login(client, maintainer_user)
    res = _get(client, target.id, s.id)
    assert res.status_code == 404
    assert res.json()["detail"] == "System not found"


def test_missing_user_is_404(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-nouser")
    db.commit()
    _login(client, admin_user)
    res = _get(client, 999999, s.id)
    assert res.status_code == 404
    assert res.json()["detail"] == "User not found"


def test_lookup_is_audited_without_secrets(
    db, client, admin_user, seed_roles, seed_distro, grp, cred
):
    s = _system(db, seed_distro, grp, cred, "p303-audit")
    target = _user(db, "p303-audit-user")
    role = _role(db, "p303-audit-role")
    _grant(db, target, s, role, target.username)
    db.commit()

    _login(client, admin_user)
    assert _get(client, target.id, s.id).status_code == 200

    ev = (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "fleet.effective_access.viewed")
        .order_by(AuditEvent.id.desc())
        .first()
    )
    assert ev is not None
    assert ev.actor_user_id == admin_user.id
    assert ev.target_system_id == s.id
    assert ev.target_id == str(target.id)
    ctx = json.loads(ev.context_json)
    assert ctx["scoped_api_access"] is True
    # No cert material / secrets / sudo text in the audit context.
    blob = ev.context_json.lower()
    assert "cert" not in blob and "praxis-user" not in blob
    assert "sudo" not in blob and "password" not in blob
