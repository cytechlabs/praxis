"""Tests for PRA-145: Active Sessions UI backend.

Covers list enrichment, maintainer visibility, and the operator
force-close endpoint with its dedicated audit event.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.access_models import AccessGrant, AuditEvent, FleetRole
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, System


def _grant(db, user, system, role):
    """PRA-281: give a scoped operator a fleet grant on a system so they are in
    scope for it (admins are tenant-wide and need no explicit grant)."""
    g = AccessGrant(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=role.id,
        login=user.username,
    )
    db.add(g)
    db.commit()
    return g


@pytest.fixture
def seed_default_group(db):
    g = db.query(Group).filter_by(name="Default").first()
    if not g:
        g = Group(name="Default")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def seed_cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(
            name="pra145-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra145",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, grp, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.7.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _mk_role(db, name="ops"):
    role = FleetRole(
        name=name,
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    return role


def _mk_session(db, user, system, role, status="active"):
    row = SessionRow(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=role.id,
        login=user.username,
        status=status,
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
        client_ip="10.0.0.99",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


# ------------------------------------------------- list enrichment


def test_list_returns_hostname_and_role_name(
    client, admin_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "host-a")
    role = _mk_role(db, "ops-role")
    _mk_session(db, admin_user, sys, role)

    _login(client, admin_user)
    res = client.get("/sessions?active_only=true&mine_only=false")
    assert res.status_code == 200
    sessions = res.json()["sessions"]
    mine = [s for s in sessions if s["hostname"] == "host-a"]
    assert len(mine) == 1
    assert mine[0]["fleet_role_name"] == "ops-role"
    assert mine[0]["client_ip"] == "10.0.0.99"


def test_maintainer_can_list_all_sessions(
    client, admin_user, maintainer_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "host-b")
    role = _mk_role(db, "ops-role-b")
    _mk_session(db, admin_user, sys, role)  # belongs to admin
    _mk_session(db, maintainer_user, sys, role)  # belongs to maintainer
    _grant(db, maintainer_user, sys, role)  # PRA-281: maintainer scoped to host-b

    _login(client, maintainer_user)
    res = client.get("/sessions?active_only=true&mine_only=false")
    assert res.status_code == 200
    user_ids = {s["user_id"] for s in res.json()["sessions"]}
    assert {admin_user.id, maintainer_user.id} <= user_ids


def test_auditor_only_sees_own_sessions(
    client, admin_user, auditor_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "host-c")
    role = _mk_role(db, "ops-role-c")
    _mk_session(db, admin_user, sys, role)
    _mk_session(db, auditor_user, sys, role)

    _login(client, auditor_user)
    # Even with mine_only=false, auditors get filtered to their own.
    res = client.get("/sessions?active_only=true&mine_only=false")
    assert res.status_code == 200
    user_ids = {s["user_id"] for s in res.json()["sessions"]}
    assert auditor_user.id in user_ids
    assert admin_user.id not in user_ids


# ------------------------------------------------- force-close


def test_force_close_forbidden_for_non_operator(
    client, admin_user, auditor_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "host-d")
    role = _mk_role(db, "ops-role-d")
    row = _mk_session(db, admin_user, sys, role)

    _login(client, auditor_user)
    res = client.post(f"/sessions/{row.id}/force-close")
    assert res.status_code == 403


def test_force_close_404_for_unknown(client, admin_user):
    _login(client, admin_user)
    res = client.post("/sessions/99999999/force-close")
    assert res.status_code == 404


def test_force_close_409_when_already_closed(
    client, admin_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "host-e")
    role = _mk_role(db, "ops-role-e")
    row = _mk_session(db, admin_user, sys, role, status="closed")

    _login(client, admin_user)
    res = client.post(f"/sessions/{row.id}/force-close")
    assert res.status_code == 409


def test_force_close_emits_audit_and_updates_row(
    client, admin_user, maintainer_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "host-f")
    role = _mk_role(db, "ops-role-f")
    row = _mk_session(db, admin_user, sys, role)
    _grant(db, maintainer_user, sys, role)  # PRA-281: maintainer scoped to host-f

    _login(client, maintainer_user)
    res = client.post(f"/sessions/{row.id}/force-close")
    assert res.status_code == 200, res.text

    db.expire_all()
    refreshed = db.query(SessionRow).filter_by(id=row.id).first()
    assert refreshed.status == "closed"
    assert refreshed.close_reason == "admin_force"
    assert refreshed.ended_at is not None

    # safe_emit opens its own DB session so events bypass the SAVEPOINT
    # rollback used by the test fixture — scope to this session id only.
    audits = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "session.force_close",
            AuditEvent.target_id == str(row.id),
        )
        .all()
    )
    assert len(audits) == 1
    ev = audits[0]
    assert ev.actor_user_id == maintainer_user.id
    # Subject of the close (the original session owner) lives in context.
    assert ev.context_json and str(admin_user.id) in ev.context_json
