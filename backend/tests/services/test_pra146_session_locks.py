"""Tests for PRA-146: session locks (emergency cut-off).

Covers the service layer (lock create / release, subject XOR, kill of
live sessions), the authorize_action gate, and the REST surface.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.access_models import AuditEvent
from app.db.access_models import Session as SessionRow
from app.db.access_models import SessionLock
from app.db.models import Credential, Group, System
from app.services import session_lock_service
from app.services.access_authorization_service import PermissionDenied, authorize_action


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
            name="pra146-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra146",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, grp, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.8.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _mk_session(db, user, system, status="active"):
    row = SessionRow(
        user_id=user.id,
        system_id=system.id,
        login=user.username,
        status=status,
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
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


# -------------------------------------------------- service: subject XOR


def test_create_lock_requires_exactly_one_subject(db, admin_user, maintainer_user):
    with pytest.raises(session_lock_service.LockError, match="exactly one"):
        session_lock_service.create_lock(db, creator=admin_user, reason="x")
    with pytest.raises(session_lock_service.LockError, match="exactly one"):
        session_lock_service.create_lock(
            db,
            creator=admin_user,
            reason="x",
            subject_user_id=maintainer_user.id,
            subject_app_role_id=1,
        )


def test_create_lock_requires_reason(db, admin_user, maintainer_user):
    with pytest.raises(session_lock_service.LockError, match="reason"):
        session_lock_service.create_lock(
            db,
            creator=admin_user,
            reason="   ",
            subject_user_id=maintainer_user.id,
        )


# -------------------------------------------------- service: kill live sessions


def test_create_lock_kills_subject_live_sessions(
    db, admin_user, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "lock-host")
    target = _mk_session(db, maintainer_user, sys)
    other = _mk_session(db, admin_user, sys)

    session_lock_service.create_lock(
        db,
        creator=admin_user,
        reason="incident",
        subject_user_id=maintainer_user.id,
    )

    db.expire_all()
    assert db.query(SessionRow).filter_by(id=target.id).first().status == "closed"
    # Admin's session is unaffected
    assert db.query(SessionRow).filter_by(id=other.id).first().status == "active"


# -------------------------------------------------- authorize_action gate


def test_authorize_action_denied_when_user_locked(
    db, admin_user, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "lock-auth")
    session_lock_service.create_lock(
        db,
        creator=admin_user,
        reason="suspended",
        subject_user_id=maintainer_user.id,
    )
    for action in ("session_open", "command_exec", "file_transfer"):
        with pytest.raises(PermissionDenied) as exc:
            authorize_action(db, maintainer_user, sys, action)
        assert exc.value.code == "locked"


def test_authorize_action_unblocked_after_release(
    db, admin_user, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "lock-rel")
    lock = session_lock_service.create_lock(
        db,
        creator=admin_user,
        reason="test",
        subject_user_id=maintainer_user.id,
    )
    session_lock_service.release_lock(db, lock_id=lock.id, releaser=admin_user)

    db.expire_all()
    # Without an AccessGrant, gate falls through to "forbidden" instead of "locked"
    with pytest.raises(PermissionDenied) as exc:
        authorize_action(db, maintainer_user, sys, "session_open")
    assert exc.value.code == "forbidden"


def test_role_lock_blocks_all_holders(
    db, admin_user, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "lock-role")
    # Lock anyone holding the maintainer role
    role = next(r for r in maintainer_user.roles if r.name == "maintainer")
    session_lock_service.create_lock(
        db,
        creator=admin_user,
        reason="role-wide",
        subject_app_role_id=role.id,
    )
    with pytest.raises(PermissionDenied) as exc:
        authorize_action(db, maintainer_user, sys, "session_open")
    assert exc.value.code == "locked"


# -------------------------------------------------- audit emission


def test_create_and_release_emit_audit(db, admin_user, maintainer_user):
    lock = session_lock_service.create_lock(
        db,
        creator=admin_user,
        reason="audit",
        subject_user_id=maintainer_user.id,
    )
    creates = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "lock.create", AuditEvent.target_id == str(lock.id)
        )
        .all()
    )
    assert len(creates) == 1
    assert creates[0].actor_user_id == admin_user.id

    session_lock_service.release_lock(db, lock_id=lock.id, releaser=admin_user)
    releases = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "lock.release", AuditEvent.target_id == str(lock.id)
        )
        .all()
    )
    assert len(releases) == 1


# -------------------------------------------------- REST: auth + happy path


def test_rest_create_forbidden_for_non_operator(client, auditor_user, admin_user):
    _login(client, auditor_user)
    res = client.post(
        "/session-locks",
        json={"reason": "test", "subject_user_id": admin_user.id},
    )
    assert res.status_code == 403


def test_rest_create_with_username_resolves(client, admin_user, maintainer_user, db):
    _login(client, admin_user)
    res = client.post(
        "/session-locks",
        json={"reason": "by name", "subject_username": maintainer_user.username},
    )
    assert res.status_code == 200, res.text
    body = res.json()["lock"]
    assert body["subject_user_id"] == maintainer_user.id
    assert body["subject_username"] == maintainer_user.username
    assert body["active"] is True


def test_rest_release_idempotency(client, admin_user, maintainer_user, db):
    _login(client, admin_user)
    res = client.post(
        "/session-locks",
        json={"reason": "rel", "subject_user_id": maintainer_user.id},
    )
    lock_id = res.json()["lock"]["id"]
    rel1 = client.post(f"/session-locks/{lock_id}/release")
    assert rel1.status_code == 200
    rel2 = client.post(f"/session-locks/{lock_id}/release")
    assert rel2.status_code == 409


def test_rest_release_404(client, admin_user):
    _login(client, admin_user)
    res = client.post("/session-locks/99999999/release")
    assert res.status_code == 404


def test_rest_list_returns_enriched_subjects(client, admin_user, maintainer_user, db):
    _login(client, admin_user)
    client.post(
        "/session-locks",
        json={"reason": "list-1", "subject_user_id": maintainer_user.id},
    )
    res = client.get("/session-locks?active_only=true")
    assert res.status_code == 200
    locks = res.json()["locks"]
    mine = [l for l in locks if l["reason"] == "list-1"]
    assert len(mine) == 1
    assert mine[0]["subject_username"] == maintainer_user.username
    assert mine[0]["created_by_username"] == admin_user.username
