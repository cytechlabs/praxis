"""Tests for PRA-147: session approval workflow.

Covers the service (request/grant/deny/consume/sweep), the open_session
integration (find usable, create pending, dedupe pending), and the REST
surface (auth, lifecycle).
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
    SessionApproval,
)
from app.db.models import Credential, Group, System
from app.services import access_binding_service as abs_svc
from app.services import session_approval_service, session_service


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
            name="pra147-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra147",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, grp, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.9.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _provision(db, system, login, mode="per_user"):
    """Seed a provisioned host_user_states row so open_session's provisioning
    pre-flight passes and the approval path under test is reached."""
    hus = HostUserState(
        system_id=system.id, login=login, mode=mode, state="provisioned"
    )
    db.add(hus)
    db.flush()
    return hus


def _approval_role(db, name):
    role = FleetRole(
        name=name,
        login_mode="per_user",
        allowed_actions_json=json.dumps(["session_open"]),
        session_requires_approval=True,
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    return role


def _bind(db, role, user, group):
    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=user.id,
        scope_group_id=group.id,
    )


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


@pytest.fixture
def basic_targets(db, seed_distro, seed_default_group, seed_cred):
    """Real system + fleet role rows so FK constraints are satisfied."""
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "appr-default")
    role = _approval_role(db, "appr-default-role")
    return sys, role


# ---------------------------------------------------------- service basics


def test_request_approval_persists_pending_row(db, admin_user, basic_targets):
    row = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
        reason="why",
    )
    assert row.id > 0
    assert row.state == "pending"
    assert row.reason == "why"


def test_grant_sets_expiry_and_approver(db, admin_user, maintainer_user, basic_targets):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    granted = session_approval_service.grant(
        db, approval_id=pending.id, approver=maintainer_user
    )
    assert granted.state == "granted"
    assert granted.approver_id == maintainer_user.id
    assert granted.expires_at is not None
    assert granted.expires_at > datetime.utcnow()


def test_deny_sets_state(db, admin_user, maintainer_user, basic_targets):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    denied = session_approval_service.deny(
        db, approval_id=pending.id, approver=maintainer_user, decision_reason="no"
    )
    assert denied.state == "denied"
    assert denied.decision_reason == "no"


def test_grant_then_grant_rejects(db, admin_user, maintainer_user, basic_targets):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    session_approval_service.grant(db, approval_id=pending.id, approver=maintainer_user)
    with pytest.raises(session_approval_service.ApprovalError) as exc:
        session_approval_service.grant(
            db, approval_id=pending.id, approver=maintainer_user
        )
    assert exc.value.code == "invalid_state"


def test_consume_requires_granted(db, admin_user, basic_targets):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    with pytest.raises(session_approval_service.ApprovalError):
        session_approval_service.consume(db, approval=pending)


def test_consume_rejects_expired(db, admin_user, maintainer_user, basic_targets):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    granted = session_approval_service.grant(
        db, approval_id=pending.id, approver=maintainer_user, ttl_seconds=1
    )
    granted.expires_at = datetime.utcnow() - timedelta(seconds=10)
    db.commit()
    with pytest.raises(session_approval_service.ApprovalError) as exc:
        session_approval_service.consume(db, approval=granted)
    assert exc.value.code == "expired"


def test_sweep_expired_marks_stale_grants(
    db, admin_user, maintainer_user, basic_targets
):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    granted = session_approval_service.grant(
        db, approval_id=pending.id, approver=maintainer_user
    )
    granted.expires_at = datetime.utcnow() - timedelta(seconds=10)
    db.commit()
    n = session_approval_service.sweep_expired(db)
    assert n >= 1
    db.expire_all()
    refreshed = db.query(SessionApproval).filter_by(id=granted.id).first()
    assert refreshed.state == "expired"


# ----------------------------------------------- open_session integration


def test_open_session_creates_pending_when_no_grant_exists(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "appr-host-1")
    role = _approval_role(db, "appr-role-1")
    _bind(db, role, maintainer_user, seed_default_group)
    _provision(db, s, maintainer_user.username)

    with pytest.raises(session_service.ApprovalRequired) as exc:
        session_service.open_session(db, maintainer_user, s.id)
    pending = db.query(SessionApproval).filter_by(id=exc.value.approval_id).first()
    assert pending is not None and pending.state == "pending"


def test_open_session_dedupes_pending(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "appr-host-2")
    role = _approval_role(db, "appr-role-2")
    _bind(db, role, maintainer_user, seed_default_group)
    _provision(db, s, maintainer_user.username)

    with pytest.raises(session_service.ApprovalRequired) as e1:
        session_service.open_session(db, maintainer_user, s.id)
    with pytest.raises(session_service.ApprovalRequired) as e2:
        session_service.open_session(db, maintainer_user, s.id)
    assert e1.value.approval_id == e2.value.approval_id


def test_open_session_consumes_existing_grant(
    db,
    admin_user,
    maintainer_user,
    seed_distro,
    seed_default_group,
    seed_cred,
    monkeypatch,
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "appr-host-3")
    role = _approval_role(db, "appr-role-3")
    _bind(db, role, maintainer_user, seed_default_group)
    _provision(db, s, maintainer_user.username)

    pending = session_approval_service.request_approval(
        db,
        requester=maintainer_user,
        system_id=s.id,
        fleet_role_id=role.id,
        login=maintainer_user.username,
    )
    session_approval_service.grant(db, approval_id=pending.id, approver=admin_user)

    # Stub out the SSH-side of open_session — we only care that it gets
    # past the approval gate to "we tried to connect".
    def boom(*_a, **_kw):
        raise session_service.SessionError("ssh_connect_failed: stub")

    monkeypatch.setattr(
        "app.services.session_service.VaultService",
        lambda *a, **kw: type("V", (), {"sign_ssh_user_cert": staticmethod(boom)})(),
    )

    with pytest.raises(session_service.SessionError) as exc:
        session_service.open_session(db, maintainer_user, s.id)
    # The failure mode is the SSH stub, not the approval gate — proves we
    # cleared the approval check.
    assert "stub" in str(exc.value) or "cert_mint_failed" in str(exc.value)

    db.expire_all()
    consumed = db.query(SessionApproval).filter_by(id=pending.id).first()
    assert consumed.state == "consumed"


# ----------------------------------------------- audit emission


def test_lifecycle_emits_audit_events(db, admin_user, maintainer_user, basic_targets):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    session_approval_service.grant(db, approval_id=pending.id, approver=maintainer_user)

    requests = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "session.approval_request",
            AuditEvent.target_id == str(pending.id),
        )
        .all()
    )
    grants = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "session.approval_grant",
            AuditEvent.target_id == str(pending.id),
        )
        .all()
    )
    assert len(requests) == 1
    assert len(grants) == 1


# ----------------------------------------------- REST


def test_rest_grant_forbidden_for_non_operator(
    client, auditor_user, admin_user, db, basic_targets
):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    _login(client, auditor_user)
    res = client.post(f"/session-approvals/{pending.id}/grant", json={})
    assert res.status_code == 403


def test_rest_lifecycle_grant_then_grant_409(
    client, admin_user, maintainer_user, db, basic_targets
):
    pending = session_approval_service.request_approval(
        db,
        requester=maintainer_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=maintainer_user.username,
    )
    _login(client, admin_user)
    grant_res = client.post(
        f"/session-approvals/{pending.id}/grant", json={"reason": "ok"}
    )
    assert grant_res.status_code == 200, grant_res.text
    # Second grant attempt -> 409 invalid_state
    again = client.post(f"/session-approvals/{pending.id}/grant", json={})
    assert again.status_code == 409


def test_rest_get_scoped_to_requester(
    client, admin_user, auditor_user, db, basic_targets
):
    pending = session_approval_service.request_approval(
        db,
        requester=admin_user,
        system_id=basic_targets[0].id,
        fleet_role_id=basic_targets[1].id,
        login=admin_user.username,
    )
    # PRA-281: reads are now additionally fleet-scoped. Grant the auditor scope on
    # the approval's system so this test still exercises the ownership 403 path
    # (in-scope but not the requester) rather than the new out-of-scope 404.
    db.add(
        AccessGrant(
            user_id=auditor_user.id,
            system_id=basic_targets[0].id,
            fleet_role_id=basic_targets[1].id,
            login=auditor_user.username,
        )
    )
    db.commit()
    _login(client, auditor_user)
    res = client.get(f"/session-approvals/{pending.id}")
    assert res.status_code == 403
