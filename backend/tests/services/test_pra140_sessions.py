"""Tests for PRA-140: interactive session runtime + service guards."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import jwt
import pytest

from app.core.auth import ALGORITHM, SECRET_KEY
from app.db.access_models import HostUserState
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, FleetRole, Group, System
from app.services import session_runtime as rt_registry
from app.services import session_service
from app.services.session_runtime import SessionRuntime

# ------------------------------------------------------------- helpers


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
            name="pra140-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra140",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, grp, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.6.0.1",
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
    pre-flight passes."""
    db.add(
        HostUserState(system_id=system.id, login=login, mode=mode, state="provisioned")
    )
    db.flush()


# -------------------------------------------------- session_runtime registry


def test_runtime_register_and_get():
    transport = MagicMock()
    channel = MagicMock()
    channel.closed = False
    channel.eof_received = False
    channel.recv_ready = MagicMock(return_value=False)

    rt = SessionRuntime(
        session_id=99999,
        transport=transport,
        channel=channel,
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    rt_registry.register(rt)
    assert rt_registry.get(99999) is rt
    rt_registry.drop(99999)
    assert rt_registry.get(99999) is None


def test_runtime_close_marks_closed_and_fires_callback():
    transport = MagicMock()
    channel = MagicMock()
    rt = SessionRuntime(
        session_id=99998,
        transport=transport,
        channel=channel,
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    reasons: list[str] = []
    rt.set_on_close(lambda sid, reason: reasons.append(reason))
    rt.close(reason="client_close")
    assert rt.closed.is_set()
    channel.close.assert_called_once()
    transport.close.assert_called_once()
    assert reasons == ["client_close"]


def test_runtime_resize_ignored_when_closed():
    channel = MagicMock()
    rt = SessionRuntime(
        session_id=99997,
        transport=MagicMock(),
        channel=channel,
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    rt.close()
    rt.resize(120, 40)
    channel.resize_pty.assert_not_called()


# ------------------------------------------------- service guards


def test_open_session_forbidden_without_grant(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p140-nogrant")
    with pytest.raises(session_service.SessionError, match="forbidden"):
        session_service.open_session(db, maintainer_user, s.id)


def test_open_session_rejects_unknown_system(db, admin_user):
    with pytest.raises(session_service.SessionError, match="not found"):
        session_service.open_session(db, admin_user, 99999999)


def test_open_session_creates_pending_approval_when_required(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    """PRA-147: open_session with an approval-required role now creates a
    pending SessionApproval and raises ApprovalRequired (subclass of
    SessionError) instead of dead-ending the caller."""
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p140-approval")
    role = FleetRole(
        name="p140-approval-role",
        login_mode="per_user",
        allowed_actions_json=json.dumps(["session_open"]),
        session_requires_approval=True,
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    from app.services import access_binding_service as abs_svc

    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=seed_default_group.id,
    )
    _provision(db, s, maintainer_user.username)
    with pytest.raises(session_service.ApprovalRequired) as exc:
        session_service.open_session(db, maintainer_user, s.id)
    assert exc.value.approval_id > 0


def test_open_session_errors_when_login_not_provisioned(
    db, maintainer_user, seed_distro, seed_default_group, seed_cred
):
    """A granted-but-unprovisioned login must fail fast with an actionable
    not_provisioned error instead of dead-ending on an opaque SSH auth
    failure (regression: a granted login that was never provisioned on the host)."""
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p140-noprov")
    role = FleetRole(
        name="p140-noprov-role",
        login_mode="per_user",
        allowed_actions_json=json.dumps(["session_open"]),
        session_requires_approval=False,
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    from app.services import access_binding_service as abs_svc

    abs_svc.create_binding(
        db,
        fleet_role_id=role.id,
        subject_user_id=maintainer_user.id,
        scope_group_id=seed_default_group.id,
    )
    # No _provision() call — host_user_states has no row for this login.
    with pytest.raises(session_service.SessionError, match="not_provisioned"):
        session_service.open_session(db, maintainer_user, s.id)


def test_close_session_updates_ledger(
    db, admin_user, seed_distro, seed_default_group, seed_cred
):
    """close_session gracefully handles sessions with no live runtime."""
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p140-close")
    # Persist a fake row directly (no paramiko side effects)
    row = SessionRow(
        user_id=admin_user.id,
        system_id=s.id,
        login=admin_user.username,
        status="active",
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    closed = session_service.close_session(db, row.id, reason="test")
    assert closed is not None
    assert closed.status == "closed"
    assert closed.close_reason == "test"
    assert closed.ended_at is not None


# ------------------------------------------------- WS ticket


def test_ws_ticket_accepts_valid_token():
    from app.api.routes.sessions import _parse_ws_ticket

    token = jwt.encode(
        {
            "sub": "alice",
            "session_id": 42,
            "purpose": "ws-ticket",
            "exp": datetime.utcnow() + timedelta(seconds=30),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    assert _parse_ws_ticket(token, 42) == "alice"


def test_ws_ticket_rejects_access_token():
    """Regular access tokens must not work as WS tickets."""
    from app.api.routes.sessions import _parse_ws_ticket

    access_token = jwt.encode(
        {
            "sub": "alice",
            "exp": datetime.utcnow() + timedelta(minutes=30),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    assert _parse_ws_ticket(access_token, 42) is None


def test_ws_ticket_rejects_wrong_session():
    from app.api.routes.sessions import _parse_ws_ticket

    token = jwt.encode(
        {
            "sub": "alice",
            "session_id": 100,
            "purpose": "ws-ticket",
            "exp": datetime.utcnow() + timedelta(seconds=30),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    assert _parse_ws_ticket(token, 99) is None


def test_ws_ticket_rejects_expired():
    from app.api.routes.sessions import _parse_ws_ticket

    token = jwt.encode(
        {
            "sub": "alice",
            "session_id": 1,
            "purpose": "ws-ticket",
            "exp": datetime.utcnow() - timedelta(seconds=10),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    assert _parse_ws_ticket(token, 1) is None


def test_ws_ticket_rejects_garbage():
    from app.api.routes.sessions import _parse_ws_ticket

    assert _parse_ws_ticket("", 1) is None
    assert _parse_ws_ticket("not.a.jwt", 1) is None
