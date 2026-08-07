"""Tests for PRA-148: session moderation / multi-subscriber join.

Covers SessionRuntime fanout, the join-ticket REST endpoint and parser,
and the GET /sessions/{id} attached enrichment.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import jwt
import pytest

from app.api.routes.sessions import _parse_ws_join_ticket
from app.core.auth import ALGORITHM, SECRET_KEY
from app.db.access_models import AccessGrant, FleetRole
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, System
from app.services import session_runtime as rt_registry
from app.services.session_runtime import SessionRuntime


def _grant(db, user, system):
    """PRA-281: scope an operator to a system via a fleet grant."""
    role = FleetRole(
        name=f"grant-role-{user.id}-{system.id}",
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    db.add(
        AccessGrant(
            user_id=user.id,
            system_id=system.id,
            fleet_role_id=role.id,
            login=user.username,
        )
    )
    db.commit()


# ----------------------------------------------------- runtime fanout


def _mk_runtime(session_id=900001):
    transport = MagicMock()
    channel = MagicMock()
    channel.closed = False
    channel.eof_received = False
    channel.recv_ready = MagicMock(return_value=False)
    return SessionRuntime(
        session_id=session_id,
        transport=transport,
        channel=channel,
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )


def test_attach_returns_unique_sids_and_dispatches_to_all():
    rt = _mk_runtime(900101)
    loop = asyncio.new_event_loop()
    try:
        q1: "asyncio.Queue[bytes | None]" = asyncio.Queue()
        q2: "asyncio.Queue[bytes | None]" = asyncio.Queue()
        sid1 = rt.attach(loop, q1, username="alice", mode="owner")
        sid2 = rt.attach(loop, q2, username="bob", mode="observe")
        assert sid1 != sid2
        # Synthesize a dispatch from the reader.
        rt._dispatch(b"hello")  # pylint: disable=protected-access
        # call_soon_threadsafe schedules onto the loop — drain the loop.
        loop.call_soon(loop.stop)
        loop.run_forever()
        assert q1.get_nowait() == b"hello"
        assert q2.get_nowait() == b"hello"
    finally:
        rt.close()
        loop.close()


def test_detach_removes_subscriber_and_signals_eof():
    rt = _mk_runtime(900102)
    loop = asyncio.new_event_loop()
    try:
        q: "asyncio.Queue[bytes | None]" = asyncio.Queue()
        sid = rt.attach(loop, q, username="alice", mode="owner")
        rt.detach(sid)
        loop.call_soon(loop.stop)
        loop.run_forever()
        # Detach pushes None as EOF marker
        assert q.get_nowait() is None
        # And the subscriber is gone from the snapshot
        assert all(s["sid"] != sid for s in rt.list_subscribers())
    finally:
        rt.close()
        loop.close()


def test_list_subscribers_snapshot_shape():
    rt = _mk_runtime(900103)
    loop = asyncio.new_event_loop()
    try:
        rt.attach(loop, asyncio.Queue(), username="alice", mode="owner")
        rt.attach(loop, asyncio.Queue(), username="bob", mode="participate")
        snapshot = rt.list_subscribers()
        modes = {s["mode"] for s in snapshot}
        names = {s["username"] for s in snapshot}
        assert modes == {"owner", "participate"}
        assert names == {"alice", "bob"}
        for s in snapshot:
            assert "sid" in s and "joined_at" in s
    finally:
        rt.close()
        loop.close()


# ------------------------------------------------------- join ticket


def _mk_join_token(
    *, session_id, sub="alice", mode="observe", purpose="ws-join-ticket", exp_offset=30
):
    return jwt.encode(
        {
            "sub": sub,
            "session_id": session_id,
            "purpose": purpose,
            "mode": mode,
            "exp": datetime.utcnow() + timedelta(seconds=exp_offset),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def test_parse_join_ticket_accepts_valid():
    tok = _mk_join_token(session_id=42, sub="alice", mode="observe")
    parsed = _parse_ws_join_ticket(tok, 42)
    assert parsed == {"username": "alice", "mode": "observe"}


def test_parse_join_ticket_rejects_owner_purpose():
    tok = _mk_join_token(session_id=42, purpose="ws-ticket")
    assert _parse_ws_join_ticket(tok, 42) is None


def test_parse_join_ticket_rejects_session_mismatch():
    tok = _mk_join_token(session_id=42, mode="observe")
    assert _parse_ws_join_ticket(tok, 7) is None


def test_parse_join_ticket_rejects_bad_mode():
    tok = _mk_join_token(session_id=1, mode="root")
    assert _parse_ws_join_ticket(tok, 1) is None


def test_parse_join_ticket_rejects_expired():
    tok = _mk_join_token(session_id=1, exp_offset=-30)
    assert _parse_ws_join_ticket(tok, 1) is None


# --------------------------------------------------- REST helpers


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
            name="pra148-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra148",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, grp, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.10.0.1",
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


def test_join_ticket_forbidden_for_auditor(
    client, admin_user, auditor_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "join-1")
    row = _mk_session(db, admin_user, sys)
    # Need a runtime in the registry so the route doesn't 410.
    rt = _mk_runtime(row.id)
    rt_registry.register(rt)
    try:
        _login(client, auditor_user)
        res = client.post(f"/sessions/{row.id}/join-ticket?mode=observe")
        assert res.status_code == 403
    finally:
        rt_registry.drop(row.id)


def test_join_ticket_410_when_runtime_missing(
    client, admin_user, maintainer_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "join-2")
    row = _mk_session(db, admin_user, sys)
    _grant(db, maintainer_user, sys)  # PRA-281: maintainer scoped to join-2
    _login(client, maintainer_user)
    res = client.post(f"/sessions/{row.id}/join-ticket?mode=observe")
    assert res.status_code == 410


def test_join_ticket_succeeds_for_admin(
    client, admin_user, maintainer_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "join-3")
    row = _mk_session(db, maintainer_user, sys)
    rt = _mk_runtime(row.id)
    rt_registry.register(rt)
    try:
        _login(client, admin_user)
        res = client.post(f"/sessions/{row.id}/join-ticket?mode=participate")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["mode"] == "participate"
        # Decode the returned ticket and confirm shape.
        decoded = jwt.decode(body["token"], SECRET_KEY, algorithms=[ALGORITHM])
        assert decoded["purpose"] == "ws-join-ticket"
        assert decoded["session_id"] == row.id
        assert decoded["mode"] == "participate"
    finally:
        rt_registry.drop(row.id)


def test_get_session_returns_attached_subscriber_list(
    client, admin_user, seed_distro, seed_default_group, seed_cred, db
):
    sys = _mk_system(db, seed_distro, seed_default_group, seed_cred, "join-4")
    row = _mk_session(db, admin_user, sys)
    rt = _mk_runtime(row.id)
    rt_registry.register(rt)
    loop = asyncio.new_event_loop()
    try:
        rt.attach(loop, asyncio.Queue(), username="alice", mode="owner")
        rt.attach(loop, asyncio.Queue(), username="bob", mode="observe")
        _login(client, admin_user)
        res = client.get(f"/sessions/{row.id}")
        assert res.status_code == 200
        body = res.json()["session"]
        modes = {a["mode"] for a in body.get("attached", [])}
        assert {"owner", "observe"} <= modes
    finally:
        rt.close()
        rt_registry.drop(row.id)
        loop.close()
