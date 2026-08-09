"""PRA-390: the mandatory-recording refusal is pinned at the route boundary.

The service-level tests prove ``open_session`` fails closed. This one drives the
same failure through ``POST /sessions`` so a later route change cannot turn a
refused session into a 500, leak the underlying cause to the caller, or hand back
a session the caller could attach to.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.db.access_models import HostUserState, Recording
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, System
from app.services import recording_service as rec_svc
from app.services import session_runtime as runtime_registry
from app.services import session_service as ss

SENTINEL_PATH = "/data/praxis/recordings/session-secret.cast"
SENTINEL_EXC_TEXT = "Permission denied"


@pytest.fixture
def system(db, seed_distro):
    group = db.query(Group).filter_by(name="pra390-api-grp").first()
    if group is None:
        group = Group(name="pra390-api-grp", description="x")
        db.add(group)
        db.flush()
    cred = db.query(Credential).first()
    if cred is None:
        cred = Credential(
            name="pra390-api-cred", auth_method="ssh_key", username="root"
        )
        db.add(cred)
        db.flush()
    row = System(
        hostname="pra390-api-host",
        ip_address="10.90.1.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(row)
    db.flush()
    return row


class _SpyClient:
    """paramiko.SSHClient stand-in that opens a fake PTY channel."""

    def __init__(self):
        self.channel = MagicMock()
        self.transport = MagicMock()
        self.closed = 0

    def set_missing_host_key_policy(self, policy):
        pass

    def get_host_keys(self):
        return MagicMock()

    def connect(self, **kw):
        pass

    def get_transport(self):
        return self.transport

    def invoke_shell(self, **kw):
        return self.channel

    def close(self):
        self.closed += 1


@pytest.fixture
def open_ready(db, admin_user, system, monkeypatch, tmp_path):
    """Everything ``open_session`` needs, up to the recording attach."""
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    db.add(
        HostUserState(
            system_id=system.id,
            login=admin_user.username,
            mode="per_user",
            state="provisioned",
        )
    )
    db.flush()

    monkeypatch.setattr(
        ss,
        "authorize_action",
        lambda *a, **k: SimpleNamespace(
            fleet_role=SimpleNamespace(id=None, name="pra390-role", max_session_s=3600),
            login=admin_user.username,
            requires_approval=False,
            requires_totp=False,
            max_session_s=3600,
            recording_retention_days=90,
        ),
    )

    pkey = MagicMock()
    pkey.get_name.return_value = "ssh-rsa"
    pkey.get_base64.return_value = "AAAA"
    monkeypatch.setattr(ss.paramiko.RSAKey, "generate", staticmethod(lambda bits: pkey))
    monkeypatch.setattr(
        ss,
        "VaultService",
        lambda db_: SimpleNamespace(sign_ssh_user_cert=lambda **kw: "signed-cert"),
    )

    import app.services.audit_event_service as aes

    monkeypatch.setattr(aes, "emit_user_cert_sign", lambda *a, **k: None)

    spy = _SpyClient()
    monkeypatch.setattr(ss.paramiko, "SSHClient", lambda: spy)
    return spy


def _fail_recording(monkeypatch):
    def _boom(*a, **k):
        raise PermissionError(13, SENTINEL_EXC_TEXT, SENTINEL_PATH)

    monkeypatch.setattr(rec_svc, "start_recording", _boom)


def test_post_sessions_refuses_when_recording_cannot_start(
    authed_client, db, system, open_ready, monkeypatch
):
    _fail_recording(monkeypatch)

    res = authed_client.post("/sessions", json={"system_id": system.id})

    # Controlled client error, not a 500 and not a success carrying a session.
    assert res.status_code == 400, res.text
    body = res.json()
    assert "session" not in body
    detail = body["detail"]
    assert "recording_unavailable" in detail

    # The response explains the refusal without exposing its cause.
    assert SENTINEL_PATH not in res.text
    assert "/data/praxis" not in res.text
    assert SENTINEL_EXC_TEXT not in res.text
    assert "Traceback" not in res.text

    # The ledger records a refused session, with no recording and no runtime.
    row = (
        db.query(SessionRow)
        .filter(SessionRow.system_id == system.id)
        .order_by(SessionRow.id.desc())
        .first()
    )
    assert row is not None
    assert row.status == "errored"
    assert row.ended_at is not None
    assert row.close_reason == "recording_unavailable"
    assert db.query(Recording).filter(Recording.session_id == row.id).first() is None
    assert runtime_registry.get(row.id) is None
    assert open_ready.closed == 1


def test_post_sessions_still_opens_when_recording_starts(
    authed_client, db, system, open_ready
):
    """The refusal path must not have broken the ordinary open."""
    res = authed_client.post("/sessions", json={"system_id": system.id})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "success"

    session_id = body["session"]["id"]
    try:
        row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
        assert row.status == "active"
        rec = db.query(Recording).filter(Recording.session_id == session_id).first()
        assert rec is not None
        assert rec.status == "active"
        assert runtime_registry.get(session_id) is not None
    finally:
        runtime_registry.drop(session_id)
