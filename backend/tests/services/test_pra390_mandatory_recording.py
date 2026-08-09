"""PRA-390: session recording is mandatory, and its startup fails closed.

An interactive browser SSH session that opens without a recording is an
audit/compliance bypass, not a degraded feature. These tests prove:

- a successful open attaches the recording writer *before* the runtime becomes
  reachable and before the session row flips to ``active``;
- a recording that cannot start refuses the session with a controlled error,
  closes the PTY channel, transport, and SSH client, leaves no registered
  runtime, and marks the ledger row ``errored``;
- the stored reason, the returned error, and the emitted log records carry no
  filesystem path, exception message, or traceback; and
- a failed recording start leaves no ``recordings`` row and no partial cast
  file, including when the failure happens after the header was written.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import paramiko
import pytest

from app.db.access_models import HostUserState, Recording
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, System
from app.services import recording_service as rec_svc
from app.services import session_runtime as runtime_registry
from app.services import session_service as ss

SENTINEL_PATH = "/data/praxis/recordings/session-secret.cast"
SENTINEL_EXC_TEXT = "Permission denied"


SERVICE_LOGGERS = (
    "app.services.session_service",
    "app.services.recording_service",
)


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def blob(self) -> str:
        """Formatted output, including any traceback attached via ``exc_info``."""
        fmt = logging.Formatter()
        return "\n".join(fmt.format(r) for r in self.records)


class _capture_service_logs:  # pylint: disable=invalid-name
    """Collect the session/recording service log records emitted in the block.

    Establishes its own logging preconditions, because an earlier test may have
    left a global ``logging.disable``, a disabled logger, or a raised level in
    place, any of which would make this capture silently empty and the
    assertions vacuous. The handler is attached to each service logger directly
    so capture does not depend on propagation.
    """

    def __enter__(self) -> _CaptureHandler:
        self._handler = _CaptureHandler()
        self._prev_disable = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self._saved = []
        for name in SERVICE_LOGGERS:
            lg = logging.getLogger(name)
            self._saved.append((lg, lg.level, lg.disabled))
            lg.disabled = False
            lg.setLevel(logging.DEBUG)
            lg.addHandler(self._handler)
        return self._handler

    def __exit__(self, *exc):
        for lg, level, disabled in self._saved:
            lg.removeHandler(self._handler)
            lg.setLevel(level)
            lg.disabled = disabled
        logging.disable(self._prev_disable)
        return False


# --------------------------------------------------------------- fixtures


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra390-grp").first()
    if not g:
        g = Group(name="pra390-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra390-cred", auth_method="ssh_key", username="root")
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


def _arrange_open(db, monkeypatch, user, system, login):
    """Stub out authorization, Vault, key material, and the SSH client."""
    db.add(
        HostUserState(
            system_id=system.id, login=login, mode="per_user", state="provisioned"
        )
    )
    db.flush()

    monkeypatch.setattr(
        ss,
        "authorize_action",
        lambda *a, **k: SimpleNamespace(
            fleet_role=SimpleNamespace(id=None, name="pra390-role", max_session_s=3600),
            login=login,
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


# ------------------------------------------------- successful open ordering


def test_recording_starts_before_the_session_becomes_reachable(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-ok")
    _arrange_open(db, monkeypatch, admin_user, system, admin_user.username)

    observed = {}
    real_start = rec_svc.start_recording

    def _spy_start(db_, runtime, **kw):
        row = db_.query(SessionRow).filter(SessionRow.id == runtime.session_id).first()
        observed["status_at_start"] = row.status
        observed["registered_at_start"] = runtime_registry.get(runtime.session_id)
        return real_start(db_, runtime, **kw)

    monkeypatch.setattr(rec_svc, "start_recording", _spy_start)

    row, runtime = ss.open_session(db, admin_user, system.id)
    try:
        # Recording attached while the session was still "opening" and before
        # any WebSocket could resolve a runtime for it.
        assert observed["status_at_start"] == "opening"
        assert observed["registered_at_start"] is None

        # ...and only then did the session become active and reachable.
        assert row.status == "active"
        assert runtime_registry.get(row.id) is runtime

        rec = db.query(Recording).filter(Recording.session_id == row.id).first()
        assert rec is not None
        assert rec.status == "active"
        assert os.path.exists(rec.file_path)
    finally:
        runtime_registry.drop(row.id)


def test_successful_recording_still_captures_output_and_finalizes(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    """The mandatory-recording gate must not disturb the capture lifecycle."""
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-capture")
    _arrange_open(db, monkeypatch, admin_user, system, admin_user.username)

    row, runtime = ss.open_session(db, admin_user, system.id)
    try:
        runtime._dispatch(b"hello from the host\n")
    finally:
        runtime_registry.drop(row.id)

    rec = rec_svc.stop_recording(db, row.id)
    assert rec is not None
    assert rec.status == "finalized"
    assert rec.frame_count == 1
    assert rec.size_bytes > 0
    frames = rec_svc.load_frames(rec)
    assert frames[0]["version"] == 2
    assert frames[1][1] == "o"
    assert frames[1][2] == "hello from the host\n"


# ------------------------------------------------- fail-closed open


def _fail_recording(monkeypatch, exc):
    def _boom(*a, **k):
        raise exc

    monkeypatch.setattr(rec_svc, "start_recording", _boom)


def test_open_session_is_refused_when_recording_cannot_start(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-failclosed")
    spy = _arrange_open(db, monkeypatch, admin_user, system, admin_user.username)
    _fail_recording(
        monkeypatch, PermissionError(13, "Permission denied", SENTINEL_PATH)
    )

    with pytest.raises(ss.SessionError) as exc:
        ss.open_session(db, admin_user, system.id)

    assert "recording_unavailable" in str(exc.value)

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

    # No shell access survived the failure.
    assert runtime_registry.get(row.id) is None
    spy.channel.close.assert_called_once()
    spy.transport.close.assert_called_once()
    assert spy.closed == 1


def test_refusal_reveals_no_path_or_raw_exception_text(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-noleak")
    _arrange_open(db, monkeypatch, admin_user, system, admin_user.username)
    _fail_recording(
        monkeypatch, PermissionError(13, "Permission denied", SENTINEL_PATH)
    )

    with pytest.raises(ss.SessionError) as exc:
        ss.open_session(db, admin_user, system.id)

    row = (
        db.query(SessionRow)
        .filter(SessionRow.system_id == system.id)
        .order_by(SessionRow.id.desc())
        .first()
    )
    for text in (str(exc.value), row.close_reason):
        assert SENTINEL_PATH not in text
        assert "/data/praxis" not in text
        assert SENTINEL_EXC_TEXT not in text


def test_refusal_logs_a_safe_failure_without_path_message_or_traceback(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    """Observable failure, but the log carries no path, message, or traceback.

    Container logs are collected, shipped, and retained far more widely than the
    session ledger, so the same redaction bar applies to them.
    """
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-logs")
    _arrange_open(db, monkeypatch, admin_user, system, admin_user.username)
    _fail_recording(monkeypatch, PermissionError(13, SENTINEL_EXC_TEXT, SENTINEL_PATH))

    with _capture_service_logs() as captured:
        with pytest.raises(ss.SessionError):
            ss.open_session(db, admin_user, system.id)

    assert captured.records, "the recording failure was not logged at all"
    blob = captured.blob()

    # The failure is visible to operators...
    assert "recording start failed" in blob
    assert "PermissionError" in blob, "the failure category must survive redaction"

    # ...without the path, the exception message, or a traceback.
    assert SENTINEL_PATH not in blob
    assert "/data/praxis" not in blob
    assert SENTINEL_EXC_TEXT not in blob
    assert "Traceback" not in blob
    assert all(r.exc_info is None for r in captured.records)


def test_refusal_leaves_no_recording_row_or_file(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-norow")
    _arrange_open(db, monkeypatch, admin_user, system, admin_user.username)

    # Fail after the writer has already created the cast file, so cleanup has a
    # partial artifact to remove rather than a no-op.
    real_writer = rec_svc._Writer

    def _explode_after_header(*a, **k):
        real_writer(*a, **k)
        raise OSError("no space left on device")

    monkeypatch.setattr(rec_svc, "_Writer", _explode_after_header)

    with pytest.raises(ss.SessionError):
        ss.open_session(db, admin_user, system.id)

    row = (
        db.query(SessionRow)
        .filter(SessionRow.system_id == system.id)
        .order_by(SessionRow.id.desc())
        .first()
    )
    assert db.query(Recording).filter(Recording.session_id == row.id).first() is None
    assert not (tmp_path / f"session-{row.id}.cast").exists()


def test_teardown_completes_when_channel_close_raises(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    """Cleanup is independent per step; one raising teardown cannot skip the rest."""
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-teardown")
    spy = _arrange_open(db, monkeypatch, admin_user, system, admin_user.username)
    spy.channel.close.side_effect = paramiko.SSHException("channel already gone")
    _fail_recording(monkeypatch, RuntimeError("recording backend offline"))

    with pytest.raises(ss.SessionError):
        ss.open_session(db, admin_user, system.id)

    row = (
        db.query(SessionRow)
        .filter(SessionRow.system_id == system.id)
        .order_by(SessionRow.id.desc())
        .first()
    )
    assert row.status == "errored"
    assert runtime_registry.get(row.id) is None
    assert spy.closed == 1


# ------------------------------------------------- recording_service cleanup


def _standalone_session(db, admin_user, system):
    row = SessionRow(
        user_id=admin_user.id,
        system_id=system.id,
        login=admin_user.username,
        status="opening",
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_start_recording_raises_and_cleans_up_on_writer_failure(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-writer")
    row = _standalone_session(db, admin_user, system)

    def _denied(*a, **k):
        raise PermissionError(13, "Permission denied", SENTINEL_PATH)

    monkeypatch.setattr(rec_svc, "_Writer", _denied)

    runtime = MagicMock()
    runtime.session_id = row.id

    with pytest.raises(rec_svc.RecordingError):
        rec_svc.start_recording(db, runtime, width=80, height=24)

    assert db.query(Recording).filter(Recording.session_id == row.id).first() is None
    assert not (tmp_path / f"session-{row.id}.cast").exists()
    assert row.id not in rec_svc._writers


def test_start_recording_removes_the_partial_file_written_before_a_later_failure(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-partial")
    row = _standalone_session(db, admin_user, system)
    cast = tmp_path / f"session-{row.id}.cast"

    runtime = MagicMock()
    runtime.session_id = row.id

    def _reject_consumer(fn):
        # The header is on disk by now: prove cleanup removes it.
        assert cast.exists()
        raise RuntimeError("runtime already torn down")

    runtime.add_consumer = _reject_consumer

    with pytest.raises(rec_svc.RecordingError):
        rec_svc.start_recording(db, runtime, width=80, height=24)

    assert not cast.exists()
    assert db.query(Recording).filter(Recording.session_id == row.id).first() is None
    assert row.id not in rec_svc._writers


def test_discard_recording_removes_a_committed_row_and_is_idempotent(
    db, admin_user, seed_distro, group, cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(rec_svc, "RECORDINGS_DIR", str(tmp_path))
    system = _system(db, seed_distro, group, cred, "pra390-discard")
    row = _standalone_session(db, admin_user, system)

    runtime = MagicMock()
    runtime.session_id = row.id
    runtime.add_consumer = lambda fn: None

    rec = rec_svc.start_recording(db, runtime, width=80, height=24)
    assert os.path.exists(rec.file_path)

    rec_svc.discard_recording(db, row.id)
    assert db.query(Recording).filter(Recording.session_id == row.id).first() is None
    assert not os.path.exists(rec.file_path)
    assert row.id not in rec_svc._writers

    # Idempotent: a second pass on an already-clean session must not raise.
    rec_svc.discard_recording(db, row.id)
