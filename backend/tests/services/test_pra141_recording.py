"""Tests for PRA-141 recording writer + lifecycle.

Integration-level (runtime + paramiko) coverage is deferred to PRA-144.
Here we exercise the pure file-format + db-state paths against tmp files
and the test DB session.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.db.access_models import FleetRole, Recording
from app.db.access_models import Session as SessionRow
from app.db.models import Credential, Group, System
from app.services import recording_service
from app.services.recording_service import _Writer

# --------------------------------------------------------------- fixtures


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
            name="pra141-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra141",
        )
        db.add(c)
        db.flush()
    return c


def _mk_system(db, distro, grp, cred, hostname):
    s = System(
        hostname=hostname,
        ip_address="10.5.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def _mk_session(db, user, system, role_id=None):
    row = SessionRow(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=role_id,
        login=user.username,
        status="active",
        started_at=datetime.utcnow(),
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# ------------------------------------------------------------- writer


def test_writer_emits_valid_asciicast_v2(tmp_path):
    path = tmp_path / "test.cast"
    w = _Writer(str(path), width=80, height=24, started_at_epoch=1700000000.0)
    w.write_output(b"hello\n")
    time.sleep(0.02)
    w.write_output(b"world\n")
    w.close()

    lines = path.read_text(encoding="utf-8").strip().split("\n")
    # First line = header
    header = json.loads(lines[0])
    assert header["version"] == 2
    assert header["width"] == 80
    assert header["height"] == 24
    assert header["timestamp"] == 1700000000
    # Subsequent lines = frames
    frame1 = json.loads(lines[1])
    frame2 = json.loads(lines[2])
    assert frame1[1] == "o" and frame1[2] == "hello\n"
    assert frame2[1] == "o" and frame2[2] == "world\n"
    # Monotonic time ordering
    assert frame2[0] >= frame1[0]


def test_writer_ignores_empty_and_after_close(tmp_path):
    path = tmp_path / "test.cast"
    w = _Writer(str(path), width=80, height=24, started_at_epoch=1.0)
    w.write_output(b"")
    w.close()
    w.write_output(b"ignored")
    assert w.frames == 0


def test_writer_counts_frames_and_size(tmp_path):
    path = tmp_path / "test.cast"
    w = _Writer(str(path), width=80, height=24, started_at_epoch=1.0)
    for _ in range(3):
        w.write_output(b"x")
    w.close()
    assert w.frames == 3
    assert w.size > 0


def test_writer_decodes_utf8_replace_safely(tmp_path):
    path = tmp_path / "test.cast"
    w = _Writer(str(path), width=80, height=24, started_at_epoch=1.0)
    w.write_output(b"\xff\xfe not utf-8")  # malformed
    w.close()
    # Should not raise; replacement characters written
    frames = [json.loads(l) for l in path.read_text().strip().split("\n")[1:]]
    assert len(frames) == 1
    assert frames[0][1] == "o"


# ---------------------------------------------------------- lifecycle


def test_start_recording_creates_row_and_registers_consumer(
    db, admin_user, seed_distro, seed_default_group, seed_cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(recording_service, "RECORDINGS_DIR", str(tmp_path))
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p141-rec-start")
    session_row = _mk_session(db, admin_user, s)

    runtime = MagicMock()
    runtime.session_id = session_row.id
    consumers = []
    runtime.add_consumer = lambda fn: consumers.append(fn)

    rec = recording_service.start_recording(db, runtime, width=80, height=24)
    assert rec.id is not None
    assert rec.session_id == session_row.id
    assert rec.status == "active"
    assert rec.retention_expires_at > datetime.utcnow()
    assert len(consumers) == 1

    # File exists on disk with asciicast header
    assert os.path.exists(rec.file_path)
    lines = open(rec.file_path).read().strip().split("\n")
    assert json.loads(lines[0])["version"] == 2


def test_stop_recording_finalizes_row_and_captures_size(
    db, admin_user, seed_distro, seed_default_group, seed_cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(recording_service, "RECORDINGS_DIR", str(tmp_path))
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p141-rec-stop")
    session_row = _mk_session(db, admin_user, s)

    runtime = MagicMock()
    runtime.session_id = session_row.id
    consumers = []
    runtime.add_consumer = lambda fn: consumers.append(fn)

    recording_service.start_recording(db, runtime, width=80, height=24)
    # Simulate the runtime delivering two output chunks
    consumers[0](b"first\n")
    consumers[0](b"second\n")

    rec = recording_service.stop_recording(db, session_row.id)
    assert rec is not None
    assert rec.status == "finalized"
    assert rec.ended_at is not None
    assert rec.frame_count == 2
    assert rec.size_bytes > 0


def test_stop_recording_missing_row_returns_none(db):
    assert recording_service.stop_recording(db, 9_999_999) is None


def test_retention_uses_fleet_role_override(
    db, admin_user, seed_distro, seed_default_group, seed_cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(recording_service, "RECORDINGS_DIR", str(tmp_path))
    role = FleetRole(
        name="p141-short-retention",
        login_mode="per_user",
        allowed_actions_json='["session_open"]',
        os_groups_json="[]",
        recording_retention_days=7,
    )
    db.add(role)
    db.flush()
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p141-retention")
    session_row = _mk_session(db, admin_user, s, role_id=role.id)

    runtime = MagicMock()
    runtime.session_id = session_row.id
    runtime.add_consumer = lambda fn: None

    rec = recording_service.start_recording(db, runtime)
    # ~7 days, +/- a few minutes
    delta = (rec.retention_expires_at - datetime.utcnow()).total_seconds()
    assert 7 * 24 * 3600 - 300 < delta < 7 * 24 * 3600 + 300


# ---------------------------------------------------------- sweeper


def test_sweep_expired_prunes_and_unlinks(
    db, admin_user, seed_distro, seed_default_group, seed_cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(recording_service, "RECORDINGS_DIR", str(tmp_path))
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p141-expire")
    session_row = _mk_session(db, admin_user, s)
    path = tmp_path / f"session-{session_row.id}.cast"
    path.write_text("{}\n")

    rec = Recording(
        session_id=session_row.id,
        user_id=admin_user.id,
        system_id=s.id,
        file_path=str(path),
        size_bytes=2,
        frame_count=0,
        started_at=datetime.utcnow() - timedelta(days=91),
        retention_expires_at=datetime.utcnow() - timedelta(days=1),
        status="finalized",
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)

    n = recording_service.sweep_expired(db)
    assert n >= 1
    db.refresh(rec)
    assert rec.status == "pruned"
    assert not path.exists()


def test_sweep_ignores_live_recordings(
    db, admin_user, seed_distro, seed_default_group, seed_cred, tmp_path, monkeypatch
):
    monkeypatch.setattr(recording_service, "RECORDINGS_DIR", str(tmp_path))
    s = _mk_system(db, seed_distro, seed_default_group, seed_cred, "p141-live")
    session_row = _mk_session(db, admin_user, s)
    path = tmp_path / f"session-{session_row.id}.cast"
    path.write_text("{}\n")

    # Already pruned — should be skipped
    Recording_already = Recording(
        session_id=session_row.id,
        user_id=admin_user.id,
        system_id=s.id,
        file_path=str(path),
        size_bytes=2,
        frame_count=0,
        started_at=datetime.utcnow() - timedelta(days=200),
        retention_expires_at=datetime.utcnow() - timedelta(days=100),
        status="pruned",
    )
    db.add(Recording_already)
    db.commit()

    n = recording_service.sweep_expired(db)
    assert n == 0  # status='pruned' excluded
