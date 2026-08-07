"""Session recording writer + lifecycle (PRA-141).

asciinema v2 format (https://docs.asciinema.org/manual/asciicast/v2/):

    {"version": 2, "width": W, "height": H, "timestamp": UNIX, "env": {...}}\n
    [elapsed_s, "o", "bytes as utf8 string"]\n
    [elapsed_s, "o", "..."]\n
    ...

One file per session, newline-delimited JSON. Writer is append-only; the
``SessionRuntime.add_consumer`` hook receives raw bytes and we serialise
them into frames with monotonic-clock deltas.

We capture output only (``"o"`` events). Keystrokes are NOT recorded:
users type passwords into sudo prompts and input-capture drastically raises
the sensitivity of the storage. The rendered output (including echoed
commands and their responses) is what goes on the wire.

Storage lives at RECORDINGS_DIR on the backend container (bind-mounted
volume in docker-compose). A pluggable backend could replace the file
writer in the future without touching the consumer registration path.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Iterator, List, Optional

from sqlalchemy.orm import Session as DbSession

from ..db.access_models import FleetRole, Recording
from ..db.access_models import Session as SessionRow
from ..db.session import SessionLocal
from .session_runtime import SessionRuntime

logger = logging.getLogger(__name__)

RECORDINGS_DIR = os.environ.get("PRAXIS_RECORDINGS_DIR", "/data/praxis/recordings")
DEFAULT_RETENTION_DAYS = 90


class RecordingError(RuntimeError):
    """Recording write / lifecycle failure."""


class _Writer:
    """Asciinema v2 framer bound to one session's output byte stream.

    Thread-safe for calls from the SessionRuntime reader thread. On close()
    or process exit the file ends with the last fully-flushed frame; partial
    sessions remain replayable.
    """

    def __init__(
        self,
        file_path: str,
        *,
        width: int,
        height: int,
        started_at_epoch: float,
    ) -> None:
        self._lock = threading.Lock()
        self._closed = False
        self._frames = 0
        self._size = 0
        self._started_monotonic = time.monotonic()
        # mode "a" so a reattach after crash won't wipe existing frames
        self._f = open(file_path, "a", encoding="utf-8")
        header: Dict[str, Any] = {
            "version": 2,
            "width": int(width),
            "height": int(height),
            "timestamp": int(started_at_epoch),
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
        }
        line = json.dumps(header, separators=(",", ":")) + "\n"
        self._f.write(line)
        self._f.flush()
        self._size += len(line)

    def write_output(self, data: bytes) -> None:
        if self._closed or not data:
            return
        elapsed = time.monotonic() - self._started_monotonic
        text = data.decode("utf-8", errors="replace")
        frame = [round(elapsed, 4), "o", text]
        line = json.dumps(frame, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            if self._closed:
                return
            self._f.write(line)
            self._f.flush()
            self._size += len(line.encode("utf-8"))
            self._frames += 1

    def write_marker(self, label: str) -> None:
        """PRA-148: emit an asciinema v2 marker frame for replay attribution.

        Markers are ``[t, "m", "label"]`` per the asciicast v2 spec; the
        replayer can render them on the timeline. We use them for moderator
        join/leave so the recording carries who-was-watching alongside the
        output stream.
        """
        if self._closed or not label:
            return
        elapsed = time.monotonic() - self._started_monotonic
        frame = [round(elapsed, 4), "m", label]
        line = json.dumps(frame, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            if self._closed:
                return
            self._f.write(line)
            self._f.flush()
            self._size += len(line.encode("utf-8"))
            self._frames += 1

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._f.close()
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("recording close: %s", e)

    @property
    def frames(self) -> int:
        return self._frames

    @property
    def size(self) -> int:
        return self._size


# Runtime registry: session_id -> _Writer
_writers: Dict[int, _Writer] = {}
_writers_lock = threading.Lock()


def _ensure_storage_dir() -> None:
    os.makedirs(RECORDINGS_DIR, exist_ok=True)


def _file_path_for(session_id: int) -> str:
    return os.path.join(RECORDINGS_DIR, f"session-{session_id}.cast")


def _retention_days_for(db: DbSession, session_id: int) -> int:
    row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    if row is None:
        return DEFAULT_RETENTION_DAYS
    # PRA-287: the session persists the CONSERVATIVE (longest) retention resolved
    # across every allowing role for its shared login at open time. Prefer it so a
    # looser role that happened to win as the representative ``fleet_role_id`` cannot
    # shorten the actual persisted recording window. Fall back to the representative
    # role only for legacy rows created before the column existed (NULL).
    persisted = getattr(row, "recording_retention_days", None)
    if persisted is not None:
        return int(persisted)
    if row.fleet_role_id is None:
        return DEFAULT_RETENTION_DAYS
    role = db.query(FleetRole).filter(FleetRole.id == row.fleet_role_id).first()
    if role is None:
        return DEFAULT_RETENTION_DAYS
    return int(
        getattr(role, "recording_retention_days", None) or DEFAULT_RETENTION_DAYS
    )


# ---------------------------------------------------------------- lifecycle


def start_recording(
    db: DbSession,
    runtime: SessionRuntime,
    *,
    width: int = 120,
    height: int = 32,
) -> Recording:
    """Attach a writer to ``runtime`` and persist a Recording row."""
    _ensure_storage_dir()
    session_id = runtime.session_id
    path = _file_path_for(session_id)
    retention_days = _retention_days_for(db, session_id)

    session_row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    if session_row is None:
        raise RecordingError(f"session {session_id} not found")

    writer = _Writer(
        path,
        width=width,
        height=height,
        started_at_epoch=time.time(),
    )
    with _writers_lock:
        _writers[session_id] = writer
    runtime.add_consumer(writer.write_output)

    rec = Recording(
        session_id=session_id,
        user_id=session_row.user_id,
        system_id=session_row.system_id,
        file_path=path,
        size_bytes=0,
        frame_count=0,
        started_at=datetime.utcnow(),
        retention_expires_at=datetime.utcnow() + timedelta(days=retention_days),
        status="active",
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    logger.info("recording %d started for session %d", rec.id, session_id)
    return rec


def add_marker(session_id: int, label: str) -> None:
    """PRA-148: write a marker frame to the live recording, if any.

    No-op when no recording is in progress (e.g. attach to a session whose
    recording was disabled or already finalized). Safe to call from the WS
    handler — never raises.
    """
    with _writers_lock:
        writer = _writers.get(session_id)
    if writer is None:
        return
    try:
        writer.write_marker(label)
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("recording marker for session %d failed: %s", session_id, e)


def stop_recording(db: DbSession, session_id: int) -> Optional[Recording]:
    """Finalize the writer and update the Recording row."""
    with _writers_lock:
        writer = _writers.pop(session_id, None)
    if writer is not None:
        writer.close()

    rec = db.query(Recording).filter(Recording.session_id == session_id).first()
    if rec is None:
        return None
    rec.ended_at = datetime.utcnow()
    rec.status = "finalized"
    if writer is not None:
        rec.frame_count = writer.frames
        rec.size_bytes = writer.size
    else:
        # Writer wasn't in memory (e.g. backend restart mid-session); fall
        # back to filesystem stat so the UI shows a reasonable value.
        try:
            st = os.stat(rec.file_path)
            rec.size_bytes = st.st_size
        except OSError:
            pass
    db.commit()
    db.refresh(rec)
    logger.info(
        "recording %d finalized (%d frames, %d bytes)",
        rec.id,
        rec.frame_count,
        rec.size_bytes,
    )
    return rec


def stream_cast(rec: Recording) -> Iterator[bytes]:
    """Generator yielding raw .cast file bytes for an HTTP download."""
    if not rec.file_path or not os.path.exists(rec.file_path):
        raise RecordingError("recording file missing")
    with open(rec.file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            yield chunk


def load_frames(rec: Recording) -> List[Any]:
    """Read the .cast file back as a list of frames (for JSON API fallback)."""
    if not rec.file_path or not os.path.exists(rec.file_path):
        return []
    out: List[Any] = []
    with open(rec.file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


# --------------------------------------------------------------- sweeper


def sweep_expired(db: Optional[DbSession] = None) -> int:
    """Delete recordings past their retention_expires_at."""
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        now = datetime.utcnow()
        expired = (
            db.query(Recording)
            .filter(
                Recording.retention_expires_at <= now,
                Recording.status != "pruned",
            )
            .all()
        )
        n = 0
        for rec in expired:
            try:
                if rec.file_path and os.path.exists(rec.file_path):
                    os.unlink(rec.file_path)
            except OSError as e:
                logger.warning("unlink %s: %s", rec.file_path, e)
            rec.status = "pruned"
            n += 1
        if n:
            db.commit()
        return n
    finally:
        if own_db:
            db.close()
