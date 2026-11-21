"""Disposable SSH/SFTP and agent fixtures for download tests (PRA-429).

Everything here is synthetic and lives in memory: a fake SFTP server that
serves lazily generated, deterministic content (so a "large" file costs no
memory), and a fake broker that feeds the real ``BrokerFileGetStream`` /
``AgentTransport`` mapping. The file-transfer service, the route, the audit
helpers and the transport error mapping all run for real on top of them; only
the network edge is replaced.

Each remote path is described by a ``RemoteFile``. A ``Tracker`` records the
resources the code under test opened and closed so cleanup is observable.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import os
import stat as stat_mod
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, AsyncIterator, Callable, Dict, Iterator, Optional
from unittest.mock import patch

import httpx

from app.services import file_transfer_service as fts
from app.services.broker_client import BrokerError, BrokerFileGetStream

_BASE = bytes((i * 31 + 7) & 0xFF for i in range(65521))
_BASE3 = _BASE * 3
SPOOL_PREFIX = "praxis-agent-dl-"


def content_at(offset: int, n: int) -> bytes:
    """Deterministic content slice; any offset, any n <= 64 KiB."""
    start = offset % len(_BASE)
    return _BASE3[start : start + n]


def content_sha256(size: int) -> str:
    sha = hashlib.sha256()
    offset = 0
    while offset < size:
        n = min(64 * 1024, size - offset)
        sha.update(content_at(offset, n))
        offset += n
    return sha.hexdigest()


@dataclass
class RemoteFile:
    """One scripted remote path.

    ``size`` is what the host reports (stat / agent header). ``available`` is
    how many bytes the body really delivers before ending (defaults to size);
    a smaller value models a file that shrank or a stream that closed early.
    ``fail_after`` makes the body raise after that many bytes.
    """

    size: int = 0
    available: Optional[int] = None
    stat_errno: Optional[int] = None
    open_errno: Optional[int] = None
    is_dir: bool = False
    mode: int = stat_mod.S_IFREG | 0o644
    fail_after: Optional[int] = None
    # Exception raised at ``fail_after`` (default: a connection reset).
    fail_exc: Optional[BaseException] = None
    # Reports st_size 0 while serving ``available`` bytes (pseudo files).
    reports_zero_size: bool = False
    # Optional hook called with the running byte offset before each read.
    on_read: Optional[Callable[[int], None]] = None

    def body_len(self) -> int:
        return self.size if self.available is None else self.available


@dataclass
class Tracker:
    """Thread-safe counters for opened/closed resources."""

    sessions_opened: int = 0
    sessions_closed: int = 0
    files_opened: int = 0
    files_closed: int = 0
    broker_streams_opened: int = 0
    broker_streams_closed: int = 0
    bytes_read: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def bump(self, name: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + n)

    @property
    def leaked(self) -> int:
        return (
            (self.sessions_opened - self.sessions_closed)
            + (self.files_opened - self.files_closed)
            + (self.broker_streams_opened - self.broker_streams_closed)
        )


def spool_files() -> list:
    """Agent spool files currently on disk (must be empty after cleanup)."""
    root = tempfile.gettempdir()
    return [n for n in os.listdir(root) if n.startswith(SPOOL_PREFIX)]


# ------------------------------------------------------------------ SSH


class _FakeHandle:
    def __init__(self, spec: RemoteFile, tracker: Tracker) -> None:
        self._spec = spec
        self._tracker = tracker
        self._offset = 0
        self._closed = False

    def prefetch(self, *_a, **_k) -> None:
        return None

    def read(self, n: int = -1) -> bytes:
        spec = self._spec
        if spec.on_read:
            spec.on_read(self._offset)
        if spec.fail_after is not None and self._offset >= spec.fail_after:
            raise spec.fail_exc or OSError(errno.ECONNRESET, "Socket is closed")
        limit = spec.body_len()
        if spec.fail_after is not None:
            limit = min(limit, spec.fail_after)
        n = 64 * 1024 if n is None or n < 0 else min(n, 64 * 1024)
        n = min(n, limit - self._offset)
        if n <= 0:
            return b""
        data = content_at(self._offset, n)
        self._offset += len(data)
        self._tracker.bump("bytes_read", len(data))
        return data

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._tracker.bump("files_closed")

    def __enter__(self) -> "_FakeHandle":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


class FakeSftp:
    """Stand-in for ``paramiko.SFTPClient`` serving ``RemoteFile`` specs."""

    def __init__(self, files: Dict[str, RemoteFile], tracker: Tracker) -> None:
        self._files = files
        self._tracker = tracker

    def _spec(self, path: str) -> RemoteFile:
        spec = self._files.get(path)
        if spec is None:
            raise OSError(errno.ENOENT, "No such file")
        return spec

    def stat(self, path: str) -> Any:
        spec = self._spec(path)
        if spec.stat_errno:
            raise OSError(spec.stat_errno, "stat refused")
        mode = (stat_mod.S_IFDIR | 0o755) if spec.is_dir else spec.mode
        size = 0 if spec.reports_zero_size else spec.size
        return SimpleNamespace(st_size=size, st_mode=mode, st_mtime=0)

    def open(self, path: str, _mode: str = "rb") -> _FakeHandle:
        spec = self._spec(path)
        if spec.open_errno:
            raise OSError(spec.open_errno, "open refused")
        self._tracker.bump("files_opened")
        return _FakeHandle(spec, self._tracker)

    def close(self) -> None:
        self._tracker.bump("sessions_closed")


# ---------------------------------------------------------------- agent


class _FakeBrokerResponse:
    def __init__(self, spec: RemoteFile) -> None:
        self._spec = spec

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        spec = self._spec
        limit = spec.body_len()
        offset = 0
        while offset < limit:
            if spec.fail_after is not None and offset >= spec.fail_after:
                raise spec.fail_exc or httpx.ReadError("peer reset the stream")
            n = min(64 * 1024, limit - offset)
            if spec.fail_after is not None:
                n = min(n, spec.fail_after - offset)
            yield content_at(offset, n)
            offset += n
        if spec.fail_after is not None and offset >= spec.fail_after:
            raise spec.fail_exc or httpx.ReadError("peer reset the stream")


class _FakeCm:
    def __init__(self, tracker: Tracker) -> None:
        self._tracker = tracker

    async def __aexit__(self, *_exc: Any) -> None:
        self._tracker.bump("broker_streams_closed")


class FakeBroker:
    """Stand-in for ``BrokerClient`` serving ``RemoteFile`` specs.

    Pre-stream refusals use the same ``BrokerError`` reasons the real broker
    forwards from the Go agent (``not_found``, ``denied``, ``is_directory``,
    ``not_regular``, ``too_large``, ``read_failed``).
    """

    def __init__(
        self,
        files: Dict[str, RemoteFile],
        tracker: Tracker,
        refuse_reason: Optional[str] = None,
    ) -> None:
        self._files = files
        self._tracker = tracker
        self._refuse = refuse_reason

    async def file_get(
        self, system_id: int, path: str, *, max_bytes: int = 0
    ) -> BrokerFileGetStream:
        if self._refuse:
            raise BrokerError(self._refuse, "pre-stream failure")
        spec = self._files.get(path)
        if spec is None or spec.stat_errno == errno.ENOENT:
            raise BrokerError("not_found", "pre-stream failure")
        if spec.stat_errno == errno.EACCES or spec.open_errno == errno.EACCES:
            raise BrokerError("denied", "pre-stream failure")
        if spec.is_dir:
            raise BrokerError("is_directory", "pre-stream failure")
        if spec.open_errno:
            raise BrokerError("read_failed", "pre-stream failure")
        self._tracker.bump("broker_streams_opened")
        return BrokerFileGetStream(
            _cm=_FakeCm(self._tracker),
            _response=_FakeBrokerResponse(spec),
            size=spec.size,
            mode="0o644",
        )

    async def __aexit__(self, *_exc: Any) -> None:
        return None


# ---------------------------------------------------------------- patching


class _NoCloseSession:
    """Proxy so code that opens and closes its own session can share the
    test transaction without ending it."""

    def __init__(self, session: Any) -> None:
        self._session = session

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    def close(self) -> None:
        return None


@dataclass
class TransferEnv:
    """Handle returned by ``patched_transfer_env``."""

    files: Dict[str, RemoteFile]
    tracker: Tracker
    transports: Dict[int, str]
    connect_error: Optional[str] = None
    broker_refusal: Optional[str] = None

    def add(self, path: str, spec: Optional[RemoteFile] = None, **kw: Any) -> None:
        self.files[path] = spec or RemoteFile(**kw)


@contextmanager
def patched_transfer_env(
    transports: Dict[int, str],
    *,
    session: Any = None,
    gate: bool = True,
    patch_audit: bool = False,
) -> Iterator[TransferEnv]:
    """Patch the network edge of ``file_transfer_service``.

    ``transports`` maps system id to ``"ssh"`` or ``"agent"``. With
    ``session`` the audit finalizer joins that (test) session. With
    ``gate=False`` the real authorization gate runs.
    """
    env = TransferEnv(files={}, tracker=Tracker(), transports=transports)

    @contextmanager
    def _fake_open_sftp(_db, _user, _system, _login):
        if env.connect_error:
            raise fts.FileTransferError(env.connect_error)
        env.tracker.bump("sessions_opened")
        sftp = FakeSftp(env.files, env.tracker)
        try:
            yield sftp
        finally:
            sftp.close()

    async def _fake_resolve(system, _db):
        return transports[system.id], None

    patches = [
        patch.object(fts, "_open_sftp", _fake_open_sftp),
        patch.object(fts, "_resolve_file_transport", _fake_resolve),
        patch.object(
            fts,
            "BrokerClient",
            lambda: FakeBroker(env.files, env.tracker, env.broker_refusal),
        ),
    ]
    if gate:

        def _fake_gate(db, _user, system_id):
            from app.db.models import System

            system = db.query(System).filter(System.id == system_id).first()
            return system, "ops"

        patches.append(patch.object(fts, "_gate", _fake_gate))
    if session is not None:
        patches.append(
            patch("app.db.session.SessionLocal", lambda: _NoCloseSession(session))
        )
    for p in patches:
        p.start()
    try:
        yield env
    finally:
        for p in reversed(patches):
            p.stop()


def run_in_loop(coro: Any) -> Any:
    """Run a coroutine to completion on a fresh loop (test convenience)."""
    return asyncio.run(coro)
