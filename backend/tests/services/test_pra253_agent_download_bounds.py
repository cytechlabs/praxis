"""PRA-253: agent-backed downloads are bounded, not full-body buffered.

The old ``_download_via_agent`` collected the whole response into one growing
``bytes`` object (``received += chunk``) before yielding a single giant buffer to
FastAPI — quadratic copying, up to the 1 GiB agent cap resident in RAM per
request, multiplied across concurrent downloads. The fix spools the agent stream
to a bounded, 0600 temp file (hashing + counting as it writes), then streams that
file back to FastAPI in fixed ``CHUNK``-sized reads, deleting the temp file in a
``finally``.

These tests prove:

- a large multi-chunk under-cap download succeeds with correct size + sha and is
  yielded in bounded ``CHUNK``-sized pieces (never one full-body buffer),
  regardless of the producer's chunk sizes;
- a declared oversize is rejected BEFORE the body is consumed;
- an actual oversize is rejected WHILE consuming;
- both over-cap paths fail closed and mark the audit row ``error`` (size 0, no
  sha);
- the temp spool file is always deleted;
- concurrent downloads each spool to their own temp file and yield bounded
  pieces — no path buffers a whole body in process memory.
"""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from app.services import file_transfer_service as fts
from app.services.transport import TransportError


@dataclass
class _SystemStub:
    id: int = 7
    hostname: str = "host.test"
    transport_preference: str = "agent"


class _FakeStream:
    """Stands in for ``FileGetStream`` — a declared ``size`` plus an async
    ``chunks`` iterator and an awaitable ``close``."""

    def __init__(self, chunks, size=0):
        self.size = size
        self.closed = False

        async def _gen():
            for c in chunks:
                yield c

        self.chunks = _gen()

    async def close(self):
        self.closed = True


def _run_agent_download(system, chunks, *, size=0, cap=None, capture_created=None):
    """Drive ``_download_via_agent`` end to end with a fake AgentTransport whose
    ``open_file_get`` returns a ``_FakeStream`` over ``chunks``. Returns
    ``(yielded_chunks, finish_mock, stream_holder)``. The audit finalize is
    captured via a patched ``_finish_audit``; ``SessionLocal`` returns a mock whose
    query resolves to a truthy row so finalize always fires.
    """
    stream_holder = {}

    def _maybe_cap():
        if cap is not None:
            return patch.object(fts, "AGENT_TRANSFER_MAX_BYTES", cap)
        return patch.object(
            fts, "AGENT_TRANSFER_MAX_BYTES", fts.AGENT_TRANSFER_MAX_BYTES
        )

    finish = MagicMock()

    async def _open_fg(path):
        stream = _FakeStream(chunks, size=size)
        stream_holder["stream"] = stream
        return stream

    real_mkstemp = fts.tempfile.mkstemp

    def _spy_mkstemp(*a, **k):
        fd, p = real_mkstemp(*a, **k)
        if capture_created is not None:
            capture_created.append(p)
        return fd, p

    with patch(
        "app.services.transport.agent.AgentTransport"
    ) as agent_cls, patch.object(fts, "_finish_audit", finish), patch(
        "app.db.session.SessionLocal", return_value=MagicMock()
    ), patch.object(
        fts.tempfile, "mkstemp", _spy_mkstemp
    ), _maybe_cap():
        agent_cls.return_value.open_file_get = _open_fg
        gen = fts._download_via_agent(MagicMock(), system, "/etc/hosts", 1)
        yielded = list(gen)

    return yielded, finish, stream_holder


def test_large_multichunk_under_cap_streams_bounded():
    """A 512 KiB body delivered as eight 64 KiB producer chunks is spooled and
    re-emitted in bounded pieces (each <= CHUNK), never one full-body buffer, with
    the correct total size and sha256 recorded on the audit row."""
    system = _SystemStub()
    body = bytes((i * 7) % 256 for i in range(512 * 1024))
    # Producer hands us oddly sized chunks; re-emission must still be CHUNK-bounded.
    producer_chunks = [body[i : i + 100_000] for i in range(0, len(body), 100_000)]
    assert len(producer_chunks) > 1

    yielded, finish, holder = _run_agent_download(system, producer_chunks)

    # Reassembled bytes are exactly the body.
    assert b"".join(yielded) == body
    # Bounded re-emission: more than one piece, none larger than CHUNK. This is the
    # anti-"one giant yield" assertion — a full-body buffer would be a single yield
    # of 512 KiB.
    assert len(yielded) > 1
    assert all(len(c) <= fts.CHUNK for c in yielded)
    assert max(len(c) for c in yielded) == fts.CHUNK

    # Audit finalized success with size + sha.
    finish.assert_called_once()
    kwargs = finish.call_args.kwargs
    assert kwargs["status"] == "success"
    assert kwargs["size_bytes"] == len(body)
    assert kwargs["sha256"] == hashlib.sha256(body).hexdigest()
    assert kwargs["error_message"] is None
    assert holder["stream"].closed is True


def test_declared_over_cap_rejected_before_consuming():
    """When the stream declares a size over the cap, the body is never consumed —
    the download fails closed and the audit row is marked error with size 0."""
    system = _SystemStub()

    consumed = {"iterated": False}

    def _tripwire():
        # A generator whose first iteration would explode — proves we bail before
        # touching the body.
        consumed["iterated"] = True
        raise AssertionError("body must not be consumed when declared size > cap")
        yield b""  # pragma: no cover - makes this a generator

    finish = MagicMock()

    async def _open_fg(path):
        stream = _FakeStream([], size=0)
        # Replace chunks with the tripwire generator; declare an oversize.
        stream.chunks = _tripwire()
        stream.size = 5_000
        return stream

    with patch(
        "app.services.transport.agent.AgentTransport"
    ) as agent_cls, patch.object(fts, "_finish_audit", finish), patch(
        "app.db.session.SessionLocal", return_value=MagicMock()
    ), patch.object(
        fts, "AGENT_TRANSFER_MAX_BYTES", 1_000
    ):
        agent_cls.return_value.open_file_get = _open_fg
        gen = fts._download_via_agent(MagicMock(), system, "/big", 1)
        with pytest.raises(fts.FileTransferError, match="exceeded max size"):
            list(gen)

    assert consumed["iterated"] is False, "declared oversize must skip body consume"
    finish.assert_called_once()
    kwargs = finish.call_args.kwargs
    assert kwargs["status"] == "error"
    assert kwargs["size_bytes"] == 0
    assert kwargs["sha256"] is None
    assert "exceeded max size" in (kwargs["error_message"] or "")


def test_actual_over_cap_rejected_while_consuming():
    """A stream that declares no size (0) but delivers more bytes than the cap is
    rejected mid-consume; the download fails closed and the audit is error."""
    system = _SystemStub()
    # Cap 150 KiB; deliver 300 KiB in 64 KiB chunks. size=0 => no declared reject,
    # so the running-total guard must catch it while writing the spool file.
    cap = 150 * 1024
    chunks = [b"\xab" * (64 * 1024) for _ in range(5)]

    yielded = None
    finish = MagicMock()

    async def _open_fg(path):
        return _FakeStream(chunks, size=0)

    with patch(
        "app.services.transport.agent.AgentTransport"
    ) as agent_cls, patch.object(fts, "_finish_audit", finish), patch(
        "app.db.session.SessionLocal", return_value=MagicMock()
    ), patch.object(
        fts, "AGENT_TRANSFER_MAX_BYTES", cap
    ):
        agent_cls.return_value.open_file_get = _open_fg
        gen = fts._download_via_agent(MagicMock(), system, "/big", 1)
        with pytest.raises(fts.FileTransferError, match="exceeded max size"):
            yielded = list(gen)

    assert yielded is None
    finish.assert_called_once()
    kwargs = finish.call_args.kwargs
    assert kwargs["status"] == "error"
    assert kwargs["size_bytes"] == 0
    assert kwargs["sha256"] is None
    assert "exceeded max size" in (kwargs["error_message"] or "")


def test_transport_error_marks_audit_error_and_fails_closed():
    """A producer-side TransportError propagates as a FileTransferError and marks
    the audit error — no silent truncation to a 'success' partial body."""
    system = _SystemStub()
    finish = MagicMock()

    async def _boom_gen():
        yield b"partial"
        raise TransportError("agent tunnel dropped")

    async def _open_fg(path):
        stream = _FakeStream([], size=0)
        stream.chunks = _boom_gen()
        return stream

    with patch(
        "app.services.transport.agent.AgentTransport"
    ) as agent_cls, patch.object(fts, "_finish_audit", finish), patch(
        "app.db.session.SessionLocal", return_value=MagicMock()
    ):
        agent_cls.return_value.open_file_get = _open_fg
        gen = fts._download_via_agent(MagicMock(), system, "/etc/hosts", 1)
        with pytest.raises(fts.FileTransferError, match="download failed"):
            list(gen)

    finish.assert_called_once()
    kwargs = finish.call_args.kwargs
    assert kwargs["status"] == "error"
    assert kwargs["sha256"] is None
    assert kwargs["error_message"]


def test_unexpected_stream_error_fails_closed_and_marks_error():
    """A non-transport error mid-spool (e.g. a broker truncation raising a plain
    exception) must fail closed: the audit is marked error and the exception
    propagates, never a silent 'success' on partial data."""
    system = _SystemStub()
    finish = MagicMock()

    async def _truncating_gen():
        yield b"first-part"
        # BrokerFileGetStream.iter_bytes raises on truncation; simulate a
        # non-Transport/Transfer exception type here.
        raise RuntimeError("stream truncated: consumed < declared size")

    async def _open_fg(path):
        stream = _FakeStream([], size=0)
        stream.chunks = _truncating_gen()
        return stream

    with patch(
        "app.services.transport.agent.AgentTransport"
    ) as agent_cls, patch.object(fts, "_finish_audit", finish), patch(
        "app.db.session.SessionLocal", return_value=MagicMock()
    ):
        agent_cls.return_value.open_file_get = _open_fg
        gen = fts._download_via_agent(MagicMock(), system, "/etc/hosts", 1)
        with pytest.raises(RuntimeError, match="truncated"):
            list(gen)

    finish.assert_called_once()
    kwargs = finish.call_args.kwargs
    assert kwargs["status"] == "error"
    assert kwargs["sha256"] is None
    assert "truncated" in (kwargs["error_message"] or "")


def test_temp_spool_file_is_deleted_after_success():
    """The 0600 temp spool file must not linger after a successful stream."""
    system = _SystemStub()
    created: list[str] = []
    body = b"x" * (200 * 1024)
    chunks = [body[i : i + fts.CHUNK] for i in range(0, len(body), fts.CHUNK)]

    yielded, finish, _ = _run_agent_download(system, chunks, capture_created=created)

    assert b"".join(yielded) == body
    assert len(created) == 1, "exactly one spool file per download"
    assert not os.path.exists(created[0]), "temp spool file must be deleted"


def test_temp_spool_file_is_deleted_after_over_cap():
    """Even when the download fails over-cap, the spool file is cleaned up."""
    system = _SystemStub()
    created: list[str] = []
    cap = 64 * 1024
    chunks = [b"z" * (64 * 1024) for _ in range(4)]

    with pytest.raises(fts.FileTransferError, match="exceeded max size"):
        _run_agent_download(system, chunks, cap=cap, capture_created=created)

    assert len(created) == 1
    assert not os.path.exists(created[0]), "temp spool file must be deleted on failure"


def test_concurrent_downloads_each_spool_bounded():
    """Several downloads run concurrently. Each spools to its OWN temp file and
    yields bounded CHUNK-sized pieces — the regression signal for the old code,
    which would have held every full body in process memory at once.

    The patches are installed ONCE around all threads (``unittest.mock.patch``
    mutates shared module state and is not thread-safe, so per-thread patch blocks
    would stomp each other). The fake ``open_file_get`` builds a fresh stream per
    call, so concurrent workers never share a generator. Correctness is checked by
    reassembling each worker's bytes rather than inspecting the shared finalize
    mock.
    """
    system = _SystemStub()
    n = 6
    body = bytes((i * 13) % 256 for i in range(300 * 1024))
    expected_sha = hashlib.sha256(body).hexdigest()
    created: list[str] = []
    created_lock = threading.Lock()

    results: dict[int, dict] = {}
    barrier = threading.Barrier(n)

    real_mkstemp = fts.tempfile.mkstemp

    def _spy_mkstemp(*a, **k):
        fd, p = real_mkstemp(*a, **k)
        with created_lock:
            created.append(p)
        return fd, p

    async def _open_fg(path):
        # Fresh oddly-chunked producer per call (generators aren't reusable).
        producer = [body[i : i + 40_000] for i in range(0, len(body), 40_000)]
        return _FakeStream(producer, size=0)

    def _worker(idx: int) -> None:
        gen = fts._download_via_agent(MagicMock(), system, "/etc/hosts", 1)
        barrier.wait(timeout=10)  # release all workers together
        chunks = list(gen)
        results[idx] = {
            "bytes": b"".join(chunks),
            "max_chunk": max(len(c) for c in chunks),
            "n_chunks": len(chunks),
        }

    with patch(
        "app.services.transport.agent.AgentTransport"
    ) as agent_cls, patch.object(fts, "_finish_audit", MagicMock()), patch(
        "app.db.session.SessionLocal", return_value=MagicMock()
    ), patch.object(
        fts.tempfile, "mkstemp", _spy_mkstemp
    ):
        agent_cls.return_value.open_file_get = _open_fg
        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

    assert len(results) == n
    for idx, r in results.items():
        assert r["bytes"] == body, f"worker {idx} body mismatch"
        assert hashlib.sha256(r["bytes"]).hexdigest() == expected_sha
        # Bounded re-emission per worker — never a single full-body yield.
        assert r["n_chunks"] > 1
        assert r["max_chunk"] <= fts.CHUNK

    # Each concurrent download used its own spool file, and none linger.
    assert len(created) == n
    for p in created:
        assert not os.path.exists(p), f"temp spool {p} must be deleted"
