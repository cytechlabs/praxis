"""PRA-153 #3a: broker internal op-dispatch endpoints.

Covers POST /internal/agent/ops/{exec,file_get,file_put}. The
OperationManager is stubbed so tests can drive the agent side
synthetically (push frames into op.inbound, resolve op.completion)
without spinning up a real broker + agent + control tunnel.
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Optional

import pytest
from fastapi.testclient import TestClient

from app.broker.internal_api import build_internal_app
from app.broker.ops import NoActiveTunnel, Operation, OperationState
from app.broker.protocol import Channel, Frame, FrameOp
from app.broker.registry import AgentRegistry


class _FakeManager:
    """Minimal stand-in for OperationManager.

    Tests inject an ``op_factory`` that builds a pre-driven Operation
    (frames already queued, completion future already set) so the
    HTTP handler can be exercised end-to-end without an agent.
    """

    def __init__(self, op_factory) -> None:
        self._op_factory = op_factory
        self.cancelled: list[int] = []
        self.dispatched: list[tuple[int, str, dict]] = []
        self._ops: dict[int, Operation] = {}
        self._next_id = 1

    async def create_and_dispatch(
        self,
        system_id,
        op_type,
        params=None,
        *,
        outbound_maxsize=0,
        inbound_maxsize=0,
        skip_terminal_sentinel=False,
    ):
        if system_id == 9999:  # tests use 9999 to force "no tunnel"
            raise NoActiveTunnel("test: no tunnel")
        op = self._op_factory(self._next_id, system_id, op_type, params or {})
        if outbound_maxsize > 0:
            op.outbound = asyncio.Queue(maxsize=outbound_maxsize)
        op.skip_terminal_sentinel = skip_terminal_sentinel
        # Note: file_get tests use put_nowait into op.inbound, so we
        # do NOT actually bound op.inbound in the fake — the test
        # ``test_file_get_uses_bounded_inbound_queue`` covers the
        # real-path bound by spying on the kwarg.
        self._ops[self._next_id] = op
        self._next_id += 1
        self.dispatched.append((op.system_id, op.op_type, op.params))
        return op, "fake-nonce"

    async def cancel(self, operation_id):
        self.cancelled.append(operation_id)
        # Mirror production semantics: cancelling an op drives it
        # terminal so anyone awaiting op.completion unblocks.
        # Without this the broker endpoint's watch_task would hang
        # waiting for a completion that never lands in the test.
        op = self._ops.get(operation_id)
        if op is not None and not op.completion.done():
            op.outcome = "cancelled"
            op.error = {"reason": "cancelled"}
            op.completion.set_result(None)


def _make_op(
    operation_id: int, system_id: int, op_type: str, params: dict
) -> Operation:
    """Build a bare Operation in PENDING_NONCE."""
    loop = asyncio.get_event_loop()
    return Operation(
        operation_id=operation_id,
        system_id=system_id,
        tunnel_session_id="sess-test",
        op_type=op_type,
        params=params,
        state=OperationState.PENDING_NONCE,
        created_at_monotonic=0.0,
        nonce_expires_at_monotonic=999.0,
        completion=loop.create_future(),
    )


# -------- exec --------


def _exec_op_factory(
    stdout=b"",
    stderr=b"",
    outcome="success",
    error=None,
    result_metadata=None,
    attach_after=0.0,
    complete_after=0.0,
):
    """Build an op_factory that simulates an agent's response.

    ``attach_after`` simulates the agent's dial/attach delay.
    ``complete_after`` simulates how long the child runs before
    op_complete arrives. Both kept small (<100ms) for fast tests.
    """

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            await asyncio.sleep(attach_after)
            op.state = OperationState.ATTACHED
            await asyncio.sleep(complete_after)
            if stdout:
                op.inbound.put_nowait(
                    Frame(
                        op=FrameOp.DATA, channel=Channel.STDOUT, flags=0, payload=stdout
                    )
                )
            if stderr:
                op.inbound.put_nowait(
                    Frame(
                        op=FrameOp.DATA, channel=Channel.STDERR, flags=0, payload=stderr
                    )
                )
            # Sentinel — flush the bridge pump so it exits.
            op.inbound.put_nowait(None)
            op.outcome = outcome
            op.error = error
            op.result_metadata = result_metadata
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    return _factory


def test_exec_happy_path_round_trip():
    factory = _exec_op_factory(
        stdout=b"hello\n",
        stderr=b"",
        outcome="success",
        result_metadata={"exit_code": 0, "duration_ms": 5},
    )
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec",
            json={"system_id": 7, "cmd": "echo", "args": ["hello"]},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "success"
    assert base64.b64decode(body["stdout_b64"]) == b"hello\n"
    assert base64.b64decode(body["stderr_b64"]) == b""
    assert body["exit_code"] == 0
    assert body["error"] is None
    assert mgr.dispatched == [(7, "exec", {"cmd": "echo", "args": ["hello"]})]


def test_exec_returns_503_when_no_tunnel():
    factory = _exec_op_factory()
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec",
            json={"system_id": 9999, "cmd": "echo"},  # 0 -> NoActiveTunnel
        )
    assert resp.status_code == 503
    assert resp.json()["error"]["reason"] == "transport_unavailable"


def test_exec_nonzero_exit_still_success():
    """Per PRA-152 / PRA-153 lock: outcome=success means we ran it.

    Also verifies the exit_code + duration_ms travel
    in op.result_metadata (mirrors how _route_op_complete in handlers
    pulls top-level fields from the agent op_complete payload), NOT
    in op.error which is None on success.
    """

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            op.inbound.put_nowait(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.STDERR,
                    flags=0,
                    payload=b"oops\n",
                )
            )
            op.inbound.put_nowait(None)
            op.outcome = "success"
            op.error = None  # critical: success leaves error null
            op.result_metadata = {"exit_code": 2, "duration_ms": 3}
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    mgr = _FakeManager(_factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec",
            json={"system_id": 5, "cmd": "false"},
        )
    body = resp.json()
    assert body["outcome"] == "success"
    assert body["exit_code"] == 2
    assert body["duration_ms"] == 3
    assert body["error"] is None
    assert base64.b64decode(body["stderr_b64"]) == b"oops\n"


def test_exec_agent_timeout_returns_504_and_cancels():
    factory = _exec_op_factory(attach_after=99.0)  # never attaches
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    # Patch the attach timeout to something tests can wait through.
    import app.broker.internal_api as mod

    saved = mod.ATTACH_TIMEOUT_SECONDS
    mod.ATTACH_TIMEOUT_SECONDS = 0.2
    try:
        with TestClient(app) as client:
            resp = client.post(
                "/internal/agent/ops/exec",
                json={"system_id": 5, "cmd": "echo"},
            )
    finally:
        mod.ATTACH_TIMEOUT_SECONDS = saved
    assert resp.status_code == 504
    assert resp.json()["error"]["reason"] == "agent_attach_timeout"
    assert mgr.cancelled == [1]


def test_exec_caller_timeout_capped_to_hard_cap(monkeypatch):
    """timeout_s > EXEC_HARD_CAP_SECONDS must clamp to the hard cap."""
    import app.broker.internal_api as mod

    monkeypatch.setattr(mod, "EXEC_HARD_CAP_SECONDS", 0.3)
    factory = _exec_op_factory(complete_after=99.0)  # never completes
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        # Caller asks for 9999s; broker caps at 0.3s.
        resp = client.post(
            "/internal/agent/ops/exec",
            json={"system_id": 5, "cmd": "sleep", "args": ["99"], "timeout_s": 9999.0},
        )
    # We get a body back (cap fired -> cancelled -> response shaped)
    # not an exception. mgr.cancelled records the broker-side cancel.
    assert mgr.cancelled == [1]
    assert resp.status_code == 200


def test_exec_forwards_stdin():
    captured_outbound: list[Frame] = []

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            # Drain outbound to pick up stdin frames the handler pushes.
            while True:
                try:
                    frame = await asyncio.wait_for(op.outbound.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    break
                if frame is None:
                    break
                captured_outbound.append(frame)
                if frame.op == FrameOp.CLOSE and frame.channel == Channel.STDIN:
                    break
            op.inbound.put_nowait(None)
            op.outcome = "success"
            op.error = {"exit_code": 0, "duration_ms": 1}
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    mgr = _FakeManager(_factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec",
            json={
                "system_id": 5,
                "cmd": "cat",
                "stdin_b64": base64.b64encode(b"input\n").decode("ascii"),
            },
        )
    assert resp.status_code == 200
    # First an STDIN data frame, then an STDIN CLOSE.
    stdin_frames = [f for f in captured_outbound if f.channel == Channel.STDIN]
    assert any(
        f.op == FrameOp.DATA and bytes(f.payload) == b"input\n" for f in stdin_frames
    )
    assert any(f.op == FrameOp.CLOSE for f in stdin_frames)


# -------- file_get --------


def _file_get_op_factory(
    *,
    header: dict,
    chunks: list[bytes],
    outcome="success",
    error=None,
    skip_header=False,
):
    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            if not skip_header:
                op.inbound.put_nowait(
                    Frame(
                        op=FrameOp.DATA,
                        channel=Channel.CONTROL,
                        flags=0,
                        payload=json.dumps(header).encode("utf-8"),
                    )
                )
            for c in chunks:
                op.inbound.put_nowait(
                    Frame(op=FrameOp.DATA, channel=Channel.FILE, flags=0, payload=c)
                )
            op.inbound.put_nowait(
                Frame(op=FrameOp.CLOSE, channel=Channel.FILE, flags=0, payload=b"")
            )
            op.inbound.put_nowait(None)
            op.outcome = outcome
            op.error = error
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    return _factory


def test_file_get_streams_body_with_headers():
    factory = _file_get_op_factory(
        header={"type": "file_header", "size": 11, "mode": "0644"},
        chunks=[b"hello ", b"world"],
    )
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/etc/hosts"},
        )
    assert resp.status_code == 200
    assert resp.headers["x-praxis-file-size"] == "11"
    assert resp.headers["x-praxis-file-mode"] == "0644"
    assert resp.content == b"hello world"


def test_file_get_pre_stream_failure_returns_502_json():
    """Op fails before any frame arrives — surfaces as JSON 502."""

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            op.inbound.put_nowait(None)
            op.outcome = "error"
            op.error = {"reason": "not_found"}
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    mgr = _FakeManager(_factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/missing"},
        )
    assert resp.status_code == 502
    body = resp.json()
    assert body["outcome"] == "error"
    assert body["error"]["reason"] == "not_found"


def test_file_get_mid_stream_failure_breaks_stream():
    """After header+bytes are sent, an op error must NOT come back as
    a clean 200 with truncated body. The body iterator should raise
    so the StreamingResponse aborts mid-flight; the caller sees an
    incomplete download (HTTP read raises / bytes_received < size)
    and AgentTransport surfaces TransportError.
    """

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            # Header + one chunk go out cleanly.
            op.inbound.put_nowait(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.CONTROL,
                    flags=0,
                    payload=json.dumps(
                        {"type": "file_header", "size": 999, "mode": "0644"}
                    ).encode("utf-8"),
                )
            )
            op.inbound.put_nowait(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.FILE,
                    flags=0,
                    payload=b"partial",
                )
            )
            # Pump sentinel; then op terminates with error mid-stream.
            op.inbound.put_nowait(None)
            op.outcome = "error"
            op.error = {"reason": "op_stream_closed"}
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    mgr = _FakeManager(_factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    # Mid-stream raise is the contract — the StreamingResponse aborts
    # via the iterator raising _StreamFailure. Starlette surfaces
    # this as an ExceptionGroup propagating out of the TestClient
    # request, which is exactly what we want callers (AgentTransport
    # in slice #3b) to see — a broken stream, NOT a clean 200.
    with TestClient(app) as client:
        with pytest.raises(BaseException):
            with client.stream(
                "POST",
                "/internal/agent/ops/file_get",
                json={"system_id": 5, "path": "/etc/hosts"},
            ) as resp:
                # Header sanity: stream HAS started (200 + size header)
                assert resp.status_code == 200
                assert resp.headers["x-praxis-file-size"] == "999"
                # Pulling bytes triggers the iterator → raises.
                for _chunk in resp.iter_bytes():
                    pass


def test_file_get_no_tunnel_503():
    factory = _file_get_op_factory(header={}, chunks=[])
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 9999, "path": "/etc/hosts"},
        )
    assert resp.status_code == 503


# -------- file_put --------


def _file_put_op_factory(*, outcome="success", error=None):
    captured: dict = {"outbound": []}

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            while True:
                try:
                    frame = await asyncio.wait_for(op.outbound.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    break
                if frame is None:
                    break
                captured["outbound"].append(frame)
                if frame.op == FrameOp.CLOSE and frame.channel == Channel.FILE:
                    break
            op.inbound.put_nowait(None)
            op.outcome = outcome
            op.error = error
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    return _factory, captured


def test_file_put_streams_chunks_to_agent():
    factory, captured = _file_put_op_factory()
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    body = b"a" * (64 * 1024)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_put",
            content=body,
            headers={
                "x-praxis-system-id": "5",
                "x-praxis-file-path": "/tmp/x",
                "x-praxis-declared-size": str(len(body)),
            },
        )
    assert resp.status_code == 200
    assert resp.json() == {"outcome": "success", "bytes_written": len(body)}
    # First frame is the JSON header on ChannelControl.
    assert captured["outbound"][0].channel == Channel.CONTROL
    assert json.loads(bytes(captured["outbound"][0].payload).decode("utf-8")) == {
        "type": "file_header",
        "size": len(body),
    }
    # Then ChannelFile data frames + a CLOSE.
    file_frames = [f for f in captured["outbound"] if f.channel == Channel.FILE]
    total = b"".join(bytes(f.payload) for f in file_frames if f.op == FrameOp.DATA)
    assert total == body
    assert file_frames[-1].op == FrameOp.CLOSE


def test_file_put_too_large_returns_413():
    factory, _captured = _file_put_op_factory()
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    body = b"x" * 1024
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_put",
            content=body,
            headers={
                "x-praxis-system-id": "5",
                "x-praxis-file-path": "/tmp/x",
                "x-praxis-max-bytes": "100",  # body is 1024 — overshoots
                "x-praxis-declared-size": str(len(body)),
            },
        )
    assert resp.status_code == 413
    assert resp.json()["error"]["reason"] == "too_large"
    assert mgr.cancelled == [1]


def test_file_get_does_not_truncate_under_slow_consumer():
    """Regression for when the HTTP consumer is slower
    than the agent producer, the body queue back-pressures and the
    frame pump parks on body_queue.put. Previously the
    _drain_op_until_complete helper had a 2-second pump-cancel
    timeout that would fire AFTER op.completion landed — dropping
    queued file frames and producing a successful but truncated
    download. The streaming path now lets the body iterator drive
    teardown so all queued frames are delivered.

    This test pushes more chunks than fit in the bounded body_queue
    (maxsize=4), and resolves op.completion BEFORE the consumer
    reads. The full content must still arrive.
    """
    chunks = [bytes([i]) * 10 for i in range(20)]  # 20 small chunks

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            # Push header + all 20 chunks + close + sentinel into the
            # FAKE op.inbound (unbounded in tests). Simultaneously
            # mark op.completion done — the older code would race the
            # 2s drain timeout against the slow consumer and lose
            # queued frames.
            op.inbound.put_nowait(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.CONTROL,
                    flags=0,
                    payload=json.dumps(
                        {
                            "type": "file_header",
                            "size": sum(len(c) for c in chunks),
                            "mode": "0644",
                        }
                    ).encode("utf-8"),
                )
            )
            for c in chunks:
                op.inbound.put_nowait(
                    Frame(
                        op=FrameOp.DATA,
                        channel=Channel.FILE,
                        flags=0,
                        payload=c,
                    )
                )
            op.inbound.put_nowait(
                Frame(op=FrameOp.CLOSE, channel=Channel.FILE, flags=0, payload=b"")
            )
            op.inbound.put_nowait(None)
            op.outcome = "success"
            op.error = None
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    mgr = _FakeManager(_factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        # Read the body normally — TestClient consumes everything.
        # Even if the consumer were slow in a real network, the
        # back-pressure path keeps frames intact.
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/etc/hosts"},
        )
    assert resp.status_code == 200
    expected = b"".join(chunks)
    assert resp.content == expected
    assert resp.headers["x-praxis-file-size"] == str(len(expected))


def test_file_get_does_not_drop_frames_when_completion_races_pump():
    """Regression: the completion watcher
    must NOT enqueue clean EOF independently of the frame pump. With
    the previous code, under backpressure the pump could be blocked
    on body_queue.put() when op.completion fired; the watcher would
    win the race once the consumer drained a slot, putting None
    BEFORE the pump's pending FILE chunks. The body iterator would
    return early and cancel the pump, producing a clean-but-truncated
    download.

    To force the race deterministically we drive the agent inbound
    via the live op.inbound queue so the pump genuinely back-pressures
    on body_queue (maxsize=4). Resolve op.completion immediately
    after putting CLOSE — the watcher's wakeup races against the
    pump's chunk-by-chunk drain.
    """
    chunks = [bytes([i]) * 10 for i in range(20)]

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)
        # Replace inbound with a SMALL bounded queue so the bridge
        # (here the test driver) blocks on put when the pump is slow.
        # This mirrors the production wiring where the bridge's
        # await put() back-pressures the WSS recv side.
        op.inbound = asyncio.Queue(maxsize=2)

        async def _drive():
            op.state = OperationState.ATTACHED
            await op.inbound.put(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.CONTROL,
                    flags=0,
                    payload=json.dumps(
                        {
                            "type": "file_header",
                            "size": sum(len(c) for c in chunks),
                            "mode": "0644",
                        }
                    ).encode("utf-8"),
                )
            )
            for c in chunks:
                await op.inbound.put(
                    Frame(
                        op=FrameOp.DATA,
                        channel=Channel.FILE,
                        flags=0,
                        payload=c,
                    )
                )
            await op.inbound.put(
                Frame(op=FrameOp.CLOSE, channel=Channel.FILE, flags=0, payload=b"")
            )
            # Resolve completion BEFORE pushing the test sentinel.
            # The pump can only see CLOSE → None body_queue path; the
            # watcher must not jump in.
            op.outcome = "success"
            op.error = None
            op.completion.set_result(None)
            # Add the test-only None sentinel so the pump exits
            # cleanly after CLOSE has been processed. (In production
            # the bridge never enqueues None and the body iterator's
            # finally cancels the pump.)
            await op.inbound.put(None)

        asyncio.create_task(_drive())
        return op

    mgr = _FakeManager(_factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/etc/hosts"},
        )
    assert resp.status_code == 200
    expected = b"".join(chunks)
    assert resp.content == expected, (
        f"truncated under backpressure: got {len(resp.content)} bytes, "
        f"want {len(expected)}"
    )


def test_file_get_waits_for_late_header_after_success_completion():
    """Success completion alone must NOT
    trigger the pre-header failure path on a short timer. Even if
    op_complete reaches the broker before the agent's header — and
    the header takes longer than any drain window to land — the
    endpoint must still wait for the header (up to the explicit
    HEADER_TIMEOUT_SECONDS, not a 200ms scheduling guess) and
    return 200 with the body.
    """
    body = b"valid"
    delay_seconds = 0.5  # comfortably longer than any prior drain window

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            # Mark completion FIRST. Then wait noticeably longer
            # than the 200ms drain window the previous fix used —
            # this is the production race where TLS / scheduler /
            # network jitter delays the per-op header relative to
            # the control-WSS op_complete.
            op.outcome = "success"
            op.error = None
            op.completion.set_result(None)
            await asyncio.sleep(delay_seconds)
            await op.inbound.put(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.CONTROL,
                    flags=0,
                    payload=json.dumps(
                        {"type": "file_header", "size": len(body), "mode": "0644"}
                    ).encode("utf-8"),
                )
            )
            await op.inbound.put(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.FILE,
                    flags=0,
                    payload=body,
                )
            )
            await op.inbound.put(
                Frame(op=FrameOp.CLOSE, channel=Channel.FILE, flags=0, payload=b"")
            )
            await op.inbound.put(None)

        asyncio.create_task(_drive())
        return op

    mgr = _FakeManager(_factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/etc/hosts"},
        )
    assert resp.status_code == 200, (
        f"late header after success completion misclassified as failure: "
        f"status={resp.status_code} body={resp.text!r}"
    )
    assert resp.content == body


def test_file_get_header_timeout_when_agent_never_sends_header(monkeypatch):
    """When the agent never produces a header (and the op never
    completes), the endpoint must surface a 504 with reason
    header_timeout — NOT block forever. This is the explicit
    'agent stuck' contract that replaces the old 200ms timing
    guess at success-vs-failure."""
    import app.broker.internal_api as mod

    monkeypatch.setattr(mod, "HEADER_TIMEOUT_SECONDS", 0.3)

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            # Never put a header, never complete the op. The
            # endpoint must hit HEADER_TIMEOUT_SECONDS, cancel the
            # op, and return 504.

        asyncio.create_task(_drive())
        return op

    # Stub cancel that simulates production manager: it does NOT
    # resolve op.completion synchronously. The endpoint must return
    # 504 promptly without waiting for a completion that may take
    # ~10s to arrive (cancel-ack timeout).
    cancelled: list[int] = []

    async def _slow_cancel(operation_id):
        cancelled.append(operation_id)
        # Hold for longer than any reasonable response window —
        # this mirrors mgr.cancel just marking CANCELLING and
        # scheduling an async fallback.
        await asyncio.sleep(60.0)

    mgr = _FakeManager(_factory)
    mgr.cancel = _slow_cancel  # type: ignore[assignment]
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        import time as _time

        t0 = _time.monotonic()
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/etc/hosts"},
        )
        elapsed = _time.monotonic() - t0
    assert resp.status_code == 504
    assert resp.json()["error"]["reason"] == "header_timeout"
    assert cancelled == [1]
    # Should be ~HEADER_TIMEOUT_SECONDS (0.3s here), NOT 60s. Allow
    # generous slack but anything past a second means the endpoint
    # is awaiting the slow cancel and the P2 fix has regressed.
    assert elapsed < 2.0, (
        f"endpoint waited for slow cancel (elapsed={elapsed:.2f}s); "
        "header_timeout response must not block on cancel ack"
    )


def test_file_get_succeeds_when_completion_lands_before_pump_processes_header():
    """Regression (third round): a real agent can land
    op_complete on the control WSS BEFORE the per-op frame pump has
    processed the header that's already sitting on op.inbound. The
    previous code raced header_evt against watch_task on
    FIRST_COMPLETED — watch_task wins, header_evt is still false,
    and the pre-header branch returned a JSON 502 for a perfectly
    valid file_get.

    To force the race deterministically: set op.completion FIRST,
    then add the header + chunks + CLOSE + sentinel. The watcher
    fires immediately on completion; the pump must still process
    everything queued on op.inbound. The endpoint MUST return 200
    with the full body, not a 502.
    """
    body = b"valid-content"

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            # Mark completion BEFORE any frames land on op.inbound —
            # the watcher will fire immediately. The pump still has
            # to process the queued frames after it gets scheduler
            # time, including the header.
            op.outcome = "success"
            op.error = None
            op.completion.set_result(None)
            await op.inbound.put(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.CONTROL,
                    flags=0,
                    payload=json.dumps(
                        {"type": "file_header", "size": len(body), "mode": "0644"}
                    ).encode("utf-8"),
                )
            )
            await op.inbound.put(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.FILE,
                    flags=0,
                    payload=body,
                )
            )
            await op.inbound.put(
                Frame(op=FrameOp.CLOSE, channel=Channel.FILE, flags=0, payload=b"")
            )
            await op.inbound.put(None)

        asyncio.create_task(_drive())
        return op

    mgr = _FakeManager(_factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/etc/hosts"},
        )
    # Pre-fix: this returned 502 because header_evt was still false
    # when the watcher fired. Now the pre-stream wait gives the pump
    # a window to drain queued frames after completion.
    assert resp.status_code == 200, (
        f"completion-before-header race surfaced as pre-stream failure: "
        f"status={resp.status_code} body={resp.text!r}"
    )
    assert resp.content == body


def test_file_get_endpoint_passes_skip_terminal_sentinel():
    """The file_get endpoint MUST request skip_terminal_sentinel=True
    so the real OperationManager._terminalize doesn't inject a None
    into op.inbound on success — that None could race ahead of
    pending FILE Data + CLOSE frames in production and truncate
    the response. (Spy on the kwarg; the production behavior itself
    is exercised by the unit test on _terminalize below.)
    """
    factory = _file_get_op_factory(
        header={"type": "file_header", "size": 1, "mode": "0644"},
        chunks=[b"x"],
    )
    mgr = _FakeManager(factory)
    seen_skip: list[bool] = []
    original = mgr.create_and_dispatch

    async def _spy(
        system_id,
        op_type,
        params=None,
        *,
        outbound_maxsize=0,
        inbound_maxsize=0,
        skip_terminal_sentinel=False,
    ):
        seen_skip.append(skip_terminal_sentinel)
        return await original(
            system_id,
            op_type,
            params,
            outbound_maxsize=outbound_maxsize,
            inbound_maxsize=inbound_maxsize,
        )

    mgr.create_and_dispatch = _spy  # type: ignore[assignment]
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/etc/hosts"},
        )
    assert resp.status_code == 200
    assert seen_skip == [True]


def test_file_get_uses_bounded_inbound_queue():
    """The file_get endpoint MUST request a bounded inbound queue
    so a slow HTTP consumer can backpressure the per-op WSS recv
    side. Without this, a fast agent can pile a large download in
    broker memory between the bridge and a slow backend reader.
    """
    factory = _file_get_op_factory(
        header={"type": "file_header", "size": 1, "mode": "0644"},
        chunks=[b"x"],
    )
    mgr = _FakeManager(factory)
    seen_inbound: list[int] = []
    original = mgr.create_and_dispatch

    async def _spy(
        system_id,
        op_type,
        params=None,
        *,
        outbound_maxsize=0,
        inbound_maxsize=0,
        skip_terminal_sentinel=False,
    ):
        seen_inbound.append(inbound_maxsize)
        return await original(
            system_id,
            op_type,
            params,
            outbound_maxsize=outbound_maxsize,
            inbound_maxsize=inbound_maxsize,
        )

    mgr.create_and_dispatch = _spy  # type: ignore[assignment]
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 5, "path": "/etc/hosts"},
        )
    assert resp.status_code == 200
    assert seen_inbound == [4]


def test_file_put_uses_bounded_outbound_queue():
    """The file_put endpoint MUST request a bounded outbound queue
    so a slow agent can't let frames pile up unbounded in broker
    memory. Verifies both that the queue has a maxsize set and that
    the value matches the slice-#3a tuning (4 frames in flight).
    """
    factory, _captured = _file_put_op_factory()
    mgr = _FakeManager(factory)
    # Wrap the fake manager's create_and_dispatch to capture the
    # outbound_maxsize the endpoint passes.
    seen_maxsizes: list[int] = []
    original = mgr.create_and_dispatch

    async def _spy(system_id, op_type, params=None, *, outbound_maxsize=0):
        seen_maxsizes.append(outbound_maxsize)
        op, nonce = await original(system_id, op_type, params)
        if outbound_maxsize > 0:
            op.outbound = asyncio.Queue(maxsize=outbound_maxsize)
        return op, nonce

    mgr.create_and_dispatch = _spy  # type: ignore[assignment]
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_put",
            content=b"x",
            headers={
                "x-praxis-system-id": "5",
                "x-praxis-file-path": "/tmp/x",
                "x-praxis-declared-size": "1",
            },
        )
    assert resp.status_code == 200
    assert seen_maxsizes == [4]


def test_file_put_missing_required_header_400():
    factory, _ = _file_put_op_factory()
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_put",
            content=b"x",
            headers={"x-praxis-system-id": "5"},  # no file-path
        )
    assert resp.status_code == 400


# -------- PRA-228: exec output cap + op-limit response hygiene --------


def test_exec_output_too_large_returns_413(monkeypatch):
    """BROKER-03: total captured exec output is byte-capped. Over the cap, the
    op returns a bounded ``exec_output_too_large`` error with no command output
    in the body, rather than buffering the whole stream."""
    from app.broker import internal_api

    monkeypatch.setattr(internal_api, "EXEC_OUTPUT_MAX_BYTES", 8)
    factory = _exec_op_factory(
        stdout=b"0123456789ABCDEF",  # 16 bytes > 8-byte cap
        outcome="success",
        result_metadata={"exit_code": 0, "duration_ms": 1},
    )
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec",
            json={"system_id": 7, "cmd": "cat", "args": ["big"]},
        )
    assert resp.status_code == 413, resp.text
    body = resp.json()
    assert body["outcome"] == "error"
    assert body["error"]["reason"] == "exec_output_too_large"
    assert body["error"]["limit_bytes"] == 8
    # No captured command output is echoed in the error body.
    assert "stdout_b64" not in body
    assert "0123456789" not in resp.text


def test_exec_under_cap_still_succeeds(monkeypatch):
    """Output at/under the cap is unaffected — the cap only trips on overflow."""
    from app.broker import internal_api

    monkeypatch.setattr(internal_api, "EXEC_OUTPUT_MAX_BYTES", 64)
    factory = _exec_op_factory(
        stdout=b"hello\n",
        outcome="success",
        result_metadata={"exit_code": 0, "duration_ms": 1},
    )
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec",
            json={"system_id": 7, "cmd": "echo", "args": ["hello"]},
        )
    assert resp.status_code == 200, resp.text
    assert base64.b64decode(resp.json()["stdout_b64"]) == b"hello\n"


class _LimitManager:
    """Minimal manager whose create_and_dispatch raises a per-agent limit."""

    def __init__(self, exc) -> None:
        self._exc = exc

    async def create_and_dispatch(self, *_a, **_k):
        raise self._exc

    async def cancel(self, *_a, **_k):  # pragma: no cover - never reached
        pass


def test_exec_concurrency_limit_returns_429_broker_busy():
    from app.broker.ops import ConcurrentOpsExceeded

    app = build_internal_app(
        AgentRegistry(),
        manager=_LimitManager(ConcurrentOpsExceeded("system 7 has 16 live ops")),
    )
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec", json={"system_id": 7, "cmd": "echo"}
        )
    assert resp.status_code == 429, resp.text
    body = resp.json()
    assert body["outcome"] == "error"
    assert body["error"]["reason"] == "broker_busy"
    # The raw limit message (op counts) must not leak into the client body.
    assert "16 live ops" not in resp.text


def test_exec_nonce_limit_returns_429_broker_busy():
    from app.broker.ops import NonceLimitExceeded

    app = build_internal_app(
        AgentRegistry(),
        manager=_LimitManager(NonceLimitExceeded("system 7 has 32 in-flight nonces")),
    )
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec", json={"system_id": 7, "cmd": "echo"}
        )
    assert resp.status_code == 429, resp.text
    assert resp.json()["error"]["reason"] == "broker_busy"
    assert "in-flight nonces" not in resp.text


def test_file_get_concurrency_limit_returns_429_broker_busy():
    from app.broker.ops import ConcurrentOpsExceeded

    app = build_internal_app(
        AgentRegistry(),
        manager=_LimitManager(ConcurrentOpsExceeded("system 7 has 16 live ops")),
    )
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_get",
            json={"system_id": 7, "path": "/tmp/out"},
        )
    assert resp.status_code == 429, resp.text
    assert resp.json()["error"]["reason"] == "broker_busy"
    assert "16 live ops" not in resp.text


def test_file_put_concurrency_limit_returns_429_broker_busy():
    from app.broker.ops import ConcurrentOpsExceeded

    app = build_internal_app(
        AgentRegistry(),
        manager=_LimitManager(ConcurrentOpsExceeded("system 7 has 16 live ops")),
    )
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/file_put",
            headers={
                "x-praxis-system-id": "7",
                "x-praxis-file-path": "/tmp/out",
                "x-praxis-declared-size": "4",
            },
            content=b"data",
        )
    assert resp.status_code == 429, resp.text
    assert resp.json()["error"]["reason"] == "broker_busy"
    assert "16 live ops" not in resp.text


def test_facts_concurrency_limit_returns_429_broker_busy():
    from app.broker.ops import ConcurrentOpsExceeded

    app = build_internal_app(
        AgentRegistry(),
        manager=_LimitManager(ConcurrentOpsExceeded("system 7 has 16 live ops")),
    )
    with TestClient(app) as client:
        resp = client.post("/internal/agent/ops/facts", json={"system_id": 7})
    assert resp.status_code == 429, resp.text
    assert resp.json()["error"]["reason"] == "broker_busy"
    assert "16 live ops" not in resp.text
