"""PRA-153 #3b: AgentTransport tests.

Drive AgentTransport against an httpx.MockTransport that fakes the
broker internal API. Verifies the BrokerClient → broker → agent
contract translates to the right CommandResult / FileGetStream /
FilePutStream and the right TransportError subclass on failure.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

import httpx
import pytest

from app.services.broker_client import BrokerClient
from app.services.transport import (
    AgentTransport,
    CommandResult,
    TransportError,
    TransportUnavailable,
    TransportUnsupported,
)


@dataclass
class _SystemStub:
    id: int


def _bc(handler) -> BrokerClient:
    """Build a BrokerClient backed by an httpx.MockTransport handler."""
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    return BrokerClient(client=client)


# -------- run_command --------


@pytest.mark.asyncio
async def test_run_command_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/agent/ops/exec"
        body = json.loads(request.content)
        assert body["system_id"] == 7
        assert body["cmd"] == "echo"
        assert body["args"] == ["hi"]
        return httpx.Response(
            200,
            json={
                "outcome": "success",
                "operation_id": 1,
                "exit_code": 0,
                "stdout_b64": base64.b64encode(b"hi\n").decode("ascii"),
                "stderr_b64": "",
                "duration_ms": 5,
                "error": None,
            },
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    result = await t.run_command(["echo", "hi"])
    assert isinstance(result, CommandResult)
    assert result.exit_code == 0
    assert result.stdout == b"hi\n"
    assert result.stderr == b""
    assert result.duration_ms == 5


@pytest.mark.asyncio
async def test_run_command_nonzero_exit_returns_command_result_not_raise():
    """outcome=success/exit_code=N is a successful TRANSPORT result.
    The command-ledger nonzero -> failed mapping happens upstream in
    command_execution_service (slice #3d), not here.
    """

    def handler(_req):
        return httpx.Response(
            200,
            json={
                "outcome": "success",
                "operation_id": 1,
                "exit_code": 2,
                "stdout_b64": "",
                "stderr_b64": base64.b64encode(b"oops\n").decode("ascii"),
                "duration_ms": 3,
                "error": None,
            },
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    result = await t.run_command(["false"])
    assert result.exit_code == 2
    assert result.stderr == b"oops\n"


@pytest.mark.asyncio
async def test_run_command_503_raises_transport_unavailable():
    def handler(_req):
        return httpx.Response(
            503,
            json={"outcome": "error", "error": {"reason": "transport_unavailable"}},
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    with pytest.raises(TransportUnavailable):
        await t.run_command(["echo", "hi"])


@pytest.mark.asyncio
async def test_run_command_504_raises_transport_error():
    def handler(_req):
        return httpx.Response(
            504,
            json={"outcome": "error", "error": {"reason": "agent_attach_timeout"}},
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    with pytest.raises(TransportError) as exc:
        await t.run_command(["echo"])
    assert "agent_attach_timeout" in str(exc.value)


@pytest.mark.asyncio
async def test_run_command_outcome_error_raises_transport_error():
    def handler(_req):
        return httpx.Response(
            200,
            json={
                "outcome": "error",
                "operation_id": 1,
                "exit_code": None,
                "stdout_b64": "",
                "stderr_b64": "",
                "duration_ms": None,
                "error": {"reason": "spawn_failed"},
            },
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    with pytest.raises(TransportError) as exc:
        await t.run_command(["nope"])
    assert "spawn_failed" in str(exc.value)


@pytest.mark.asyncio
async def test_run_command_413_exec_output_too_large_preserves_reason():
    def handler(_req):
        return httpx.Response(
            413,
            json={
                "outcome": "error",
                "error": {"reason": "exec_output_too_large", "limit_bytes": 1024},
            },
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    with pytest.raises(TransportError) as exc:
        await t.run_command(["cat", "/large"])
    text = str(exc.value)
    assert "exec_output_too_large" in text
    assert "1024" not in text


@pytest.mark.asyncio
async def test_run_command_forwards_stdin_b64():
    captured = {}

    def handler(req):
        captured["body"] = json.loads(req.content)
        return httpx.Response(
            200,
            json={
                "outcome": "success",
                "operation_id": 1,
                "exit_code": 0,
                "stdout_b64": "",
                "stderr_b64": "",
                "duration_ms": 1,
                "error": None,
            },
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    await t.run_command(["cat"], stdin=b"hello\n")
    assert "stdin_b64" in captured["body"]
    assert base64.b64decode(captured["body"]["stdin_b64"]) == b"hello\n"


# -------- open_pty (must raise) --------


@pytest.mark.asyncio
async def test_open_pty_raises_transport_unsupported():
    """Agent PTY deferred per the slice-#3 design lock — force-agent
    for sessions surfaces here as a clear TransportUnsupported.

    PRA-181 Slice 1: this is the 1.0 interactive-session transport
    boundary. Browser terminal sessions always use SSH; the agent
    advertises a ``pty`` capability but the backend never routes a
    browser session over it. The exception message must explicitly
    route operators to SSH so the boundary is unambiguous to callers
    (and matches the UI/docs copy)."""

    def handler(_req):  # never actually called
        return httpx.Response(500)

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    with pytest.raises(TransportUnsupported) as exc:
        await t.open_pty(["/bin/bash"])
    msg = str(exc.value).lower()
    assert (
        "ssh" in msg
    ), f"open_pty error should route operators to SSH, got: {exc.value!r}"
    assert "pty" in msg or "interactive" in msg or "shell" in msg


# -------- open_file_get --------


@pytest.mark.asyncio
async def test_file_get_streams_bytes():
    body = b"hello world"

    def handler(_req):
        return httpx.Response(
            200,
            content=body,
            headers={
                "x-praxis-file-size": str(len(body)),
                "x-praxis-file-mode": "0o644",
            },
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    stream = await t.open_file_get("/etc/hosts")
    assert stream.size == len(body)
    assert stream.mode == 0o644
    received = b""
    async for chunk in stream.chunks:
        received += chunk
    await stream.close()
    assert received == body


@pytest.mark.asyncio
async def test_file_get_pre_stream_failure_raises():
    def handler(_req):
        return httpx.Response(
            502,
            json={"outcome": "error", "error": {"reason": "not_found"}},
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    with pytest.raises(TransportError) as exc:
        await t.open_file_get("/missing")
    assert "not_found" in str(exc.value)


@pytest.mark.asyncio
async def test_file_get_503_raises_transport_unavailable():
    def handler(_req):
        return httpx.Response(503)

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    with pytest.raises(TransportUnavailable):
        await t.open_file_get("/etc/hosts")


@pytest.mark.asyncio
async def test_file_get_504_preserves_distinct_reason_codes():
    """The broker returns 504 for both
    agent_attach_timeout (per-op WSS never opened) and header_timeout
    (attached but no header). The previous code collapsed both to
    'header_timeout', misleading audit/UI dashboards. AgentTransport
    must surface whichever reason the broker actually reported.
    """

    for sent_reason in ("agent_attach_timeout", "header_timeout"):

        def handler(_req, _r=sent_reason):
            return httpx.Response(
                504,
                json={"outcome": "error", "error": {"reason": _r}},
            )

        t = AgentTransport(_SystemStub(id=7), _bc(handler))
        with pytest.raises(TransportError) as exc:
            await t.open_file_get("/etc/hosts")
        assert sent_reason in str(
            exc.value
        ), f"504 reason {sent_reason!r} collapsed; got {exc.value!r}"


@pytest.mark.asyncio
async def test_file_get_short_body_surfaces_as_transport_error():
    """If the broker promises N bytes but delivers fewer (mid-stream
    abort), the iterator must raise TransportError at the end so
    callers don't silently install a truncated download."""

    def handler(_req):
        return httpx.Response(
            200,
            content=b"only-half",
            headers={
                "x-praxis-file-size": "999",
                "x-praxis-file-mode": "0o644",
            },
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    stream = await t.open_file_get("/etc/hosts")
    received = b""
    with pytest.raises(TransportError) as exc:
        async for chunk in stream.chunks:
            received += chunk
    await stream.close()
    assert "op_stream_closed" in str(exc.value)


# -------- open_file_put --------


@pytest.mark.asyncio
async def test_file_put_writes_full_body():
    captured = {"body": b"", "headers": None}

    def handler(req):
        captured["body"] = req.content
        captured["headers"] = dict(req.headers)
        return httpx.Response(
            200, json={"outcome": "success", "bytes_written": len(req.content)}
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    stream = await t.open_file_put("/tmp/x", size=11)
    await stream.write(b"hello ")
    await stream.write(b"world")
    await stream.finish()
    assert captured["body"] == b"hello world"
    assert captured["headers"]["x-praxis-system-id"] == "7"
    assert captured["headers"]["x-praxis-file-path"] == "/tmp/x"
    assert captured["headers"]["x-praxis-declared-size"] == "11"


@pytest.mark.asyncio
async def test_file_put_propagates_413_too_large():
    def handler(_req):
        return httpx.Response(
            413, json={"outcome": "error", "error": {"reason": "too_large"}}
        )

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    stream = await t.open_file_put("/tmp/x", size=100)
    await stream.write(b"x" * 100)
    with pytest.raises(TransportError) as exc:
        await stream.finish()
    assert "too_large" in str(exc.value)


@pytest.mark.asyncio
async def test_file_put_503_raises_transport_unavailable():
    def handler(_req):
        return httpx.Response(503)

    t = AgentTransport(_SystemStub(id=7), _bc(handler))
    stream = await t.open_file_put("/tmp/x", size=1)
    await stream.write(b"x")
    with pytest.raises(TransportUnavailable):
        await stream.finish()


@pytest.mark.asyncio
async def test_file_put_write_unblocks_when_broker_rejects_early():
    """If the broker rejects (e.g. 503 no tunnel) without
    consuming the request body, the runner exits early. write()'s
    chunk_q.put would otherwise block forever waiting for a consumer
    that's gone — large uploads would hang instead of seeing the
    503.

    Stub BrokerClient.file_put directly: drain a couple of chunks
    (so chunk_q fills past maxsize=4) then raise BrokerError without
    consuming the rest. write() must wake on runner_task completion
    and surface TransportUnavailable.
    """

    class _StubBC:
        async def file_put(self, system_id, path, body, **_kwargs):
            # Reject WITHOUT consuming the body — mirrors a 503 from
            # the broker before any body bytes are read. The body
            # iterator never runs, so chunk_q never drains. Without
            # the fix, write() blocks on put after maxsize=4 chunks.
            raise BrokerError("transport_unavailable", "no tunnel")

    from app.services.broker_client import BrokerError

    t = AgentTransport(_SystemStub(id=7), _StubBC())
    stream = await t.open_file_put("/tmp/x", size=10_000_000)
    chunk = b"x" * 1024
    raised = None
    # Loop generously — we expect to wake on a write within the
    # first few iterations after chunk_q fills + runner exits.
    for _ in range(50):
        try:
            await stream.write(chunk)
        except (TransportUnavailable, TransportError) as exc:
            raised = exc
            break
    assert raised is not None, (
        "write() never surfaced the early broker rejection; would hang "
        "in production after the bounded queue fills"
    )
    assert isinstance(raised, TransportUnavailable)


# -------- PRA-228 TRANSPORT-01: caller-visible error hygiene --------


def test_broker_error_detail_not_leaked_to_caller():
    """The raw BrokerError detail (internal broker URL / connection internals /
    stack-ish text) must not appear in the caller-visible transport error, while
    the stable reason code is retained for operator/audit actionability."""
    from app.services.broker_client import BrokerError
    from app.services.transport.agent import _broker_error_to_transport

    exc = BrokerError(
        "broker_unreachable",
        "ConnectError: [Errno 111] connect to http://agent-broker:8444 refused",
    )
    err = _broker_error_to_transport(exc)
    text = str(err)
    assert "agent-broker:8444" not in text
    assert "ConnectError" not in text
    assert "Errno 111" not in text
    # stable reason code stays for actionability
    assert "broker_unreachable" in text


def test_broker_busy_maps_to_transport_error_with_reason():
    from app.services.broker_client import BrokerError
    from app.services.transport.agent import _broker_error_to_transport
    from app.services.transport.base import TransportError

    err = _broker_error_to_transport(
        BrokerError("broker_busy", "system 7 has 16 live ops")
    )
    assert isinstance(err, TransportError)
    text = str(err)
    assert "broker_busy" in text
    assert "16 live ops" not in text
