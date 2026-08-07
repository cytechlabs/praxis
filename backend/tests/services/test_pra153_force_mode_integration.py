"""PRA-153 #3f: real broker + fake-agent integration tests.

Wires the real broker FastAPI internal app + a stub OperationManager
behind an httpx ASGI BrokerClient. The whole BrokerClient → broker
internal HTTP → OperationManager → dispatched op chain runs
end-to-end (no Go agent, no WSS), so a wiring bug between those
layers fails here that would have shipped under the unit seam tests
in slice #3e.

Scope (per the slice #3f design lock):
    * Real broker internal_api + a fake OperationManager.
    * AgentTransport exec/file_get/file_put round-trips end to end.
    * Force ssh + healthy agent → SSH path (no broker dispatch).
    * Force agent + healthy tunnel → agent path used.
    * Force agent + tunnel down → TransportUnavailable + audit row
      transport='agent' status='error'.
    * Auto + healthy tunnel → agent for upload/download.
    * Auto + tunnel down → SSH fallback.
    * Directory ops with force-agent → already covered in #3e
      (no broker needed, so not duplicated here).

Deferred (NOT covered here, by design):
    * Agent PTY / session recording — waits on effective_login design.
      Existing SSH recording regression coverage lives in
      tests/services/test_pra141_recording.py.
    * Go-binary subprocess E2E.
    * UI / browser force-mode coverage — slice #4.
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.broker.internal_api import build_internal_app
from app.broker.ops import NoActiveTunnel, Operation, OperationState
from app.broker.protocol import Channel, Frame, FrameOp
from app.broker.registry import AgentRegistry, TunnelEntry
from app.services import file_transfer_service as fts
from app.services.broker_client import BrokerClient
from app.services.transport import TransportUnavailable
from app.services.transport.agent import AgentTransport

# --------------------------------------------------------------------------
# Fake OperationManager + op factories
#
# Mirrors the pattern in tests/broker/test_internal_ops_api.py, kept inline
# so this file stands alone. Each factory builds an Operation pre-driven
# with the frames the agent would have produced + a resolved completion.
# --------------------------------------------------------------------------


_NO_TUNNEL_SENTINEL = 9999


class _FakeManager:
    """Stub OperationManager. ``op_factory`` is a sync callable that
    builds the next Operation; tests overwrite it per-case. Raising
    ``NoActiveTunnel`` for system_id == 9999 lets us exercise the
    broker's 503 path without unregistering the agent.
    """

    def __init__(self) -> None:
        self.op_factory = None
        self.dispatched: list[tuple[int, str, dict]] = []
        self.cancelled: list[int] = []
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
        if system_id == _NO_TUNNEL_SENTINEL:
            raise NoActiveTunnel(f"no tunnel for system {system_id}")
        if self.op_factory is None:
            raise RuntimeError("test forgot to set _FakeManager.op_factory")
        op = self.op_factory(self._next_id, system_id, op_type, params or {})
        if outbound_maxsize > 0:
            op.outbound = asyncio.Queue(maxsize=outbound_maxsize)
        op.skip_terminal_sentinel = skip_terminal_sentinel
        self._ops[self._next_id] = op
        self._next_id += 1
        self.dispatched.append((system_id, op_type, op.params))
        return op, "fake-nonce"

    async def cancel(self, operation_id):
        self.cancelled.append(operation_id)
        op = self._ops.get(operation_id)
        if op is not None and not op.completion.done():
            op.outcome = "cancelled"
            op.error = {"reason": "cancelled"}
            op.completion.set_result(None)


def _bare_op(operation_id, system_id, op_type, params):
    loop = asyncio.get_event_loop()
    return Operation(
        operation_id=operation_id,
        system_id=system_id,
        tunnel_session_id=f"sess-{system_id}",
        op_type=op_type,
        params=params,
        state=OperationState.PENDING_NONCE,
        created_at_monotonic=time.monotonic(),
        nonce_expires_at_monotonic=time.monotonic() + 999.0,
        completion=loop.create_future(),
    )


def _exec_factory(stdout=b"", stderr=b"", exit_code=0):
    def _make(operation_id, system_id, op_type, params):
        op = _bare_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            if stdout:
                op.inbound.put_nowait(
                    Frame(op=FrameOp.DATA, channel=Channel.STDOUT, payload=stdout)
                )
            if stderr:
                op.inbound.put_nowait(
                    Frame(op=FrameOp.DATA, channel=Channel.STDERR, payload=stderr)
                )
            op.inbound.put_nowait(None)
            op.outcome = "success"
            op.result_metadata = {"exit_code": exit_code, "duration_ms": 5}
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    return _make


def _file_get_factory(body=b"hello", mode="0o644"):
    def _make(operation_id, system_id, op_type, params):
        op = _bare_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            header = {"type": "file_header", "size": len(body), "mode": mode}
            op.inbound.put_nowait(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.CONTROL,
                    payload=json.dumps(header).encode("utf-8"),
                )
            )
            op.inbound.put_nowait(
                Frame(op=FrameOp.DATA, channel=Channel.FILE, payload=body)
            )
            op.inbound.put_nowait(
                Frame(op=FrameOp.CLOSE, channel=Channel.FILE, payload=b"")
            )
            # No terminal None — the broker file_get endpoint owns EOF
            # via FILE CLOSE and the manager would suppress the
            # sentinel anyway (skip_terminal_sentinel=True in prod).
            op.outcome = "success"
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    return _make


def _file_put_factory():
    """File-put fake. Drains op.outbound (file_put bounds it at 4
    frames so we must consume or the broker endpoint blocks on the
    awaited put for the next chunk)."""
    captured: dict = {"frames": []}

    def _make(operation_id, system_id, op_type, params):
        op = _bare_op(operation_id, system_id, op_type, params)

        async def _drive():
            op.state = OperationState.ATTACHED
            while True:
                frame = await op.outbound.get()
                if frame is None:
                    break
                captured["frames"].append(frame)
                if frame.op == FrameOp.CLOSE and frame.channel == Channel.FILE:
                    break
            op.inbound.put_nowait(None)
            op.outcome = "success"
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    return _make, captured


# --------------------------------------------------------------------------
# Fixture: real broker app + ASGI BrokerClient redirect
# --------------------------------------------------------------------------


@pytest.fixture
def fake_broker(monkeypatch):
    """Stand up the real broker internal FastAPI app behind an ASGI
    BrokerClient. Every BrokerClient created during the test routes
    in-process to our app; no real network.
    """
    registry = AgentRegistry()
    manager = _FakeManager()
    app = build_internal_app(registry=registry, manager=manager)

    async def _ensure_client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://broker.test",
            )
            self._owns_client = True
        return self._client

    async def _aenter(self):
        await _ensure_client(self)
        return self

    async def _health(self, system_id):
        client = await _ensure_client(self)
        return await self._do_health(client, system_id)

    monkeypatch.setattr(BrokerClient, "_ensure_client", _ensure_client)
    monkeypatch.setattr(BrokerClient, "__aenter__", _aenter)
    monkeypatch.setattr(BrokerClient, "health", _health)

    return {"registry": registry, "manager": manager, "app": app}


def _register_healthy_agent(registry: AgentRegistry, system_id: int) -> None:
    """Drop a TunnelEntry into the registry so health() returns
    'healthy'. Bypasses the lock — fine for single-threaded tests."""
    entry = TunnelEntry(
        system_id=system_id,
        tunnel_session_id=f"sess-{system_id}",
        ws=MagicMock(),
        identity=MagicMock(),
        capabilities=["exec", "facts"],
        agent_version="fake-0.1",
    )
    now = time.monotonic()
    entry.last_recv_monotonic = now
    entry.connected_at_monotonic = now
    registry._by_system[entry.system_id] = entry


# --------------------------------------------------------------------------
# AgentTransport round-trips through the real broker
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_transport_exec_round_trip_through_real_broker(fake_broker):
    """run_command → BrokerClient.exec → broker internal_api → fake
    manager → response. Catches wire-shape drift across all four
    layers — would have caught the BrokerClient/ASGITransport mismatch
    or the result_metadata routing if either drifted."""
    fake_broker["manager"].op_factory = _exec_factory(
        stdout=b"hi\n", stderr=b"", exit_code=0
    )
    _register_healthy_agent(fake_broker["registry"], system_id=42)

    system = MagicMock()
    system.id = 42
    transport = AgentTransport(system, BrokerClient())

    result = await transport.run_command(["echo", "hi"])

    assert result.exit_code == 0
    assert result.stdout == b"hi\n"
    assert fake_broker["manager"].dispatched[0][1] == "exec"


@pytest.mark.asyncio
async def test_agent_transport_file_get_round_trip_through_real_broker(fake_broker):
    fake_broker["manager"].op_factory = _file_get_factory(body=b"payload-bytes")
    _register_healthy_agent(fake_broker["registry"], system_id=42)

    system = MagicMock()
    system.id = 42
    transport = AgentTransport(system, BrokerClient())

    stream = await transport.open_file_get("/etc/hosts")
    assert stream.size == len(b"payload-bytes")
    received = b""
    async for chunk in stream.chunks:
        received += chunk
    await stream.close()

    assert received == b"payload-bytes"
    assert fake_broker["manager"].dispatched[0][1] == "file_get"


@pytest.mark.asyncio
async def test_agent_transport_file_put_round_trip_through_real_broker(fake_broker):
    factory, captured = _file_put_factory()
    fake_broker["manager"].op_factory = factory
    _register_healthy_agent(fake_broker["registry"], system_id=42)

    system = MagicMock()
    system.id = 42
    transport = AgentTransport(system, BrokerClient())

    stream = await transport.open_file_put("/tmp/x", size=5, overwrite=True)
    await stream.write(b"hello")
    await stream.finish()

    assert fake_broker["manager"].dispatched[0][1] == "file_put"
    # Header CONTROL frame, then FILE data, then FILE CLOSE.
    assert captured["frames"][0].channel == Channel.CONTROL
    file_payload = b"".join(
        bytes(f.payload) for f in captured["frames"] if f.channel == Channel.FILE
    )
    assert file_payload == b"hello"


@pytest.mark.asyncio
async def test_agent_transport_exec_raises_unavailable_when_no_tunnel(fake_broker):
    """Health endpoint returns 'unregistered' (no entry in registry).
    AgentTransport must surface this as TransportUnavailable, NOT
    silently fall back."""
    fake_broker["manager"].op_factory = _exec_factory()
    # NOTE: no _register_healthy_agent — registry is empty for this system.

    system = MagicMock()
    system.id = 999
    # AgentTransport.run_command does NOT itself call health(); the
    # 503 path is exercised when the broker raises NoActiveTunnel.
    # Drive that via the special sentinel.
    system.id = _NO_TUNNEL_SENTINEL
    transport = AgentTransport(system, BrokerClient())

    from app.services.transport import TransportUnavailable as TU

    with pytest.raises(TU):
        await transport.run_command(["echo", "hi"])


# --------------------------------------------------------------------------
# file_transfer_service routing matrix through real broker
#
# Bypasses the auth gate (orthogonal to transport routing — covered
# elsewhere). Drives upload_stream / download_stream end-to-end and
# asserts both the routing decision (via mock spies on the SSH helpers
# or _FakeManager.dispatched) AND the audit row attribution.
# --------------------------------------------------------------------------


def _patch_gate(system, login="ops"):
    return patch.object(fts, "_gate", return_value=(system, login))


def _patch_audit_capture():
    rows: list = []

    def _fake_open(db, **kw):
        row = MagicMock()
        for k, v in kw.items():
            setattr(row, k, v)
        row.id = len(rows) + 1
        row.status = "in_progress"
        row.error_message = None
        row.size_bytes = 0
        row.sha256 = None
        rows.append(row)
        return row

    finishes: list = []

    def _fake_finish(db, row, **kw):
        for k, v in kw.items():
            setattr(row, k, v)
        finishes.append(row)

    return (
        rows,
        finishes,
        patch.object(fts, "_open_audit", side_effect=_fake_open),
        patch.object(fts, "_finish_audit", side_effect=_fake_finish),
    )


def _make_system(pref: str, system_id: int = 42):
    sys_obj = MagicMock()
    sys_obj.id = system_id
    sys_obj.hostname = "host.test"
    sys_obj.transport_preference = pref
    return sys_obj


def test_upload_pref_agent_healthy_routes_to_agent_via_real_broker(fake_broker):
    """Force-agent + healthy tunnel: upload_stream goes through the
    real broker stack, broker.dispatched records a file_put op, and
    the audit row records transport='agent' status='success'."""
    factory, _captured = _file_put_factory()
    fake_broker["manager"].op_factory = factory
    _register_healthy_agent(fake_broker["registry"], system_id=42)

    system = _make_system("agent", system_id=42)
    user = MagicMock()
    user.id = 1
    rows, finishes, p_open, p_finish = _patch_audit_capture()

    with _patch_gate(system), p_open, p_finish, patch.object(
        fts, "_upload_via_ssh"
    ) as ssh_upload:
        result = fts.upload_stream(
            MagicMock(), user, system.id, "/tmp/x", iter([b"hello"])
        )

    ssh_upload.assert_not_called()
    # Real broker dispatched a file_put op.
    assert fake_broker["manager"].dispatched[0][1] == "file_put"
    # Audit row records the agent transport.
    assert rows[0].transport == "agent"
    assert finishes[-1].status == "success"
    assert result["size"] == len(b"hello")


def test_download_pref_agent_healthy_routes_to_agent_via_real_broker(fake_broker):
    fake_broker["manager"].op_factory = _file_get_factory(body=b"hello-from-agent")
    _register_healthy_agent(fake_broker["registry"], system_id=42)

    system = _make_system("agent", system_id=42)
    user = MagicMock()
    user.id = 1
    rows, finishes, p_open, p_finish = _patch_audit_capture()

    # _download_via_agent finalizes the audit through a SessionLocal
    # opened inside _stream's finally — totally separate from the
    # caller's `db`. Patch it so the lookup-by-id resolves to the row
    # _open_audit captured, otherwise the post-stream _finish_audit
    # would silently no-op and a regression leaving the row stuck in
    # "in_progress" wouldn't fail this test.
    fake_db = MagicMock()
    fake_db.query.return_value.filter.return_value.first.side_effect = (
        lambda: rows[-1] if rows else None
    )

    with _patch_gate(system), p_open, p_finish, patch.object(
        fts, "_download_via_ssh"
    ) as ssh_dl, patch("app.db.session.SessionLocal", return_value=fake_db):
        gen = fts.download_stream(MagicMock(), user, system.id, "/etc/hosts")
        body = b"".join(gen)

    ssh_dl.assert_not_called()
    assert body == b"hello-from-agent"
    assert fake_broker["manager"].dispatched[0][1] == "file_get"
    assert rows[0].transport == "agent"
    # Post-stream finalization actually ran.
    assert finishes, "expected _download_via_agent to finalize the audit row"
    assert finishes[-1].status == "success"
    assert finishes[-1].size_bytes == len(b"hello-from-agent")
    import hashlib

    assert finishes[-1].sha256 == hashlib.sha256(b"hello-from-agent").hexdigest()
    assert finishes[-1].transport == "agent"


def test_upload_pref_agent_tunnel_down_raises_unavailable_with_audit(fake_broker):
    """Force-agent + tunnel down: TransportUnavailable + audit row
    transport='agent' status='error' error_message='transport_unavailable'.
    Real broker's health endpoint returns 'unregistered'."""
    # Don't set op_factory — the tunnel-down path never calls dispatch.
    # (Don't register an agent either.)
    system = _make_system("agent", system_id=43)
    user = MagicMock()
    user.id = 1
    rows, finishes, p_open, p_finish = _patch_audit_capture()

    with _patch_gate(system), p_open, p_finish:
        with pytest.raises(TransportUnavailable):
            fts.upload_stream(MagicMock(), user, system.id, "/tmp/x", iter([b"hello"]))

    assert len(rows) == 1
    assert rows[0].transport == "agent"
    assert finishes and finishes[-1].status == "error"
    assert finishes[-1].error_message == "transport_unavailable"


def test_upload_pref_ssh_with_healthy_agent_uses_ssh_path(fake_broker):
    """pref=ssh forces SSH even when the agent is healthy. The factory
    short-circuits at pref=ssh so the broker is never consulted —
    asserted by _FakeManager.dispatched staying empty."""
    _register_healthy_agent(fake_broker["registry"], system_id=42)

    system = _make_system("ssh", system_id=42)
    user = MagicMock()
    user.id = 1
    rows, _finishes, p_open, p_finish = _patch_audit_capture()

    ssh_result = {"remote_path": "/tmp/x", "size": 5, "sha256": "abc"}
    with _patch_gate(system), p_open, p_finish, patch.object(
        fts, "_upload_via_ssh", return_value=ssh_result
    ) as ssh_upload, patch.object(fts, "_upload_via_agent") as agent_upload:
        fts.upload_stream(MagicMock(), user, system.id, "/tmp/x", iter([b"hello"]))

    ssh_upload.assert_called_once()
    agent_upload.assert_not_called()
    assert fake_broker["manager"].dispatched == []
    assert rows[0].transport == "ssh"


def test_upload_pref_auto_tunnel_down_falls_back_to_ssh(fake_broker):
    """pref=auto + no agent in registry: factory falls back to SSH,
    audit row records transport='ssh'."""
    # No agent registered → health returns 'unregistered'.
    system = _make_system("auto", system_id=44)
    user = MagicMock()
    user.id = 1
    rows, _finishes, p_open, p_finish = _patch_audit_capture()

    ssh_result = {"remote_path": "/tmp/x", "size": 5, "sha256": "abc"}
    with _patch_gate(system), p_open, p_finish, patch.object(
        fts, "_upload_via_ssh", return_value=ssh_result
    ) as ssh_upload, patch.object(fts, "_upload_via_agent") as agent_upload:
        fts.upload_stream(MagicMock(), user, system.id, "/tmp/x", iter([b"hello"]))

    ssh_upload.assert_called_once()
    agent_upload.assert_not_called()
    assert rows[0].transport == "ssh"


def test_upload_pref_auto_healthy_tunnel_routes_to_agent_via_real_broker(fake_broker):
    """pref=auto + healthy tunnel: factory chooses agent path. Real
    broker handles the file_put dispatch."""
    factory, _captured = _file_put_factory()
    fake_broker["manager"].op_factory = factory
    _register_healthy_agent(fake_broker["registry"], system_id=42)

    system = _make_system("auto", system_id=42)
    user = MagicMock()
    user.id = 1
    rows, _finishes, p_open, p_finish = _patch_audit_capture()

    with _patch_gate(system), p_open, p_finish, patch.object(
        fts, "_upload_via_ssh"
    ) as ssh_upload:
        fts.upload_stream(MagicMock(), user, system.id, "/tmp/x", iter([b"hello"]))

    ssh_upload.assert_not_called()
    assert fake_broker["manager"].dispatched[0][1] == "file_put"
    assert rows[0].transport == "agent"
