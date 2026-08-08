"""PRA-151 task #16: op-nonce flow + per-op WSS lifecycle.

Covers:
  * frame envelope encode/decode + size limits
  * OperationManager nonce semantics (hash-only storage, TTL,
    single-use, reissue invalidation, system_id binding)
  * per-agent limits (max concurrent ops, max in-flight nonces)
  * end-to-end attach/stream cycle through a fake agent
  * manager.cancel() (CANCELLING -> agent op_complete -> CANCELLED)
  * manager.cancel() timeout (forces CANCELLED if no ack)
  * orphan-op cleanup on tunnel disconnect / replacement
  * agent op_complete on control WSS terminalises the op

No real exec/PTY behavior — payload is a fake echo/sink.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
from contextlib import asynccontextmanager

import pytest
import websockets
from cryptography.hazmat.primitives import serialization

from app.broker.handlers import op_handler, tunnel_handler
from app.broker.ops import (
    ConcurrentOpsExceeded,
    NoActiveTunnel,
    NonceExpired,
    NonceInvalid,
    NonceLimitExceeded,
    OperationManager,
    OperationState,
)
from app.broker.protocol import (
    Channel,
    Frame,
    FrameError,
    FrameOp,
    decode_frame,
    encode_frame,
)
from app.broker.registry import AgentRegistry
from app.broker.tls import build_server_ssl_context

from . import _certfx as cfx

# ===========================================================================
# Frame envelope
# ===========================================================================


def test_frame_round_trip():
    f = Frame(op=FrameOp.DATA, channel=Channel.STDOUT, payload=b"hello world")
    assert decode_frame(encode_frame(f)) == f


def test_frame_round_trip_empty_payload():
    f = Frame(op=FrameOp.CLOSE, channel=Channel.CONTROL, payload=b"")
    assert decode_frame(encode_frame(f)) == f


def test_frame_round_trip_max_payload():
    payload = b"\xab" * (1 << 20)  # exactly 1 MiB
    f = Frame(op=FrameOp.DATA, channel=Channel.PTY, payload=payload)
    out = decode_frame(encode_frame(f))
    assert out.payload == payload


def test_frame_encode_refuses_oversize_payload():
    f = Frame(op=FrameOp.DATA, channel=Channel.STDOUT, payload=b"x" * 100)
    with pytest.raises(FrameError, match="exceeds max"):
        encode_frame(f, max_payload=50)


def test_frame_decode_refuses_oversize_declared_length():
    """Decoder must refuse a frame whose declared length exceeds the
    cap, even if the buffer happens to match it."""
    payload = b"y" * 200
    wire = encode_frame(Frame(op=FrameOp.DATA, channel=Channel.STDOUT, payload=payload))
    with pytest.raises(FrameError, match="exceeds max"):
        decode_frame(wire, max_payload=100)


def test_frame_decode_unknown_op():
    bad = bytes([1, 0xFE, 1, 0, 0, 0, 0, 0])  # version=1, op=0xFE invalid
    with pytest.raises(FrameError, match="frame op"):
        decode_frame(bad)


def test_frame_decode_unknown_channel():
    bad = bytes([1, 0x01, 0xFE, 0, 0, 0, 0, 0])
    with pytest.raises(FrameError, match="channel"):
        decode_frame(bad)


def test_frame_decode_short_buffer():
    with pytest.raises(FrameError, match="shorter"):
        decode_frame(b"\x01\x01\x01")


def test_frame_decode_length_mismatch():
    # claim length=10, supply 5 payload bytes
    wire = bytes([1, 1, 1, 0, 0, 0, 0, 10]) + b"abcde"
    with pytest.raises(FrameError, match="does not match"):
        decode_frame(wire)


# ===========================================================================
# OperationManager — pure unit tests (no WSS plumbing)
# ===========================================================================


@pytest.fixture
def fake_registry_with_tunnel():
    """A registry holding an entry whose ws is a stub that captures sends."""
    from unittest.mock import MagicMock

    reg = AgentRegistry()

    class StubWs:
        def __init__(self):
            self.sent = []

        async def send(self, m):
            self.sent.append(m)

        async def close(self, **_):
            pass

    ws = StubWs()
    from app.broker.registry import TunnelEntry

    entry = TunnelEntry(
        system_id=42,
        tunnel_session_id="T1",
        ws=ws,  # type: ignore[arg-type]
        identity=MagicMock(not_after=None),
        capabilities=[],
        agent_version="0.1.0",
    )
    asyncio.get_event_loop().run_until_complete(reg.register(entry))
    return reg, ws


@pytest.mark.asyncio
async def test_create_dispatches_op_request_and_op_nonce():
    reg = AgentRegistry()
    sent = []

    class StubWs:
        async def send(self, m):
            sent.append(json.loads(m))

        async def close(self, **_):
            pass

    from unittest.mock import MagicMock

    from app.broker.registry import TunnelEntry

    entry = TunnelEntry(
        system_id=42,
        tunnel_session_id="T1",
        ws=StubWs(),  # type: ignore[arg-type]
        identity=MagicMock(),
        capabilities=[],
        agent_version="0.1.0",
    )
    await reg.register(entry)

    mgr = OperationManager(reg, nonce_ttl_seconds=10)
    op, raw_nonce = await mgr.create_and_dispatch(42, "exec", {"cmd": "uname"})
    assert op.state == OperationState.PENDING_NONCE
    assert isinstance(raw_nonce, str) and len(raw_nonce) >= 32
    assert [m["type"] for m in sent] == ["op_request", "op_nonce"]
    assert sent[0]["operation_id"] == op.operation_id
    assert sent[1]["nonce"] == raw_nonce  # raw goes on the wire ONCE
    # internal storage holds only the hash
    digest = hashlib.sha256(raw_nonce.encode()).hexdigest()
    assert mgr._nonce_to_op[digest] == op.operation_id  # type: ignore[attr-defined]
    assert raw_nonce not in mgr._nonce_to_op  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_redeem_succeeds_and_is_one_shot():
    reg = AgentRegistry()
    from unittest.mock import MagicMock

    from app.broker.registry import TunnelEntry

    class StubWs:
        async def send(self, m):
            pass

        async def close(self, **_):
            pass

    await reg.register(
        TunnelEntry(
            system_id=42,
            tunnel_session_id="T",
            ws=StubWs(),  # type: ignore[arg-type]
            identity=MagicMock(),
            capabilities=[],
            agent_version="0.1.0",
        )
    )
    mgr = OperationManager(reg)
    op, nonce = await mgr.create_and_dispatch(42, "exec", {})

    redeemed = await mgr.redeem_nonce(nonce, system_id=42)
    assert redeemed.operation_id == op.operation_id
    assert redeemed.state == OperationState.ATTACHED

    with pytest.raises(NonceInvalid):
        await mgr.redeem_nonce(nonce, system_id=42)


@pytest.mark.asyncio
async def test_redeem_wrong_system_id_rejected():
    reg = AgentRegistry()
    from unittest.mock import MagicMock

    from app.broker.registry import TunnelEntry

    class StubWs:
        async def send(self, m):
            pass

        async def close(self, **_):
            pass

    await reg.register(
        TunnelEntry(
            system_id=42,
            tunnel_session_id="T",
            ws=StubWs(),  # type: ignore[arg-type]
            identity=MagicMock(),
            capabilities=[],
            agent_version="0.1.0",
        )
    )
    mgr = OperationManager(reg)
    _op, nonce = await mgr.create_and_dispatch(42, "exec", {})
    with pytest.raises(NonceInvalid, match="different system_id"):
        await mgr.redeem_nonce(nonce, system_id=99)


@pytest.mark.asyncio
async def test_redeem_after_ttl_expires():
    reg = AgentRegistry()
    from unittest.mock import MagicMock

    from app.broker.registry import TunnelEntry

    class StubWs:
        async def send(self, m):
            pass

        async def close(self, **_):
            pass

    await reg.register(
        TunnelEntry(
            system_id=42,
            tunnel_session_id="T",
            ws=StubWs(),  # type: ignore[arg-type]
            identity=MagicMock(),
            capabilities=[],
            agent_version="0.1.0",
        )
    )
    mgr = OperationManager(reg, nonce_ttl_seconds=0.05)
    _op, nonce = await mgr.create_and_dispatch(42, "exec", {})
    await asyncio.sleep(0.1)
    with pytest.raises(NonceExpired):
        await mgr.redeem_nonce(nonce, system_id=42)


@pytest.mark.asyncio
async def test_reissue_invalidates_prior_nonce():
    reg = AgentRegistry()
    from unittest.mock import MagicMock

    from app.broker.registry import TunnelEntry

    class StubWs:
        async def send(self, m):
            pass

        async def close(self, **_):
            pass

    await reg.register(
        TunnelEntry(
            system_id=42,
            tunnel_session_id="T",
            ws=StubWs(),  # type: ignore[arg-type]
            identity=MagicMock(),
            capabilities=[],
            agent_version="0.1.0",
        )
    )
    mgr = OperationManager(reg)
    op, original = await mgr.create_and_dispatch(42, "exec", {})
    new = await mgr.reissue_nonce(op.operation_id)
    assert new != original

    with pytest.raises(NonceInvalid):
        await mgr.redeem_nonce(original, system_id=42)
    redeemed = await mgr.redeem_nonce(new, system_id=42)
    assert redeemed.operation_id == op.operation_id


@pytest.mark.asyncio
async def test_concurrent_ops_limit():
    reg = AgentRegistry()
    from unittest.mock import MagicMock

    from app.broker.registry import TunnelEntry

    class StubWs:
        async def send(self, m):
            pass

        async def close(self, **_):
            pass

    await reg.register(
        TunnelEntry(
            system_id=42,
            tunnel_session_id="T",
            ws=StubWs(),  # type: ignore[arg-type]
            identity=MagicMock(),
            capabilities=[],
            agent_version="0.1.0",
        )
    )
    mgr = OperationManager(reg, max_concurrent_ops_per_agent=2)
    await mgr.create_and_dispatch(42, "exec", {})
    await mgr.create_and_dispatch(42, "exec", {})
    with pytest.raises(ConcurrentOpsExceeded):
        await mgr.create_and_dispatch(42, "exec", {})


@pytest.mark.asyncio
async def test_no_active_tunnel_rejects_create():
    reg = AgentRegistry()
    mgr = OperationManager(reg)
    with pytest.raises(NoActiveTunnel):
        await mgr.create_and_dispatch(42, "exec", {})


# ===========================================================================
# End-to-end op WSS flow (real broker, fake agent)
# ===========================================================================


@pytest.fixture
def trust_setup():
    ca_key, ca_cert = cfx.mk_ca()
    server_key, server_cert = cfx.mk_server_cert(ca_key, ca_cert)
    server_key_path, server_cert_path = cfx.write_pair(server_key, server_cert)
    ca_path = cfx.write_ca(ca_cert)
    return {
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "ca_path": ca_path,
        "server_cert_path": server_cert_path,
        "server_key_path": server_key_path,
    }


@asynccontextmanager
async def _broker(trust_setup, port, *, registry, manager):
    """Run a websockets server that dispatches /agent/tunnel and
    /agent/op to the real handlers."""

    def _validator(identity):
        return {"system_id": identity.system_id, "hostname": "h"}

    async def dispatch(ws):
        if ws.path == "/agent/tunnel":
            await tunnel_handler(
                ws,
                identity_validator=_validator,
                registry=registry,
                manager=manager,
                heartbeat_interval_seconds=10.0,
                heartbeat_dead_seconds=30.0,
            )
        elif ws.path == "/agent/op":
            await op_handler(
                ws,
                identity_validator=_validator,
                registry=registry,
                manager=manager,
            )
        else:
            await ws.close(code=4404, reason="unknown_path")

    ssl_ctx = build_server_ssl_context(
        server_certfile=trust_setup["server_cert_path"],
        server_keyfile=trust_setup["server_key_path"],
        client_ca_certfile=trust_setup["ca_path"],
    )
    server = await websockets.serve(
        dispatch,
        host="127.0.0.1",
        port=port,
        ssl=ssl_ctx,
        ping_interval=None,
        max_size=1 << 21,  # roomy enough for 1 MiB op frames
    )
    try:
        yield
    finally:
        server.close()
        await server.wait_closed()


def _hello(client_cert, capabilities=None):
    fp = hashlib.sha256(
        client_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    return {
        "type": "hello",
        "protocol_version": 1,
        "agent_version": "0.1.0",
        "capabilities": capabilities or ["exec", "facts", "heartbeat"],
        "cert_fingerprint": "sha256:" + fp,
    }


async def _connect_tunnel(port, ca_path, client_cert_path, client_key_path, hello):
    ctx = cfx.client_ssl_ctx(client_key_path, client_cert_path, ca_path)
    ws = await websockets.connect(f"wss://127.0.0.1:{port}/agent/tunnel", ssl=ctx)
    await ws.send(json.dumps(hello))
    welcome = json.loads(await ws.recv())
    assert welcome["type"] == "welcome"
    return ws


async def _read_op_request(ws):
    """Drain the next two control messages: op_request then op_nonce."""
    msg1 = json.loads(await ws.recv())
    msg2 = json.loads(await ws.recv())
    if msg1["type"] == "op_request" and msg2["type"] == "op_nonce":
        return msg1, msg2
    if msg1["type"] == "op_nonce" and msg2["type"] == "op_request":
        return msg2, msg1
    raise AssertionError(
        f"expected op_request + op_nonce, got {msg1['type']}/{msg2['type']}"
    )


@pytest.mark.asyncio
async def test_end_to_end_op_attach_and_stream(trust_setup, unused_tcp_port):
    registry = AgentRegistry()
    manager = OperationManager(registry, nonce_ttl_seconds=10)

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=42
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        try:
            # Backend (test) creates the op. Manager pushes op_request + op_nonce
            # over the tunnel.
            op, _ = await manager.create_and_dispatch(42, "exec", {"cmd": "echo hi"})
            req, nonce_msg = await _read_op_request(tunnel_ws)
            assert req["operation_id"] == op.operation_id
            nonce = nonce_msg["nonce"]

            # Agent dials the per-op WSS with the nonce header and sends op_attach.
            ctx = cfx.client_ssl_ctx(
                client_key_path, client_cert_path, trust_setup["ca_path"]
            )
            op_ws = await websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/op",
                ssl=ctx,
                extra_headers=[("X-Praxis-Op-Nonce", nonce)],
            )
            try:
                await op_ws.send(
                    json.dumps({"type": "op_attach", "operation_id": op.operation_id})
                )
                # Agent streams a stdout frame.
                await op_ws.send(
                    encode_frame(
                        Frame(
                            op=FrameOp.DATA,
                            channel=Channel.STDOUT,
                            payload=b"hello",
                        )
                    )
                )
                # Backend receives it via op.inbound.
                got = await asyncio.wait_for(op.inbound.get(), timeout=2.0)
                assert isinstance(got, Frame)
                assert got.channel == Channel.STDOUT
                assert got.payload == b"hello"

                # Backend writes a stdin frame back.
                await op.outbound.put(
                    Frame(op=FrameOp.DATA, channel=Channel.STDIN, payload=b"input")
                )
                wire = await asyncio.wait_for(op_ws.recv(), timeout=2.0)
                back = decode_frame(wire)
                assert back.channel == Channel.STDIN
                assert back.payload == b"input"

                # Agent reports completion on the control WSS, then closes
                # the per-op WSS.
                await tunnel_ws.send(
                    json.dumps(
                        {
                            "type": "op_complete",
                            "operation_id": op.operation_id,
                            "outcome": "success",
                        }
                    )
                )
                await op_ws.close()
                outcome, _err = await asyncio.wait_for(op.completion, timeout=2.0)
                assert outcome == "success"
                assert op.state == OperationState.COMPLETED
            finally:
                if not op_ws.closed:
                    await op_ws.close()
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_op_handler_rejects_missing_nonce_header(trust_setup, unused_tcp_port):
    registry = AgentRegistry()
    manager = OperationManager(registry)
    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=43
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        # Need a control tunnel first or we get rejected for "no_active_tunnel"
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        try:
            ctx = cfx.client_ssl_ctx(
                client_key_path, client_cert_path, trust_setup["ca_path"]
            )
            try:
                async with websockets.connect(
                    f"wss://127.0.0.1:{unused_tcp_port}/agent/op", ssl=ctx
                ) as ws:
                    with pytest.raises(websockets.exceptions.ConnectionClosed) as ei:
                        await ws.recv()
                    assert ei.value.code == 4001
                    assert "missing_nonce" in (ei.value.reason or "")
            except websockets.exceptions.InvalidStatusCode:
                pass
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_op_handler_rejects_when_no_active_tunnel(trust_setup, unused_tcp_port):
    registry = AgentRegistry()
    manager = OperationManager(registry)

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=44
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        ctx = cfx.client_ssl_ctx(
            client_key_path, client_cert_path, trust_setup["ca_path"]
        )
        try:
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/op",
                ssl=ctx,
                extra_headers=[("X-Praxis-Op-Nonce", "anything")],
            ) as ws:
                with pytest.raises(websockets.exceptions.ConnectionClosed) as ei:
                    await ws.recv()
                assert ei.value.code == 4001
                assert "no_active_tunnel" in (ei.value.reason or "")
        except websockets.exceptions.InvalidStatusCode:
            pass


@pytest.mark.asyncio
async def test_op_handler_rejects_bad_nonce(trust_setup, unused_tcp_port):
    registry = AgentRegistry()
    manager = OperationManager(registry)

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=45
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        try:
            ctx = cfx.client_ssl_ctx(
                client_key_path, client_cert_path, trust_setup["ca_path"]
            )
            try:
                async with websockets.connect(
                    f"wss://127.0.0.1:{unused_tcp_port}/agent/op",
                    ssl=ctx,
                    extra_headers=[("X-Praxis-Op-Nonce", "bogus-nonce")],
                ) as ws:
                    with pytest.raises(websockets.exceptions.ConnectionClosed) as ei:
                        await ws.recv()
                    assert ei.value.code == 4001
                    assert "nonce_invalid" in (ei.value.reason or "")
            except websockets.exceptions.InvalidStatusCode:
                pass
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_op_attach_mismatch_rejected(trust_setup, unused_tcp_port):
    registry = AgentRegistry()
    manager = OperationManager(registry)

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=46
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        try:
            op, _ = await manager.create_and_dispatch(46, "exec", {})
            _req, nonce_msg = await _read_op_request(tunnel_ws)

            ctx = cfx.client_ssl_ctx(
                client_key_path, client_cert_path, trust_setup["ca_path"]
            )
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/op",
                ssl=ctx,
                extra_headers=[("X-Praxis-Op-Nonce", nonce_msg["nonce"])],
            ) as op_ws:
                await op_ws.send(
                    json.dumps(
                        {
                            "type": "op_attach",
                            "operation_id": op.operation_id + 999,
                        }
                    )
                )
                with pytest.raises(websockets.exceptions.ConnectionClosed) as ei:
                    await op_ws.recv()
                assert "attach_mismatch" in (ei.value.reason or "")
            outcome, err = await asyncio.wait_for(op.completion, timeout=2.0)
            assert outcome == "error"
            assert err == {"reason": "attach_mismatch"}
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_cancel_then_agent_acks_with_op_complete(trust_setup, unused_tcp_port):
    registry = AgentRegistry()
    manager = OperationManager(registry, cancel_ack_timeout_seconds=5.0)

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=47
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        try:
            op, _ = await manager.create_and_dispatch(47, "exec", {})
            await _read_op_request(tunnel_ws)

            # Backend cancels.
            await manager.cancel(op.operation_id)
            # Agent receives op_cancel.
            cancel_msg = json.loads(await tunnel_ws.recv())
            assert cancel_msg["type"] == "op_cancel"
            assert cancel_msg["operation_id"] == op.operation_id
            # State is CANCELLING (not yet terminal).
            assert op.state == OperationState.CANCELLING

            # Agent acks with op_complete(cancelled).
            await tunnel_ws.send(
                json.dumps(
                    {
                        "type": "op_complete",
                        "operation_id": op.operation_id,
                        "outcome": "cancelled",
                    }
                )
            )
            outcome, _ = await asyncio.wait_for(op.completion, timeout=2.0)
            assert outcome == "cancelled"
            assert op.state == OperationState.CANCELLED
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_cancel_timeout_forces_terminal(trust_setup, unused_tcp_port):
    registry = AgentRegistry()
    manager = OperationManager(registry, cancel_ack_timeout_seconds=0.2)

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=48
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        try:
            op, _ = await manager.create_and_dispatch(48, "exec", {})
            await _read_op_request(tunnel_ws)

            await manager.cancel(op.operation_id)
            # Agent never replies — timeout fires.
            outcome, _ = await asyncio.wait_for(op.completion, timeout=2.0)
            assert outcome == "cancelled"
            assert op.state == OperationState.CANCELLED
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_expired_pending_nonces_do_not_consume_capacity(
    trust_setup, unused_tcp_port
):
    """P1: an agent that never dials /agent/op for prior ops must not
    block new ops. After the nonce TTL elapses, in-flight count drops
    so the next create succeeds."""
    registry = AgentRegistry()
    manager = OperationManager(
        registry,
        nonce_ttl_seconds=0.05,
        max_inflight_nonces_per_agent=2,
    )

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=51
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        try:
            await manager.create_and_dispatch(51, "exec", {})
            await manager.create_and_dispatch(51, "exec", {})
            # Limit hit; next create raises.
            with pytest.raises(NonceLimitExceeded):
                await manager.create_and_dispatch(51, "exec", {})
            # Wait for both nonces to expire.
            await asyncio.sleep(0.15)
            # Should now succeed — _enforce_limits sweeps stale pending.
            await manager.create_and_dispatch(51, "exec", {})
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_bad_inbound_frame_terminalises_op_as_errored(
    trust_setup, unused_tcp_port
):
    """P2: a malformed per-op frame must surface as ERRORED, not as a
    silent COMPLETED. Audit and callers must see the protocol violation."""
    registry = AgentRegistry()
    manager = OperationManager(registry)

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=52
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        try:
            op, _ = await manager.create_and_dispatch(52, "exec", {})
            _, nonce_msg = await _read_op_request(tunnel_ws)

            ctx = cfx.client_ssl_ctx(
                client_key_path, client_cert_path, trust_setup["ca_path"]
            )
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/op",
                ssl=ctx,
                extra_headers=[("X-Praxis-Op-Nonce", nonce_msg["nonce"])],
            ) as op_ws:
                await op_ws.send(
                    json.dumps({"type": "op_attach", "operation_id": op.operation_id})
                )
                # Junk binary that is not a valid frame (length mismatch).
                bad = bytes([1, 1, 1, 0, 0, 0, 0, 99]) + b"too_short"
                await op_ws.send(bad)
                # Server closes; client sees ConnectionClosed soon after.
                with pytest.raises(websockets.exceptions.ConnectionClosed):
                    await op_ws.recv()

            outcome, err = await asyncio.wait_for(op.completion, timeout=2.0)
            assert outcome == "error"
            assert err is not None
            assert err.get("reason") == "bad_frame"
            assert op.state == OperationState.ERRORED
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_tunnel_replacement_does_not_kill_new_tunnel_ops(
    trust_setup, unused_tcp_port
):
    """P1: when a tunnel is replaced, ops dispatched on the NEW tunnel
    must survive the OLD tunnel's cleanup. Cleanup is scoped to
    tunnel_session_id, not system_id."""
    registry = AgentRegistry()
    manager = OperationManager(registry)

    client_key1, client_cert1 = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=53
    )
    client_key2, client_cert2 = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=53
    )
    p1 = cfx.write_pair(client_key1, client_cert1)
    p2 = cfx.write_pair(client_key2, client_cert2)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_a = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            p1[1],
            p1[0],
            _hello(client_cert1),
        )
        # Connect tunnel B which replaces A.
        tunnel_b = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            p2[1],
            p2[0],
            _hello(client_cert2),
        )
        try:
            # Drain the bye:replaced from A so it doesn't trip later.
            try:
                await asyncio.wait_for(tunnel_a.recv(), timeout=1.0)
            except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError):
                pass
            # Give the orphan-ops cleanup task a moment to run (it
            # operates on A's session id; should not affect B's ops).
            await asyncio.sleep(0.1)

            # Dispatch a new op on B's tunnel. It must not be reaped by
            # A's cleanup.
            op_b, _ = await manager.create_and_dispatch(53, "exec", {})
            await _read_op_request(tunnel_b)
            await asyncio.sleep(0.2)
            assert op_b.state == OperationState.PENDING_NONCE
            assert manager.get(op_b.operation_id) is not None
        finally:
            with contextlib.suppress(Exception):
                await tunnel_a.close()
            await tunnel_b.close()


@pytest.mark.asyncio
async def test_tunnel_close_terminalises_orphan_ops(trust_setup, unused_tcp_port):
    registry = AgentRegistry()
    manager = OperationManager(registry)

    client_key, client_cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=49
    )
    client_key_path, client_cert_path = cfx.write_pair(client_key, client_cert)

    async with _broker(
        trust_setup, unused_tcp_port, registry=registry, manager=manager
    ):
        tunnel_ws = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            client_cert_path,
            client_key_path,
            _hello(client_cert),
        )
        op, _ = await manager.create_and_dispatch(49, "exec", {})
        await _read_op_request(tunnel_ws)

        # Hang up without doing anything else.
        await tunnel_ws.close()

        outcome, err = await asyncio.wait_for(op.completion, timeout=2.0)
        assert outcome == "errored"
        assert err == {"reason": "tunnel_closed"}
        assert op.state == OperationState.ERRORED


# ===========================================================================
# PRA-153 #3a: skip_terminal_sentinel honored by _terminalize
# ===========================================================================


@pytest.mark.asyncio
async def test_complete_skips_inbound_sentinel_for_streaming_ops():
    """Streaming endpoints (PRA-153 file_get) own EOF themselves via
    a protocol signal (FILE CLOSE). The manager's terminal None push
    on op.inbound would race ahead of remaining FILE frames in the
    bridge and truncate the stream. Verify _terminalize honors
    skip_terminal_sentinel=True by NOT injecting None for those ops.
    """
    from unittest.mock import MagicMock

    from app.broker.registry import TunnelEntry

    reg = AgentRegistry()

    class StubWs:
        sent = []

        async def send(self, m):
            self.sent.append(m)

        async def close(self, **_):
            pass

    entry = TunnelEntry(
        system_id=77,
        tunnel_session_id="T-stream",
        ws=StubWs(),  # type: ignore[arg-type]
        identity=MagicMock(not_after=None),
        capabilities=[],
        agent_version="0.1.0",
    )
    await reg.register(entry)

    mgr = OperationManager(reg, nonce_ttl_seconds=10)

    # Streaming op — file_get-style.
    streaming_op, _ = await mgr.create_and_dispatch(
        77, "file_get", {}, skip_terminal_sentinel=True
    )
    # Non-streaming op for contrast — exec-style.
    accumulator_op, _ = await mgr.create_and_dispatch(77, "exec", {})

    # Push some "real" frames into both inboxes to mimic frames the
    # bridge has delivered ahead of op_complete.
    for op in (streaming_op, accumulator_op):
        op.inbound.put_nowait(
            Frame(op=FrameOp.DATA, channel=Channel.STDOUT, flags=0, payload=b"x")
        )

    # Drive both through manager.complete(success). _terminalize fires.
    await mgr.complete(streaming_op.operation_id, outcome="success")
    await mgr.complete(accumulator_op.operation_id, outcome="success")

    # Drain. Streaming op's queue must contain ONLY the original
    # frame — no None added by _terminalize. Accumulator's queue
    # must have the frame followed by the None sentinel.
    streaming_items = []
    while not streaming_op.inbound.empty():
        streaming_items.append(streaming_op.inbound.get_nowait())
    assert (
        len(streaming_items) == 1
    ), f"streaming op inbound got terminal sentinel: {streaming_items}"
    assert streaming_items[0].channel == Channel.STDOUT

    accum_items = []
    while not accumulator_op.inbound.empty():
        accum_items.append(accumulator_op.inbound.get_nowait())
    assert (
        len(accum_items) == 2
    ), f"accumulator op missing terminal sentinel: {accum_items}"
    assert accum_items[0].channel == Channel.STDOUT
    assert accum_items[1] is None
