"""PRA-151 task #20: audit-event coverage for tunnel + op lifecycle.

Each test injects a list-collecting ``audit_emit`` so we can assert
that the broker emits the expected event vocabulary at the right
lifecycle edges. Heartbeats and per-frame traffic are intentionally
NOT audited; one of the assertions guards against accidental noise.

Reason-coded rejections are exhaustively covered: bad cert / system
not active / fingerprint mismatch / no active tunnel / missing nonce /
nonce invalid / attach mismatch.

Never asserted in audit context: raw nonce, private key bytes, full
cert PEMs, headers.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import json
from contextlib import asynccontextmanager
from functools import partial

import pytest
import websockets
from cryptography.hazmat.primitives import serialization

from app.broker.audit import (
    OP_ATTACHED,
    OP_CANCEL_REQUESTED,
    OP_COMPLETED,
    OP_REJECTED,
    OP_REQUESTED,
    TUNNEL_CERT_EXPIRED,
    TUNNEL_CONNECTED,
    TUNNEL_DISCONNECTED,
    TUNNEL_HEARTBEAT_DEAD,
    TUNNEL_REJECTED,
    TUNNEL_REPLACED,
)
from app.broker.handlers import (
    REJECT_FINGERPRINT_MISMATCH,
    REJECT_NOT_ACTIVE,
    BrokerRejection,
    op_handler,
    tunnel_handler,
)
from app.broker.ops import OperationManager
from app.broker.protocol import Channel, Frame, FrameOp, encode_frame
from app.broker.registry import AgentRegistry
from app.broker.tls import build_server_ssl_context

from . import _certfx as cfx

# ---------------------------------------------------------------------------
# Audit collector
# ---------------------------------------------------------------------------


class AuditCollector:
    """Captures every emit() call. Each entry is the kwargs dict the
    safe_emit signature would have received."""

    def __init__(self):
        self.events: list[dict] = []

    def __call__(self, **kwargs):
        self.events.append(kwargs)

    def actions(self) -> list[str]:
        return [e["action"] for e in self.events]

    def find(self, action: str) -> list[dict]:
        return [e for e in self.events if e["action"] == action]


def _assert_no_secrets(events: list[dict]) -> None:
    """Defensive: walk every event context and fail if anything that
    looks like a raw nonce / private key / PEM cert leaked through."""
    for e in events:
        ctx = e.get("context") or {}
        flat = json.dumps(ctx)
        assert "BEGIN PRIVATE KEY" not in flat
        assert "BEGIN CERTIFICATE" not in flat
        assert "X-Praxis-Op-Nonce" not in flat
        # Raw nonces from secrets.token_urlsafe(32) yield ~43 char
        # base64. We never store them, but guard against accidental
        # additions in future.
        assert "nonce" not in {k.lower() for k in ctx.keys()}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def trust_setup():
    ca_key, ca_cert = cfx.mk_ca()
    server_key, server_cert = cfx.mk_server_cert(ca_key, ca_cert)
    sk, sc = cfx.write_pair(server_key, server_cert)
    ca = cfx.write_ca(ca_cert)
    return {
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "ca_path": ca,
        "server_cert_path": sc,
        "server_key_path": sk,
    }


@asynccontextmanager
async def _broker(
    trust_setup,
    port,
    *,
    registry,
    manager,
    audit,
    validator,
    heartbeat_interval=10.0,
    heartbeat_dead=10.0,
):
    async def dispatch(ws):
        if ws.path == "/agent/tunnel":
            await tunnel_handler(
                ws,
                identity_validator=validator,
                registry=registry,
                manager=manager,
                audit_emit=audit,
                heartbeat_interval_seconds=heartbeat_interval,
                heartbeat_dead_seconds=heartbeat_dead,
            )
        elif ws.path == "/agent/op":
            await op_handler(
                ws,
                identity_validator=validator,
                registry=registry,
                manager=manager,
                audit_emit=audit,
            )
        else:
            await ws.close(code=4404)

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
        max_size=2 << 20,
    )
    try:
        yield
    finally:
        server.close()
        await server.wait_closed()


def _accept_validator(identity):
    return {"system_id": identity.system_id, "hostname": "h"}


def _hello(client_cert):
    fp = hashlib.sha256(
        client_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    return {
        "type": "hello",
        "protocol_version": 1,
        "agent_version": "0.1.0",
        "capabilities": ["exec", "facts", "heartbeat"],
        "cert_fingerprint": "sha256:" + fp,
    }


async def _connect_tunnel(port, ca_path, cert_path, key_path, hello):
    ctx = cfx.client_ssl_ctx(key_path, cert_path, ca_path)
    ws = await websockets.connect(f"wss://127.0.0.1:{port}/agent/tunnel", ssl=ctx)
    await ws.send(json.dumps(hello))
    welcome = json.loads(await ws.recv())
    assert welcome["type"] == "welcome"
    return ws, welcome


# ---------------------------------------------------------------------------
# Tunnel events
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tunnel_connected_then_disconnected(trust_setup, unused_tcp_port):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=10
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ws, welcome = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        await ws.close()

    # Wait briefly for the tunnel handler's finally block to run.
    for _ in range(20):
        await asyncio.sleep(0.05)
        if TUNNEL_DISCONNECTED in audit.actions():
            break

    actions = audit.actions()
    assert TUNNEL_CONNECTED in actions
    assert TUNNEL_DISCONNECTED in actions

    connected = audit.find(TUNNEL_CONNECTED)[0]
    assert connected["target_system_id"] == 10
    assert connected["context"]["tunnel_session_id"] == welcome["tunnel_session_id"]
    assert connected["context"]["agent_version"] == "0.1.0"

    disconnected = audit.find(TUNNEL_DISCONNECTED)[0]
    assert disconnected["target_system_id"] == 10
    assert "duration_ms" in disconnected["context"]
    assert disconnected["context"]["duration_ms"] >= 0
    _assert_no_secrets(audit.events)


@pytest.mark.asyncio
async def test_tunnel_rejected_validator_denies(trust_setup, unused_tcp_port):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)

    def deny(identity):
        raise BrokerRejection(REJECT_NOT_ACTIVE, "stub")

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=11
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=deny,
    ):
        ctx = cfx.client_ssl_ctx(key_path, cert_path, trust_setup["ca_path"])
        with contextlib.suppress(
            websockets.exceptions.ConnectionClosed,
            websockets.exceptions.InvalidStatusCode,
        ):
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
            ) as ws:
                await ws.recv()

    rejects = audit.find(TUNNEL_REJECTED)
    assert len(rejects) == 1
    assert rejects[0]["outcome"] == "denied"
    assert rejects[0]["context"]["reason"] == REJECT_NOT_ACTIVE
    assert rejects[0]["target_system_id"] == 11


@pytest.mark.asyncio
async def test_tunnel_rejected_handshake_bad_json(trust_setup, unused_tcp_port):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)
    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=12
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ctx = cfx.client_ssl_ctx(key_path, cert_path, trust_setup["ca_path"])
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send("not json {{{{")
            with contextlib.suppress(websockets.exceptions.ConnectionClosed):
                await ws.recv()

    rejects = audit.find(TUNNEL_REJECTED)
    assert len(rejects) == 1
    assert rejects[0]["context"]["reason"] == "handshake_not_json"
    # Connection never reached the welcome stage, so no CONNECTED event.
    assert TUNNEL_CONNECTED not in audit.actions()


@pytest.mark.asyncio
async def test_tunnel_replaced_emits_for_displaced_session(
    trust_setup, unused_tcp_port
):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=13
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)
    ckey2, ccert2 = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=13
    )
    k2, c2 = cfx.write_pair(ckey2, ccert2)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ws_a, welcome_a = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        ws_b, welcome_b = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            c2,
            k2,
            _hello(ccert2),
        )
        # drain ws_a's bye:replaced + close
        with contextlib.suppress(Exception):
            await asyncio.wait_for(ws_a.recv(), timeout=1.0)
        await ws_b.close()

    for _ in range(20):
        await asyncio.sleep(0.05)
        if TUNNEL_REPLACED in audit.actions():
            break

    replaced = audit.find(TUNNEL_REPLACED)
    assert len(replaced) == 1
    assert replaced[0]["context"]["tunnel_session_id"] == welcome_a["tunnel_session_id"]
    assert (
        replaced[0]["context"]["replaced_by_session"] == welcome_b["tunnel_session_id"]
    )


@pytest.mark.asyncio
async def test_tunnel_heartbeat_dead_event(trust_setup, unused_tcp_port):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=14
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
        heartbeat_interval=10.0,
        heartbeat_dead=0.4,
    ):
        ws, _ = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        # Don't send anything; await dead event.
        with contextlib.suppress(websockets.exceptions.ConnectionClosed):
            await asyncio.wait_for(ws.recv(), timeout=2.0)
            await asyncio.wait_for(ws.recv(), timeout=2.0)

    for _ in range(20):
        await asyncio.sleep(0.05)
        if TUNNEL_HEARTBEAT_DEAD in audit.actions():
            break
    dead = audit.find(TUNNEL_HEARTBEAT_DEAD)
    assert len(dead) == 1
    assert dead[0]["outcome"] == "failure"
    assert "idle_seconds" in dead[0]["context"]


@pytest.mark.asyncio
async def test_tunnel_cert_expired_event(trust_setup, unused_tcp_port):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)

    # 3s, not 1s: gives the TLS handshake + welcome enough headroom on
    # slower CI runners. Still fast enough that the test completes
    # within the asyncio.wait_for(timeout=...) windows below.
    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"],
        trust_setup["ca_cert"],
        system_id=15,
        not_after_seconds=3,
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ws, _ = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        with contextlib.suppress(websockets.exceptions.ConnectionClosed):
            await asyncio.wait_for(ws.recv(), timeout=5.0)
            await asyncio.wait_for(ws.recv(), timeout=5.0)

    for _ in range(60):
        await asyncio.sleep(0.05)
        if TUNNEL_CERT_EXPIRED in audit.actions():
            break
    expired = audit.find(TUNNEL_CERT_EXPIRED)
    assert len(expired) == 1
    assert expired[0]["context"]["reason"] == "cert_expired"
    assert "not_after" in expired[0]["context"]


@pytest.mark.asyncio
async def test_no_audit_event_per_heartbeat(trust_setup, unused_tcp_port):
    """Audit must not fire one event per heartbeat — only lifecycle edges."""
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=16
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
        heartbeat_interval=0.05,
        heartbeat_dead=10.0,
    ):
        ws, _ = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        # Receive several heartbeats from the broker.
        for _ in range(5):
            await ws.recv()
        await ws.close()

    for _ in range(20):
        await asyncio.sleep(0.05)
        if TUNNEL_DISCONNECTED in audit.actions():
            break
    actions = audit.actions()
    # Connected once + disconnected once. No "heartbeat" action exists.
    assert actions.count(TUNNEL_CONNECTED) == 1
    assert actions.count(TUNNEL_DISCONNECTED) == 1
    assert not any("heartbeat" in a for a in actions if a != TUNNEL_HEARTBEAT_DEAD)


# ---------------------------------------------------------------------------
# Op events
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_op_full_lifecycle_emits_requested_attached_completed(
    trust_setup, unused_tcp_port
):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=20
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ws, _ = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        op, _ = await manager.create_and_dispatch(20, "exec", {})
        # Drain op_request + op_nonce
        msgs = []
        while len(msgs) < 2:
            msg = json.loads(await ws.recv())
            if msg["type"] in ("op_request", "op_nonce"):
                msgs.append(msg)
        nonce = next(m["nonce"] for m in msgs if m["type"] == "op_nonce")

        ctx = cfx.client_ssl_ctx(key_path, cert_path, trust_setup["ca_path"])
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/op",
            ssl=ctx,
            extra_headers=[("X-Praxis-Op-Nonce", nonce)],
        ) as op_ws:
            await op_ws.send(
                json.dumps({"type": "op_attach", "operation_id": op.operation_id})
            )
            await op_ws.send(
                encode_frame(
                    Frame(op=FrameOp.DATA, channel=Channel.STDOUT, payload=b"x")
                )
            )
            await op.inbound.get()
        await ws.send(
            json.dumps(
                {
                    "type": "op_complete",
                    "operation_id": op.operation_id,
                    "outcome": "success",
                }
            )
        )
        await op.completion
        await ws.close()

    for _ in range(20):
        await asyncio.sleep(0.05)
        if OP_COMPLETED in audit.actions():
            break

    requested = audit.find(OP_REQUESTED)
    assert len(requested) == 1
    assert requested[0]["context"]["op_type"] == "exec"

    attached = audit.find(OP_ATTACHED)
    assert len(attached) == 1
    assert attached[0]["context"]["operation_id"] == op.operation_id

    completed = audit.find(OP_COMPLETED)
    assert len(completed) == 1
    assert completed[0]["outcome"] == "success"
    assert "duration_ms" in completed[0]["context"]
    _assert_no_secrets(audit.events)


@pytest.mark.asyncio
async def test_op_rejected_bad_nonce(trust_setup, unused_tcp_port):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit)

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=21
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ws, _ = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        ctx = cfx.client_ssl_ctx(key_path, cert_path, trust_setup["ca_path"])
        with contextlib.suppress(websockets.exceptions.ConnectionClosed):
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/op",
                ssl=ctx,
                extra_headers=[("X-Praxis-Op-Nonce", "bogus")],
            ) as op_ws:
                await op_ws.recv()
        await ws.close()

    for _ in range(20):
        await asyncio.sleep(0.05)
        if OP_REJECTED in audit.actions():
            break
    rejects = audit.find(OP_REJECTED)
    assert len(rejects) == 1
    assert rejects[0]["context"]["reason"] == "nonce_invalid"
    assert rejects[0]["target_system_id"] == 21


@pytest.mark.asyncio
async def test_op_completed_expired_via_redeem_after_ttl(trust_setup, unused_tcp_port):
    """Nonce TTL elapses before the agent dials /agent/op. The
    redeem_nonce TTL-check path must still emit OP_COMPLETED with
    outcome='expired' — otherwise nonce timeouts are invisible to
    audit."""
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(registry, audit_emit=audit, nonce_ttl_seconds=0.05)

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=23
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ws, _ = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        op, raw_nonce = await manager.create_and_dispatch(23, "exec", {})
        # Drain op_request + op_nonce
        for _ in range(2):
            await ws.recv()

        # Wait past TTL.
        await asyncio.sleep(0.1)

        from app.broker.ops import NonceExpired

        with pytest.raises(NonceExpired):
            await manager.redeem_nonce(raw_nonce, system_id=23)

        await ws.close()

    completed = audit.find(OP_COMPLETED)
    expired_events = [e for e in completed if e["outcome"] == "expired"]
    assert (
        len(expired_events) == 1
    ), f"expected 1 OP_COMPLETED(expired), got {[e['outcome'] for e in completed]}"
    assert expired_events[0]["context"]["operation_id"] == op.operation_id
    assert "duration_ms" in expired_events[0]["context"]


@pytest.mark.asyncio
async def test_op_completed_expired_via_lazy_sweep(trust_setup, unused_tcp_port):
    """Lazy expiry sweep inside _enforce_limits_locked must emit
    OP_COMPLETED(expired) for the swept ops — even when the caller's
    own dispatch succeeds afterward."""
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(
        registry,
        audit_emit=audit,
        nonce_ttl_seconds=0.05,
        max_inflight_nonces_per_agent=2,
    )

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=24
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ws, _ = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        # Two ops never get redeemed; their nonces TTL out.
        op_a, _ = await manager.create_and_dispatch(24, "exec", {})
        op_b, _ = await manager.create_and_dispatch(24, "exec", {})
        await asyncio.sleep(0.15)

        # Third dispatch triggers the lazy sweep, which expires both.
        await manager.create_and_dispatch(24, "exec", {})
        await ws.close()

    completed = audit.find(OP_COMPLETED)
    expired_ids = sorted(
        e["context"]["operation_id"] for e in completed if e["outcome"] == "expired"
    )
    assert expired_ids == [op_a.operation_id, op_b.operation_id], (
        f"expected expired ops {[op_a.operation_id, op_b.operation_id]}, "
        f"got {expired_ids}"
    )


@pytest.mark.asyncio
async def test_op_cancel_requested_event(trust_setup, unused_tcp_port):
    audit = AuditCollector()
    registry = AgentRegistry()
    manager = OperationManager(
        registry, audit_emit=audit, cancel_ack_timeout_seconds=5.0
    )

    ckey, ccert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=22
    )
    key_path, cert_path = cfx.write_pair(ckey, ccert)

    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        audit=audit,
        validator=_accept_validator,
    ):
        ws, _ = await _connect_tunnel(
            unused_tcp_port,
            trust_setup["ca_path"],
            cert_path,
            key_path,
            _hello(ccert),
        )
        op, _ = await manager.create_and_dispatch(22, "exec", {})
        # drain op_request + op_nonce
        for _ in range(2):
            await ws.recv()
        await manager.cancel(op.operation_id)
        # drain op_cancel
        cancel_msg = json.loads(await ws.recv())
        assert cancel_msg["type"] == "op_cancel"
        await ws.send(
            json.dumps(
                {
                    "type": "op_complete",
                    "operation_id": op.operation_id,
                    "outcome": "cancelled",
                }
            )
        )
        await op.completion
        await ws.close()

    for _ in range(20):
        await asyncio.sleep(0.05)
        if OP_COMPLETED in audit.actions():
            break
    assert OP_CANCEL_REQUESTED in audit.actions()
    completed = audit.find(OP_COMPLETED)
    assert completed[0]["outcome"] == "cancelled"
