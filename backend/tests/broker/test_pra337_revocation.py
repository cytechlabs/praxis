"""PRA-337: live agent disable / revoke enforcement in the broker.

Covers, with simulated committed identity state (``Authority``) driving the
real handlers over real mTLS WSS and, where ordering matters, stub sockets:

  * dispatch refused after the status change commits, with nothing sent
  * dispatch fails closed when status is unreadable or the read hangs
  * unaffected agents keep working
  * eviction: confirmed / not_started / unconfirmed in-flight reporting
  * idempotency, stale-session and delayed-signal safety, replacement
  * convergence without the backend signal (self-revalidation loop)
  * start gate (op_ready) refusing a revoked identity before any work
  * eviction vs concurrent dispatch ordering (linearization invariant)
  * internal API: evict endpoint, auth, dispatch refusal mapping
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import httpx
import pytest
import websockets

from app.broker.handlers import (
    REJECT_NOT_ACTIVE,
    BrokerRejection,
    op_handler,
    tunnel_handler,
)
from app.broker.internal_api import build_internal_app
from app.broker.ops import (
    AgentNotAuthorized,
    NoActiveTunnel,
    OperationManager,
    OperationState,
)
from app.broker.registry import AgentRegistry, TunnelEntry
from app.broker.tls import build_server_ssl_context

from . import _certfx as cfx
from .test_op_lifecycle import _connect_tunnel, _hello, _read_op_request


@pytest.fixture
def trust_setup():
    ca_key, ca_cert = cfx.mk_ca()
    server_key, server_cert = cfx.mk_server_cert(ca_key, ca_cert)
    server_key_path, server_cert_path = cfx.write_pair(server_key, server_cert)
    return {
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "ca_path": cfx.write_ca(ca_cert),
        "server_cert_path": server_cert_path,
        "server_key_path": server_key_path,
    }


class Authority:
    """Stands in for the committed System row the validator reads."""

    def __init__(self):
        self.status = {}  # system_id -> status (default active)
        self.fail = False  # status unreadable
        self.hang = False  # status read never returns in time
        self.calls = 0
        self.deny_from_call = None  # deny every call from the Nth on

    def validator(self, identity):
        self.calls += 1
        if self.hang:
            time.sleep(1.0)
        if self.fail:
            raise RuntimeError("database unavailable")
        if self.deny_from_call is not None and self.calls >= self.deny_from_call:
            raise BrokerRejection(REJECT_NOT_ACTIVE, "agent_status=disabled")
        status = self.status.get(identity.system_id, "active")
        if status != "active":
            raise BrokerRejection(REJECT_NOT_ACTIVE, f"agent_status={status}")
        return {"system_id": identity.system_id, "hostname": "h"}


class Audit:
    def __init__(self):
        self.events = []

    def __call__(self, **kw):
        self.events.append(kw)

    def actions(self):
        return [e["action"] for e in self.events]

    def last(self, action):
        return [e for e in self.events if e["action"] == action][-1]


@asynccontextmanager
async def _broker(trust_setup, port, *, registry, manager, authority, audit, **kw):
    async def dispatch(ws):
        if ws.path == "/agent/tunnel":
            await tunnel_handler(
                ws,
                identity_validator=authority.validator,
                registry=registry,
                manager=manager,
                audit_emit=audit,
                heartbeat_interval_seconds=10.0,
                heartbeat_dead_seconds=30.0,
                **kw,
            )
        elif ws.path == "/agent/op":
            await op_handler(
                ws,
                identity_validator=authority.validator,
                registry=registry,
                manager=manager,
                audit_emit=audit,
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
        max_size=1 << 21,
    )
    try:
        yield
    finally:
        server.close()
        await server.wait_closed()


def _agent_creds(trust_setup, system_id):
    key, cert = cfx.mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=system_id
    )
    key_path, cert_path = cfx.write_pair(key, cert)
    return cert, key_path, cert_path


async def _connect(trust_setup, port, system_id):
    cert, key_path, cert_path = _agent_creds(trust_setup, system_id)
    ws = await _connect_tunnel(
        port, trust_setup["ca_path"], cert_path, key_path, _hello(cert)
    )
    return ws, (key_path, cert_path)


async def _attach(trust_setup, port, creds, op, nonce, *, gated=True):
    key_path, cert_path = creds
    ctx = cfx.client_ssl_ctx(key_path, cert_path, trust_setup["ca_path"])
    op_ws = await websockets.connect(
        f"wss://127.0.0.1:{port}/agent/op",
        ssl=ctx,
        extra_headers=[("X-Praxis-Op-Nonce", nonce)],
    )
    attach = {"type": "op_attach", "operation_id": op.operation_id}
    if gated:
        attach["await_ready"] = True
    await op_ws.send(json.dumps(attach))
    return op_ws


async def _no_message(ws, seconds=0.3):
    try:
        got = await asyncio.wait_for(ws.recv(), timeout=seconds)
    except (asyncio.TimeoutError, websockets.ConnectionClosed):
        return None
    return got


async def _wait_for(pred, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        await asyncio.sleep(0.02)
    return pred()


# ---------------------------------------------------------------------------
# Dispatch authority
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_refused_after_commit_and_unaffected_agent_still_works(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        revoked_ws, _ = await _connect(trust_setup, unused_tcp_port, 42)
        healthy_ws, _ = await _connect(trust_setup, unused_tcp_port, 43)
        try:
            # Active control: dispatch reaches the agent.
            op, _n = await manager.create_and_dispatch(42, "exec", {"cmd": "id"})
            req, _nonce = await _read_op_request(revoked_ws)
            assert req["operation_id"] == op.operation_id
            assert req["await_ready"] is True

            authority.status[42] = "revoked"  # the commit

            with pytest.raises(AgentNotAuthorized) as exc:
                await manager.create_and_dispatch(42, "exec", {"cmd": "touch /x"})
            assert exc.value.code == REJECT_NOT_ACTIVE
            assert not exc.value.unverifiable
            # Nothing was sent to the revoked agent for the refused dispatch.
            assert await _no_message(revoked_ws) is None
            # No second op exists for the system.
            assert [o.operation_id for o in manager.for_system(42)] == [op.operation_id]

            # Unaffected agent still dispatches.
            op2, _ = await manager.create_and_dispatch(43, "exec", {"cmd": "id"})
            req2, _ = await _read_op_request(healthy_ws)
            assert req2["operation_id"] == op2.operation_id
        finally:
            await revoked_ws.close()
            await healthy_ws.close()


@pytest.mark.asyncio
async def test_dispatch_fails_closed_when_status_unreadable(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(
        registry, audit_emit=audit, authorize_timeout_seconds=0.2
    )
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        ws, _ = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            authority.fail = True
            with pytest.raises(AgentNotAuthorized) as exc:
                await manager.create_and_dispatch(42, "exec", {"cmd": "id"})
            assert exc.value.unverifiable
            authority.fail = False

            authority.hang = True  # lookup exceeds the bound
            with pytest.raises(AgentNotAuthorized) as exc:
                await manager.create_and_dispatch(42, "exec", {"cmd": "id"})
            assert exc.value.unverifiable
            authority.hang = False
            assert await _no_message(ws) is None
            assert manager.for_system(42) == []

            # Recovered status authorizes again (no latched denial).
            op, _ = await manager.create_and_dispatch(42, "exec", {"cmd": "id"})
            await _read_op_request(ws)
            assert op.state == OperationState.PENDING_NONCE
        finally:
            await ws.close()


# ---------------------------------------------------------------------------
# Eviction and in-flight reporting
# ---------------------------------------------------------------------------


async def _running_op(trust_setup, port, manager, creds, tunnel_ws, system_id=42):
    """Dispatch an op, attach it as a gated agent and release it."""
    op, _ = await manager.create_and_dispatch(system_id, "exec", {"cmd": "sleep 60"})
    _req, nonce_msg = await _read_op_request(tunnel_ws)
    op_ws = await _attach(trust_setup, port, creds, op, nonce_msg["nonce"])
    ready = json.loads(await asyncio.wait_for(op_ws.recv(), timeout=2.0))
    assert ready == {"type": "op_ready", "operation_id": op.operation_id}
    assert op.state == OperationState.ATTACHED
    return op, op_ws


async def _agent_acks_cancel(tunnel_ws, op, extra):
    """Behave like an agent: wait for op_cancel, then report op_complete."""
    while True:
        msg = json.loads(await tunnel_ws.recv())
        if msg["type"] == "op_cancel" and msg["operation_id"] == op.operation_id:
            await tunnel_ws.send(
                json.dumps(
                    {
                        "type": "op_complete",
                        "operation_id": op.operation_id,
                        "outcome": "cancelled",
                        "exit_code": None,
                        "duration_ms": 5,
                        **extra,
                    }
                )
            )
            return


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra,expected_reason,expected_termination",
    [
        ({"termination": "confirmed"}, "agent_revoked", "confirmed"),
        ({"termination": "not_started"}, "agent_revoked", "not_started"),
        # Agent that predates the field: cancelled is not evidence of a stop.
        ({}, "agent_revoked_unconfirmed", "unconfirmed"),
        (
            {"termination": "unconfirmed"},
            "agent_revoked_unconfirmed",
            "unconfirmed",
        ),
        # Unknown value must not be trusted as confirmation.
        ({"termination": "yes"}, "agent_revoked_unconfirmed", "unconfirmed"),
    ],
)
async def test_eviction_reports_only_what_agent_confirmed(
    trust_setup, unused_tcp_port, extra, expected_reason, expected_termination
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit, evict_ack_timeout_seconds=3)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        tunnel_ws, creds = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            op, op_ws = await _running_op(
                trust_setup, unused_tcp_port, manager, creds, tunnel_ws
            )
            acker = asyncio.create_task(_agent_acks_cancel(tunnel_ws, op, extra))
            authority.status[42] = "revoked"

            summary = await manager.evict_system(42, reason="revoked")
            await acker

            assert summary["result"] == "evicted"
            assert summary["ops"] == {expected_termination: 1}
            assert op.state == OperationState.CANCELLED
            assert op.error["reason"] == expected_reason
            assert op.error["termination"] == expected_termination
            assert op.error["cause"] == "revoked"
            assert registry.get(42) is None
            # The agent is told why and the socket is closed.
            bye = json.loads(await asyncio.wait_for(tunnel_ws.recv(), timeout=2.0))
            assert bye == {"type": "bye", "reason": "revoked"}
            with pytest.raises(websockets.ConnectionClosed):
                await asyncio.wait_for(tunnel_ws.recv(), timeout=2.0)
            ev = audit.last("agent.tunnel.evicted")
            assert ev["context"]["reason"] == "revoked"
            assert ev["context"]["ops"] == {expected_termination: 1}
            done = audit.last("agent.op.completed")
            assert done["context"]["reason"] == expected_reason
            assert done["context"]["termination"] == expected_termination
            await op_ws.close()
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_eviction_without_agent_ack_is_unconfirmed_within_bound(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(
        registry, audit_emit=audit, evict_ack_timeout_seconds=0.4
    )
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        tunnel_ws, creds = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            op, op_ws = await _running_op(
                trust_setup, unused_tcp_port, manager, creds, tunnel_ws
            )
            authority.status[42] = "disabled"
            started = time.monotonic()
            summary = await manager.evict_system(42, reason="disabled")
            elapsed = time.monotonic() - started

            assert elapsed < 2.0  # bounded by the ack window, not the exec cap
            assert summary["ops"] == {"unconfirmed": 1}
            assert op.state == OperationState.ERRORED
            assert op.error["reason"] == "agent_revoked_unconfirmed"
            assert op.error["termination"] == "unconfirmed"
            # A per-op socket that closes is not evidence of a stop.
            await op_ws.close()
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_op_finished_before_cancel_stays_success(trust_setup, unused_tcp_port):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit, evict_ack_timeout_seconds=3)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        tunnel_ws, creds = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            op, op_ws = await _running_op(
                trust_setup, unused_tcp_port, manager, creds, tunnel_ws
            )

            async def finish_instead():
                while True:
                    msg = json.loads(await tunnel_ws.recv())
                    if msg["type"] == "op_cancel":
                        await tunnel_ws.send(
                            json.dumps(
                                {
                                    "type": "op_complete",
                                    "operation_id": op.operation_id,
                                    "outcome": "success",
                                    "exit_code": 0,
                                }
                            )
                        )
                        return

            t = asyncio.create_task(finish_instead())
            authority.status[42] = "revoked"
            await manager.evict_system(42, reason="revoked")
            await t
            # Truthful: it ran to completion; eviction does not rewrite that.
            assert op.state == OperationState.COMPLETED
            assert op.outcome == "success"
            assert op.error is None
            await op_ws.close()
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_evict_signal_is_idempotent_and_safe_after_reenable(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        ws, _ = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            session = registry.get(42).tunnel_session_id

            # Delayed signal arrives after the operator already re-enabled:
            # the broker re-reads authority and leaves the session alone.
            res = await manager.evict_system(42, reason="disabled")
            assert res["result"] == "not_evicted"
            assert registry.get(42) is not None
            assert "agent.tunnel.evicted" not in audit.actions()

            # Wrong session id (stale signal for a replaced session): no-op.
            authority.status[42] = "disabled"
            stale = await manager.evict_system(
                42, reason="disabled", expected_session_id="not-this-one"
            )
            assert stale["result"] == "stale_session"
            assert registry.get(42).tunnel_session_id == session

            # Duplicate and concurrent signals share one eviction.
            a, b = await asyncio.gather(
                manager.evict_system(42, reason="disabled"),
                manager.evict_system(42, reason="disabled"),
            )
            assert a["result"] == b["result"] == "evicted"
            assert audit.actions().count("agent.tunnel.evicted") == 1
            again = await manager.evict_system(42, reason="disabled")
            assert again["result"] == "no_session"
            assert audit.actions().count("agent.tunnel.evicted") == 1
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_stale_eviction_does_not_touch_replacement_session(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        old_ws, _ = await _connect(trust_setup, unused_tcp_port, 42)
        old_session = registry.get(42).tunnel_session_id
        new_ws, _ = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            await _wait_for(lambda: registry.get(42).tunnel_session_id != old_session)
            new_session = registry.get(42).tunnel_session_id
            authority.status[42] = "disabled"
            authority.status[42] = "active"  # operator flipped it back

            res = await manager.evict_system(
                42, reason="disabled", expected_session_id=old_session
            )
            assert res["result"] == "stale_session"
            assert registry.get(42).tunnel_session_id == new_session
            op, _ = await manager.create_and_dispatch(42, "exec", {"cmd": "id"})
            req, _ = await _read_op_request(new_ws)
            assert req["operation_id"] == op.operation_id
        finally:
            await old_ws.close()
            await new_ws.close()


# ---------------------------------------------------------------------------
# Convergence without the backend signal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missed_signal_converges_through_revalidation(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit, evict_ack_timeout_seconds=1)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=0.15,
    ):
        ws, creds = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            op, op_ws = await _running_op(
                trust_setup, unused_tcp_port, manager, creds, ws
            )
            acker = asyncio.create_task(
                _agent_acks_cancel(ws, op, {"termination": "confirmed"})
            )
            authority.status[42] = "revoked"  # no backend signal is ever sent
            started = time.monotonic()
            assert await _wait_for(lambda: registry.get(42) is None, timeout=3.0)
            assert time.monotonic() - started < 2.0
            await acker
            assert op.error["reason"] == "agent_revoked"
            assert (
                audit.last("agent.tunnel.evicted")["context"]["reason"] == "not_active"
            )
            await op_ws.close()
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_revalidation_keeps_tunnel_when_identity_stays_authorized(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=0.05,
    ):
        ws, _ = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            await asyncio.sleep(0.5)
            assert registry.get(42) is not None
            # A single unreadable status is a blip, not an eviction.
            authority.fail = True
            await asyncio.sleep(0.08)
            authority.fail = False
            await asyncio.sleep(0.4)
            assert registry.get(42) is not None
            assert "agent.tunnel.evicted" not in audit.actions()
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_persistently_unverifiable_status_evicts(trust_setup, unused_tcp_port):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=0.05,
    ):
        ws, _ = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            authority.fail = True
            assert await _wait_for(lambda: registry.get(42) is None, timeout=3.0)
            assert (
                audit.last("agent.tunnel.evicted")["context"]["reason"]
                == "unverifiable"
            )
        finally:
            await ws.close()


# ---------------------------------------------------------------------------
# Data-channel start gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_gate_refuses_revoked_identity_before_any_work(
    trust_setup, unused_tcp_port
):
    """Dispatch happened while authorized; the status changed before the agent
    attached. The per-op handshake may still pass its own check, but the
    broker re-reads authority at the gate and never sends op_ready."""
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        tunnel_ws, creds = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            op, _ = await manager.create_and_dispatch(42, "exec", {"cmd": "touch /x"})
            _req, nonce_msg = await _read_op_request(tunnel_ws)
            # Calls so far: handshake (1) + dispatch (2) + per-op handshake (3).
            # Deny the gate's own re-read (4th).
            authority.deny_from_call = authority.calls + 2
            op_ws = await _attach(
                trust_setup, unused_tcp_port, creds, op, nonce_msg["nonce"]
            )
            try:
                got = await asyncio.wait_for(op_ws.recv(), timeout=2.0)
            except websockets.ConnectionClosed:
                got = None
            assert got is None  # closed, never op_ready
            assert await _wait_for(lambda: op.state == OperationState.ERRORED)
            assert op.error["reason"] == "agent_revoked"
            assert op.error["termination"] == "not_started"
            assert "start_refused" in [e["context"].get("reason") for e in audit.events]
        finally:
            await tunnel_ws.close()


@pytest.mark.asyncio
async def test_legacy_agent_without_await_ready_is_not_gated(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        tunnel_ws, creds = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            op, _ = await manager.create_and_dispatch(42, "exec", {"cmd": "id"})
            _req, nonce_msg = await _read_op_request(tunnel_ws)
            op_ws = await _attach(
                trust_setup,
                unused_tcp_port,
                creds,
                op,
                nonce_msg["nonce"],
                gated=False,
            )
            # No op_ready is sent to an agent that did not ask for the gate.
            assert await _no_message(op_ws) is None
            assert op.state == OperationState.ATTACHED
            assert op.agent_gated is False
            await op_ws.close()
        finally:
            await tunnel_ws.close()


# ---------------------------------------------------------------------------
# Eviction vs concurrent dispatch (ordering invariant, stub sockets)
# ---------------------------------------------------------------------------


class _StubWs:
    def __init__(self):
        self.sent = []
        self.closed = False

    async def send(self, m):
        await asyncio.sleep(0)  # yield mid-send, as a real socket would
        self.sent.append(json.loads(m))

    async def close(self, **_):
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("seed", range(40))
async def test_eviction_orders_against_concurrent_dispatch(seed):
    """For every dispatch racing an eviction, exactly one of:
    (a) it was refused and nothing about it reached the agent, or
    (b) its op_request reached the agent BEFORE the op_cancel for it, and the
        op ended interrupted (never left running or pending).
    No op_request is ever sent after the eviction began."""
    registry = AgentRegistry()
    ws = _StubWs()
    entry = TunnelEntry(
        system_id=7,
        tunnel_session_id="S",
        ws=ws,  # type: ignore[arg-type]
        identity=MagicMock(),
        capabilities=[],
        agent_version="t",
        authorize=lambda: None,
    )
    await registry.register(entry)
    manager = OperationManager(
        registry, evict_ack_timeout_seconds=0.05, audit_emit=Audit()
    )

    results = []

    async def dispatch(delay):
        for _ in range(delay):
            await asyncio.sleep(0)
        try:
            op, _ = await manager.create_and_dispatch(7, "exec", {"cmd": "x"})
            results.append(("ok", op))
        except (NoActiveTunnel, AgentNotAuthorized) as exc:
            results.append(("refused", exc))

    async def evict(delay):
        for _ in range(delay):
            await asyncio.sleep(0)
        await manager.evict_tunnel(entry, reason="revoked")

    delays = [(seed * 7 + i * 3) % 9 for i in range(6)]
    await asyncio.gather(*[dispatch(d) for d in delays[:5]], evict(delays[5]))

    requests = {
        m["operation_id"]: i for i, m in enumerate(ws.sent) if m["type"] == "op_request"
    }
    cancels = {
        m["operation_id"]: i for i, m in enumerate(ws.sent) if m["type"] == "op_cancel"
    }
    for kind, val in results:
        if kind == "ok":
            op = val
            assert op.operation_id in requests
            assert op.operation_id in cancels
            assert requests[op.operation_id] < cancels[op.operation_id]
            assert op.state in (OperationState.ERRORED, OperationState.CANCELLED)
            assert op.revocation_reason == "revoked"
    assert set(cancels) <= set(requests)  # never a cancel for an unsent op
    # Everything the manager still tracks is terminal: nothing left pending.
    for op in manager.for_system(7):
        assert op.state in (
            OperationState.ERRORED,
            OperationState.CANCELLED,
            OperationState.COMPLETED,
        )
    refused_ids = {
        o.operation_id for o in manager.for_system(7) if o.operation_id not in requests
    }
    for oid in refused_ids:
        assert manager.get(oid).termination == "not_started"


class _GatedWs(_StubWs):
    """Stub socket whose op_request send can be held open by the test."""

    def __init__(self):
        super().__init__()
        self.hold_request = asyncio.Event()
        self.request_started = asyncio.Event()
        self.hold_request.set()

    async def send(self, m):
        if json.loads(m)["type"] == "op_request":
            self.request_started.set()
            await self.hold_request.wait()
        await super().send(m)


def _stub_entry(ws):
    return TunnelEntry(
        system_id=7,
        tunnel_session_id="S",
        ws=ws,  # type: ignore[arg-type]
        identity=MagicMock(),
        capabilities=[],
        agent_version="t",
        authorize=lambda: None,
    )


@pytest.mark.asyncio
async def test_dispatch_that_loses_to_eviction_sends_nothing():
    """Dispatch has registered its op and is about to send; eviction begins
    first. The op_request must never reach the agent, and no op_cancel is sent
    for an op the agent never heard of."""
    registry = AgentRegistry()
    ws = _GatedWs()
    entry = _stub_entry(ws)
    await registry.register(entry)
    manager = OperationManager(
        registry, evict_ack_timeout_seconds=0.05, audit_emit=Audit()
    )

    await entry.send_lock.acquire()  # hold dispatch at the send boundary
    dispatching = asyncio.create_task(manager.create_and_dispatch(7, "exec", {}))
    assert await _wait_for(lambda: len(manager.for_system(7)) == 1)
    evicting = asyncio.create_task(manager.evict_tunnel(entry, reason="revoked"))
    assert await _wait_for(lambda: entry.evicted)
    entry.send_lock.release()

    with pytest.raises(AgentNotAuthorized):
        await dispatching
    await evicting
    assert [m["type"] for m in ws.sent if m["type"].startswith("op_")] == []
    (op,) = manager.for_system(7)
    assert op.state == OperationState.ERRORED
    assert op.error["termination"] == "not_started"


@pytest.mark.asyncio
async def test_dispatch_that_wins_sends_request_before_cancel():
    registry = AgentRegistry()
    ws = _GatedWs()
    entry = _stub_entry(ws)
    await registry.register(entry)
    manager = OperationManager(
        registry, evict_ack_timeout_seconds=0.05, audit_emit=Audit()
    )

    ws.hold_request.clear()  # dispatch is mid-send of op_request
    dispatching = asyncio.create_task(manager.create_and_dispatch(7, "exec", {}))
    await asyncio.wait_for(ws.request_started.wait(), timeout=2)
    evicting = asyncio.create_task(manager.evict_tunnel(entry, reason="revoked"))
    assert await _wait_for(lambda: entry.evicted)
    await asyncio.sleep(0.05)
    assert [m["type"] for m in ws.sent] == []  # cancel is queued behind the request
    ws.hold_request.set()

    op, _ = await dispatching
    await evicting
    kinds = [m["type"] for m in ws.sent if m["type"].startswith("op_")]
    assert kinds == ["op_request", "op_nonce", "op_cancel"]
    assert op.error["reason"] == "agent_revoked_unconfirmed"


@pytest.mark.asyncio
async def test_closed_per_op_socket_is_not_evidence_the_process_stopped(
    trust_setup, unused_tcp_port
):
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(registry, audit_emit=audit, evict_ack_timeout_seconds=3)
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=999,
    ):
        tunnel_ws, creds = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            op, op_ws = await _running_op(
                trust_setup, unused_tcp_port, manager, creds, tunnel_ws
            )
            authority.status[42] = "revoked"
            evicting = asyncio.create_task(manager.evict_system(42, reason="revoked"))
            assert await _wait_for(lambda: op.revocation_reason == "revoked")
            await op_ws.close()  # agent drops the data channel first ...
            await asyncio.sleep(0.2)
            assert op.state == OperationState.CANCELLING  # ... which proves nothing
            await _agent_acks_cancel(tunnel_ws, op, {"termination": "confirmed"})
            await evicting
            assert op.state == OperationState.CANCELLED
            assert op.error["termination"] == "confirmed"
        finally:
            await tunnel_ws.close()


# ---------------------------------------------------------------------------
# Internal API
# ---------------------------------------------------------------------------


def _entry_with_authority(system_id, authority_state):
    ws = _StubWs()
    entry = TunnelEntry(
        system_id=system_id,
        tunnel_session_id=f"sess-{system_id}",
        ws=ws,  # type: ignore[arg-type]
        identity=MagicMock(),
        capabilities=["exec"],
        agent_version="t",
        authorize=lambda: authority_state["code"],
    )
    return entry, ws


@pytest.mark.asyncio
async def test_internal_api_evict_requires_auth_and_reports_verdicts():
    registry = AgentRegistry()
    state = {"code": None}
    entry, ws = _entry_with_authority(9, state)
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())
    app = build_internal_app(registry, manager, auth_token="secret")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://broker") as c:
        url = "/internal/agent/sessions/9/evict"
        body = {"reason": "disabled"}

        assert (await c.post(url, json=body)).status_code == 401

        h = {"x-praxis-internal-auth": "secret"}
        r = await c.post(url, json=body, headers=h)
        assert r.status_code == 200 and r.json()["result"] == "not_evicted"
        assert registry.get(9) is not None

        bad = await c.post(url, json={"reason": "whatever"}, headers=h)
        assert bad.status_code == 422

        state["code"] = "system_not_active"
        r = await c.post(url, json=body, headers=h)
        assert r.json()["result"] == "evicted"
        assert r.json()["tunnel_session_id"] == "sess-9"
        assert registry.get(9) is None
        assert ws.sent[-1] == {"type": "bye", "reason": "disabled"}

        r = await c.post(url, json=body, headers=h)
        assert r.json()["result"] == "no_session"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,reason",
    [
        ("system_not_active", "agent_not_active"),
        ("identity_unverifiable", "identity_unverifiable"),
    ],
)
async def test_internal_dispatch_endpoints_refuse_with_distinct_reason(code, reason):
    registry = AgentRegistry()
    entry, ws = _entry_with_authority(9, {"code": code})
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())
    app = build_internal_app(registry, manager)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://broker") as c:
        calls = [
            c.post("/internal/agent/ops/exec", json={"system_id": 9, "cmd": "id"}),
            c.post("/internal/agent/ops/facts", json={"system_id": 9}),
            c.post(
                "/internal/agent/ops/file_get",
                json={"system_id": 9, "path": "/etc/hostname"},
            ),
            c.post(
                "/internal/agent/ops/file_put",
                content=b"x",
                headers={
                    "x-praxis-system-id": "9",
                    "x-praxis-file-path": "/tmp/x",
                },
            ),
        ]
        for resp in await asyncio.gather(*calls):
            assert resp.status_code == 403
            assert resp.json()["error"]["reason"] == reason
    assert ws.sent == []  # nothing was ever sent to the agent


# ---------------------------------------------------------------------------
# Bounded eviction, session binding and fail-closed authority
# ---------------------------------------------------------------------------


class _Transport:
    def __init__(self):
        self.aborted = False

    def abort(self):
        self.aborted = True


class _StallWs(_StubWs):
    """Socket whose writes of the chosen frame types never complete."""

    def __init__(self, stall=("op_cancel",), stall_close=False):
        super().__init__()
        self.stall = set(stall)
        self.stall_close = stall_close
        self.transport = _Transport()

    async def send(self, m):
        if json.loads(m)["type"] in self.stall:
            await asyncio.sleep(3600)
        await super().send(m)

    async def close(self, **_):
        if self.stall_close:
            await asyncio.sleep(3600)
        self.closed = True


async def _live_op(manager, entry):
    op, _ = await manager.create_and_dispatch(entry.system_id, "exec", {"cmd": "x"})
    return op


def _bounded_manager(registry, **kw):
    return OperationManager(
        registry,
        evict_ack_timeout_seconds=kw.pop("ack", 0.2),
        evict_total_timeout_seconds=kw.pop("total", 1.0),
        evict_io_timeout_seconds=kw.pop("io", 0.2),
        audit_emit=Audit(),
        **kw,
    )


@pytest.mark.asyncio
async def test_blocked_cancel_write_is_bounded_and_reports_unconfirmed():
    registry = AgentRegistry()
    ws = _StallWs(stall=("op_cancel",))
    entry = _stub_entry(ws)
    await registry.register(entry)
    manager = _bounded_manager(registry)
    op = await _live_op(manager, entry)

    started = time.monotonic()
    result = await asyncio.wait_for(
        manager.evict_tunnel(entry, reason="revoked"), timeout=5
    )
    assert time.monotonic() - started < 2.5
    assert result["result"] == "evicted"
    assert ws.transport.aborted  # the stuck socket was dropped, not waited on
    assert op.state == OperationState.ERRORED
    assert op.error["reason"] == "agent_revoked_unconfirmed"
    assert op.error["termination"] == "unconfirmed"


@pytest.mark.asyncio
async def test_stalled_send_lock_holder_cannot_stall_eviction():
    registry = AgentRegistry()
    ws = _StallWs(stall=())
    entry = _stub_entry(ws)
    await registry.register(entry)
    manager = _bounded_manager(registry)
    op = await _live_op(manager, entry)

    await entry.send_lock.acquire()  # a dispatch write that never finishes
    result = await asyncio.wait_for(
        manager.evict_tunnel(entry, reason="revoked"), timeout=5
    )
    assert result["result"] == "evicted"
    assert op.error["termination"] == "unconfirmed"
    entry.send_lock.release()


@pytest.mark.asyncio
async def test_stalled_close_is_bounded():
    registry = AgentRegistry()
    ws = _StallWs(stall=(), stall_close=True)
    entry = _stub_entry(ws)
    await registry.register(entry)
    manager = _bounded_manager(registry)
    result = await asyncio.wait_for(
        manager.evict_tunnel(entry, reason="disabled"), timeout=5
    )
    assert result["result"] == "evicted"
    assert ws.transport.aborted


@pytest.mark.asyncio
async def test_overall_deadline_forces_unconfirmed_when_nothing_acks():
    registry = AgentRegistry()
    ws = _StallWs(stall=())
    entry = _stub_entry(ws)
    await registry.register(entry)
    # The ack window is longer than the hard deadline: the deadline wins.
    manager = _bounded_manager(registry, ack=30.0, total=0.4)
    op = await _live_op(manager, entry)
    started = time.monotonic()
    result = await asyncio.wait_for(
        manager.evict_tunnel(entry, reason="revoked"), timeout=5
    )
    assert time.monotonic() - started < 2.0
    assert result["deadline_exceeded"] is True
    assert op.error["termination"] == "unconfirmed"
    assert ws.transport.aborted


@pytest.mark.asyncio
async def test_retry_during_teardown_observes_pending_eviction():
    registry = AgentRegistry()
    ws = _StallWs(stall=())
    entry = _stub_entry(ws)
    await registry.register(entry)
    manager = _bounded_manager(registry, ack=0.6, total=3.0)
    op = await _live_op(manager, entry)
    state = {"code": "system_not_active"}
    entry.authorize = lambda: state["code"]

    first = asyncio.create_task(manager.evict_system(7, reason="revoked"))
    assert await _wait_for(lambda: entry.evicted and registry.get(7) is None)
    # Registry no longer lists the session, but the eviction is still draining.
    again = await manager.evict_system(7, reason="revoked", expected_session_id="S")
    assert again["result"] == "evicted"  # not no_session
    assert again["tunnel_session_id"] == "S"
    assert (await first)["result"] == "evicted"
    assert op.state in (OperationState.ERRORED, OperationState.CANCELLED)
    # After it ends the session is gone for good.
    assert (await manager.evict_system(7, reason="revoked"))["result"] == "no_session"


@pytest.mark.asyncio
async def test_retry_with_old_session_id_finds_draining_session_not_replacement():
    registry = AgentRegistry()
    ws = _StallWs(stall=())
    old = _stub_entry(ws)
    await registry.register(old)
    manager = _bounded_manager(registry, ack=0.6, total=3.0)
    await _live_op(manager, old)
    first = asyncio.create_task(manager.evict_tunnel(old, reason="revoked"))
    assert await _wait_for(lambda: old.evicted and registry.get(7) is None)
    new = TunnelEntry(
        system_id=7,
        tunnel_session_id="NEW",
        ws=_StubWs(),  # type: ignore[arg-type]
        identity=MagicMock(),
        capabilities=[],
        agent_version="t",
        authorize=lambda: None,
    )
    await registry.register(new)
    res = await manager.evict_system(7, reason="revoked", expected_session_id="S")
    assert res["tunnel_session_id"] == "S" and res["result"] == "evicted"
    await first
    assert registry.get(7) is new and not new.evicted  # replacement untouched


@pytest.mark.asyncio
async def test_confirm_start_refuses_when_session_replaced_during_validation():
    import threading

    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    gate = threading.Event()
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())
    op = await _live_op(manager, entry)
    op.state = OperationState.ATTACHED
    entry.authorize = lambda: (gate.wait(5), None)[1]  # slow only from now on
    per_op = _StubWs()

    starting = asyncio.create_task(manager.confirm_start(op, per_op))  # type: ignore[arg-type]
    await asyncio.sleep(0.05)
    replacement = TunnelEntry(
        system_id=7,
        tunnel_session_id="NEW",
        ws=_StubWs(),  # type: ignore[arg-type]
        identity=MagicMock(),
        capabilities=[],
        agent_version="t",
        authorize=lambda: None,
    )
    await registry.register(replacement)
    gate.set()
    assert await starting is False
    assert per_op.sent == []  # no op_ready for the predecessor's pending op


@pytest.mark.asyncio
async def test_op_complete_only_accepted_from_the_owning_session():
    from app.broker.handlers import _route_op_complete

    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())
    op = await _live_op(manager, entry)
    op.revocation_reason = "revoked"
    op.state = OperationState.CANCELLING
    msg = {
        "type": "op_complete",
        "operation_id": op.operation_id,
        "outcome": "cancelled",
        "termination": "confirmed",
    }

    await _route_op_complete(manager, 7, "NEW", msg)  # replacement, same system
    assert op.state == OperationState.CANCELLING
    assert op.result_metadata is None

    await _route_op_complete(manager, 7, "S", msg)  # the owner
    assert op.state == OperationState.CANCELLED
    assert op.error["termination"] == "confirmed"


@pytest.mark.asyncio
async def test_missing_authority_fails_closed_at_dispatch_and_start():
    registry = AgentRegistry()
    ws = _StubWs()
    entry = _stub_entry(ws)
    entry.authorize = None  # no authority source bound
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())

    with pytest.raises(AgentNotAuthorized) as err:
        await manager.create_and_dispatch(7, "exec", {})
    assert err.value.unverifiable
    assert ws.sent == []

    entry.authorize = lambda: None  # bind one to create an op, then remove it
    op = await _live_op(manager, entry)
    op.state = OperationState.ATTACHED
    entry.authorize = None
    per_op = _StubWs()
    assert await manager.confirm_start(op, per_op) is False  # type: ignore[arg-type]
    assert per_op.sent == []


@pytest.mark.asyncio
async def test_status_lookup_timeouts_converge_within_the_documented_bound(
    trust_setup, unused_tcp_port
):
    """Database unavailable and every lookup hanging: dispatch is refused at
    once, and the session is evicted after UNVERIFIABLE_EVICT_AFTER rounds of
    (interval + lookup timeout). Production values are 3 x (30 s + 5 s)."""
    from app.broker.handlers import UNVERIFIABLE_EVICT_AFTER

    interval, lookup_timeout = 0.3, 0.2
    registry, authority, audit = AgentRegistry(), Authority(), Audit()
    manager = OperationManager(
        registry,
        audit_emit=audit,
        authorize_timeout_seconds=lookup_timeout,
        evict_ack_timeout_seconds=0.5,
    )
    async with _broker(
        trust_setup,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        authority=authority,
        audit=audit,
        revalidate_interval_seconds=interval,
    ):
        tunnel_ws, _creds = await _connect(trust_setup, unused_tcp_port, 42)
        try:
            authority.hang = True  # every status read now overruns its bound
            t0 = time.monotonic()
            with pytest.raises(AgentNotAuthorized) as err:
                await manager.create_and_dispatch(42, "exec", {"cmd": "id"})
            assert err.value.unverifiable  # refused immediately, not after eviction
            assert time.monotonic() - t0 < lookup_timeout + 0.5

            assert await _wait_for(lambda: registry.get(42) is None, timeout=10)
            elapsed = time.monotonic() - t0
            bound = UNVERIFIABLE_EVICT_AFTER * (interval + lookup_timeout)
            assert elapsed >= bound - interval  # not dropped on the first blip
            assert elapsed <= bound + 2.0  # plus the eviction window
            assert (
                audit.last("agent.tunnel.evicted")["context"]["reason"]
                == "unverifiable"
            )
        finally:
            await tunnel_ws.close()


def _completed(audit, op):
    return [
        e
        for e in audit.events
        if e["action"] == "agent.op.completed"
        and e["context"].get("operation_id") == op.operation_id
    ]


async def _attached_ops(manager, entry, n, stall_close=True):
    ops = []
    for _ in range(n):
        op = await _live_op(manager, entry)
        op.state = OperationState.ATTACHED
        op.attached_ws = _StallWs(stall=(), stall_close=stall_close)
        ops.append(op)
    return ops


@pytest.mark.asyncio
async def test_deadline_during_data_socket_close_keeps_audit_and_aborts_socket():
    registry = AgentRegistry()
    entry = _stub_entry(_StallWs(stall=()))
    await registry.register(entry)
    audit = Audit()
    # Per-socket bound is longer than the total deadline: the outer deadline
    # cancels the close mid-transition.
    manager = OperationManager(
        registry,
        audit_emit=audit,
        evict_ack_timeout_seconds=0.1,
        evict_total_timeout_seconds=0.4,
        evict_io_timeout_seconds=5.0,
    )
    (op,) = await _attached_ops(manager, entry, 1)
    data_ws = op.attached_ws

    result = await asyncio.wait_for(
        manager.evict_tunnel(entry, reason="revoked"), timeout=5
    )
    assert result["deadline_exceeded"] is True
    assert op.state == OperationState.ERRORED
    assert op.error["termination"] == "unconfirmed"
    assert len(_completed(audit, op)) == 1  # exactly once, not lost, not repeated
    assert data_ws.transport.aborted
    assert op.attached_ws is None


@pytest.mark.asyncio
async def test_many_stalled_data_sockets_share_one_teardown_deadline():
    registry = AgentRegistry()
    entry = _stub_entry(_StallWs(stall=()))
    await registry.register(entry)
    audit = Audit()
    manager = OperationManager(
        registry,
        audit_emit=audit,
        evict_ack_timeout_seconds=0.1,
        evict_total_timeout_seconds=0.6,
        evict_io_timeout_seconds=0.5,
    )
    ops = await _attached_ops(manager, entry, 6)

    started = time.monotonic()
    result = await asyncio.wait_for(
        manager.evict_tunnel(entry, reason="revoked"), timeout=10
    )
    elapsed = time.monotonic() - started
    # Six sockets at 0.5 s each would be 3 s if each got a fresh wait.
    assert elapsed < 1.2, elapsed
    assert result["ops"] == {"unconfirmed": 6}
    for op in ops:
        assert op.state == OperationState.ERRORED
        assert op.error["reason"] == "agent_revoked_unconfirmed"
        assert len(_completed(audit, op)) == 1
        assert op.attached_ws is None
