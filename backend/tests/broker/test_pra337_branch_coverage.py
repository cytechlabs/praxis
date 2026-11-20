"""PRA-337: observable-behavior coverage for the revocation/eviction branches
that the lifecycle suite does not reach.

Every test asserts what an operator or the agent can observe: whether work is
released to start, how an interrupted operation is reported, and whether
sockets end up closed or aborted.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from websockets.exceptions import ConnectionClosedError

from app.broker.handlers import (
    REJECT_FINGERPRINT_MISMATCH,
    REJECT_NOT_ACTIVE,
    REJECT_SERIAL_MISMATCH,
    _eviction_reason,
    _revalidation_loop,
)
from app.broker.ops import NoActiveTunnel, OperationManager, OperationState
from app.broker.registry import AgentRegistry

from .test_pra337_revocation import (
    Audit,
    _attached_ops,
    _bounded_manager,
    _completed,
    _live_op,
    _StallWs,
    _stub_entry,
    _StubWs,
    _wait_for,
)


def _closed():
    return ConnectionClosedError(None, None)


class _DeadWs(_StallWs):
    """Socket whose peer is gone: chosen frame types raise ConnectionClosed."""

    def __init__(self, dead=("op_cancel",), **kw):
        super().__init__(stall=(), **kw)
        self.dead = set(dead)

    async def send(self, m):
        if json.loads(m)["type"] in self.dead:
            raise _closed()
        await super().send(m)


# ---------------------------------------------------------------------------
# Revalidation loop: reason mapping and exit after eviction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,expected",
    [
        (REJECT_NOT_ACTIVE, "not_active"),
        (REJECT_SERIAL_MISMATCH, "identity_changed"),
        (REJECT_FINGERPRINT_MISMATCH, "identity_changed"),
        ("some_other_code", "some_other_code"),
    ],
)
def test_eviction_reason_mapping(code, expected):
    assert _eviction_reason(code) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,expected",
    [
        (REJECT_SERIAL_MISMATCH, "identity_changed"),
        (REJECT_FINGERPRINT_MISMATCH, "identity_changed"),
        ("some_other_code", "some_other_code"),
    ],
)
async def test_revalidation_evicts_with_mapped_reason(code, expected):
    registry = AgentRegistry()
    ws = _StubWs()
    entry = _stub_entry(ws)
    await registry.register(entry)
    manager = OperationManager(
        registry, audit_emit=Audit(), evict_ack_timeout_seconds=0.05
    )
    op = await _live_op(manager, entry)
    entry.authorize = lambda: code  # the identity changes after dispatch

    await asyncio.wait_for(_revalidation_loop(entry, manager, 0.01), timeout=5)

    assert entry.evicted and entry.evict_reason == expected
    assert registry.get(7) is None
    assert ws.closed  # the session socket was closed
    assert op.state in (OperationState.ERRORED, OperationState.CANCELLED)
    assert op.error["cause"] == expected
    assert {"type": "bye", "reason": expected} in ws.sent


@pytest.mark.asyncio
async def test_revalidation_stops_without_rereading_when_already_evicted():
    registry = AgentRegistry()
    ws = _StubWs()
    entry = _stub_entry(ws)
    reads = []
    entry.authorize = lambda: reads.append(1) or REJECT_NOT_ACTIVE
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())

    looping = asyncio.create_task(_revalidation_loop(entry, manager, 0.05))
    await asyncio.sleep(0)
    entry.evicted = True  # another path evicted the session during the sleep
    await asyncio.wait_for(looping, timeout=2)

    assert reads == []  # authority is not re-read for a session already gone
    assert not ws.closed  # and the loop does not tear anything down itself
    assert registry.get(7) is entry


# ---------------------------------------------------------------------------
# Dispatch: tunnel lost mid-send
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tunnel_lost_during_dispatch_errors_the_op_and_reports_no_tunnel():
    registry = AgentRegistry()
    ws = _DeadWs(dead=("op_request",))
    entry = _stub_entry(ws)
    await registry.register(entry)
    audit = Audit()
    manager = OperationManager(registry, audit_emit=audit)

    with pytest.raises(NoActiveTunnel):
        await manager.create_and_dispatch(7, "exec", {"cmd": "id"})

    (op,) = manager.for_system(7)
    assert op.state == OperationState.ERRORED
    assert op.error == {"reason": "tunnel_closed"}
    assert ws.sent == []  # nothing, including the nonce, reached the agent
    assert "agent.op.requested" not in audit.actions()


# ---------------------------------------------------------------------------
# Start gate
# ---------------------------------------------------------------------------


async def _attached(manager, entry):
    op = await _live_op(manager, entry)
    op.state = OperationState.ATTACHED
    return op


@pytest.mark.asyncio
async def test_start_gate_releases_a_live_attached_op():
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())
    op = await _attached(manager, entry)
    per_op = _StubWs()

    assert await manager.confirm_start(op, per_op) is True  # type: ignore[arg-type]
    assert per_op.sent == [{"type": "op_ready", "operation_id": op.operation_id}]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["missing", "replaced", "evicted", "dead_socket"])
async def test_start_gate_refuses_without_releasing_work(case):
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())
    op = await _attached(manager, entry)
    per_op = _StubWs()

    if case == "missing":
        await registry.unregister(7, entry.tunnel_session_id)
    elif case == "replaced":
        op.tunnel_session_id = "OLDER"  # op belongs to a predecessor session
    elif case == "evicted":
        entry.evicted = True
    else:

        async def _boom(_m):
            raise _closed()

        per_op.send = _boom  # type: ignore[method-assign]

    assert await manager.confirm_start(op, per_op) is False  # type: ignore[arg-type]
    assert per_op.sent == []  # no op_ready: the agent starts nothing


@pytest.mark.asyncio
async def test_start_gate_skips_the_authority_lookup_for_an_evicted_session():
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())
    op = await _attached(manager, entry)
    # Counted only after the op exists, so dispatch-time lookups are excluded.
    lookups = []
    entry.authorize = lambda: lookups.append(1)  # type: ignore[assignment]
    entry.evicted = True
    per_op = _StubWs()

    assert await manager.confirm_start(op, per_op) is False  # type: ignore[arg-type]
    assert lookups == []  # refused before any authority read
    assert per_op.sent == []


@pytest.mark.asyncio
async def test_start_gate_refuses_when_eviction_lands_during_the_lookup():
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=Audit())
    op = await _attached(manager, entry)
    lookups = []

    def _authorized_but_evicted_meanwhile():
        lookups.append(1)
        entry.evicted = True  # the eviction commits while the read is in flight
        return None  # the read itself still reports the identity authorized

    entry.authorize = _authorized_but_evicted_meanwhile  # type: ignore[assignment]
    per_op = _StubWs()

    assert await manager.confirm_start(op, per_op) is False  # type: ignore[arg-type]
    assert lookups == [1]  # the lookup did run: only the post-lookup check refuses
    assert per_op.sent == []


# ---------------------------------------------------------------------------
# Eviction outcome counting and reporting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_eviction_counts_only_interrupted_ops_by_outcome():
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = OperationManager(
        registry, audit_emit=Audit(), evict_ack_timeout_seconds=0.05
    )
    finished_earlier = await _live_op(manager, entry)
    await manager.complete(finished_earlier.operation_id, outcome="success")
    live = await _live_op(manager, entry)
    won_the_race = await _live_op(manager, entry)

    evicting = asyncio.create_task(manager.evict_tunnel(entry, reason="revoked"))
    assert await _wait_for(lambda: live.revocation_reason == "revoked")
    # The agent finishes successfully while the eviction is in flight.
    await manager.complete(won_the_race.operation_id, outcome="success")
    result = await evicting

    assert finished_earlier.revocation_reason is None
    assert result["ops"] == {"unconfirmed": 1, "completed": 1}
    assert result["ops_interrupted"] == 2  # not 3: the earlier op is not counted
    assert won_the_race.state == OperationState.COMPLETED
    assert live.error["termination"] == "unconfirmed"


@pytest.mark.asyncio
async def test_cancel_delivery_to_a_dead_tunnel_still_terminalizes_and_drops_socket():
    registry = AgentRegistry()
    ws = _DeadWs(dead=("op_cancel", "bye"))
    entry = _stub_entry(ws)
    await registry.register(entry)
    manager = _bounded_manager(registry)
    op = await _live_op(manager, entry)

    result = await asyncio.wait_for(
        manager.evict_tunnel(entry, reason="revoked"), timeout=5
    )

    assert result["result"] == "evicted"
    assert result["ops"] == {"unconfirmed": 1}
    assert op.state == OperationState.ERRORED
    assert op.error["reason"] == "agent_revoked_unconfirmed"
    assert not [m for m in ws.sent if m["type"] == "op_cancel"]
    assert ws.transport.aborted  # farewell could not be sent: socket dropped


async def _file_get_op(manager, entry):
    op, _ = await manager.create_and_dispatch(
        entry.system_id, "file_get", {"path": "x"}
    )
    return op


@pytest.mark.asyncio
async def test_non_process_op_is_not_applicable_when_agent_answers():
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = OperationManager(
        registry, audit_emit=Audit(), evict_ack_timeout_seconds=3
    )
    op = await _file_get_op(manager, entry)

    evicting = asyncio.create_task(manager.evict_tunnel(entry, reason="revoked"))
    assert await _wait_for(lambda: op.revocation_reason == "revoked")
    await manager.complete(
        op.operation_id, outcome="cancelled", result_metadata={"bytes": 0}
    )
    result = await evicting

    assert op.error["termination"] == "not_applicable"
    assert op.error["reason"] == "agent_revoked"
    assert result["ops"] == {"not_applicable": 1}


@pytest.mark.asyncio
async def test_non_process_op_without_agent_answer_is_unconfirmed():
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = OperationManager(
        registry, audit_emit=Audit(), evict_ack_timeout_seconds=0.05
    )
    op = await _file_get_op(manager, entry)

    await manager.evict_tunnel(entry, reason="revoked")

    assert op.error["termination"] == "unconfirmed"
    assert op.error["reason"] == "agent_revoked_unconfirmed"


# ---------------------------------------------------------------------------
# Per-op data socket close handling
# ---------------------------------------------------------------------------


class _RaisingCloseWs(_StubWs):
    def __init__(self, exc):
        super().__init__()
        self.exc = exc
        self.calls = 0

    async def close(self, **_):
        self.calls += 1
        raise self.exc


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [_closed(), RuntimeError("closing")])
async def test_data_socket_close_errors_do_not_block_terminalization(exc):
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    audit = Audit()
    manager = OperationManager(registry, audit_emit=audit)
    op = await _live_op(manager, entry)
    op.state = OperationState.ATTACHED
    data_ws = _RaisingCloseWs(exc)
    op.attached_ws = data_ws  # type: ignore[assignment]

    await manager.complete(op.operation_id, outcome="error", error={"reason": "x"})

    assert data_ws.calls == 1  # a close was attempted, exactly once
    assert op.state == OperationState.ERRORED
    assert op.attached_ws is None
    assert len(_completed(audit, op)) == 1


@pytest.mark.asyncio
async def test_data_socket_that_never_closes_is_aborted_after_the_io_bound():
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = _bounded_manager(registry, io=0.1)
    (op,) = await _attached_ops(manager, entry, 1)
    data_ws = op.attached_ws

    await asyncio.wait_for(
        manager.complete(op.operation_id, outcome="error", error={"reason": "x"}),
        timeout=3,
    )

    assert op.state == OperationState.ERRORED
    assert data_ws.transport.aborted
    assert op.attached_ws is None


@pytest.mark.asyncio
async def test_data_socket_is_aborted_without_a_close_when_deadline_has_passed():
    registry = AgentRegistry()
    entry = _stub_entry(_StubWs())
    await registry.register(entry)
    manager = _bounded_manager(registry)
    (op,) = await _attached_ops(manager, entry, 1, stall_close=False)
    data_ws = op.attached_ws

    await manager._terminalize(  # pylint: disable=protected-access
        op, OperationState.ERRORED, error={"reason": "x"}, deadline=0.0
    )

    assert data_ws.transport.aborted
    assert not data_ws.closed  # no graceful close was waited on
    assert op.attached_ws is None
