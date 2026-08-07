"""PRA-153 transport factory resolution matrix.

Verifies the per-host preference + tunnel-health → Transport choice
without touching any real network or paramiko. Uses stub
BrokerClient + minimal System mock + stub SSHService.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pytest

from app.services.broker_client import TunnelHealth
from app.services.transport import (
    AgentTransport,
    SSHTransport,
    TransportUnavailable,
    get_transport,
)


@dataclass
class _SystemStub:
    id: int
    transport_preference: str


class _BrokerClientStub:
    """Stub that returns a canned TunnelHealth without any HTTP."""

    def __init__(self, state: str = "unregistered") -> None:
        self.state = state
        self.calls = 0

    async def health(self, system_id: int) -> TunnelHealth:
        self.calls += 1
        return TunnelHealth(system_id=system_id, state=self.state)


class _SSHServiceStub:
    """Stub for the SSHService dependency.

    Slice #3c plumbs SSHService into the factory; tests don't actually
    exercise paramiko here — they just verify the right transport
    class comes back for the (pref, health) combo.
    """


# ---- pref=ssh ----


@pytest.mark.asyncio
async def test_pref_ssh_returns_ssh_regardless_of_health():
    sys = _SystemStub(id=1, transport_preference="ssh")
    bc = _BrokerClientStub(state="healthy")
    t = await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert isinstance(t, SSHTransport)
    # pref=ssh should NOT bother the broker — wasted hop otherwise.
    assert bc.calls == 0


@pytest.mark.asyncio
async def test_pref_ssh_without_ssh_service_raises():
    """Resolver committed to SSH but caller forgot to plumb the
    SSHService — a programmer error worth surfacing as
    TransportUnavailable so the audit ledger gets a row."""
    sys = _SystemStub(id=1, transport_preference="ssh")
    bc = _BrokerClientStub(state="healthy")
    with pytest.raises(TransportUnavailable):
        await get_transport(sys, bc, ssh_service=None)


# ---- pref=auto ----


@pytest.mark.asyncio
async def test_pref_auto_picks_agent_when_healthy():
    sys = _SystemStub(id=2, transport_preference="auto")
    bc = _BrokerClientStub(state="healthy")
    t = await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert isinstance(t, AgentTransport)
    assert bc.calls == 1


@pytest.mark.asyncio
async def test_pref_auto_falls_back_to_ssh_when_unregistered():
    sys = _SystemStub(id=3, transport_preference="auto")
    bc = _BrokerClientStub(state="unregistered")
    t = await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert isinstance(t, SSHTransport)


@pytest.mark.asyncio
async def test_pref_auto_falls_back_to_ssh_when_stale():
    sys = _SystemStub(id=4, transport_preference="auto")
    bc = _BrokerClientStub(state="stale")
    t = await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert isinstance(t, SSHTransport)


# ---- pref=agent ----


@pytest.mark.asyncio
async def test_pref_agent_returns_agent_when_healthy():
    sys = _SystemStub(id=5, transport_preference="agent")
    bc = _BrokerClientStub(state="healthy")
    t = await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert isinstance(t, AgentTransport)


@pytest.mark.asyncio
async def test_pref_agent_raises_when_unregistered():
    sys = _SystemStub(id=6, transport_preference="agent")
    bc = _BrokerClientStub(state="unregistered")
    with pytest.raises(TransportUnavailable) as exc:
        await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert "tunnel state=unregistered" in str(exc.value)


@pytest.mark.asyncio
async def test_pref_agent_raises_when_stale():
    """Force-agent + stale tunnel must fail loud, not fall back."""
    sys = _SystemStub(id=7, transport_preference="agent")
    bc = _BrokerClientStub(state="stale")
    with pytest.raises(TransportUnavailable) as exc:
        await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert "tunnel state=stale" in str(exc.value)


@pytest.mark.asyncio
async def test_pref_agent_does_not_need_ssh_service():
    """Force-agent with healthy tunnel should work even if the
    caller didn't pass ssh_service — the resolver never lands on
    the SSH path."""
    sys = _SystemStub(id=10, transport_preference="agent")
    bc = _BrokerClientStub(state="healthy")
    t = await get_transport(sys, bc, ssh_service=None)
    assert isinstance(t, AgentTransport)


# ---- defensive defaults ----


@pytest.mark.asyncio
async def test_unknown_pref_defaults_to_auto():
    sys = _SystemStub(id=8, transport_preference="garbage")
    bc = _BrokerClientStub(state="unregistered")
    # Unknown pref shouldn't crash — defaults to auto behavior so a
    # future enum value or DB drift can't take a host completely
    # offline. Logged at the call site.
    t = await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert isinstance(t, SSHTransport)


@pytest.mark.asyncio
async def test_null_pref_defaults_to_auto():
    sys = _SystemStub(id=9, transport_preference=None)
    bc = _BrokerClientStub(state="healthy")
    t = await get_transport(sys, bc, ssh_service=_SSHServiceStub())
    assert isinstance(t, AgentTransport)
