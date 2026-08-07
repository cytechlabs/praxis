"""PRA-153 slice #1: BrokerClient happy path + failure-mode tests.

httpx ships a MockTransport so we can stub the broker end without
spinning up uvicorn. Verifies:
    - happy-path response is parsed into TunnelHealth
    - HTTP 5xx degrades to state=unregistered (not raises)
    - network error degrades to state=unregistered
    - is_usable matches the spec (only "healthy" is True)
"""

from __future__ import annotations

import httpx
import pytest

from app.services.broker_client import BrokerClient, TunnelHealth


@pytest.mark.asyncio
async def test_health_parses_healthy_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/agent/health/42"
        return httpx.Response(
            200,
            json={
                "system_id": 42,
                "state": "healthy",
                "tunnel_session_id": "sess-x",
                "since_seconds": 60.0,
                "last_heartbeat_age_seconds": 5.0,
            },
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    bc = BrokerClient(client=client)
    h = await bc.health(42)
    assert h == TunnelHealth(
        system_id=42,
        state="healthy",
        tunnel_session_id="sess-x",
        since_seconds=60.0,
        last_heartbeat_age_seconds=5.0,
    )
    assert h.is_usable is True


@pytest.mark.asyncio
async def test_health_5xx_degrades_to_unknown():
    """PRA-153 #4: broker errors degrade to ``unknown`` (NOT
    ``unregistered``) so the operator UI doesn't imply 'agent
    missing' when the broker call itself failed. Routing behaviour
    is unchanged — both still fail ``is_usable``."""

    def handler(_req):
        return httpx.Response(503, text="boom")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    bc = BrokerClient(client=client)
    h = await bc.health(42)
    assert h.state == "unknown"
    assert h.is_usable is False


@pytest.mark.asyncio
async def test_health_network_error_degrades_to_unknown():
    def handler(_req):
        raise httpx.ConnectError("broker down")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    bc = BrokerClient(client=client)
    h = await bc.health(42)
    assert h.state == "unknown"
    assert h.is_usable is False


def test_tunnel_health_is_usable_only_when_healthy():
    """Stale must NOT count as usable — see broker_client docstring."""
    assert TunnelHealth(system_id=1, state="healthy").is_usable is True
    assert TunnelHealth(system_id=1, state="stale").is_usable is False
    assert TunnelHealth(system_id=1, state="unregistered").is_usable is False
    assert TunnelHealth(system_id=1, state="unknown").is_usable is False


# ---------------------------------------------------------------- facts


@pytest.mark.asyncio
async def test_facts_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/agent/ops/facts"
        return httpx.Response(
            200,
            json={
                "outcome": "success",
                "operation_id": 1,
                "facts": {
                    "schema_version": 1,
                    "collected_at": "2026-05-01T12:00:00Z",
                    "cpu_cores": 4,
                },
                "partial_errors": [],
            },
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    from app.services.broker_client import BrokerClient

    bc = BrokerClient(client=client)
    res = await bc.facts(7)
    assert res.outcome == "success"
    assert res.facts["cpu_cores"] == 4
    assert res.partial_errors == []


@pytest.mark.asyncio
async def test_facts_504_preserves_agent_attach_timeout_reason():
    """PRA-155 #2b-b-α: the broker emits 504 for both ``facts_timeout``
    and ``agent_attach_timeout``. BrokerClient must not collapse them
    into one reason — the refresh endpoint surfaces ``error.reason``
    on the response body and a future UI may key on the distinction."""

    def handler(_req):
        return httpx.Response(
            504,
            json={"outcome": "error", "error": {"reason": "agent_attach_timeout"}},
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    from app.services.broker_client import BrokerClient, BrokerError

    bc = BrokerClient(client=client)
    with pytest.raises(BrokerError) as exc:
        await bc.facts(7)
    assert exc.value.reason == "agent_attach_timeout"


@pytest.mark.asyncio
async def test_facts_504_falls_back_to_facts_timeout_when_body_missing_reason():
    """Defensive: a future broker that emits 504 without the structured
    body should still surface a meaningful BrokerError reason."""

    def handler(_req):
        return httpx.Response(504, text="gateway timeout")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    from app.services.broker_client import BrokerClient, BrokerError

    bc = BrokerClient(client=client)
    with pytest.raises(BrokerError) as exc:
        await bc.facts(7)
    assert exc.value.reason == "facts_timeout"


@pytest.mark.asyncio
async def test_facts_503_preserves_transport_unavailable():
    def handler(_req):
        return httpx.Response(
            503,
            json={"outcome": "error", "error": {"reason": "transport_unavailable"}},
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    from app.services.broker_client import BrokerClient, BrokerError

    bc = BrokerClient(client=client)
    with pytest.raises(BrokerError) as exc:
        await bc.facts(7)
    assert exc.value.reason == "transport_unavailable"


@pytest.mark.asyncio
async def test_facts_502_preserves_collector_panicked():
    def handler(_req):
        return httpx.Response(
            502,
            json={"outcome": "error", "error": {"reason": "collector_panicked"}},
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://broker.test"
    )
    from app.services.broker_client import BrokerClient, BrokerError

    bc = BrokerClient(client=client)
    with pytest.raises(BrokerError) as exc:
        await bc.facts(7)
    assert exc.value.reason == "collector_panicked"


def test_tunnel_health_capabilities_default_empty_and_has_capability_works():
    """PRA-155 #2b-b: capability gate for transport selection."""
    h = TunnelHealth(system_id=1, state="healthy")
    assert h.capabilities == ()
    assert h.has_capability("facts") is False
    h2 = TunnelHealth(system_id=1, state="healthy", capabilities=("facts", "exec"))
    assert h2.has_capability("facts") is True
    assert h2.has_capability("pty") is False
