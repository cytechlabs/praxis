"""PRA-153 slice #1: broker internal HTTP API.

Tests the /internal/agent/health/{system_id} endpoint against three
registry states without spinning up a real tunnel: synthesise
TunnelEntry instances directly into a fresh AgentRegistry and assert
the JSON shape + state classification.

TestClient instances are wrapped in `with` blocks so the FastAPI
lifespan event loop tears down between tests — without that, we
leak a closed-loop reference into pytest-asyncio fixtures used by
later tests in the same process (e.g. test_tls_handshake.py).
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.broker.internal_api import build_internal_app
from app.broker.protocol import HEARTBEAT_DEAD_SECONDS
from app.broker.registry import AgentRegistry, TunnelEntry


def _entry(system_id: int = 42, age_seconds: float = 0.0) -> TunnelEntry:
    """Build a TunnelEntry whose last_recv was `age_seconds` in the past."""
    now = time.monotonic()
    return TunnelEntry(
        system_id=system_id,
        tunnel_session_id=f"sess-{system_id}",
        ws=MagicMock(),
        identity=MagicMock(),
        capabilities=["heartbeat"],
        agent_version="test",
        connected_at_monotonic=now - 60.0,
        last_recv_monotonic=now - age_seconds,
    )


def test_health_unregistered_when_no_entry():
    registry = AgentRegistry()
    with TestClient(build_internal_app(registry)) as client:
        resp = client.get("/internal/agent/health/99")
    assert resp.status_code == 200
    body = resp.json()
    assert body["system_id"] == 99
    assert body["state"] == "unregistered"
    assert body["tunnel_session_id"] is None
    assert body["since_seconds"] is None
    assert body["last_heartbeat_age_seconds"] is None


def test_health_healthy_when_recent_heartbeat():
    registry = AgentRegistry()
    registry._by_system[42] = _entry(system_id=42, age_seconds=5.0)
    with TestClient(build_internal_app(registry)) as client:
        resp = client.get("/internal/agent/health/42")
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "healthy"
    assert body["tunnel_session_id"] == "sess-42"
    assert body["last_heartbeat_age_seconds"] == pytest.approx(5.0, abs=1.0)
    assert body["since_seconds"] == pytest.approx(60.0, abs=2.0)


def test_health_stale_when_heartbeat_past_dead_window():
    registry = AgentRegistry()
    registry._by_system[42] = _entry(
        system_id=42, age_seconds=HEARTBEAT_DEAD_SECONDS + 5
    )
    with TestClient(build_internal_app(registry)) as client:
        resp = client.get("/internal/agent/health/42")
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "stale"
    assert body["tunnel_session_id"] == "sess-42"


def test_health_no_docs_or_openapi_published():
    """Defensive: this is an internal API, no operator-facing docs."""
    with TestClient(build_internal_app(AgentRegistry())) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/redoc").status_code == 404
