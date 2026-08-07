"""PRA-180 P2 Remediation (PRA-222): broker internal API authentication.

BROKER-01: the broker internal HTTP API (``:8444 /internal/agent/...``) had no
authentication and trusted the docker network, so any backend-net container
could dispatch agent ops. A shared-secret bearer (derived from ``SECRET_KEY``,
or ``PRAXIS_BROKER_INTERNAL_TOKEN``) is now required.

Covers:
- token derivation precedence + constant-time compare (``internal_auth``).
- the broker app rejects missing/wrong tokens (``401``) and lets a correct token
  through, including for POST op endpoints.
- ``auth_token=None`` keeps the historical unauthenticated behavior for op-flow
  unit tests.
- the backend ``BrokerClient`` attaches the header and unlocks the authed app.
"""

from __future__ import annotations

import hashlib
import hmac

import httpx
import pytest
from fastapi.testclient import TestClient

from app.broker.internal_api import build_internal_app
from app.broker.internal_auth import (
    INTERNAL_AUTH_HEADER,
    derive_internal_token,
    tokens_match,
)
from app.broker.registry import AgentRegistry
from app.services.broker_client import BrokerClient, _auth_headers

TOKEN = "broker-internal-test-token"


# ── token derivation + compare ─────────────────────────────────────────────


def test_explicit_token_takes_precedence(monkeypatch):
    monkeypatch.setenv("PRAXIS_BROKER_INTERNAL_TOKEN", "explicit-token")
    monkeypatch.setenv("SECRET_KEY", "some-secret")
    assert derive_internal_token() == "explicit-token"


def test_token_derived_from_secret_key(monkeypatch):
    monkeypatch.delenv("PRAXIS_BROKER_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("SECRET_KEY", "the-shared-secret")
    expected = hmac.new(
        b"the-shared-secret", b"praxis-broker-internal-api-v1", hashlib.sha256
    ).hexdigest()
    assert derive_internal_token() == expected


def test_token_none_when_no_secret(monkeypatch):
    monkeypatch.delenv("PRAXIS_BROKER_INTERNAL_TOKEN", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert derive_internal_token() is None


def test_tokens_match():
    assert tokens_match("abc", "abc") is True
    assert tokens_match("abc", "abd") is False
    assert tokens_match(None, "abc") is False
    assert tokens_match("abc", None) is False
    assert tokens_match("", "") is False


# ── broker app enforcement ─────────────────────────────────────────────────


def test_health_rejected_without_token():
    app = build_internal_app(AgentRegistry(), auth_token=TOKEN)
    with TestClient(app) as client:
        resp = client.get("/internal/agent/health/1")
    assert resp.status_code == 401
    assert resp.json()["error"]["reason"] == "unauthorized"


def test_health_rejected_with_wrong_token():
    app = build_internal_app(AgentRegistry(), auth_token=TOKEN)
    with TestClient(app) as client:
        resp = client.get(
            "/internal/agent/health/1",
            headers={INTERNAL_AUTH_HEADER: "not-the-token"},
        )
    assert resp.status_code == 401


def test_health_allowed_with_correct_token():
    app = build_internal_app(AgentRegistry(), auth_token=TOKEN)
    with TestClient(app) as client:
        resp = client.get(
            "/internal/agent/health/1",
            headers={INTERNAL_AUTH_HEADER: TOKEN},
        )
    assert resp.status_code == 200
    assert resp.json()["state"] == "unregistered"


def test_op_endpoint_rejected_before_handler_without_token():
    """An unauthenticated POST to an op endpoint is rejected at the middleware
    (401) — it never reaches the manager-not-initialised handler error."""
    app = build_internal_app(AgentRegistry(), auth_token=TOKEN)  # no manager
    with TestClient(app) as client:
        resp = client.post(
            "/internal/agent/ops/exec",
            json={"system_id": 1, "cmd": "id"},
        )
    assert resp.status_code == 401


def test_op_endpoint_passes_auth_then_reaches_handler():
    """A correct token clears the middleware; with no manager wired the handler
    itself returns 500, proving the request got past auth into the route."""
    app = build_internal_app(AgentRegistry(), auth_token=TOKEN)  # manager=None
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/internal/agent/ops/exec",
            json={"system_id": 1, "cmd": "id"},
            headers={INTERNAL_AUTH_HEADER: TOKEN},
        )
    assert resp.status_code == 500


def test_no_auth_when_token_unset():
    """Back-compat: op-flow tests build the app without a token and stay open."""
    app = build_internal_app(AgentRegistry())  # auth_token defaults to None
    with TestClient(app) as client:
        resp = client.get("/internal/agent/health/1")
    assert resp.status_code == 200


# ── BrokerClient attaches the header ───────────────────────────────────────


def test_auth_headers_uses_derived_token(monkeypatch):
    monkeypatch.delenv("PRAXIS_BROKER_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("SECRET_KEY", "client-secret")
    headers = _auth_headers()
    assert headers == {INTERNAL_AUTH_HEADER: derive_internal_token()}


def test_auth_headers_empty_without_secret(monkeypatch):
    monkeypatch.delenv("PRAXIS_BROKER_INTERNAL_TOKEN", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert _auth_headers() == {}


@pytest.mark.asyncio
async def test_broker_client_unlocks_authed_app(monkeypatch):
    """End-to-end over ASGITransport: the app derives its token from SECRET_KEY,
    and the client presents the same derived header, so health() succeeds."""
    monkeypatch.delenv("PRAXIS_BROKER_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("SECRET_KEY", "e2e-shared-secret")
    app = build_internal_app(AgentRegistry(), auth_token=derive_internal_token())
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(
        transport=transport, base_url="http://broker.test", headers=_auth_headers()
    )
    bc = BrokerClient(client=client)
    try:
        health = await bc.health(7)
        assert health.state == "unregistered"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_broker_client_without_header_degrades_to_unknown(monkeypatch):
    """Without the header the authed app returns 401, which health() degrades to
    state='unknown' rather than raising."""
    monkeypatch.delenv("PRAXIS_BROKER_INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("SECRET_KEY", "e2e-shared-secret")
    app = build_internal_app(AgentRegistry(), auth_token=derive_internal_token())
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://broker.test")
    bc = BrokerClient(client=client)
    try:
        health = await bc.health(7)
        assert health.state == "unknown"
    finally:
        await client.aclose()
