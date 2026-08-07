"""PRA-367: OIDC discovery / token / JWKS SSRF hardening.

The OIDC provider config is admin-controlled and the discovery document is
attacker-influenceable, so every outbound OIDC request (discovery, token
exchange, JWKS) goes through the shared SSRF guard: HTTPS required, DNS resolved,
internal/loopback/link-local/metadata targets rejected, no redirects. This covers
the API boundary (create/update/test) and the discovered-endpoint re-validation
in the service flow.
"""

import socket

import httpx
import pytest

from app.db.models import OIDCProvider
from app.services.oidc_service import OIDCError, OIDCService

_REAL_GETADDRINFO = socket.getaddrinfo


def _gai(mapping):
    """Resolver stub: hosts in *mapping* return the given IPs (empty -> gaierror);
    unmapped hosts fall through to the real resolver."""

    def _inner(host, *args, **kwargs):
        if host in mapping:
            ips = mapping[host]
            if not ips:
                raise socket.gaierror(f"no record for {host}")
            return [
                (
                    socket.AF_INET6 if ":" in ip else socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    (ip, 0),
                )
                for ip in ips
            ]
        return _REAL_GETADDRINFO(host, *args, **kwargs)

    return _inner


def _install_mock_transport(monkeypatch, handler):
    """Route the guard's async httpx client through a MockTransport so a 'public'
    provider path can be exercised without real network."""
    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.setdefault("transport", httpx.MockTransport(handler))
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def _create(client, discovery_url, name="pra367"):
    return client.post(
        "/auth/oidc/providers",
        json={
            "name": name,
            "discovery_url": discovery_url,
            "client_id": "praxis-client",
            "client_secret": "shh",
        },
    )


# --- create/update route rejection ---


@pytest.mark.parametrize(
    "discovery_url",
    [
        "https://127.0.0.1/",  # loopback
        "https://[::1]/",  # IPv6 loopback
        "https://10.0.0.5/",  # RFC1918
        "https://192.168.1.10/",  # RFC1918
        "https://169.254.169.254/",  # cloud metadata / link-local
        "https://[fd00::1]/",  # IPv6 ULA
        "ftp://idp.example.com/",  # bad scheme
    ],
)
def test_create_rejects_disallowed_literal(authed_client, discovery_url):
    res = _create(authed_client, discovery_url)
    assert res.status_code == 400, res.text


def test_create_rejects_dns_resolved_private(authed_client, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _gai({"evil.idp.test": ["10.0.0.5"]}))
    res = _create(authed_client, "https://evil.idp.test/")
    assert res.status_code == 400, res.text


def test_create_rejects_mixed_dns_answers(authed_client, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai({"mixed.idp.test": ["1.1.1.1", "127.0.0.1"]})
    )
    res = _create(authed_client, "https://mixed.idp.test/")
    assert res.status_code == 400, res.text


def test_create_rejects_http_scheme_by_default(authed_client, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _gai({"pub.idp.test": ["1.1.1.1"]}))
    res = _create(authed_client, "http://pub.idp.test/")
    assert res.status_code == 400, res.text


def test_create_allows_public_https(authed_client, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai({"good.idp.test": ["93.184.216.34"]})
    )
    res = _create(authed_client, "https://good.idp.test/", name="pra367-ok")
    assert res.status_code == 201, res.text


def test_update_rejects_private_discovery_url(authed_client, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai({"good.idp.test": ["93.184.216.34"]})
    )
    created = _create(authed_client, "https://good.idp.test/", name="pra367-upd")
    assert created.status_code == 201, created.text
    pid = created.json()["id"]

    res = authed_client.put(
        f"/auth/oidc/providers/{pid}",
        json={"discovery_url": "https://169.254.169.254/"},
    )
    assert res.status_code == 400, res.text


def test_test_route_reports_blocked_discovery_target(authed_client):
    res = authed_client.post(
        "/auth/oidc/providers/test",
        params={"discovery_url": "https://10.0.0.5/"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["success"] is False
    assert "not allowed" in body["error"]


# --- discovered-endpoint re-validation (service flow) ---


def _provider():
    return OIDCProvider(
        name="idp", discovery_url="https://idp.test", client_id="c", client_secret="s"
    )


@pytest.mark.asyncio
async def test_exchange_code_rejects_private_token_endpoint(db, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai({"internal.idp.test": ["10.0.0.5"]})
    )
    svc = OIDCService(db)
    doc = {"token_endpoint": "https://internal.idp.test/token"}
    with pytest.raises(OIDCError):
        await svc.exchange_code(_provider(), "code", "https://app/cb", doc)


@pytest.mark.asyncio
async def test_validate_id_token_rejects_private_jwks_uri(db, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai({"internal.idp.test": ["10.0.0.5"]})
    )
    svc = OIDCService(db)
    doc = {"jwks_uri": "https://internal.idp.test/jwks", "issuer": "https://idp.test"}
    with pytest.raises(OIDCError):
        await svc.validate_id_token("dummy.token", _provider(), doc, "nonce")


@pytest.mark.asyncio
async def test_exchange_code_rejects_metadata_token_endpoint_literal(db):
    svc = OIDCService(db)
    doc = {"token_endpoint": "https://169.254.169.254/token"}
    with pytest.raises(OIDCError):
        await svc.exchange_code(_provider(), "code", "https://app/cb", doc)


@pytest.mark.asyncio
async def test_discover_public_path_works(db, monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai({"idp.example.test": ["93.184.216.34"]})
    )

    def _handler(request):
        assert request.url.path.endswith("/.well-known/openid-configuration")
        return httpx.Response(
            200,
            json={
                "issuer": "https://idp.example.test",
                "authorization_endpoint": "https://idp.example.test/auth",
                "token_endpoint": "https://idp.example.test/token",
                "jwks_uri": "https://idp.example.test/jwks",
            },
        )

    _install_mock_transport(monkeypatch, _handler)
    svc = OIDCService(db)
    doc = await svc.discover("https://idp.example.test")
    assert doc["token_endpoint"] == "https://idp.example.test/token"
    assert doc["jwks_uri"] == "https://idp.example.test/jwks"


@pytest.mark.asyncio
async def test_discover_rejects_private_discovery_host(db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _gai({"evil.idp.test": ["10.0.0.5"]}))
    svc = OIDCService(db)
    with pytest.raises(OIDCError):
        await svc.discover("https://evil.idp.test")


@pytest.mark.asyncio
async def test_discover_cache_does_not_bypass_runtime_validation(db, monkeypatch):
    """A cached discovery doc must not let a later call skip validation: if the
    host rebinds to a private address after caching, the next discover() is
    rejected even though the doc is cached."""

    def _handler(request):
        return httpx.Response(
            200,
            json={
                "issuer": "https://idp.example.test",
                "authorization_endpoint": "https://idp.example.test/auth",
                "token_endpoint": "https://idp.example.test/token",
                "jwks_uri": "https://idp.example.test/jwks",
            },
        )

    _install_mock_transport(monkeypatch, _handler)
    svc = OIDCService(db)

    # First call resolves public and populates the cache.
    monkeypatch.setattr(
        socket, "getaddrinfo", _gai({"idp.example.test": ["93.184.216.34"]})
    )
    await svc.discover("https://idp.example.test")
    assert "https://idp.example.test" in svc._discovery_cache

    # Rebind: the same host now resolves to a private address. The cached doc must
    # NOT be served without re-validation.
    monkeypatch.setattr(socket, "getaddrinfo", _gai({"idp.example.test": ["10.0.0.5"]}))
    with pytest.raises(OIDCError):
        await svc.discover("https://idp.example.test")
