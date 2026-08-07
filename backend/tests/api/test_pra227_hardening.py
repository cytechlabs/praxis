"""PRA-227: audit HTTP-sink target guardrails + bounded Vault error detail.

- AUDIT-03: operator-configured HTTP audit sinks must not target
  loopback/link-local/private/metadata endpoints (SSRF-style guardrail) and
  must use TLS for non-local hosts, unless an explicit env escape hatch is set.
- VAULT-01: Vault route failures return bounded, user-safe messages; the raw
  exception text is never echoed to the (privileged) client.
"""

import ipaddress
import socket

import pytest
from fastapi import HTTPException

from app.api.routes.audit import _validate_http_sink_target
from app.services import outbound_http_guard

# ── AUDIT-03: target classification ────────────────────────────────────────

# The sink guard now resolves DNS, so the fake public hostnames these tests use
# are mapped to a stable public IP; unmapped hosts (literal IPs, real names) pass
# through to the real resolver. Literal private IPs and local names never hit DNS.
_REAL_GETADDRINFO = socket.getaddrinfo
_PUBLIC_NAMES = {
    "audit.example.com": "93.184.216.34",
    "collector.example.com": "93.184.216.34",
    "collector.acme.io": "93.184.216.34",
}


def _fake_getaddrinfo(host, *args, **kwargs):
    if host in _PUBLIC_NAMES:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_NAMES[host], 0))]
    return _REAL_GETADDRINFO(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def _patch_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


@pytest.mark.parametrize(
    "ip,blocked",
    [
        ("127.0.0.1", True),
        ("10.0.0.5", True),
        ("192.168.1.1", True),
        ("172.16.9.9", True),
        ("169.254.169.254", True),
        ("::1", True),
        ("::ffff:127.0.0.1", True),  # IPv4-mapped loopback
        ("8.8.8.8", False),
        ("93.184.216.34", False),
    ],
)
def test_ip_classification(ip, blocked):
    assert outbound_http_guard.ip_is_blocked(ipaddress.ip_address(ip)) is blocked


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/collect",  # loopback
        "https://169.254.169.254/latest",  # cloud metadata
        "https://10.0.0.5/collect",  # private
        "http://audit.example.com/collect",  # non-local must be https
        "ftp://audit.example.com/collect",  # bad scheme
        "https:///no-host",  # missing host
        "http://localhost/collect",  # local name
        "http://metadata/latest",  # metadata name
    ],
)
def test_validate_rejects(target):
    with pytest.raises(HTTPException):
        _validate_http_sink_target(target)


def test_validate_allows_public_https():
    _validate_http_sink_target("https://audit.example.com/collect")  # no raise


def test_validate_allows_internal_with_env(monkeypatch):
    monkeypatch.setenv("AUDIT_SINK_ALLOW_PRIVATE_TARGETS", "1")
    _validate_http_sink_target("http://10.0.0.5:514/collect")  # no raise


# ── AUDIT-03: route boundary ───────────────────────────────────────────────


def test_create_http_sink_rejects_internal_target(authed_client):
    res = authed_client.post(
        "/audit/sinks",
        json={
            "name": "pra227-bad",
            "kind": "http",
            "target": "http://169.254.169.254/x",
        },
    )
    assert res.status_code == 400, res.text


def test_create_http_sink_allows_public_https(authed_client):
    res = authed_client.post(
        "/audit/sinks",
        json={
            "name": "pra227-ok",
            "kind": "http",
            "target": "https://collector.example.com/audit",
        },
    )
    assert res.status_code == 200, res.text


def test_create_syslog_sink_unaffected(authed_client):
    res = authed_client.post(
        "/audit/sinks",
        json={"name": "pra227-syslog", "kind": "syslog", "target": "localhost:514"},
    )
    assert res.status_code == 200, res.text


def test_update_http_sink_rejects_internal_target(authed_client):
    created = authed_client.post(
        "/audit/sinks",
        json={
            "name": "pra227-upd",
            "kind": "http",
            "target": "https://collector.example.com/audit",
        },
    )
    assert created.status_code == 200, created.text
    sink_id = created.json()["sink"]["id"]
    res = authed_client.patch(
        f"/audit/sinks/{sink_id}", json={"target": "http://127.0.0.1/collect"}
    )
    assert res.status_code == 400, res.text


# ── VAULT-01: bounded error detail ─────────────────────────────────────────


def test_vault_connection_error_is_bounded(authed_client, monkeypatch):
    from app.services import vault_service as vs

    def _boom(self):
        raise vs.VaultConnectionError("raw-transport-SECRET-9xyz at 10.1.2.3:8200")

    monkeypatch.setattr(vs.VaultService, "list_kv_stores", _boom)
    res = authed_client.get("/vault/secrets/kv-stores")
    assert res.status_code == 503, res.text
    detail = res.json()["detail"]
    assert "SECRET-9xyz" not in detail
    assert "10.1.2.3" not in detail
    assert (
        detail
        == "Vault is currently unavailable. Verify the Vault connection and retry."
    )


def test_vault_generic_error_is_bounded(authed_client, monkeypatch):
    from app.services import vault_service as vs

    def _boom(self):
        raise RuntimeError("hvac stacktrace TOPSECRET-abc /vault/internal path")

    monkeypatch.setattr(vs.VaultService, "list_kv_stores", _boom)
    res = authed_client.get("/vault/secrets/kv-stores")
    assert res.status_code == 500, res.text
    detail = res.json()["detail"]
    assert "TOPSECRET-abc" not in detail
    assert detail == "Failed to list KV stores."


def test_vault_not_found_http_exception_is_preserved(authed_client, monkeypatch):
    from app.services import vault_service as vs

    def _missing(self, path):
        return None

    monkeypatch.setattr(vs.VaultService, "read_secret", _missing)
    res = authed_client.get("/vault/secrets/secret", params={"path": "missing/path"})
    assert res.status_code == 404, res.text
    assert res.json()["detail"] == "Secret not found at path: missing/path"
