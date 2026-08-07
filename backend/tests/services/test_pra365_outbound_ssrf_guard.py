"""PRA-365: shared outbound HTTP SSRF guard.

Covers scheme/host validation, DNS resolution with fail-closed classification of
loopback/private/link-local/metadata/reserved/multicast/unspecified addresses
(IPv4 + IPv6 + IPv4-mapped), mixed-answer rejection, the audit https policy, the
explicit private-target override, redirect suppression, IP pinning, and
delivery-time revalidation (DNS rebinding).
"""

import http.server
import socket
import socketserver
import threading

import pytest

from app.services import outbound_http_guard as g
from app.services.outbound_http_guard import SsrfBlocked

_REAL_GETADDRINFO = socket.getaddrinfo


def _fake_getaddrinfo(mapping):
    """Resolver stub. Hosts in *mapping* return the given IPs (empty list ->
    gaierror). Unmapped hosts (e.g. the pinned literal IP httpx connects to)
    pass through to the real resolver so real delivery still works."""

    def _gai(host, *args, **kwargs):
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

    return _gai


# --------------------------------------------------------------- literals


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://127.0.0.53/",
        "https://[::1]/",
        "http://10.0.0.5/",
        "http://192.168.1.10/",
        "http://172.16.5.5/",
        "https://[fd00::1]/",  # IPv6 ULA
        "http://169.254.169.254/",  # cloud metadata
        "https://[fe80::1]/",  # link-local
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped loopback
        "http://0.0.0.0/",  # unspecified
        "http://224.0.0.1/",  # multicast
    ],
)
def test_blocks_disallowed_literals(url):
    with pytest.raises(SsrfBlocked):
        g.validate_target(url, allow_private=False)


def test_allows_public_literal():
    # A public literal IP is fine.
    assert str(g.validate_target("https://8.8.8.8/", allow_private=False)) == "8.8.8.8"


def test_rejects_non_http_scheme_and_missing_host():
    with pytest.raises(SsrfBlocked):
        g.validate_target("ftp://example.com/", allow_private=False)
    with pytest.raises(SsrfBlocked):
        g.validate_target("file:///etc/passwd", allow_private=False)


def test_blocks_local_names_before_dns():
    for url in ("http://localhost/", "http://metadata/", "http://foo.internal/"):
        with pytest.raises(SsrfBlocked):
            g.validate_target(url, allow_private=False)


# --------------------------------------------------------------- DNS


def test_dns_resolving_to_private_is_blocked(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"evil.example": ["10.1.2.3"]})
    )
    with pytest.raises(SsrfBlocked):
        g.validate_target("https://evil.example/", allow_private=False)


def test_dns_resolving_to_metadata_is_blocked(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        _fake_getaddrinfo({"rebind.example": ["169.254.169.254"]}),
    )
    with pytest.raises(SsrfBlocked):
        g.validate_target("https://rebind.example/", allow_private=False)


def test_dns_mixed_answers_fail_closed(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        _fake_getaddrinfo({"mixed.example": ["1.1.1.1", "127.0.0.1"]}),
    )
    with pytest.raises(SsrfBlocked):
        g.validate_target("https://mixed.example/", allow_private=False)


def test_dns_public_answer_allowed(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"ok.example": ["1.1.1.1"]})
    )
    assert (
        str(g.validate_target("https://ok.example/", allow_private=False)) == "1.1.1.1"
    )


def test_unresolvable_host_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({"nope.example": []}))
    with pytest.raises(SsrfBlocked):
        g.validate_target("https://nope.example/", allow_private=False)


# --------------------------------------------------------------- https policy


def test_require_https_blocks_public_http(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"pub.example": ["1.1.1.1"]})
    )
    with pytest.raises(SsrfBlocked):
        g.validate_target(
            "http://pub.example/", allow_private=False, require_https=True
        )


def test_require_https_allows_public_https(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"pub.example": ["1.1.1.1"]})
    )
    g.validate_target("https://pub.example/", allow_private=False, require_https=True)


# --------------------------------------------------------------- override


def test_private_target_override_allows_internal():
    # Explicit override permits an internal collector.
    assert g.validate_target("http://127.0.0.1/", allow_private=True) is not None
    assert g.validate_target("http://10.0.0.5/", allow_private=True) is not None


def test_validate_defaults_to_blocked_without_kwarg():
    # The guard never reads env implicitly: no allow_private kwarg -> blocked.
    with pytest.raises(SsrfBlocked):
        g.validate_target("http://127.0.0.1/")


def test_audit_and_alert_flags_are_independent(monkeypatch):
    # The audit override must not open alert targets, and vice versa.
    monkeypatch.delenv("ALERT_ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.setenv("AUDIT_SINK_ALLOW_PRIVATE_TARGETS", "1")
    assert g.allow_private_targets() is True
    assert g.alert_allow_private_targets() is False

    monkeypatch.setenv("AUDIT_SINK_ALLOW_PRIVATE_TARGETS", "0")
    monkeypatch.setenv("ALERT_ALLOW_PRIVATE_TARGETS", "yes")
    assert g.allow_private_targets() is False
    assert g.alert_allow_private_targets() is True


# --------------------------------------------------------------- delivery


@pytest.fixture
def local_server():
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen["host"] = self.headers.get("Host")
            seen["path"] = self.path
            seen["sig"] = self.headers.get("X-Praxis-Signature")
            length = int(self.headers.get("Content-Length", "0"))
            seen["body"] = self.rfile.read(length)
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        def do_GET(self):
            seen["host"] = self.headers.get("Host")
            seen["path"] = self.path
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield port, seen
    finally:
        srv.shutdown()
        srv.server_close()


def test_delivery_pins_and_preserves_host_header(monkeypatch, local_server):
    port, seen = local_server
    # A named target that resolves to the IPv4 loopback the test server listens on.
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"webhook.test": ["127.0.0.1"]})
    )
    resp = g.post(
        f"http://webhook.test:{port}/hook",
        content=b"payload",
        headers={"X-Praxis-Signature": "sha256=abc"},
        timeout=5.0,
        allow_private=True,
    )
    assert resp.status_code == 200
    # Connected to the pinned IP, but Host + custom headers are preserved.
    assert seen["host"] == f"webhook.test:{port}"
    assert seen["path"] == "/hook"
    assert seen["sig"] == "sha256=abc"
    assert seen["body"] == b"payload"


def test_delivery_does_not_follow_redirects(monkeypatch, local_server):
    port, _seen = local_server
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"webhook.test": ["127.0.0.1"]})
    )
    resp = g.post(
        f"http://webhook.test:{port}/redir",
        content=b"x",
        headers={},
        timeout=5.0,
        allow_private=True,
    )
    # The 3xx is returned as-is, never followed to the metadata Location.
    assert resp.status_code == 302


def test_delivery_revalidates_and_blocks_rebinding(monkeypatch, local_server):
    port, _seen = local_server
    # At delivery time the name resolves to a private address (DNS rebind).
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"rebound.example": ["10.9.9.9"]})
    )
    with pytest.raises(SsrfBlocked):
        g.post(
            f"http://rebound.example:{port}/hook",
            content=b"x",
            headers={},
            timeout=5.0,
            allow_private=False,
        )


# --------------------------------------------------- async delivery (PRA-367)


@pytest.mark.asyncio
async def test_get_async_pins_and_preserves_host(monkeypatch, local_server):
    port, seen = local_server
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"idp.test": ["127.0.0.1"]})
    )
    resp = await g.get_async(
        f"http://idp.test:{port}/keys",
        timeout=5.0,
        allow_private=True,
        require_https=False,
    )
    assert resp.status_code == 200
    # Connected to the pinned loopback IP, but Host + path are the real ones.
    assert seen["host"] == f"idp.test:{port}"
    assert seen["path"] == "/keys"


@pytest.mark.asyncio
async def test_get_async_does_not_follow_redirects(monkeypatch, local_server):
    port, _seen = local_server
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"idp.test": ["127.0.0.1"]})
    )
    resp = await g.get_async(
        f"http://idp.test:{port}/redir",
        timeout=5.0,
        allow_private=True,
        require_https=False,
    )
    # The 3xx to the metadata Location is returned as-is, never followed.
    assert resp.status_code == 302


@pytest.mark.asyncio
async def test_get_async_blocks_private_and_rebinding(monkeypatch):
    # A literal private target is rejected outright.
    with pytest.raises(SsrfBlocked):
        await g.get_async("https://10.0.0.5/keys", timeout=5.0, allow_private=False)
    # A name that resolves to a private address at call time (rebind) is rejected.
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"rebound.idp": ["10.9.9.9"]})
    )
    with pytest.raises(SsrfBlocked):
        await g.get_async("https://rebound.idp/keys", timeout=5.0, allow_private=False)


@pytest.mark.asyncio
async def test_get_async_requires_https_for_public_by_default(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"pub.idp": ["1.1.1.1"]})
    )
    with pytest.raises(SsrfBlocked):
        await g.get_async("http://pub.idp/keys", timeout=5.0, allow_private=False)


@pytest.mark.asyncio
async def test_post_async_pins_and_sends_body(monkeypatch, local_server):
    port, seen = local_server
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"idp.test": ["127.0.0.1"]})
    )
    resp = await g.post_async(
        f"http://idp.test:{port}/token",
        content=b"grant_type=authorization_code",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=5.0,
        allow_private=True,
        require_https=False,
    )
    assert resp.status_code == 200
    assert seen["host"] == f"idp.test:{port}"
    assert seen["path"] == "/token"
    assert seen["body"] == b"grant_type=authorization_code"
