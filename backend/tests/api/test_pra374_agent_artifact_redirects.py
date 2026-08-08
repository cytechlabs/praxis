"""PRA-374: hardened redirect policy for agent artifact downloads.

Both the artifact stream and the checksum fetch validate every redirect
hop before it is issued: HTTPS only, exact GitHub release hosts, no
embedded credentials, and the configured token dropped for good as soon
as a hop leaves the release origin.

No test here touches the network. Scripted request/response doubles
replace the transport, and the one test that exercises the real urllib
opener binds a throwaway server on the loopback interface.
"""

from __future__ import annotations

import email.message
import http.server
import io
import logging
import threading
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest

from app.api.routes import agent_bootstrap

# Mirrors the pinned constants in the route module. Kept by hand so a
# version or host change has to be acknowledged here too.
_RELEASE_VERSION = "v0.0.0-rc1"
_TARBALL = f"praxis-agent-{_RELEASE_VERSION}-linux-amd64.tar.gz"
_RELEASE_BASE = (
    "https://github.com/cytechlabs/praxis/releases/download/"
    f"agent-{_RELEASE_VERSION}"
)
_TARBALL_URL = f"{_RELEASE_BASE}/{_TARBALL}"
_CHECKSUMS_URL = f"{_RELEASE_BASE}/checksums.txt"

_ARTIFACT_PATH = "/agent/download/amd64/agent.tar.gz"
_CHECKSUM_PATH = "/agent/download/amd64/agent.tar.gz.sha256"

_TOKEN = "gho-pra374-token-must-never-leak"
_UPSTREAM_BODY = b"UPSTREAM-BODY-MUST-NEVER-BE-LOGGED"
_TARBALL_BODY = b"REDIRECTED_TARBALL"
_DIGEST = "a" * 64
_CHECKSUMS_BODY = f"{_DIGEST}  {_TARBALL}\n".encode("utf-8")

_OBJECTS_HOST = "https://objects.githubusercontent.com"
_ASSETS_HOST = "https://release-assets.githubusercontent.com"


# ---------------------------------------------------------------- doubles


class _FakeResponse:
    """Minimal stand-in for the object urllib returns on success."""

    def __init__(self, body: bytes, url: str):
        self._body = body
        self._index = 0
        self.headers = {"Content-Length": str(len(body))}
        self.url = url
        self.closed = False

    def read(self, size=None) -> bytes:
        if size is None:
            chunk = self._body[self._index :]
            self._index = len(self._body)
            return chunk
        chunk = self._body[self._index : self._index + size]
        self._index += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class _Hop:
    """What the transport actually saw for one exchange."""

    def __init__(self, request: urllib.request.Request):
        self.url = request.full_url
        self.redirected_headers = dict(request.headers)
        self.authorization = request.get_header("Authorization")
        # The hardened opener seeds urllib's loop-detection budget so no
        # redirect is ever followed for us. Its absence means a caller
        # reached the unrestricted default opener.
        self.no_follow = bool(getattr(request, "redirect_dict", None))


class _ScriptedTransport:
    """Replay a scripted redirect chain in place of ``urlopen``."""

    def __init__(self, script):
        self._script = script
        self.hops = []
        self.responses = []

    def __call__(self, request, timeout=None):
        self.hops.append(_Hop(request))
        url = request.full_url
        if url not in self._script:
            raise AssertionError(f"unscripted upstream request to {url}")
        entry = self._script[url]
        kind = entry[0]
        if kind == "redirect":
            raise urllib.error.HTTPError(
                url,
                entry[2],
                "Found",
                _headers({"Location": entry[1]}),
                io.BytesIO(_UPSTREAM_BODY),
            )
        if kind == "bare_redirect":
            raise urllib.error.HTTPError(
                url, entry[1], "Found", _headers({}), io.BytesIO(_UPSTREAM_BODY)
            )
        if kind == "error":
            raise urllib.error.HTTPError(
                url, entry[1], "Nope", _headers({}), io.BytesIO(_UPSTREAM_BODY)
            )
        if kind == "unreachable":
            raise urllib.error.URLError("connection refused")
        response = _FakeResponse(entry[1], entry[2] if len(entry) > 2 else url)
        self.responses.append(response)
        return response


def _headers(pairs) -> email.message.Message:
    message = email.message.Message()
    for key, value in pairs.items():
        message[key] = value
    return message


def _redirect(location: str, code: int = 302):
    return ("redirect", location, code)


def _ok(body: bytes, reported_url: str = None):
    return ("ok", body, reported_url) if reported_url else ("ok", body)


def _fetch(client, path, script):
    transport = _ScriptedTransport(script)
    with patch("urllib.request.urlopen", new=transport):
        response = client.get(path)
    return response, transport


@pytest.fixture
def upstream_only(monkeypatch, tmp_path):
    """Force the GitHub fallback arm and start from an unauthenticated
    control plane."""
    monkeypatch.setenv("PRAXIS_AGENT_ARTIFACT_DIR", str(tmp_path / "empty"))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)


@pytest.fixture
def with_token(monkeypatch, upstream_only):
    monkeypatch.setenv("GITHUB_TOKEN", _TOKEN)


@pytest.fixture
def route_warnings():
    """Collect the route module's warning records.

    A handler on the module logger rather than ``caplog``: the alembic
    ``fileConfig`` call in test-database setup disables every logger that
    already existed, so plain capture drops these records and would make
    "the token is never logged" assertions vacuous."""
    records = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector()
    logger = agent_bootstrap.logger
    previous_level = logger.level
    previously_disabled = logger.disabled
    logger.disabled = False
    # setLevel also clears the process-wide isEnabledFor cache.
    logger.setLevel(logging.WARNING)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.disabled = previously_disabled


def _logged_text(records) -> str:
    return "\n".join(record.getMessage() for record in records)


# ---------------------------------------------------------------- allow-list


def test_allowlist_is_exact_reviewed_hosts():
    """Exact hostnames only. A suffix rule on githubusercontent.com would
    admit user-controlled raw/gist/Pages subdomains."""
    assert agent_bootstrap._ALLOWED_HOP_HOSTS == frozenset(
        {
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        }
    )
    assert all("*" not in host for host in agent_bootstrap._ALLOWED_HOP_HOSTS)
    assert "raw.githubusercontent.com" not in agent_bootstrap._ALLOWED_HOP_HOSTS


# ---------------------------------------------------------------- initial hop


def test_initial_request_without_token_sends_no_authorization(client, upstream_only):
    res, transport = _fetch(client, _ARTIFACT_PATH, {_TARBALL_URL: _ok(_TARBALL_BODY)})
    assert res.status_code == 200
    assert res.content == _TARBALL_BODY
    assert [hop.url for hop in transport.hops] == [_TARBALL_URL]
    assert transport.hops[0].authorization is None
    assert transport.hops[0].no_follow is True


def test_initial_request_attaches_token_as_unredirected_header(client, with_token):
    res, transport = _fetch(client, _ARTIFACT_PATH, {_TARBALL_URL: _ok(_TARBALL_BODY)})
    assert res.status_code == 200
    hop = transport.hops[0]
    assert hop.authorization == f"Bearer {_TOKEN}"
    # Unredirected headers are the ones urllib refuses to copy onto a
    # redirect target.
    assert "Authorization" not in hop.redirected_headers


# ---------------------------------------------------------------- redirects


def test_same_origin_redirect_retains_authorization(client, with_token):
    moved = f"{_RELEASE_BASE}/relocated/{_TARBALL}"
    res, transport = _fetch(
        client,
        _ARTIFACT_PATH,
        {_TARBALL_URL: _redirect(moved), moved: _ok(_TARBALL_BODY)},
    )
    assert res.status_code == 200
    assert res.content == _TARBALL_BODY
    assert [hop.url for hop in transport.hops] == [_TARBALL_URL, moved]
    assert all(hop.authorization == f"Bearer {_TOKEN}" for hop in transport.hops)


def test_approved_cross_origin_redirect_strips_authorization(client, with_token):
    signed = f"{_ASSETS_HOST}/releases/1?sig=SIGNED-QUERY"
    res, transport = _fetch(
        client,
        _ARTIFACT_PATH,
        {_TARBALL_URL: _redirect(signed), signed: _ok(_TARBALL_BODY)},
    )
    assert res.status_code == 200
    assert res.content == _TARBALL_BODY
    assert transport.hops[0].authorization == f"Bearer {_TOKEN}"
    assert transport.hops[1].authorization is None
    assert "Authorization" not in transport.hops[1].redirected_headers


def test_relative_redirect_stays_on_the_release_origin(client, with_token):
    target = f"{_RELEASE_BASE}/relative/{_TARBALL}"
    res, transport = _fetch(
        client,
        _ARTIFACT_PATH,
        {
            _TARBALL_URL: _redirect(
                f"/cytechlabs/praxis/releases/download/agent-{_RELEASE_VERSION}/relative/{_TARBALL}"
            ),
            target: _ok(_TARBALL_BODY),
        },
    )
    assert res.status_code == 200
    assert [hop.url for hop in transport.hops] == [_TARBALL_URL, target]


def test_multi_hop_chain_never_reattaches_stripped_credentials(client, with_token):
    """Every hop is checked, and once the token has been dropped for a
    cross-origin hop it must not come back even when the chain returns to
    the release origin."""
    first = f"{_OBJECTS_HOST}/hop-one"
    second = f"{_ASSETS_HOST}/hop-two"
    third = f"{_RELEASE_BASE}/hop-three/{_TARBALL}"
    res, transport = _fetch(
        client,
        _ARTIFACT_PATH,
        {
            _TARBALL_URL: _redirect(first),
            first: _redirect(second, code=307),
            second: _redirect(third, code=301),
            third: _ok(_TARBALL_BODY),
        },
    )
    assert res.status_code == 200
    assert res.content == _TARBALL_BODY
    assert [hop.url for hop in transport.hops] == [_TARBALL_URL, first, second, third]
    assert transport.hops[0].authorization == f"Bearer {_TOKEN}"
    assert [hop.authorization for hop in transport.hops[1:]] == [None, None, None]
    assert all(hop.no_follow for hop in transport.hops)


def test_redirect_chain_longer_than_policy_is_rejected(client, with_token):
    hops = [f"{_OBJECTS_HOST}/hop-{index}" for index in range(8)]
    script = {_TARBALL_URL: _redirect(hops[0])}
    for index, url in enumerate(hops[:-1]):
        script[url] = _redirect(hops[index + 1])
    script[hops[-1]] = _ok(_TARBALL_BODY)

    res, transport = _fetch(client, _ARTIFACT_PATH, script)
    assert res.status_code == 502
    assert res.json()["detail"] == "agent artifact unavailable"
    assert len(transport.hops) == agent_bootstrap._MAX_REDIRECT_HOPS + 1


@pytest.mark.parametrize(
    "location",
    [
        # Unapproved origin.
        "https://evil.example.com/asset",
        # Suffix trick that a wildcard rule would admit.
        "https://objects.githubusercontent.com.evil.example.com/asset",
        # Sibling subdomain that serves user-controlled content.
        "https://raw.githubusercontent.com/asset",
        # HTTPS to HTTP downgrade, on both an asset host and the origin.
        "http://release-assets.githubusercontent.com/asset",
        "http://github.com/cytechlabs/praxis/asset",
        # Non-HTTP scheme.
        "ftp://release-assets.githubusercontent.com/asset",
        # Embedded user info, including host confusion.
        "https://user:pw@release-assets.githubusercontent.com/asset",
        "https://github.com@evil.example.com/asset",
        # Malformed target.
        "https://[oops/asset",
        # Unexpected port on an approved host.
        "https://release-assets.githubusercontent.com:8443/asset",
    ],
)
def test_rejected_redirect_targets_fail_closed(client, with_token, location):
    res, transport = _fetch(client, _ARTIFACT_PATH, {_TARBALL_URL: _redirect(location)})
    assert res.status_code == 502
    assert res.json()["detail"] == "agent artifact unavailable"
    # The rejected target is never contacted.
    assert [hop.url for hop in transport.hops] == [_TARBALL_URL]


def test_redirect_without_location_fails_closed(client, with_token):
    res, transport = _fetch(
        client, _ARTIFACT_PATH, {_TARBALL_URL: ("bare_redirect", 302)}
    )
    assert res.status_code == 502
    assert len(transport.hops) == 1


def test_unvalidated_upstream_redirect_fails_closed(client, with_token):
    """If the transport ever followed a redirect itself, the response URL
    would not match the requested URL. That must fail closed."""
    res, transport = _fetch(
        client,
        _ARTIFACT_PATH,
        {_TARBALL_URL: _ok(_TARBALL_BODY, reported_url=f"{_OBJECTS_HOST}/followed")},
    )
    assert res.status_code == 502
    assert transport.responses[0].closed is True


# ---------------------------------------------------------------- both paths


def test_checksum_path_uses_the_same_redirect_policy(client, with_token):
    signed = f"{_OBJECTS_HOST}/checksums?sig=SIGNED-QUERY"
    res, transport = _fetch(
        client,
        _CHECKSUM_PATH,
        {_CHECKSUMS_URL: _redirect(signed), signed: _ok(_CHECKSUMS_BODY)},
    )
    assert res.status_code == 200
    digest, name = res.text.strip().split(maxsplit=1)
    assert digest == _DIGEST
    assert name == "agent.tar.gz"
    assert [hop.url for hop in transport.hops] == [_CHECKSUMS_URL, signed]
    assert transport.hops[0].authorization == f"Bearer {_TOKEN}"
    assert transport.hops[1].authorization is None
    assert all(hop.no_follow for hop in transport.hops)


def test_checksum_path_rejects_unapproved_redirect(client, with_token):
    res, transport = _fetch(
        client,
        _CHECKSUM_PATH,
        {_CHECKSUMS_URL: _redirect("https://evil.example.com/checksums")},
    )
    assert res.status_code == 502
    assert [hop.url for hop in transport.hops] == [_CHECKSUMS_URL]


def test_public_unauthenticated_download_follows_approved_redirect(
    client, upstream_only
):
    """No token configured: the same validated redirect path still serves
    the artifact and the checksum."""
    tarball_target = f"{_ASSETS_HOST}/public-tarball"
    checksums_target = f"{_ASSETS_HOST}/public-checksums"

    tar_res, tar_transport = _fetch(
        client,
        _ARTIFACT_PATH,
        {
            _TARBALL_URL: _redirect(tarball_target),
            tarball_target: _ok(_TARBALL_BODY),
        },
    )
    assert tar_res.status_code == 200
    assert tar_res.content == _TARBALL_BODY

    sum_res, sum_transport = _fetch(
        client,
        _CHECKSUM_PATH,
        {
            _CHECKSUMS_URL: _redirect(checksums_target),
            checksums_target: _ok(_CHECKSUMS_BODY),
        },
    )
    assert sum_res.status_code == 200
    assert sum_res.text.strip().endswith("agent.tar.gz")

    for transport in (tar_transport, sum_transport):
        assert len(transport.hops) == 2
        assert all(hop.authorization is None for hop in transport.hops)
        assert all(hop.no_follow for hop in transport.hops)


# ---------------------------------------------------------------- disclosure


def test_upstream_error_maps_to_502_without_disclosure(
    client, with_token, route_warnings
):
    res, _ = _fetch(client, _ARTIFACT_PATH, {_TARBALL_URL: ("error", 404)})
    logged = _logged_text(route_warnings)
    assert res.status_code == 502
    assert res.json()["detail"] == "agent artifact unavailable"
    assert "HTTP 404" in logged
    assert _TOKEN not in logged
    assert _UPSTREAM_BODY.decode() not in logged


def test_unreachable_upstream_maps_to_502_without_disclosure(
    client, with_token, route_warnings
):
    res, _ = _fetch(client, _ARTIFACT_PATH, {_TARBALL_URL: ("unreachable",)})
    logged = _logged_text(route_warnings)
    assert res.status_code == 502
    assert "unreachable" in logged
    assert _TOKEN not in logged


def test_rejection_logs_omit_token_body_and_signed_query(
    client, with_token, route_warnings
):
    location = "https://evil.example.com/asset?sig=SIGNED-QUERY"
    res, _ = _fetch(client, _ARTIFACT_PATH, {_TARBALL_URL: _redirect(location)})
    logged = _logged_text(route_warnings)
    assert res.status_code == 502
    assert "redirect rejected" in logged
    # The host is useful for operators; the token, the upstream body, and
    # the signed query string are not disclosed.
    assert "evil.example.com" in logged
    assert _TOKEN not in logged
    assert _UPSTREAM_BODY.decode() not in logged
    assert "SIGNED-QUERY" not in logged
    assert _TOKEN not in res.text


# ---------------------------------------------------------------- transport


def test_single_hop_open_never_follows_a_redirect():
    """Guards the hardened opener against the stock urllib behavior of
    following redirects internally, which would hide hops from
    validation. Loopback only, so no external host is reachable."""
    requested = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler contract
            requested.append(self.path)
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/followed")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"FOLLOWED"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            """Silence the stdlib per-request logging this test server emits."""

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/start", method="GET"
        )
        with pytest.raises(urllib.error.HTTPError) as caught:
            agent_bootstrap._open_single_hop(request, 10)
        assert caught.value.code == 302
        assert caught.value.headers.get("Location") == "/followed"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)

    assert requested == ["/start"]
