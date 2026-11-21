"""PRA-429: what a real HTTP client sees from a download.

The TestClient hides connection aborts, so these tests serve the real route over
uvicorn (tests/helpers/file_transfer_harness.py) and read it with httpx. They
pin the client contract documented on the download endpoint:

* failures that precede the first byte are error responses,
* a failure after the 200 aborts the connection so the body is observably
  incomplete (``Content-Length`` unmet, or an unterminated chunked body),
* an empty file is a complete, zero-length 200, and
* a client that walks away leaves a failure audit and no leaked resources.
"""

from __future__ import annotations

import hashlib
import time
from urllib.parse import quote

import httpx
import pytest

from tests.helpers.file_transfer_fakes import content_sha256
from tests.helpers.file_transfer_harness import AGENT_SYSTEM, MIB, SSH_SYSTEM, serving

TRANSPORTS = pytest.mark.parametrize(
    "system", [SSH_SYSTEM, AGENT_SYSTEM], ids=["ssh", "agent"]
)


@pytest.fixture(scope="module")
def harness():
    with serving() as h:
        yield h


@pytest.fixture
def server(harness):
    httpx.post(harness["base_url"] + "/__reset")
    return harness


def _url(harness, system, path):
    return (
        f"{harness['base_url']}/transfer/{system}/download?path={quote(path, safe='')}"
    )


def _state(harness):
    return httpx.get(harness["base_url"] + "/__state").json()


def _settled_audit(harness, timeout=10.0):
    """The single audit row once it has left in_progress."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = _state(harness)["audits"]
        if rows and all(r["status"] != "in_progress" for r in rows):
            return rows
        time.sleep(0.05)
    raise AssertionError(f"audit never settled: {_state(harness)['audits']}")


def _download(harness, system, path):
    """(status, headers, body, error) as a strict client sees it."""
    body = bytearray()
    with httpx.Client(timeout=30) as client:
        try:
            with client.stream("GET", _url(harness, system, path)) as res:
                status, headers = res.status_code, res.headers
                try:
                    for chunk in res.iter_bytes():
                        body.extend(chunk)
                except httpx.TransportError as exc:
                    return status, headers, bytes(body), exc
        except httpx.TransportError as exc:  # failed before any response
            return None, {}, bytes(body), exc
    return status, headers, bytes(body), None


@TRANSPORTS
def test_complete_download_matches_declared_length(server, system):
    status, headers, body, err = _download(server, system, "/ok/medium.bin")
    size = 5 * MIB + 3
    assert (status, err) == (200, None)
    assert headers["content-length"] == str(size)
    assert hashlib.sha256(body).hexdigest() == content_sha256(size)
    row = _settled_audit(server)[0]
    assert (row["status"], row["size_bytes"]) == ("success", size)
    assert row["sha256"] == content_sha256(size)


@TRANSPORTS
def test_empty_file_is_a_complete_zero_length_success(server, system):
    status, headers, body, err = _download(server, system, "/ok/empty.bin")
    assert (status, body, err) == (200, b"", None)
    assert headers["content-length"] == "0"
    assert _settled_audit(server)[0]["status"] == "success"


@TRANSPORTS
@pytest.mark.parametrize(
    "path,expected",
    [
        ("/missing/file", 404),
        ("/err/denied.bin", 403),
        ("/err/dir", 400),
    ],
)
def test_failures_before_the_first_byte_are_error_responses(
    server, system, path, expected
):
    status, headers, body, err = _download(server, system, path)
    assert (status, err) == (expected, None)
    assert "content-disposition" not in headers
    assert "detail" in httpx.Response(status, content=body).json()
    row = _settled_audit(server)[0]
    assert row["status"] == "error"


def test_ssh_failure_after_the_200_aborts_the_connection(server):
    """The original defect. Status 200 is already out, so the only honest
    signal left is a body that never reaches its declared length."""
    status, headers, body, err = _download(server, SSH_SYSTEM, "/err/midstream.bin")
    assert status == 200
    assert headers["content-length"] == str(8 * MIB)
    assert isinstance(err, httpx.RemoteProtocolError), err
    assert 0 < len(body) < 8 * MIB
    row = _settled_audit(server)[0]
    assert row["status"] == "error"
    assert row["sha256"] is None
    assert server["env"].tracker.leaked == 0


def test_ssh_remote_ending_early_aborts_the_connection(server):
    status, _headers, body, err = _download(server, SSH_SYSTEM, "/err/short.bin")
    assert status == 200
    assert isinstance(err, httpx.RemoteProtocolError), err
    assert len(body) < 4 * MIB
    row = _settled_audit(server)[0]
    assert row["status"] == "error"
    assert "incomplete" in row["error"]


def test_unsized_ssh_stream_failure_leaves_the_chunked_body_unterminated(server):
    status, headers, _body, err = _download(
        server, SSH_SYSTEM, "/err/midstream-chunked.bin"
    )
    assert status == 200
    assert "content-length" not in headers
    assert headers["transfer-encoding"] == "chunked"
    assert isinstance(err, httpx.RemoteProtocolError), err
    assert _settled_audit(server)[0]["status"] == "error"


def test_unsized_ssh_stream_that_completes_is_served_in_full(server):
    status, headers, body, err = _download(server, SSH_SYSTEM, "/ok/pseudo.txt")
    assert (status, err) == (200, None)
    assert "content-length" not in headers
    assert hashlib.sha256(body).hexdigest() == content_sha256(300 * 1024)
    assert _settled_audit(server)[0]["status"] == "success"


@pytest.mark.parametrize(
    "path", ["/err/midstream.bin", "/err/short.bin"], ids=["stream-error", "short"]
)
def test_agent_failure_during_transfer_is_never_a_200(server, path):
    status, headers, _body, err = _download(server, AGENT_SYSTEM, path)
    assert (status, err) == (502, None)
    assert "content-disposition" not in headers
    row = _settled_audit(server)[0]
    assert (row["status"], row["transport"]) == ("error", "agent")
    state = _state(server)
    assert state["leaked"] == 0
    assert state["spool_files"] == []


@TRANSPORTS
def test_client_abandoning_a_download_cleans_up_and_audits_failure(server, system):
    with (
        httpx.Client(timeout=30) as client,
        client.stream("GET", _url(server, system, "/big/huge.bin")) as res,
    ):
        assert res.status_code == 200
        first = next(res.iter_bytes(), None)
        assert first, "no first body chunk was received"
    # Leaving the block closes the connection mid-body.
    row = _settled_audit(server)[0]
    assert row["status"] == "error"
    assert row["error"] == "client_disconnected"
    assert row["sha256"] is None
    state = _state(server)
    assert state["leaked"] == 0
    assert state["spool_files"] == []
    if system == SSH_SYSTEM:
        # The backend stopped reading the host soon after the client left.
        assert state["bytes_read"] < 48 * MIB


def test_non_ascii_filename_yields_a_valid_attachment_header(server):
    status, headers, body, err = _download(server, SSH_SYSTEM, "/ok/naive \u00fc.bin")
    assert (status, err, len(body)) == (200, None, 2048)
    disposition = headers["content-disposition"]
    assert 'filename="naive _.bin"' in disposition
    assert "filename*=UTF-8''naive%20%C3%BC.bin" in disposition
