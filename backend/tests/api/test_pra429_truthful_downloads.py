"""PRA-429: file downloads report failure truthfully.

A download used to do all of its work inside the streaming generator, so any
failure (missing file, permission error, dead host) happened after the 200
headers had been sent and the client saw a successful, empty download. These
tests drive the real route, service, audit helpers and agent transport mapping
against in-memory SSH/agent fixtures (tests/helpers/file_transfer_fakes.py) and
assert on what the HTTP client observes and what is persisted.

Contract under test:

* Anything that can be known before the first byte (authorization, file
  existence/readability/type, size cap, connection setup, and for the agent
  transport the whole body) fails with a non-2xx status and a sanitized detail.
* A successful 200 declares ``Content-Length`` whenever the size is known, so a
  body that ends early is detectably incomplete rather than a clean short file.
* A zero-byte file is a 200 with ``Content-Length: 0``.
* Every outcome is persisted: the transfer audit row and the ``file.download``
  audit event agree with what the client saw.
"""

from __future__ import annotations

import errno
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.db.access_models import AuditEvent, FileTransferAudit
from app.db.models import Credential, Group, System
from app.services import file_transfer_service as fts
from tests.helpers.file_transfer_fakes import (
    RemoteFile,
    content_sha256,
    patched_transfer_env,
    spool_files,
)

KIB = 1024
SSH_HOST = "pra429-ssh"
AGENT_HOST = "pra429-agent"
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


@pytest.fixture
def hosts(db, seed_distro):
    group = db.query(Group).filter_by(name="Default").first()
    if group is None:
        group = Group(name="Default")
        db.add(group)
        db.flush()
    cred = db.query(Credential).first()
    if cred is None:
        cred = Credential(
            name="pra429-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra429",
        )
        db.add(cred)
        db.flush()
    made = {}
    for key, hostname, ip in (
        ("ssh", SSH_HOST, "10.4.29.1"),
        ("agent", AGENT_HOST, "10.4.29.2"),
    ):
        s = System(
            hostname=hostname,
            ip_address=ip,
            transport_preference=key,
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=cred.id,
        )
        db.add(s)
        db.flush()
        made[key] = s
    return made


@pytest.fixture
def env(db, hosts):
    transports = {hosts["ssh"].id: "ssh", hosts["agent"].id: "agent"}
    with patched_transfer_env(transports, session=db) as e:
        yield e
    assert spool_files() == []


@pytest.fixture
def http(authed_client):
    """Client that reports what the server did instead of re-raising it."""
    c = TestClient(app, client=("127.0.0.1", 50000), raise_server_exceptions=False)
    c.headers.update(authed_client.headers)
    return c


def _get(http, system, path):
    return http.get(f"/transfer/{system.id}/download", params={"path": path})


def _audit(db, system):
    rows = (
        db.query(FileTransferAudit)
        .filter(
            FileTransferAudit.system_id == system.id,
            FileTransferAudit.direction == "download",
        )
        .all()
    )
    assert len(rows) == 1, [r.status for r in rows]
    return rows[0]


def _event(db, system):
    rows = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "file.download",
            AuditEvent.target_system_id == system.id,
        )
        .all()
    )
    assert len(rows) == 1
    ev = rows[0]
    return ev.outcome, json.loads(ev.context_json)


TRANSPORTS = pytest.mark.parametrize("kind", ["ssh", "agent"])


# ------------------------------------------------------------ successes


@TRANSPORTS
def test_successful_download_is_complete_and_audited(http, db, hosts, env, kind):
    size = 300 * KIB + 17
    env.add("/data/report.bin", size=size)
    res = _get(http, hosts[kind], "/data/report.bin")
    assert res.status_code == 200
    assert res.headers["content-length"] == str(size)
    assert hashlib.sha256(res.content).hexdigest() == content_sha256(size)
    row = _audit(db, hosts[kind])
    assert (row.status, row.transport, row.size_bytes) == ("success", kind, size)
    assert row.sha256 == content_sha256(size)
    outcome, ctx = _event(db, hosts[kind])
    assert outcome == "success"
    assert (ctx["size_bytes"], ctx["transport"], ctx["error"]) == (size, kind, None)


@TRANSPORTS
def test_zero_byte_file_is_a_successful_empty_download(http, db, hosts, env, kind):
    env.add("/data/empty", size=0)
    res = _get(http, hosts[kind], "/data/empty")
    assert res.status_code == 200
    assert res.headers["content-length"] == "0"
    assert res.content == b""
    row = _audit(db, hosts[kind])
    assert (row.status, row.size_bytes, row.sha256) == ("success", 0, EMPTY_SHA)
    assert _event(db, hosts[kind])[0] == "success"


def test_pseudo_file_with_unreported_size_streams_to_eof(http, db, hosts, env):
    """A file whose stat size is 0 but which has content (procfs style) is
    still served in full, without a Content-Length that would truncate it."""
    env.add("/proc/pseudo", size=200 * KIB, reports_zero_size=True)
    res = _get(http, hosts["ssh"], "/proc/pseudo")
    assert res.status_code == 200
    assert "content-length" not in res.headers
    assert hashlib.sha256(res.content).hexdigest() == content_sha256(200 * KIB)
    assert _audit(db, hosts["ssh"]).status == "success"


# ------------------------------------------ failures before any header


@TRANSPORTS
@pytest.mark.parametrize(
    "spec,status,needle",
    [
        (None, 404, "not found"),
        (RemoteFile(stat_errno=errno.EACCES), 403, "permission denied"),
        (RemoteFile(size=10, open_errno=errno.EACCES), 403, "permission denied"),
        (RemoteFile(is_dir=True), 400, "not a regular file"),
    ],
    ids=["missing", "stat-denied", "open-denied", "directory"],
)
def test_file_problems_fail_before_headers(
    http, db, hosts, env, kind, spec, status, needle
):
    if spec is not None:
        env.add("/data/target", spec)
    res = _get(http, hosts[kind], "/data/target")
    assert res.status_code == status, res.text
    assert needle in res.json()["detail"]
    assert "content-disposition" not in res.headers
    row = _audit(db, hosts[kind])
    assert row.status == "error"
    assert needle in row.error_message
    assert row.sha256 is None
    outcome, ctx = _event(db, hosts[kind])
    assert outcome == "failure"
    assert needle in ctx["error"]


def test_ssh_connect_failure_is_a_gateway_error_with_redacted_detail(
    http, db, hosts, env
):
    env.connect_error = "ssh_connect_failed: dial failed password=hunter2"
    res = _get(http, hosts["ssh"], "/data/report.bin")
    assert res.status_code == 502
    assert "hunter2" not in res.text
    row = _audit(db, hosts["ssh"])
    assert row.status == "error"
    assert "hunter2" not in (row.error_message or "")
    assert _event(db, hosts["ssh"])[0] == "failure"


@pytest.mark.parametrize(
    "reason,status",
    [
        ("transport_unavailable", 503),
        ("agent_attach_timeout", 502),
        ("header_timeout", 502),
    ],
)
def test_agent_dispatch_failures_fail_before_headers(
    http, db, hosts, env, reason, status
):
    env.broker_refusal = reason
    res = _get(http, hosts["agent"], "/data/report.bin")
    assert res.status_code == status, res.text
    row = _audit(db, hosts["agent"])
    assert (row.status, row.transport) == ("error", "agent")
    assert _event(db, hosts["agent"])[0] == "failure"


def test_ssh_size_cap_is_rejected_before_headers(http, db, hosts, env, monkeypatch):
    monkeypatch.setattr(fts, "MAX_TRANSFER_BYTES", 100 * KIB)
    env.add("/data/huge", size=200 * KIB)
    res = _get(http, hosts["ssh"], "/data/huge")
    assert res.status_code == 413
    assert _audit(db, hosts["ssh"]).status == "error"


def test_agent_size_cap_is_rejected_before_headers(http, db, hosts, env, monkeypatch):
    monkeypatch.setattr(fts, "AGENT_TRANSFER_MAX_BYTES", 100 * KIB)
    env.add("/data/huge", size=200 * KIB)
    res = _get(http, hosts["agent"], "/data/huge")
    assert res.status_code == 413
    assert env.tracker.bytes_read == 0
    assert _audit(db, hosts["agent"]).status == "error"


def test_unauthorized_user_never_reaches_the_host(db, hosts, maintainer_user, client):
    """Fail closed: a user with no fleet grant is refused before any audit
    row, SFTP session or agent stream exists."""
    with patched_transfer_env(
        {hosts["ssh"].id: "ssh"}, session=db, gate=False
    ) as strict:
        strict.add("/data/report.bin", size=KIB)
        token = client.post(
            "/auth/login",
            data={"username": maintainer_user.username, "password": "testpass123"},
        ).json()["access_token"]
        res = client.get(
            f"/transfer/{hosts['ssh'].id}/download",
            params={"path": "/data/report.bin"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 403
        assert strict.tracker.sessions_opened == 0
    assert (
        db.query(FileTransferAudit)
        .filter(FileTransferAudit.system_id == hosts["ssh"].id)
        .count()
        == 0
    )


# ----------------------------------------------- failures after streaming


def test_ssh_failure_mid_stream_is_detectably_incomplete(http, db, hosts, env):
    """The original defect: a read error after headers were sent. The status
    cannot change, so the response must not look like a clean success: the
    declared Content-Length is never met and the audit records the failure."""
    size = 1024 * KIB
    env.add("/data/big.bin", size=size, fail_after=256 * KIB)
    res = _get(http, hosts["ssh"], "/data/big.bin")
    assert res.headers["content-length"] == str(size)
    assert len(res.content) < size
    row = _audit(db, hosts["ssh"])
    assert row.status == "error"
    assert row.sha256 is None
    assert row.size_bytes == len(res.content)
    outcome, ctx = _event(db, hosts["ssh"])
    assert outcome == "failure"
    assert ctx["error"]
    assert env.tracker.leaked == 0


def test_ssh_stream_ending_early_is_incomplete_not_success(http, db, hosts, env):
    size = 512 * KIB
    env.add("/data/shrunk.bin", size=size, available=128 * KIB)
    res = _get(http, hosts["ssh"], "/data/shrunk.bin")
    assert res.headers["content-length"] == str(size)
    assert len(res.content) < size
    row = _audit(db, hosts["ssh"])
    assert row.status == "error"
    assert "incomplete" in row.error_message
    assert _event(db, hosts["ssh"])[0] == "failure"
    assert env.tracker.leaked == 0


@pytest.mark.parametrize(
    "spec",
    [
        RemoteFile(size=1024 * KIB, fail_after=256 * KIB),
        RemoteFile(size=512 * KIB, available=128 * KIB),
    ],
    ids=["stream-error", "short-body"],
)
def test_agent_failure_during_transfer_is_a_clean_error_status(
    http, db, hosts, env, spec
):
    """The agent body is fully received before any header is sent, so a
    mid-transfer failure is an ordinary 502, never a 200."""
    env.add("/data/big.bin", spec)
    res = _get(http, hosts["agent"], "/data/big.bin")
    assert res.status_code == 502, res.status_code
    assert "content-disposition" not in res.headers
    row = _audit(db, hosts["agent"])
    assert (row.status, row.sha256) == ("error", None)
    assert _event(db, hosts["agent"])[0] == "failure"
    assert env.tracker.leaked == 0


# ------------------------------------------------- cancellation + memory


@TRANSPORTS
def test_abandoned_download_is_audited_as_failure_and_cleaned_up(
    db, hosts, env, admin_user, kind
):
    """A client that goes away mid-transfer must not leave a success row, an
    open SFTP session/broker stream, or an agent spool file behind."""
    env.add("/data/big.bin", size=4 * 1024 * KIB)
    stream = fts.download_stream(db, admin_user, hosts[kind].id, "/data/big.bin")
    first = next(iter(stream))
    assert len(first) > 0
    stream.close()
    row = _audit(db, hosts[kind])
    assert row.status == "error"
    assert row.error_message == "client_disconnected"
    assert row.sha256 is None
    outcome, ctx = _event(db, hosts[kind])
    assert (outcome, ctx["error"]) == ("failure", "client_disconnected")
    assert env.tracker.leaked == 0
    assert spool_files() == []


@TRANSPORTS
def test_large_download_keeps_memory_bounded(db, hosts, env, admin_user, kind):
    """A 96 MiB transfer is consumed one chunk at a time; the process never
    holds a meaningful fraction of the body."""
    import tracemalloc

    size = 96 * 1024 * KIB
    env.add("/data/large.bin", size=size)
    tracemalloc.start()
    try:
        stream = fts.download_stream(db, admin_user, hosts[kind].id, "/data/large.bin")
        total = 0
        for chunk in stream:
            total += len(chunk)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert total == size
    assert peak < 8 * 1024 * KIB, peak
    assert _audit(db, hosts[kind]).status == "success"
    assert env.tracker.leaked == 0


def test_ssh_stream_reads_only_as_fast_as_the_client_consumes(
    db, hosts, env, admin_user
):
    """Backpressure: the SFTP side is never read ahead of the consumer by more
    than one chunk, so a slow client cannot make the backend buffer the file."""
    env.add("/data/large.bin", size=64 * 1024 * KIB)
    stream = fts.download_stream(db, admin_user, hosts["ssh"].id, "/data/large.bin")
    consumed = 0
    for i, chunk in enumerate(stream):
        consumed += len(chunk)
        assert env.tracker.bytes_read - consumed <= fts.CHUNK
        if i == 50:
            break
    stream.close()
    assert _audit(db, hosts["ssh"]).error_message == "client_disconnected"


# ------------------------------------- audit finalization is unconditional


def test_agent_spool_allocation_failure_is_audited_and_sanitized(
    http, db, hosts, env, monkeypatch
):
    """The audit row exists from the moment the download starts, so a spool
    area that cannot be allocated must finalize it as a failure."""

    def _no_space(*_a, **_k):
        raise OSError(errno.ENOSPC, "No space left on device: /var/tmp/secret-path")

    monkeypatch.setattr(fts.tempfile, "mkstemp", _no_space)
    env.add("/data/report.bin", size=KIB)
    res = _get(http, hosts["agent"], "/data/report.bin")
    assert res.status_code == 502
    assert "secret-path" not in res.text
    row = _audit(db, hosts["agent"])
    assert (row.status, row.sha256) == ("error", None)
    assert "stage" in row.error_message
    assert _event(db, hosts["agent"])[0] == "failure"
    assert spool_files() == []


def test_agent_spool_write_failure_is_audited_and_cleaned_up(
    http, db, hosts, env, monkeypatch
):
    real_open = open

    class _FullDisk:
        def __init__(self, fh):
            self._fh = fh

        def write(self, _data):
            raise OSError(errno.ENOSPC, "No space left on device")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._fh.close()

    def _open(path, mode="r", *a, **k):
        fh = real_open(path, mode, *a, **k)
        return _FullDisk(fh) if mode == "wb" else fh

    monkeypatch.setattr(fts, "open", _open, raising=False)
    env.add("/data/report.bin", size=300 * KIB)
    res = _get(http, hosts["agent"], "/data/report.bin")
    assert res.status_code == 502
    assert "stage" in res.json()["detail"]
    row = _audit(db, hosts["agent"])
    assert (row.status, row.sha256) == ("error", None)
    assert spool_files() == []


@TRANSPORTS
@pytest.mark.parametrize("exc", [TimeoutError, EOFError], ids=lambda e: e.__name__)
def test_exception_with_empty_message_is_still_a_failure(
    http, db, hosts, env, kind, exc
):
    """TimeoutError() and EOFError() stringify to "", which must not be read as
    "no error" and finalized as a success."""
    assert str(exc()) == ""
    env.add("/data/big.bin", size=1024 * KIB, fail_after=256 * KIB, fail_exc=exc())
    _get(http, hosts[kind], "/data/big.bin")
    row = _audit(db, hosts[kind])
    assert row.status == "error"
    assert row.sha256 is None
    assert row.error_message == exc.__name__
    outcome, ctx = _event(db, hosts[kind])
    assert (outcome, ctx["error"]) == ("failure", exc.__name__)


def test_exception_with_empty_message_before_the_first_byte(http, db, hosts, env):
    env.add("/data/big.bin", size=1024 * KIB, fail_after=0, fail_exc=TimeoutError())
    res = _get(http, hosts["ssh"], "/data/big.bin")
    assert res.status_code == 502
    row = _audit(db, hosts["ssh"])
    assert (row.status, row.error_message) == ("error", "TimeoutError")


# ------------------------- other file operations keep their status contract


@pytest.mark.parametrize(
    "message,expected",
    [
        ("ssh_host_key_error: key changed", 400),
        ("sftp_open_failed: subsystem refused", 400),
        ("host_cooling_down: retry in 30s", 400),
        ("file too large: 10 > 5", 400),
        ("transfer exceeded max size", 400),
        ("download failed: x", 400),
        ("ssh_connect_failed: no route", 502),
        ("ssh_auth_failed: rejected", 502),
        ("forbidden: nope", 403),
        ("action_not_allowed: nope", 403),
        ("system 9 not found", 404),
    ],
)
def test_shared_status_mapping_is_unchanged_for_other_operations(
    authed_client, hosts, monkeypatch, message, expected
):
    def _raise(*_a, **_k):
        raise fts.FileTransferError(message)

    monkeypatch.setattr(fts, "stat", _raise)
    res = authed_client.get(
        f"/transfer/{hosts['ssh'].id}/stat", params={"path": "/etc/hosts"}
    )
    assert res.status_code == expected
    assert res.json()["detail"] == message


def test_other_operations_do_not_redact_or_remap_details(
    authed_client, hosts, monkeypatch
):
    def _raise(*_a, **_k):
        raise fts.FileTransferError("stat failed: token=abc123")

    monkeypatch.setattr(fts, "stat", _raise)
    res = authed_client.get(
        f"/transfer/{hosts['ssh'].id}/stat", params={"path": "/etc/hosts"}
    )
    assert (res.status_code, res.json()["detail"]) == (400, "stat failed: token=abc123")


@pytest.mark.parametrize(
    "message,expected",
    [
        ("ssh_host_key_error: key changed", 502),
        ("sftp_open_failed: subsystem refused", 502),
        ("host_cooling_down: retry in 30s", 503),
        ("file too large: 10 > 5", 413),
        ("transfer exceeded max size", 413),
    ],
)
def test_download_extends_the_mapping(
    authed_client, hosts, monkeypatch, message, expected
):
    def _raise(*_a, **_k):
        raise fts.FileTransferError(message)

    monkeypatch.setattr(fts, "download_stream", _raise)
    res = authed_client.get(
        f"/transfer/{hosts['ssh'].id}/download", params={"path": "/etc/hosts"}
    )
    assert res.status_code == expected
