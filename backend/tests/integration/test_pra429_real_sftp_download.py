"""PRA-429: SSH download read-ahead and cleanup against a real SFTP server.

The in-memory fixtures cannot show what paramiko's read-ahead does, so this
module drives the real ``_download_via_ssh`` through a real paramiko SFTP
session to a real OpenSSH ``sftp-server``. It self-skips unless
``PRAXIS_REAL_SFTP`` names a disposable server:

    PRAXIS_REAL_SFTP=host:port:user:/path/to/private_key:/server/fixture/dir

The fixture directory must hold ``big.bin`` (a sparse 1 GiB file),
``small.bin``, ``empty.bin`` and ``denied.bin`` (mode 000). The test must run
as the same unix user that the server logs in, so it can read the server
process's I/O counters from /proc.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import paramiko
import pytest

from app.services import file_transfer_service as fts

_SPEC = os.getenv("PRAXIS_REAL_SFTP")
pytestmark = pytest.mark.skipif(not _SPEC, reason="PRAXIS_REAL_SFTP not set")

MIB = 1024 * 1024


def _server():
    host, port, user, key, root = _SPEC.split(":", 4)
    return host, int(port), user, key, root


def _sftp_server_pids():
    uid = os.getuid()
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as fh:
                cmd = fh.read()
            if b"sftp-server" in cmd and os.stat(f"/proc/{name}").st_uid == uid:
                pids.append(int(name))
        except OSError:
            continue
    return pids


def _received_bytes(sftp) -> int:
    """Bytes the SSH transport has taken off the socket so far."""
    packetizer = sftp.get_channel().get_transport().packetizer
    return packetizer._Packetizer__received_bytes  # pylint: disable=protected-access


def _read_ahead(sftp):
    """(outstanding read requests, bytes buffered by paramiko for the file)."""
    # pylint: disable=protected-access
    pending = dict(sftp._expecting)
    buffered = 0
    for fobj in set(pending.values()):
        buffered += sum(len(v) for v in list(fobj._prefetch_data.values()))
    return len(pending), buffered


def _rss_bytes() -> int:
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    return 0


@pytest.fixture
def real_sftp():
    host, port, user, key, root = _server()
    opened = []

    @contextmanager
    def _open(_db, _user, _system, _login):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            port=port,
            username=user,
            key_filename=key,
            allow_agent=False,
            look_for_keys=False,
            timeout=10,
        )
        sftp = client.open_sftp()
        opened.append(sftp)
        try:
            yield sftp
        finally:
            sftp.close()
            client.close()

    finals = []
    with (
        patch.object(fts, "_open_sftp", _open),
        patch.object(
            fts,
            "_finalize_download_audit",
            lambda audit_id, **kw: finals.append(kw),
        ),
    ):
        yield SimpleNamespace(root=root, finals=finals, opened=opened)


def _download(env, name):
    system = SimpleNamespace(id=1)
    return fts._download_via_ssh(None, None, system, "ops", f"{env.root}/{name}", 1)


def _wait_for(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def test_complete_download_through_real_sftp(real_sftp):
    stream = _download(real_sftp, "small.bin")
    body = b"".join(stream)
    assert stream.size == len(body) == 1234
    with open(f"{real_sftp.root}/small.bin", "rb") as fh:
        assert hashlib.sha256(body).digest() == hashlib.sha256(fh.read()).digest()
    assert real_sftp.finals[-1]["failed"] is False


def test_empty_file_through_real_sftp(real_sftp):
    stream = _download(real_sftp, "empty.bin")
    assert (stream.size, b"".join(stream)) == (0, b"")
    assert real_sftp.finals[-1]["failed"] is False


def test_missing_and_denied_files_fail_before_streaming(real_sftp):
    with pytest.raises(fts.FileTransferError, match="not found"):
        _download(real_sftp, "no-such-file.bin")
    if os.getuid() != 0:
        with pytest.raises(fts.FileTransferError, match="forbidden"):
            _download(real_sftp, "denied.bin")
    assert all(f["failed"] and f["error"] for f in real_sftp.finals)


def test_slow_reader_does_not_pull_the_file_ahead(real_sftp):
    """A client that reads 1 MiB and then stalls must not make the backend
    request, or the host send, the rest of a 1 GiB file."""
    threads_before = threading.active_count()
    rss_before = _rss_bytes()
    stream = _download(real_sftp, "big.bin")
    assert stream.size == 1024 * MIB
    sftp = real_sftp.opened[-1]
    received_before = _received_bytes(sftp)
    consumed = 0
    for chunk in stream:
        consumed += len(chunk)
        if consumed >= MIB:
            break
    time.sleep(4)  # the stalled client; any read-ahead would run during this
    received = _received_bytes(sftp) - received_before
    outstanding, buffered = _read_ahead(sftp)
    rss_growth = _rss_bytes() - rss_before
    print(
        f"received={received / MIB:.1f}MiB outstanding_requests={outstanding} "
        f"buffered={buffered / MIB:.1f}MiB rss_growth={rss_growth / MIB:.1f}MiB"
    )
    assert received <= consumed + 6 * MIB, received
    assert outstanding * 32 * 1024 <= 4 * MIB, outstanding
    assert buffered <= 4 * MIB, buffered
    assert rss_growth < 32 * MIB, rss_growth

    # Disconnect: everything is released and the audit says why.
    stream.close()
    assert real_sftp.finals[-1]["error"] == "client_disconnected"
    assert _wait_for(lambda: not _sftp_server_pids()), "sftp-server still running"
    assert _wait_for(
        lambda: threading.active_count() <= threads_before
    ), threading.enumerate()


def test_streaming_a_large_range_stays_bounded_and_complete(real_sftp):
    """Read 64 MiB of the sparse file at full speed: counts match, memory flat."""
    stream = _download(real_sftp, "big.bin")
    rss_before = _rss_bytes()
    total = 0
    for chunk in stream:
        total += len(chunk)
        if total >= 64 * MIB:
            break
    stream.close()
    assert total >= 64 * MIB
    assert _rss_bytes() - rss_before < 48 * MIB
