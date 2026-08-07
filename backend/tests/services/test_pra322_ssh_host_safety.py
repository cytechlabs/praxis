"""PRA-322: bounded SSH command execution + per-host single-flight + reachability.

Covers the acceptance surface:
- large-output SSH execution drains without deadlock and is byte-bounded;
- a command that never exits hits the wall-clock timeout and the channel is closed;
- expensive package work is single-flight per host (concurrent op -> already_running);
- reachability: a successful CONNECT marks the host reachable even if the command
  fails/times out; an AUTH failure stays distinct from offline (not Unreachable);
  a TRANSPORT failure counts toward Unreachable.
"""

from __future__ import annotations

import os
import threading

import pytest

from app.db.models import Credential, Group, System, SystemMetadata
from app.services import package_service as pkgmod
from app.services.package_service import PackageService
from app.services.ssh_service import SSHCommandTimeout, SSHConnectionError, SSHService

# --------------------------------------------------------------------- fixtures


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="pra322-grp").first()
    if not g:
        g = Group(name="pra322-grp", description="x")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def cred(db):
    c = db.query(Credential).first()
    if c is None:
        c = Credential(name="pra322-cred", auth_method="ssh_key", username="root")
        db.add(c)
        db.flush()
    return c


def _system(db, seed_distro, group, cred, hostname, *, status="Active"):
    s = System(
        hostname=hostname,
        ip_address="10.132.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status=status,
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    md = SystemMetadata(system_id=s.id)
    db.add(md)
    s.system_metadata = md
    db.flush()
    return s


# ----------------------------------------------------------- fake SSH channel


class _FakeChannel:
    """Enough of a paramiko Channel to drive ``_run_bounded_command``. Backed by a
    real pipe fd so ``select.select`` works; the pipe is kept readable so select
    returns promptly and the loop drives itself off recv_ready / exit_status."""

    def __init__(self, out_chunks, err_chunks=(), exit_code=0, *, never_exit=False):
        self._out = list(out_chunks)
        self._err = list(err_chunks)
        self._exit = exit_code
        self._never_exit = never_exit
        self.closed = False
        self.exec_cmd = None
        self._r, self._w = os.pipe()
        os.write(self._w, b"x")  # always readable

    def settimeout(self, _t):  # noqa: D401
        pass

    def exec_command(self, cmd):
        self.exec_cmd = cmd

    def sendall(self, _data):
        pass

    def shutdown_write(self):
        pass

    def fileno(self):
        return self._r

    def recv_ready(self):
        return bool(self._out)

    def recv(self, _n):
        return self._out.pop(0) if self._out else b""

    def recv_stderr_ready(self):
        return bool(self._err)

    def recv_stderr(self, _n):
        return self._err.pop(0) if self._err else b""

    def exit_status_ready(self):
        if self._never_exit:
            return False
        return not self._out and not self._err

    def recv_exit_status(self):
        return self._exit

    def close(self):
        self.closed = True
        for fd in (self._r, self._w):
            try:
                os.close(fd)
            except OSError:
                pass


class _FakeTransport:
    def __init__(self, chan):
        self._chan = chan

    def is_active(self):
        return True

    def open_session(self):
        return self._chan


class _FakeClient:
    def __init__(self, chan):
        self._t = _FakeTransport(chan)

    def get_transport(self):
        return self._t


def _svc(db):
    return SSHService(db)


# ------------------------------------------------------- bounded execution


def test_large_output_is_drained_and_byte_bounded(db):
    svc = _svc(db)
    # ~19 MiB of output in 64 KiB chunks, capped at 1 KiB.
    chunks = [b"a" * 65536 for _ in range(300)]
    chan = _FakeChannel(chunks, exit_code=0)
    exit_code, out, err, truncated = svc._run_bounded_command(
        _FakeClient(chan), "big", wall_timeout=10, max_bytes=1024
    )
    assert exit_code == 0
    assert truncated is True
    assert len(out) == 1024  # captured stream is bounded
    assert err == ""
    assert chan.closed is True  # channel cleaned up


def test_command_timeout_closes_channel(db):
    svc = _svc(db)
    chan = _FakeChannel([], exit_code=0, never_exit=True)
    with pytest.raises(SSHCommandTimeout):
        svc._run_bounded_command(_FakeClient(chan), "hang", wall_timeout=0.3)
    assert chan.closed is True


def test_nonzero_exit_is_captured(db):
    svc = _svc(db)
    chan = _FakeChannel([b"partial\n"], err_chunks=[b"boom\n"], exit_code=2)
    exit_code, out, err, truncated = svc._run_bounded_command(
        _FakeClient(chan), "fail", wall_timeout=5
    )
    assert exit_code == 2
    assert out == "partial\n"
    assert err == "boom\n"
    assert truncated is False


# ----------------------------------------------------- reachability semantics


def test_connect_success_then_command_failure_stays_reachable(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra322-cmdfail")
    system.system_metadata.consecutive_failures = 1
    db.flush()
    svc = _svc(db)
    chan = _FakeChannel([b""], err_chunks=[b"nope\n"], exit_code=1)
    monkeypatch.setattr(
        svc, "get_connection", lambda sid, **kw: (_FakeClient(chan), True)
    )

    res = svc.execute_command(system.id, "do-thing")
    assert res["status"] == "warning"  # command failed (nonzero)
    assert res["outcome"] == "command_failed"
    # Reachable: connect succeeded -> Active, failure counter cleared.
    assert system.status == "Active"
    assert system.system_metadata.consecutive_failures == 0


def test_command_timeout_does_not_mark_unreachable(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra322-timeout")
    svc = _svc(db)
    chan = _FakeChannel([], never_exit=True)
    monkeypatch.setattr(
        svc, "get_connection", lambda sid, **kw: (_FakeClient(chan), True)
    )
    closed = {"n": 0}
    monkeypatch.setattr(
        svc, "close_connection", lambda sid: closed.__setitem__("n", closed["n"] + 1)
    )

    res = svc.execute_command(system.id, "slow", timeout=1)
    assert res["status"] == "failed"
    assert res["outcome"] == "command_timeout"
    assert res["timed_out"] is True
    assert system.status != "Unreachable"  # reachable — command just timed out
    assert closed["n"] == 1  # wedged pooled client dropped


def test_auth_failure_is_reachable_not_unreachable(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra322-auth", status="Unreachable")
    system.system_metadata.consecutive_failures = 5
    db.flush()
    svc = _svc(db)

    def _raise_auth(sid, **kw):
        raise SSHConnectionError(f"Authentication failed for {system.hostname}")

    monkeypatch.setattr(svc, "get_connection", _raise_auth)

    res = svc.execute_command(system.id, "x")
    assert res["status"] == "failed"
    assert res["outcome"] == "auth_failure"
    # Reachable -> stale Unreachable cleared, no escalation.
    assert system.status != "Unreachable"
    assert system.system_metadata.consecutive_failures == 0
    assert system.system_metadata.connection_status == "auth_failed"


def test_transport_failure_counts_toward_unreachable(
    db, seed_distro, group, cred, monkeypatch
):
    system = _system(db, seed_distro, group, cred, "pra322-transport")
    system.system_metadata.consecutive_failures = 0
    db.flush()
    svc = _svc(db)
    # unreachable_threshold default is 2.
    svc._unreachable_threshold = 2

    def _raise_transport(sid, **kw):
        raise SSHConnectionError(f"Socket error for {system.hostname}: timed out")

    monkeypatch.setattr(svc, "get_connection", _raise_transport)

    r1 = svc.execute_command(system.id, "x")
    assert r1["outcome"] == "transport_failure"
    assert system.system_metadata.consecutive_failures == 1
    assert system.status != "Unreachable"
    r2 = svc.execute_command(system.id, "x")
    assert r2["outcome"] == "transport_failure"
    assert system.system_metadata.consecutive_failures == 2
    assert system.status == "Unreachable"  # escalates after threshold


# ------------------------------------------------------------- single-flight


def test_scan_is_single_flight_per_host(db, seed_distro, group, cred):
    system = _system(db, seed_distro, group, cred, "pra322-sf")
    svc = PackageService(db)

    # A different thread holds the host work lock (simulating an in-flight scan).
    lock = pkgmod._host_worklock(system.id)
    acquired = threading.Event()
    release = threading.Event()

    def _holder():
        lock.acquire()
        acquired.set()
        release.wait(5)
        lock.release()

    t = threading.Thread(target=_holder)
    t.start()
    try:
        assert acquired.wait(5)
        # Main thread requests a scan while one is "running" -> rejected fast.
        res = svc.scan_packages(system.id)
        assert res["status"] == "already_running"
        assert "already running" in res["message"]
    finally:
        release.set()
        t.join(5)


def test_single_flight_runs_when_free(db, seed_distro, group, cred, monkeypatch):
    system = _system(db, seed_distro, group, cred, "pra322-sf-free")
    svc = PackageService(db)
    monkeypatch.setattr(
        svc, "_scan_packages_impl", lambda sid: {"status": "success", "system_id": sid}
    )
    res = svc.scan_packages(system.id)
    assert res["status"] == "success"
    # Lock is released afterwards, so a subsequent scan runs again.
    res2 = svc.scan_packages(system.id)
    assert res2["status"] == "success"
