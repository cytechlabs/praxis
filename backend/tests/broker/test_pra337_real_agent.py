"""PRA-337: revocation against the REAL agent binary.

Runs the unmodified Go agent (``PRAXIS_REAL_AGENT_BIN``) as a subprocess over
real mTLS WSS against the real broker handlers and internal API. Only the
committed identity state is simulated (``Authority`` instead of PostgreSQL).
This proves what the agent actually does with a process on revoke: it is not a
full-stack run (no database, secrets service, API or UI).

Skipped unless PRAXIS_REAL_AGENT_BIN points at a built ``praxis-agent``.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import websockets

from app.broker.handlers import (
    REJECT_NOT_ACTIVE,
    BrokerRejection,
    op_handler,
    tunnel_handler,
)
from app.broker.internal_api import build_internal_app
from app.broker.ops import OperationManager
from app.broker.registry import AgentRegistry
from app.broker.tls import build_server_ssl_context

from . import _certfx as cfx

AGENT_BIN = os.environ.get("PRAXIS_REAL_AGENT_BIN", "")
# An agent built from the tree before the start gate existed; optional.
LEGACY_AGENT_BIN = os.environ.get("PRAXIS_LEGACY_AGENT_BIN", "")

pytestmark = [
    pytest.mark.skipif(
        not AGENT_BIN or not os.access(AGENT_BIN, os.X_OK),
        reason="PRAXIS_REAL_AGENT_BIN not set to an executable agent binary",
    ),
    pytest.mark.skipif(sys.platform != "linux", reason="agent exec is linux-only"),
]


class Authority:
    def __init__(self):
        self.status = {}
        self.calls = 0
        self.deny_from_call = None

    def validator(self, identity):
        self.calls += 1
        if self.deny_from_call is not None and self.calls >= self.deny_from_call:
            raise BrokerRejection(REJECT_NOT_ACTIVE, "agent_status=disabled")
        status = self.status.get(identity.system_id, "active")
        if status != "active":
            raise BrokerRejection(REJECT_NOT_ACTIVE, f"agent_status={status}")
        return {"system_id": identity.system_id, "hostname": "h"}


class Audit:
    def __init__(self):
        self.events = []

    def __call__(self, **kw):
        self.events.append(kw)

    def count(self, action, **ctx):
        return sum(
            1
            for e in self.events
            if e["action"] == action
            and all(e["context"].get(k) == v for k, v in ctx.items())
        )


class Lab:
    """Real broker handlers + internal API + real agent subprocesses."""

    def __init__(self, port, revalidate=999.0):
        self.port = port
        self.revalidate = revalidate
        self.registry = AgentRegistry()
        self.authority = Authority()
        self.audit = Audit()
        self.manager = OperationManager(
            self.registry, audit_emit=self.audit, evict_ack_timeout_seconds=5.0
        )
        self.agents = {}
        self.tmp = Path(tempfile.mkdtemp(prefix="praxis-337-"))
        self.ca_key, self.ca_cert = cfx.mk_ca()
        self.app = build_internal_app(self.registry, self.manager)

    async def start(self):
        key, cert = cfx.mk_server_cert(self.ca_key, self.ca_cert)
        kp, cp = cfx.write_pair(key, cert)
        ca_path = cfx.write_ca(self.ca_cert)
        self.ca_path = ca_path

        async def dispatch(ws):
            if ws.path == "/agent/tunnel":
                await tunnel_handler(
                    ws,
                    identity_validator=self.authority.validator,
                    registry=self.registry,
                    manager=self.manager,
                    audit_emit=self.audit,
                    heartbeat_interval_seconds=10.0,
                    heartbeat_dead_seconds=30.0,
                    revalidate_interval_seconds=self.revalidate,
                )
            elif ws.path == "/agent/op":
                await op_handler(
                    ws,
                    identity_validator=self.authority.validator,
                    registry=self.registry,
                    manager=self.manager,
                    audit_emit=self.audit,
                )

        ssl_ctx = build_server_ssl_context(
            server_certfile=cp, server_keyfile=kp, client_ca_certfile=ca_path
        )
        self.server = await websockets.serve(
            dispatch,
            host="127.0.0.1",
            port=self.port,
            ssl=ssl_ctx,
            ping_interval=None,
            max_size=1 << 21,
        )
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://broker",
            timeout=30.0,
        )

    def start_agent(self, system_id, binary=None):
        cdir = self.tmp / f"agent-{system_id}"
        cdir.mkdir()
        key, cert = cfx.mk_client_cert(self.ca_key, self.ca_cert, system_id=system_id)
        kp, cp = cfx.write_pair(key, cert)
        shutil.copy(kp, cdir / "agent.key")
        shutil.copy(cp, cdir / "agent.crt")
        shutil.copy(self.ca_path, cdir / "broker-ca.crt")
        (cdir / "config.json").write_text(
            json.dumps(
                {
                    "backend_url": "http://unused",
                    "broker_url": f"wss://localhost:{self.port}",
                    "system_id": system_id,
                }
            )
        )
        os.chmod(cdir / "agent.key", 0o600)
        log = open(self.tmp / f"agent-{system_id}.log", "wb")
        proc = subprocess.Popen(  # noqa: S603
            [binary or AGENT_BIN, "connect", "--config-dir", str(cdir)],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        self.agents[system_id] = proc
        return proc

    async def wait_connected(self, system_id, timeout=15.0):
        return await wait_for(lambda: self.registry.get(system_id) is not None, timeout)

    async def exec(self, system_id, cmd, *args, timeout_s=0):
        body = {"system_id": system_id, "cmd": cmd, "args": list(args)}
        if timeout_s:
            body["timeout_s"] = timeout_s
        return await self.http.post("/internal/agent/ops/exec", json=body)

    async def evict(self, system_id, reason):
        return await self.http.post(
            f"/internal/agent/sessions/{system_id}/evict", json={"reason": reason}
        )

    async def stop(self):
        for proc in self.agents.values():
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        await self.http.aclose()
        self.server.close()
        await self.server.wait_closed()
        shutil.rmtree(self.tmp, ignore_errors=True)


async def wait_for(pred, timeout=5.0, step=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        await asyncio.sleep(step)
    return pred()


def _alive(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            state = f.read().rsplit(b")", 1)[1].split()[0]
    except OSError:
        return False
    return state not in (b"Z", b"X")


@pytest_asyncio.fixture
async def lab(unused_tcp_port):
    lab = Lab(unused_tcp_port)
    await lab.start()
    try:
        yield lab
    finally:
        await lab.stop()


@pytest.mark.asyncio
async def test_revoked_agent_refuses_new_work_and_unaffected_agent_runs(lab, tmp_path):
    lab.start_agent(42)
    lab.start_agent(43)
    assert await lab.wait_connected(42) and await lab.wait_connected(43)

    ok = await lab.exec(42, "echo", "active-control")
    assert ok.status_code == 200 and ok.json()["outcome"] == "success"

    lab.authority.status[42] = "revoked"  # committed; no signal sent yet
    marker = tmp_path / "must-not-exist"
    refused = await lab.exec(42, "touch", str(marker))
    assert refused.status_code == 403
    assert refused.json()["error"]["reason"] == "agent_not_active"
    await asyncio.sleep(0.5)
    assert not marker.exists()  # no process ever ran

    # The signal then tears the live tunnel down; the agent is refused on redial.
    res = await lab.evict(42, "revoked")
    assert res.json()["result"] == "evicted"
    assert await wait_for(lambda: lab.audit.count("agent.tunnel.rejected") >= 1, 20)
    assert lab.registry.get(42) is None

    # Unaffected agent still works.
    still = await lab.exec(43, "echo", "still-fine")
    assert still.json()["outcome"] == "success"


@pytest.mark.asyncio
async def test_in_flight_process_group_is_killed_and_verified(lab, tmp_path):
    lab.start_agent(42)
    assert await lab.wait_connected(42)
    pidfile = tmp_path / "grandchild.pid"
    parent_pid = tmp_path / "parent.pid"
    script = f"echo $$ > {parent_pid}; sleep 120 & echo $! > {pidfile}; sleep 120"

    inflight = asyncio.create_task(lab.exec(42, "sh", "-c", script))
    assert await wait_for(lambda: pidfile.exists() and pidfile.read_text().strip(), 10)
    child = int(pidfile.read_text())
    parent = int(parent_pid.read_text())
    assert _alive(child) and _alive(parent)

    lab.authority.status[42] = "revoked"
    started = time.monotonic()
    res = await lab.evict(42, "revoked")
    assert res.json()["result"] == "evicted"
    assert res.json()["ops"] == {"confirmed": 1}

    done = await asyncio.wait_for(inflight, timeout=15)
    assert time.monotonic() - started < 10
    body = done.json()
    assert body["outcome"] == "cancelled"
    assert body["error"]["reason"] == "agent_revoked"
    assert body["error"]["termination"] == "confirmed"
    # Independent of the agent's own claim: both processes are really gone.
    assert not _alive(child) and not _alive(parent)


@pytest.mark.asyncio
async def test_missed_signal_converges_without_backend(unused_tcp_port, tmp_path):
    lab = Lab(unused_tcp_port, revalidate=0.3)
    await lab.start()
    try:
        lab.start_agent(42)
        assert await lab.wait_connected(42)
        pidfile = tmp_path / "pid"
        inflight = asyncio.create_task(
            lab.exec(42, "sh", "-c", f"echo $$ > {pidfile}; sleep 120")
        )
        assert await wait_for(
            lambda: pidfile.exists() and pidfile.read_text().strip(), 10
        )
        pid = int(pidfile.read_text())

        lab.authority.status[42] = "disabled"  # no evict call is ever made
        t0 = time.monotonic()
        assert await wait_for(lambda: lab.registry.get(42) is None, 10)
        done = await asyncio.wait_for(inflight, timeout=15)
        assert time.monotonic() - t0 < 6
        assert done.json()["error"]["termination"] == "confirmed"
        assert not _alive(pid)
    finally:
        await lab.stop()


@pytest.mark.asyncio
async def test_reenable_lets_the_same_agent_reconnect(lab):
    lab.start_agent(42)
    assert await lab.wait_connected(42)
    lab.authority.status[42] = "disabled"
    assert (await lab.evict(42, "disabled")).json()["result"] == "evicted"
    assert await wait_for(lambda: lab.audit.count("agent.tunnel.rejected") >= 1, 20)

    lab.authority.status[42] = "active"  # operator re-enables; no re-enrolment
    assert await lab.wait_connected(42, timeout=45)
    again = await lab.exec(42, "echo", "back")
    assert again.json()["outcome"] == "success"


@pytest.mark.asyncio
async def test_start_gate_stops_a_dispatched_op_before_any_process(lab, tmp_path):
    lab.start_agent(42)
    assert await lab.wait_connected(42)
    marker = tmp_path / "must-not-exist"
    # Calls: dispatch authorize (+1), per-op handshake (+2), start gate (+3).
    lab.authority.deny_from_call = lab.authority.calls + 3
    res = await lab.exec(42, "touch", str(marker))
    body = res.json()
    assert body["outcome"] == "error"
    assert body["error"]["reason"] == "agent_revoked"
    assert body["error"]["termination"] == "not_started"
    await asyncio.sleep(0.5)
    assert not marker.exists()


legacy_only = pytest.mark.skipif(
    not LEGACY_AGENT_BIN or not os.access(LEGACY_AGENT_BIN, os.X_OK),
    reason="PRAXIS_LEGACY_AGENT_BIN not set to an executable pre-gate agent",
)


@legacy_only
@pytest.mark.asyncio
async def test_legacy_agent_still_works_against_the_new_broker(lab):
    lab.start_agent(42, binary=LEGACY_AGENT_BIN)
    assert await lab.wait_connected(42)
    res = await lab.exec(42, "echo", "legacy-ok")
    assert res.status_code == 200 and res.json()["outcome"] == "success"


@legacy_only
@pytest.mark.asyncio
async def test_legacy_agent_has_no_start_gate_and_reports_unconfirmed(lab, tmp_path):
    """Documents the weaker guarantee for agents without ``await_ready``.

    Authority is checked at dispatch and at the per-op handshake, but there is
    no later point to hold the process back: a revoke that lands after the
    handshake does not stop the process from starting. Eviction then cancels
    it; the legacy agent gives no termination evidence, so the outcome is
    reported unconfirmed even though the process did stop here."""
    lab.start_agent(42, binary=LEGACY_AGENT_BIN)
    assert await lab.wait_connected(42)
    pidfile = tmp_path / "pid"
    # Calls: dispatch authorize (+1), per-op handshake (+2); nothing after.
    inflight = asyncio.create_task(
        lab.exec(42, "sh", "-c", f"echo $$ > {pidfile}; sleep 120")
    )
    assert await wait_for(lambda: pidfile.exists() and pidfile.read_text().strip(), 10)
    pid = int(pidfile.read_text())

    lab.authority.status[42] = "revoked"
    res = await lab.evict(42, "revoked")
    assert res.json()["ops"] == {"unconfirmed": 1}
    body = (await asyncio.wait_for(inflight, timeout=15)).json()
    assert body["error"]["reason"] == "agent_revoked_unconfirmed"
    assert body["error"]["termination"] == "unconfirmed"
    assert await wait_for(lambda: not _alive(pid), 5)  # it did stop; just unproven


@legacy_only
@pytest.mark.asyncio
async def test_legacy_agent_refused_after_revoke_commit(lab, tmp_path):
    lab.start_agent(42, binary=LEGACY_AGENT_BIN)
    assert await lab.wait_connected(42)
    lab.authority.status[42] = "revoked"
    marker = tmp_path / "must-not-exist"
    refused = await lab.exec(42, "touch", str(marker))
    assert refused.status_code == 403
    await asyncio.sleep(0.5)
    assert not marker.exists()
