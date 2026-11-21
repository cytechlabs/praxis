"""PRA-429: file downloads through the real Go agent and the real broker.

Runs the unmodified agent binary (``PRAXIS_REAL_AGENT_BIN``) over real mTLS WSS
against the real broker handlers and internal API (shared-secret auth on), and
drives the real download route, service, ``BrokerClient`` and ``AgentTransport``
on top. Only the identity authority is simulated and the PostgreSQL test
session carries the audit rows; the files are real files on this host that the
agent reads off disk.

Skipped unless PRAXIS_REAL_AGENT_BIN points at a built ``praxis-agent``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import socket
import threading
import time

import pytest
import pytest_asyncio
import uvicorn
from fastapi.testclient import TestClient

from app.api.main import app
from app.broker.internal_api import build_internal_app
from app.broker.internal_auth import INTERNAL_AUTH_HEADER, derive_internal_token
from app.db.access_models import AuditEvent, FileTransferAudit
from app.db.models import Credential, Group, System
from app.services import file_transfer_service as fts
from app.services.broker_client import BrokerClient
from tests.helpers.file_transfer_fakes import patched_transfer_env, spool_files

from .test_pra337_real_agent import AGENT_BIN, Lab, wait_for

pytestmark = pytest.mark.skipif(
    not AGENT_BIN or not os.access(AGENT_BIN, os.X_OK),
    reason="PRAXIS_REAL_AGENT_BIN not set to an executable agent binary",
)

MIB = 1024 * 1024


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def agent_host(db, seed_distro):
    group = db.query(Group).filter_by(name="Default").first()
    if group is None:
        group = Group(name="Default")
        db.add(group)
        db.flush()
    cred = db.query(Credential).first()
    if cred is None:
        cred = Credential(
            name="pra429-real-agent",
            auth_method="password",
            username="root",
            vault_path="v/pra429-real-agent",
        )
        db.add(cred)
        db.flush()
    system = System(
        hostname="pra429-real-agent",
        ip_address="10.4.29.9",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
        transport_preference="agent",
    )
    db.add(system)
    db.flush()
    return system


@pytest_asyncio.fixture
async def stack(unused_tcp_port, agent_host, db, authed_client):
    """Real agent + broker + internal API, and the real route wired to them."""
    lab = Lab(unused_tcp_port)
    lab.app = build_internal_app(
        lab.registry, lab.manager, auth_token=derive_internal_token()
    )
    await lab.start()
    api_port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            lab.app,
            host="127.0.0.1",
            port=api_port,
            log_level="warning",
            lifespan="off",
            timeout_graceful_shutdown=3,
        )
    )
    serving = asyncio.create_task(server.serve())
    assert await wait_for(lambda: server.started, 10)
    lab.start_agent(agent_host.id)
    assert await lab.wait_connected(agent_host.id)

    http = TestClient(app, client=("127.0.0.1", 50000), raise_server_exceptions=False)
    http.headers.update(authed_client.headers)
    url = f"http://127.0.0.1:{api_port}"
    with patched_transfer_env({agent_host.id: "agent"}, session=db) as env:
        # Keep the gate, routing and audit session; use the REAL broker client.
        real = fts.BrokerClient
        fts.BrokerClient = lambda: BrokerClient(base_url=url)
        try:
            yield type("Stack", (), {"lab": lab, "http": http, "env": env})
        finally:
            fts.BrokerClient = real
    server.should_exit = True
    await serving
    # A bounded stop that FAILS on timeout: a socket or task that outlives its
    # download must not be waited out silently.
    await asyncio.wait_for(lab.stop(), 30)


def _bridge_tasks():
    """Names of per-op bridge tasks still alive on the broker's loop."""
    return sorted(
        t.get_name()
        for t in asyncio.all_tasks()
        if t.get_name().startswith(("op_in:", "op_out:")) and not t.done()
    )


async def _assert_rejected_download_released(stack, host, tmp_path):
    """A download that was refused or failed after the agent started sending
    leaves nothing behind on the broker, the shared control tunnel is intact,
    and the next ordinary download works."""
    lab = stack.lab
    ops = list(lab.manager._ops.values())  # pylint: disable=protected-access
    assert ops, "the rejected download never reached the broker"
    assert await wait_for(lambda: all(o.completion.done() for o in ops), 15), "op"
    assert await wait_for(lambda: not _bridge_tasks(), 15), _bridge_tasks()
    # Only the control tunnel's socket remains; the per-op socket is closed.
    assert await wait_for(lambda: len(lab.server.websockets) == 1, 15), len(
        lab.server.websockets
    )
    assert lab.registry.get(host.id) is not None
    health = await lab.http.get(
        f"/internal/agent/health/{host.id}",
        headers={INTERNAL_AUTH_HEADER: derive_internal_token()},
    )
    assert health.status_code == 200

    follow_up = tmp_path / "after.bin"
    body = os.urandom(300 * 1024)
    follow_up.write_bytes(body)
    res = await _get(stack, host, str(follow_up))
    assert res.status_code == 200, res.text[:200]
    assert res.content == body
    assert await wait_for(lambda: not _bridge_tasks(), 15), _bridge_tasks()


async def _get(stack, host, path):
    return await asyncio.to_thread(
        stack.http.get, f"/transfer/{host.id}/download", params={"path": path}
    )


def _audit(db, host):
    rows = db.query(FileTransferAudit).filter(FileTransferAudit.system_id == host.id)
    rows = rows.all()
    assert len(rows) == 1, [r.status for r in rows]
    return rows[0]


def _event(db, host):
    ev = (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "file.download")
        .filter(AuditEvent.target_system_id == host.id)
        .one()
    )
    return ev.outcome, json.loads(ev.context_json)


@pytest.mark.asyncio
async def test_successful_download_through_real_agent(stack, agent_host, db, tmp_path):
    path = tmp_path / "payload.bin"
    body = os.urandom(3 * MIB + 17)
    path.write_bytes(body)
    res = await _get(stack, agent_host, str(path))
    assert res.status_code == 200, res.text[:200]
    assert res.headers["content-length"] == str(len(body))
    assert res.content == body
    row = _audit(db, agent_host)
    assert (row.status, row.transport, row.size_bytes) == (
        "success",
        "agent",
        len(body),
    )
    assert row.sha256 == hashlib.sha256(body).hexdigest()
    assert _event(db, agent_host)[0] == "success"
    assert spool_files() == []


@pytest.mark.asyncio
async def test_empty_file_through_real_agent(stack, agent_host, db, tmp_path):
    path = tmp_path / "empty"
    path.write_bytes(b"")
    res = await _get(stack, agent_host, str(path))
    assert (res.status_code, res.content) == (200, b"")
    assert res.headers["content-length"] == "0"
    assert _audit(db, agent_host).status == "success"


@pytest.mark.asyncio
async def test_missing_file_through_real_agent_is_a_404(
    stack, agent_host, db, tmp_path
):
    res = await _get(stack, agent_host, str(tmp_path / "absent.bin"))
    assert res.status_code == 404, res.text
    assert "not found" in res.json()["detail"]
    assert "content-disposition" not in res.headers
    row = _audit(db, agent_host)
    assert (row.status, row.sha256) == ("error", None)
    assert _event(db, agent_host)[0] == "failure"
    assert spool_files() == []


@pytest.mark.asyncio
async def test_directory_and_unreadable_file_through_real_agent(
    stack, agent_host, db, tmp_path
):
    res = await _get(stack, agent_host, str(tmp_path))
    assert res.status_code == 400
    assert "not a regular file" in res.json()["detail"]
    if os.getuid() != 0:
        locked = tmp_path / "locked"
        locked.write_bytes(b"secret")
        locked.chmod(0)
        res = await _get(stack, agent_host, str(locked))
        assert res.status_code == 403
        assert "permission denied" in res.json()["detail"]
    statuses = [r.status for r in db.query(FileTransferAudit).all()]
    assert statuses and set(statuses) == {"error"}


@pytest.mark.asyncio
async def test_declared_oversize_is_rejected_before_the_body_is_read(
    stack, agent_host, db, tmp_path, monkeypatch
):
    monkeypatch.setattr(fts, "AGENT_TRANSFER_MAX_BYTES", MIB)
    path = tmp_path / "big.bin"
    path.write_bytes(b"\0" * (4 * MIB))
    res = await _get(stack, agent_host, str(path))
    assert res.status_code == 413, res.text
    assert _audit(db, agent_host).status == "error"
    assert spool_files() == []
    await _assert_rejected_download_released(stack, agent_host, tmp_path)


@pytest.mark.asyncio
async def test_agent_dying_mid_transfer_is_an_error_not_a_200(
    stack, agent_host, db, tmp_path, monkeypatch
):
    """Kill the real agent while it is sending a large file."""
    monkeypatch.setattr(fts, "AGENT_TRANSFER_MAX_BYTES", 512 * MIB)
    path = tmp_path / "huge.bin"
    with open(path, "wb") as fh:
        fh.truncate(384 * MIB)
    proc = stack.lab.agents[agent_host.id]

    def _kill_once_spooling():
        deadline = time.time() + 30
        while time.time() < deadline:
            for name in spool_files():
                try:
                    if os.path.getsize(os.path.join("/tmp", name)) > 4 * MIB:
                        proc.send_signal(signal.SIGKILL)
                        return
                except OSError:
                    pass
            time.sleep(0.02)

    killer = threading.Thread(target=_kill_once_spooling, daemon=True)
    killer.start()
    res = await _get(stack, agent_host, str(path))
    killer.join(timeout=5)
    assert proc.poll() is not None, "agent was never killed mid-transfer"
    assert res.status_code == 502, (res.status_code, res.text[:200])
    assert "content-disposition" not in res.headers
    row = _audit(db, agent_host)
    assert (row.status, row.sha256) == ("error", None)
    assert _event(db, agent_host)[0] == "failure"
    assert spool_files() == []


@pytest.mark.asyncio
async def test_local_spool_failure_mid_body_releases_the_broker(
    stack, agent_host, db, tmp_path, monkeypatch
):
    """The backend gives up part-way through a large body (disk full): the
    agent is still sending, and the broker must still let go of the op."""
    real_open = open

    class _FullDisk:
        def __init__(self, fh):
            self._fh = fh
            self._written = 0

        def write(self, data):
            self._written += len(data)
            if self._written > 2 * MIB:
                raise OSError(28, "No space left on device")
            return self._fh.write(data)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._fh.close()

    def _open(path, mode="r", *a, **k):
        fh = real_open(path, mode, *a, **k)
        return _FullDisk(fh) if mode == "wb" else fh

    big = tmp_path / "big.bin"
    with real_open(big, "wb") as fh:
        fh.truncate(64 * MIB)
    monkeypatch.setattr(fts, "open", _open, raising=False)
    res = await _get(stack, agent_host, str(big))
    monkeypatch.undo()
    assert res.status_code == 502, res.text[:200]
    row = _audit(db, agent_host)
    assert (row.status, row.sha256) == ("error", None)
    assert spool_files() == []
    await _assert_rejected_download_released(stack, agent_host, tmp_path)
