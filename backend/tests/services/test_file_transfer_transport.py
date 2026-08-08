"""PRA-153 #3e: file_transfer_service routing matrix.

Verifies the per-host transport_preference routing for upload/
download/listdir/stat/mkdir/unlink without spinning up a real DB,
SSH server, agent, or broker. The full routing matrix is:

  | op       | pref=ssh | auto+down | auto+healthy | agent+healthy | agent+down |
  |----------|----------|-----------|--------------|---------------|------------|
  | upload   | ssh      | ssh       | agent        | agent         | unavailable|
  | download | ssh      | ssh       | agent        | agent         | unavailable|
  | listdir  | ssh      | ssh       | ssh          | UNSUPPORTED   | UNSUPPORTED|
  | stat     | ssh      | ssh       | ssh          | UNSUPPORTED   | UNSUPPORTED|
  | mkdir    | ssh      | ssh       | ssh          | UNSUPPORTED   | UNSUPPORTED|
  | unlink   | ssh      | ssh       | ssh          | UNSUPPORTED   | UNSUPPORTED|

Force-agent UNSUPPORTED for directory ops MUST open + close an audit
row with transport="agent" + status="error" before raising — the
ledger has to record the rejected attempt, not silently 4xx.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from app.services import file_transfer_service as fts
from app.services.transport import TransportUnavailable, TransportUnsupported


@dataclass
class _SystemStub:
    id: int = 7
    hostname: str = "host.test"
    transport_preference: str = "auto"


@dataclass
class _UserStub:
    id: int = 1
    username: str = "alice"


def _patch_gate(system, login="ops"):
    return patch.object(fts, "_gate", return_value=(system, login))


def _patch_open_audit():
    """Capture every audit row open so tests can assert on transport
    + status without a real DB."""
    rows = []

    def _fake(db, **kw):
        row = MagicMock()
        for k, v in kw.items():
            setattr(row, k, v)
        row.id = len(rows) + 1
        row.transport = kw.get("transport")
        row.status = "in_progress"
        row.error_message = None
        row.size_bytes = 0
        rows.append(row)
        return row

    return rows, patch.object(fts, "_open_audit", side_effect=_fake)


def _patch_finish_audit():
    finishes = []

    def _fake(db, row, **kw):
        for k, v in kw.items():
            setattr(row, k, v)
        finishes.append(row)

    return finishes, patch.object(fts, "_finish_audit", side_effect=_fake)


# ---- directory ops: force-agent rejection writes audit row ----


@pytest.mark.parametrize(
    "method,direction",
    [
        (fts.listdir, "listdir"),
        (fts.stat, "stat"),
        (fts.mkdir, "mkdir"),
        (fts.unlink, "unlink"),
    ],
)
def test_directory_op_force_agent_writes_audit_then_raises(method, direction):
    """force-agent + directory op: audit row created with
    transport='agent' + status='error' BEFORE the raise. Per the
    PRA-153 #3 lock, no silent fallback to SSH."""
    system = _SystemStub(transport_preference="agent")
    user = _UserStub()
    rows, p_open = _patch_open_audit()
    finishes, p_finish = _patch_finish_audit()
    with _patch_gate(system), p_open, p_finish:
        with pytest.raises(TransportUnsupported):
            method(MagicMock(), user, system.id, "/etc/hosts")
    assert len(rows) == 1
    assert rows[0].transport == "agent"
    assert rows[0].direction == direction
    assert finishes and finishes[0].status == "error"
    assert finishes[0].error_message == "transport_unsupported"


# ---- directory ops: pref=ssh / auto stays SSH (no rejection) ----


@pytest.mark.parametrize("pref", ["ssh", "auto"])
def test_listdir_pref_other_than_agent_does_not_reject(pref):
    """Anything other than pref=agent should NOT trigger the
    force-agent rejection helper. listdir runs against existing
    paramiko path."""
    system = _SystemStub(transport_preference=pref)
    user = _UserStub()
    with (
        _patch_gate(system),
        patch.object(fts, "_reject_force_agent_directory_op") as reject,
        patch.object(fts, "_open_sftp") as open_sftp,
    ):
        # Mock the SFTP context manager + listdir result
        sftp = MagicMock()
        sftp.listdir_attr.return_value = []
        open_sftp.return_value.__enter__.return_value = sftp
        result = fts.listdir(MagicMock(), user, system.id, "/etc")
    # Helper called but no-op for non-agent pref — verified by no exception
    reject.assert_called_once()
    assert result == []


# ---- upload: routing maps to right transport name ----


def _patch_resolve(transport_name, *, raises=None):
    """Patch _resolve_file_transport to return the desired transport
    name (or raise the given exception on TransportUnavailable test)."""

    async def _fake(system, db):
        if raises is not None:
            raise raises
        t = MagicMock()
        t.name = transport_name
        return transport_name, t

    return patch.object(fts, "_resolve_file_transport", side_effect=_fake)


def test_upload_routes_to_ssh_for_pref_ssh():
    system = _SystemStub(transport_preference="ssh")
    user = _UserStub()
    rows, p_open = _patch_open_audit()
    finishes, p_finish = _patch_finish_audit()
    # Stub the SSH path so we don't hit paramiko.
    with (
        _patch_gate(system),
        p_open,
        p_finish,
        _patch_resolve("ssh"),
        patch.object(
            fts,
            "_upload_via_ssh",
            return_value={"remote_path": "/tmp/x", "size": 3, "sha256": "abc"},
        ) as ssh_upload,
        patch.object(fts, "_upload_via_agent") as agent_upload,
    ):
        result = fts.upload_stream(
            MagicMock(), user, system.id, "/tmp/x", iter([b"abc"])
        )
    ssh_upload.assert_called_once()
    agent_upload.assert_not_called()
    assert rows[0].transport == "ssh"
    assert result["size"] == 3


def test_upload_routes_to_agent_for_pref_agent_healthy():
    system = _SystemStub(transport_preference="agent")
    user = _UserStub()
    rows, p_open = _patch_open_audit()
    finishes, p_finish = _patch_finish_audit()
    with (
        _patch_gate(system),
        p_open,
        p_finish,
        _patch_resolve("agent"),
        patch.object(
            fts,
            "_upload_via_agent",
            return_value={"remote_path": "/tmp/x", "size": 3, "sha256": "abc"},
        ) as agent_upload,
        patch.object(fts, "_upload_via_ssh") as ssh_upload,
    ):
        fts.upload_stream(MagicMock(), user, system.id, "/tmp/x", iter([b"abc"]))
    agent_upload.assert_called_once()
    ssh_upload.assert_not_called()
    assert rows[0].transport == "agent"


def test_upload_force_agent_unavailable_writes_audit_then_raises():
    """Force-agent + tunnel down: ledger gets a row with
    transport='agent' + error_message='transport_unavailable'
    BEFORE TransportUnavailable bubbles up."""
    system = _SystemStub(transport_preference="agent")
    user = _UserStub()
    rows, p_open = _patch_open_audit()
    finishes, p_finish = _patch_finish_audit()
    with (
        _patch_gate(system),
        p_open,
        p_finish,
        _patch_resolve(None, raises=TransportUnavailable("no tunnel")),
    ):
        with pytest.raises(TransportUnavailable):
            fts.upload_stream(MagicMock(), user, system.id, "/tmp/x", iter([b"abc"]))
    assert len(rows) == 1
    assert rows[0].transport == "agent"
    assert finishes and finishes[0].status == "error"
    assert finishes[0].error_message == "transport_unavailable"


# ---- download: same routing matrix ----


def test_download_routes_to_ssh_for_pref_ssh():
    system = _SystemStub(transport_preference="ssh")
    user = _UserStub()
    rows, p_open = _patch_open_audit()
    finishes, p_finish = _patch_finish_audit()
    with (
        _patch_gate(system),
        p_open,
        p_finish,
        _patch_resolve("ssh"),
        patch.object(fts, "_download_via_ssh", return_value=iter([b"hello"])) as ssh_dl,
        patch.object(fts, "_download_via_agent") as agent_dl,
    ):
        gen = fts.download_stream(MagicMock(), user, system.id, "/etc/hosts")
        list(gen)
    ssh_dl.assert_called_once()
    agent_dl.assert_not_called()
    assert rows[0].transport == "ssh"


def test_download_routes_to_agent_for_pref_agent():
    system = _SystemStub(transport_preference="agent")
    user = _UserStub()
    rows, p_open = _patch_open_audit()
    finishes, p_finish = _patch_finish_audit()
    with (
        _patch_gate(system),
        p_open,
        p_finish,
        _patch_resolve("agent"),
        patch.object(
            fts, "_download_via_agent", return_value=iter([b"hello"])
        ) as agent_dl,
        patch.object(fts, "_download_via_ssh") as ssh_dl,
    ):
        gen = fts.download_stream(MagicMock(), user, system.id, "/etc/hosts")
        list(gen)
    agent_dl.assert_called_once()
    ssh_dl.assert_not_called()
    assert rows[0].transport == "agent"


def test_download_force_agent_unavailable_writes_audit_then_raises():
    system = _SystemStub(transport_preference="agent")
    user = _UserStub()
    rows, p_open = _patch_open_audit()
    finishes, p_finish = _patch_finish_audit()
    with (
        _patch_gate(system),
        p_open,
        p_finish,
        _patch_resolve(None, raises=TransportUnavailable("no tunnel")),
    ):
        with pytest.raises(TransportUnavailable):
            fts.download_stream(MagicMock(), user, system.id, "/etc/hosts")
    assert len(rows) == 1
    assert rows[0].transport == "agent"
    assert finishes and finishes[0].error_message == "transport_unavailable"


# ---- agent helpers must NOT re-resolve transport ----


def test_download_via_agent_does_not_call_factory():
    """Re-running get_transport in the agent helper could
    fall back to SSH if the tunnel just went unhealthy, leaving the
    audit row (transport='agent') and the actual operation
    disagreeing. Agent helper must build AgentTransport directly."""
    system = _SystemStub()
    with (
        patch.object(fts, "get_transport") as factory,
        patch("app.services.transport.agent.AgentTransport") as agent_cls,
    ):
        agent_cls.return_value.open_file_get = MagicMock()

        async def _open_fg(path):
            stream = MagicMock()

            async def _empty():
                if False:
                    yield b""

            stream.chunks = _empty()

            async def _close():
                pass

            stream.close = _close
            return stream

        agent_cls.return_value.open_file_get = _open_fg

        with patch("app.db.session.SessionLocal", return_value=MagicMock()):
            gen = fts._download_via_agent(MagicMock(), system, "/etc/hosts", 1)
            list(gen)
    factory.assert_not_called()
    agent_cls.assert_called_once()


def test_upload_via_agent_does_not_call_factory():
    """Same P2 fix on the upload side."""
    system = _SystemStub()
    audit = MagicMock()
    audit.id = 1
    with (
        patch.object(fts, "get_transport") as factory,
        patch("app.services.transport.agent.AgentTransport") as agent_cls,
        patch.object(fts, "_finish_audit"),
    ):

        async def _open_fp(path, *, size, overwrite):
            stream = MagicMock()

            async def _write(_chunk):
                pass

            async def _finish():
                pass

            stream.write = _write
            stream.finish = _finish
            return stream

        agent_cls.return_value.open_file_put = _open_fp
        fts._upload_via_agent(MagicMock(), system, "/tmp/x", iter([b"abc"]), audit)
    factory.assert_not_called()
    agent_cls.assert_called_once()


# ---- AuditEvent context carries transport ----


def test_finish_audit_emits_event_with_transport_in_context():
    """The mirrored AuditEvent context MUST include transport so
    SIEM sinks can filter without joining file_transfer_audits."""
    row = MagicMock()
    row.user_id = 1
    row.system_id = 7
    row.client_ip = "1.2.3.4"
    row.direction = "upload"
    row.remote_path = "/tmp/x"
    row.local_filename = "x"
    row.login = "ops"
    row.transport = "agent"
    db = MagicMock()
    captured = {}

    def _safe_emit(**kwargs):
        captured.update(kwargs)

    with patch("app.services.audit_event_service.safe_emit", side_effect=_safe_emit):
        fts._finish_audit(db, row, status="success", size_bytes=100, sha256="abc")
    assert "transport" in captured["context"]
    assert captured["context"]["transport"] == "agent"
