"""PRA-153 #3d: command_execution_service routes through the
transport factory and writes the transport column on every
CommandExecutionResult row.

Tests stub the transport factory + result-saving so we don't need
a real SSH server, agent, broker, OR a live database. The focus is:

    1. The right transport is consulted (per System.transport_preference).
    2. CommandResult.exit_code → execution_status (existing
       semantics preserved: 0 = success, nonzero = failed).
    3. CommandExecutionResult.transport column populated with
       transport.name on success and the operator-intent string on
       TransportUnavailable (so audit shows what was asked, not
       what wasn't tried).
    4. TransportUnsupported and generic TransportError both result
       in execution_status=failed with the right error_type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.services.command_execution_service import CommandExecutionService
from app.services.transport import (
    CommandResult,
    TransportError,
    TransportUnavailable,
    TransportUnsupported,
)


@dataclass
class _SystemStub:
    id: int
    hostname: str = "host.test"
    transport_preference: str = "auto"


def _service_with_transport(transport_obj):
    """Build a CommandExecutionService whose factory returns
    ``transport_obj`` regardless of system / pref. We bypass the
    DB + validation entirely and call the private executor directly.
    """
    svc = CommandExecutionService.__new__(CommandExecutionService)
    svc.db = MagicMock()
    svc.ssh_service = MagicMock()
    svc.broker_client = MagicMock()
    svc.validation_service = MagicMock()
    svc._active_executions = {}
    import threading

    svc._execution_lock = threading.RLock()

    async def _fake_get_transport(system, broker_client, ssh_service=None):
        if isinstance(transport_obj, Exception):
            raise transport_obj
        return transport_obj

    return svc, _fake_get_transport


class _StubTransport:
    def __init__(
        self,
        name: str,
        *,
        exit_code: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
        raises: Exception | None = None,
    ):
        self.name = name
        self._raises = raises
        self._result = CommandResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=5,
        )
        self.calls: list[list[str]] = []

    async def run_command(self, cmd, **_kwargs):
        self.calls.append(cmd)
        if self._raises is not None:
            raise self._raises
        return self._result


def _run(svc, system, command="echo hi", timeout=30):
    """Drive the private executor with a stubbed-out factory."""
    rl = MagicMock()
    return svc._execute_command_with_monitoring(system, command, timeout, rl, 1)


# -------- happy paths --------


def test_zero_exit_returns_success_with_transport_name():
    transport = _StubTransport("agent", exit_code=0, stdout=b"hi\n")
    svc, fake = _service_with_transport(transport)
    sys = _SystemStub(id=7, transport_preference="agent")
    with patch(
        "app.services.command_execution_service.get_transport", side_effect=fake
    ):
        result = _run(svc, sys)
    assert result["status"] == "success"
    assert result["exit_code"] == 0
    assert result["stdout"] == "hi\n"
    assert result["transport"] == "agent"
    # Sanity: argv was wrapped in sh -c so shell features still work.
    assert transport.calls == [["sh", "-c", "echo hi"]]


def test_nonzero_exit_returns_failed_but_keeps_transport():
    """PRA-153 lock: nonzero exit is still 'we ran it', so the
    ledger gets the transport name AND execution_status=failed."""
    transport = _StubTransport("ssh", exit_code=2, stderr=b"oops\n")
    svc, fake = _service_with_transport(transport)
    sys = _SystemStub(id=7, transport_preference="ssh")
    with patch(
        "app.services.command_execution_service.get_transport", side_effect=fake
    ):
        result = _run(svc, sys, command="false")
    assert result["status"] == "failed"
    assert result["exit_code"] == 2
    assert result["stderr"] == "oops\n"
    assert result["transport"] == "ssh"


# -------- transport-layer failures --------


def test_transport_unavailable_attribution_is_agent():
    """Force-agent + tunnel down: audit must reflect operator intent
    ('agent'), not 'ssh' which we never actually tried."""
    svc, fake = _service_with_transport(TransportUnavailable("no tunnel"))
    sys = _SystemStub(id=7, transport_preference="agent")
    with patch(
        "app.services.command_execution_service.get_transport", side_effect=fake
    ):
        result = _run(svc, sys)
    assert result["status"] == "failed"
    assert result["error_type"] == "transport_unavailable"
    assert result["transport"] == "agent"


def test_transport_unsupported_marks_failure():
    svc, fake = _service_with_transport(TransportUnsupported("op not supported"))
    sys = _SystemStub(id=7, transport_preference="agent")
    with patch(
        "app.services.command_execution_service.get_transport", side_effect=fake
    ):
        result = _run(svc, sys)
    assert result["status"] == "failed"
    assert result["error_type"] == "transport_unsupported"
    assert result["transport"] == "agent"


def test_transport_error_falls_back_to_pref_for_attribution():
    """Generic TransportError doesn't carry transport-name info; we
    attribute by system pref so the audit row isn't NULL."""
    svc, fake = _service_with_transport(TransportError("boom"))
    sys = _SystemStub(id=7, transport_preference="auto")
    with patch(
        "app.services.command_execution_service.get_transport", side_effect=fake
    ):
        result = _run(svc, sys)
    assert result["status"] == "failed"
    assert result["error_type"] == "transport_error"
    assert result["transport"] == "auto"


# -------- transport-error from run_command itself --------


def test_run_command_raises_transport_error_marks_failure():
    """If the factory selects a transport and run_command
    THEN raises TransportError, the audit row must reflect the
    actual selected transport — not system.transport_preference.
    For pref=auto + healthy agent the row should say "agent", not
    "auto", so audit reflects what was attempted.
    """
    transport = _StubTransport("agent", raises=TransportError("link down"))
    svc, fake = _service_with_transport(transport)
    sys = _SystemStub(id=7, transport_preference="auto")
    with patch(
        "app.services.command_execution_service.get_transport", side_effect=fake
    ):
        result = _run(svc, sys)
    assert result["status"] == "failed"
    assert result["error_type"] == "transport_error"
    # The fix: transport reflects the SELECTED transport (agent),
    # NOT operator pref ("auto"). Audit invariant requires
    # ssh|agent for any attempted operation.
    assert result["transport"] == "agent", (
        "post-selection TransportError should attribute to the "
        "selected transport, not system.transport_preference"
    )


def test_default_constructor_does_not_persist_broker_client():
    """Storing a default BrokerClient would leak an
    httpx.AsyncClient bound to whatever event loop happened to be
    running on first use. _run_async_from_sync uses asyncio.run /
    fresh-thread loops that close after each call, so the persistent
    client would be tied to a dead loop on the second execute_command
    call. Constructor without broker_client must leave the field
    None so the executor builds + tears down a fresh client per call.
    """
    from app.services.command_execution_service import CommandExecutionService

    svc = CommandExecutionService(db=MagicMock())
    assert svc.broker_client is None


def test_format_execution_result_includes_transport():
    """API/history responses must surface the transport
    field so UI / dashboards don't have to re-query the model."""
    from app.services.command_execution_service import CommandExecutionService

    svc = CommandExecutionService(db=MagicMock())
    # _format_execution_result queries the db for user + system; mock both.
    svc.db.query.return_value.filter.return_value.first.return_value = MagicMock(
        username="alice", hostname="host.test"
    )
    row = MagicMock()
    row.id = 42
    row.system_id = 7
    row.user_id = 1
    row.session_id = "s"
    row.command = "echo hi"
    row.normalized_command = "echo hi"
    row.command_hash = "x" * 64
    row.execution_status = "success"
    row.exit_code = 0
    row.stdout = "hi\n"
    row.stderr = ""
    row.started_at = None
    row.completed_at = None
    row.execution_time_ms = 5
    row.timeout_seconds = 30
    row.max_memory_usage_bytes = None
    row.cpu_time_ms = None
    row.validation_status = "validated"
    row.risk_level = "low"
    row.requires_sudo = False
    row.actual_user = None
    row.transport = "agent"
    row.error_type = None
    row.error_message = None
    row.retry_count = 0
    row.created_at = None
    row.updated_at = None
    row.get_execution_context = MagicMock(return_value=None)
    row.ip_address = None
    row.user_agent = None
    payload = svc._format_execution_result(row)
    assert payload["transport"] == "agent", (
        "transport field missing from formatted result; UI/API "
        "consumers couldn't display the new attribution"
    )
