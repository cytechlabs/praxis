"""PRA-376: the cert-expiry closer stays cancellable.

``_maybe_schedule_cert_expiry`` arms a one-shot task that closes a tunnel at the
peer cert's ``not_after``. When the tunnel goes away first, the handler cancels
that task, and cancellation must propagate: no ``bye`` frame, no socket close,
and no ``tunnel.cert_expired`` audit event for a tunnel that never reached its
expiry boundary.

These tests pin both halves of that contract so the cancellation assertions
cannot pass vacuously:

- a cancelled task raises ``CancelledError`` and touches neither the websocket
  nor the audit sink;
- the same task, left alone, does send ``bye`` / close and does emit the expiry
  event, proving the cancelled case suppressed real work.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta

import pytest

from app.broker.audit import TUNNEL_CERT_EXPIRED
from app.broker.handlers import _maybe_schedule_cert_expiry
from app.broker.registry import TunnelEntry
from app.broker.tls import PeerIdentity


class _RecordingWs:
    """Minimal websocket stand-in that records send/close activity."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.closed: list[tuple[int, str]] = []

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed.append((code, reason))


class _AuditCollector:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def __call__(self, **kwargs) -> None:
        self.events.append(kwargs)

    def actions(self) -> list[str]:
        return [e["action"] for e in self.events]


def _entry(ws: _RecordingWs, expires_in_seconds: float) -> TunnelEntry:
    identity = PeerIdentity(
        system_id=4242,
        serial_hex="ab12",
        fingerprint_sha256="f" * 64,
        not_after=datetime.utcnow() + timedelta(seconds=expires_in_seconds),
        subject_cn="agent-4242",
    )
    return TunnelEntry(
        system_id=identity.system_id,
        tunnel_session_id="sess-cert-expiry",
        ws=ws,
        identity=identity,
        capabilities=[],
        agent_version="1.0.0",
    )


@pytest.mark.asyncio
async def test_cancelled_expiry_task_closes_nothing_and_emits_nothing():
    """Cancelling before the cert expires must surface ``CancelledError`` and
    leave the tunnel and audit trail untouched."""
    ws = _RecordingWs()
    audit = _AuditCollector()

    task = _maybe_schedule_cert_expiry(_entry(ws, 3600), audit)
    assert task is not None

    # Let the task reach its sleep before cancelling, so the cancellation lands
    # inside the wait rather than before the coroutine ever starts.
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert task.cancelled() is True
    assert ws.sent == []
    assert ws.closed == []
    assert audit.events == []


@pytest.mark.asyncio
async def test_uncancelled_expiry_task_sends_bye_and_emits_event():
    """The counterpart: left to run, the task does close the tunnel and emit
    ``tunnel.cert_expired``, so the cancellation test above is not vacuous."""
    ws = _RecordingWs()
    audit = _AuditCollector()

    task = _maybe_schedule_cert_expiry(_entry(ws, 0.05), audit)
    assert task is not None
    await asyncio.wait_for(task, timeout=5.0)

    assert [json.loads(p) for p in ws.sent] == [
        {"type": "bye", "reason": "cert_expired"}
    ]
    assert [code for code, _ in ws.closed] == [1000]
    assert audit.actions() == [TUNNEL_CERT_EXPIRED]
    assert audit.events[0]["context"]["reason"] == "cert_expired"
    assert audit.events[0]["outcome"] == "failure"


@pytest.mark.asyncio
async def test_already_expired_cert_schedules_nothing():
    """A cert already past ``not_after`` arms no task; the liveness watchdog
    owns that teardown."""
    ws = _RecordingWs()
    audit = _AuditCollector()

    assert _maybe_schedule_cert_expiry(_entry(ws, -1), audit) is None
    assert ws.sent == []
    assert audit.events == []
