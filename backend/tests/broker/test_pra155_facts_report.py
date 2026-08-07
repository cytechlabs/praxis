"""PRA-155 #2a: broker control-tunnel ``facts_report`` routing.

The agent's only authenticated path to the control plane is the mTLS
WSS to the broker. ``facts_report`` is a new control-message type
handled in ``_recv_loop``: the broker calls the injected
``facts_writer`` with ``(system_id, payload)`` where ``system_id``
comes from the mTLS-validated ``TunnelEntry``, never from the message
body.

These tests exercise ``_route_facts_report`` directly because it's a
sync helper — no need to spin up a real WSS / SSL handshake to assert
the routing contract.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from app.broker.handlers import _route_facts_report


def test_route_facts_report_passes_payload_to_writer():
    writer = MagicMock()
    msg = {
        "type": "facts_report",
        "schema_version": 1,
        "collected_at": "2026-05-01T12:00:00",
        "cpu_model": "AMD EPYC",
        "cpu_cores": 8,
    }
    _route_facts_report(writer, system_id=42, msg=msg)
    writer.assert_called_once()
    args, _ = writer.call_args
    assert args[0] == 42
    payload = args[1]
    # Wire envelope keys stripped.
    assert "type" not in payload
    # Facts kept verbatim.
    assert payload["cpu_model"] == "AMD EPYC"
    assert payload["cpu_cores"] == 8


def test_route_facts_report_ignores_body_system_id():
    """Critical security property: a malicious / buggy agent cannot
    push facts about a different host by spoofing system_id in the
    message body. The broker uses TunnelEntry.system_id (mTLS-extracted)
    and discards anything in the message claiming to be system_id."""
    writer = MagicMock()
    msg = {
        "type": "facts_report",
        "system_id": 999,  # malicious — claim to be a different host
        "cpu_cores": 1,
    }
    _route_facts_report(writer, system_id=42, msg=msg)
    args, _ = writer.call_args
    # Writer is called with the trusted entry-derived system_id.
    assert args[0] == 42
    # The body's "system_id" must NOT have leaked into the payload —
    # if it did, the FactsService caller could re-trust it later.
    assert "system_id" not in args[1]


def test_route_facts_report_swallows_writer_exceptions():
    """A buggy writer must not propagate up through the recv loop —
    that would tear down the control tunnel. Inventory is best-effort
    on the next collection."""

    def _boom(system_id, payload):
        raise RuntimeError("simulated DB failure")

    # No raise — caller's try/except in _recv_loop is what matters in
    # production, but the helper itself logs + swallows so the
    # liveness path is never compromised by an ingest blowup.
    _route_facts_report(_boom, system_id=42, msg={"type": "facts_report"})
