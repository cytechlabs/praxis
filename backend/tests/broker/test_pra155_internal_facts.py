"""PRA-155 #2b-a: broker /internal/agent/ops/facts.

The agent reports facts inline on op_complete (no per-op streaming);
``_route_op_complete`` captures the top-level ``facts`` and
``partial_errors`` keys into ``op.result_metadata``. This endpoint
dispatches op_type='facts', waits for op_complete, and surfaces the
inline payload.

Error-vocabulary parity with /internal/agent/ops/exec is the contract
PRA-155 #2b-b will lean on for transport selection — the SSH-vs-agent
refresh endpoint maps these into HTTP status codes for callers.
"""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from app.broker.internal_api import build_internal_app
from app.broker.ops import Operation, OperationState
from app.broker.registry import AgentRegistry

from .test_internal_ops_api import _FakeManager, _make_op


def _facts_op_factory(
    *,
    facts: dict | None = None,
    partial_errors: list | None = None,
    outcome: str = "success",
    error: dict | None = None,
    attach_after: float = 0.0,
    complete_after: float = 0.0,
):
    """Build an op_factory that simulates the agent's response to a
    facts op. Mirrors the exec factory shape — frames are not used
    because facts is inline-only; we just stage result_metadata."""

    def _factory(operation_id, system_id, op_type, params):
        op = _make_op(operation_id, system_id, op_type, params)

        async def _drive():
            await asyncio.sleep(attach_after)
            op.state = OperationState.ATTACHED
            await asyncio.sleep(complete_after)
            # Sentinel so the no-op frame pump exits cleanly.
            op.inbound.put_nowait(None)
            op.outcome = outcome
            op.error = error
            md: dict = {}
            if facts is not None:
                md["facts"] = facts
            if partial_errors is not None:
                md["partial_errors"] = partial_errors
            op.result_metadata = md or None
            op.completion.set_result(None)

        asyncio.create_task(_drive())
        return op

    return _factory


def test_facts_happy_path_returns_inline_facts():
    facts = {
        "schema_version": 1,
        "collected_at": "2026-05-01T12:00:00Z",
        "cpu_model": "AMD EPYC",
        "cpu_cores": 8,
        "kernel_version": "5.15.0-x",
    }
    factory = _facts_op_factory(facts=facts, partial_errors=[])
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post("/internal/agent/ops/facts", json={"system_id": 7})
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "success"
    assert body["facts"]["cpu_model"] == "AMD EPYC"
    assert body["facts"]["cpu_cores"] == 8
    assert body["partial_errors"] == []
    # Confirms we dispatched op_type='facts' with no params — the
    # agent's runFacts ignores params; sending them anyway would still
    # work but enlarges the trust surface for no benefit.
    assert mgr.dispatched == [(7, "facts", {})]


def test_facts_passes_through_partial_errors():
    facts = {"schema_version": 1, "collected_at": "2026-05-01T12:00:00Z"}
    partial = [
        {"key": "cloud_metadata", "error": "no cloud metadata service responded"},
        {"key": "virtualization", "error": "systemd-detect-virt missing"},
    ]
    factory = _facts_op_factory(facts=facts, partial_errors=partial)
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post("/internal/agent/ops/facts", json={"system_id": 7})
    assert resp.status_code == 200
    body = resp.json()
    err_keys = {e["key"] for e in body["partial_errors"]}
    assert err_keys == {"cloud_metadata", "virtualization"}


def test_facts_returns_503_when_no_tunnel():
    factory = _facts_op_factory(facts={})
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post("/internal/agent/ops/facts", json={"system_id": 9999})
    assert resp.status_code == 503
    assert resp.json()["error"]["reason"] == "transport_unavailable"


def test_facts_returns_502_on_agent_error():
    factory = _facts_op_factory(
        facts=None, outcome="error", error={"reason": "collector_panicked"}
    )
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post("/internal/agent/ops/facts", json={"system_id": 7})
    assert resp.status_code == 502
    body = resp.json()
    assert body["outcome"] == "error"
    assert body["error"]["reason"] == "collector_panicked"


def test_facts_returns_502_when_success_without_inline_facts():
    """A back-revved agent that still routes op_type='facts' through
    runStub would report success but never set result_metadata['facts'].
    Surface that as 502 (missing_inline_facts) so the refresh
    endpoint doesn't ingest an empty row as a healthy poll."""
    factory = _facts_op_factory(facts=None, partial_errors=None, outcome="success")
    mgr = _FakeManager(factory)
    app = build_internal_app(AgentRegistry(), manager=mgr)
    with TestClient(app) as client:
        resp = client.post("/internal/agent/ops/facts", json={"system_id": 7})
    assert resp.status_code == 502
    assert resp.json()["error"]["reason"] == "missing_inline_facts"
