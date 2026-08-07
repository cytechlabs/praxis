"""PRA-155 #2b-b: POST /systems/{id}/facts/refresh transport selection.

Covers the locked PRA-153-style transport matrix:

    transport_preference=ssh    → SSH always
    transport_preference=agent  → agent or 503 (no fallback)
    transport_preference=auto   → agent if active + healthy + facts cap
                                  else SSH

Also covers status-code mapping for forced-agent failures (503/504/502)
and the response body contract.

These tests stub the SshFactsCollectorService + BrokerClient so we
don't need a real SSH host or live tunnel — what we're verifying is
the route's selection logic + error mapping, not the underlying
transport plumbing (those have their own #2b-a unit/api tests).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional
from unittest.mock import patch

import pytest

from app.db.models import Credential, Group, System
from app.services import facts_service, ssh_facts_collector_service
from app.services.broker_client import BrokerError, BrokerFactsResult, TunnelHealth


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra155-refresh", description="x")
    db.add(g)
    db.flush()
    cred = Credential(
        name="cred-pra155-refresh", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="refresh.example.com",
        ip_address="10.0.0.70",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    db.commit()
    return sys_row


def _set_transport(db, host, *, pref: str, agent_status: str = "none"):
    host.transport_preference = pref
    host.agent_status = agent_status
    db.add(host)
    db.commit()


def _fake_ingest_result(status="upserted"):
    """Build an IngestResult with a real-looking row stub."""
    from datetime import datetime

    class _Row:
        collected_at = datetime(2026, 5, 1, 12, 0, 0)

    return facts_service.IngestResult(
        status=status, row=_Row(), rejected_keys=[], partial_errors=[]
    )


class _FakeBroker:
    """Stub for app.services.broker_client.BrokerClient. Matches the
    async-context-manager surface plus health()/facts() so the route
    can use the real call sites unchanged."""

    def __init__(
        self,
        *,
        health: TunnelHealth,
        facts: Optional[BrokerFactsResult] = None,
        facts_error: Optional[BrokerError] = None,
    ):
        self._health = health
        self._facts = facts
        self._facts_error = facts_error

    @asynccontextmanager
    async def __call__(self, *_a, **_kw):
        yield self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return None

    async def health(self, _system_id):  # noqa: D401
        return self._health

    async def facts(self, _system_id):
        if self._facts_error is not None:
            raise self._facts_error
        return self._facts


def _patch_broker(broker: _FakeBroker):
    """Patch BrokerClient at the import site used inside facts.py."""
    return patch("app.api.routes.facts.BrokerClient", lambda *a, **kw: broker)


def _patch_ssh(result):
    return patch(
        "app.services.ssh_facts_collector_service.collect_and_ingest",
        return_value=result,
    )


# ---------------------------------------------------------------- ssh path


def test_pref_ssh_always_uses_ssh(authed_client, db, host):
    _set_transport(db, host, pref="ssh", agent_status="active")
    # Even with a healthy agent advertising facts, ssh-pref hosts skip
    # the agent path entirely. Broker must not be queried.
    broker = _FakeBroker(
        health=TunnelHealth(system_id=host.id, state="healthy", capabilities=("facts",))
    )
    with _patch_broker(broker), _patch_ssh(_fake_ingest_result()) as ssh_mock:
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source_transport"] == "ssh"
    assert body["status"] == "upserted"
    assert ssh_mock.call_count == 1


# ---------------------------------------------------------------- forced agent


def test_pref_agent_healthy_with_capability_uses_agent(authed_client, db, host):
    _set_transport(db, host, pref="agent", agent_status="active")
    broker = _FakeBroker(
        health=TunnelHealth(
            system_id=host.id, state="healthy", capabilities=("facts",)
        ),
        facts=BrokerFactsResult(
            outcome="success",
            facts={
                "schema_version": 1,
                "collected_at": "2026-05-01T12:00:00Z",
                "cpu_model": "x86_64",
                "cpu_cores": 4,
            },
            partial_errors=[],
        ),
    )
    with _patch_broker(broker):
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source_transport"] == "agent"
    assert body["status"] == "upserted"


def test_pref_agent_no_tunnel_returns_503_no_ssh_fallback(authed_client, db, host):
    """Forced-agent + no live tunnel → 503. Route MUST NOT silently
    drop to SSH for forced-agent (locked PRA-153 semantics)."""
    _set_transport(db, host, pref="agent", agent_status="active")
    broker = _FakeBroker(
        health=TunnelHealth(system_id=host.id, state="unregistered"),
    )
    with _patch_broker(broker), _patch_ssh(_fake_ingest_result()) as ssh_mock:
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 503
    assert resp.json()["error"] == "transport_unavailable"
    assert ssh_mock.call_count == 0


def test_pref_agent_lacks_facts_capability_returns_503(authed_client, db, host):
    """Back-revved agent that's healthy but doesn't advertise facts
    must NOT be silently treated as agent-capable."""
    _set_transport(db, host, pref="agent", agent_status="active")
    broker = _FakeBroker(
        health=TunnelHealth(system_id=host.id, state="healthy", capabilities=("exec",)),
    )
    with _patch_broker(broker):
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 503
    assert resp.json()["error"] == "transport_unavailable"


def test_pref_agent_facts_timeout_maps_to_504(authed_client, db, host):
    _set_transport(db, host, pref="agent", agent_status="active")
    broker = _FakeBroker(
        health=TunnelHealth(
            system_id=host.id, state="healthy", capabilities=("facts",)
        ),
        facts_error=BrokerError("facts_timeout", "agent didn't respond"),
    )
    with _patch_broker(broker):
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 504
    assert resp.json()["error"] == "facts_timeout"


def test_pref_agent_collector_error_maps_to_502(authed_client, db, host):
    _set_transport(db, host, pref="agent", agent_status="active")
    broker = _FakeBroker(
        health=TunnelHealth(
            system_id=host.id, state="healthy", capabilities=("facts",)
        ),
        facts_error=BrokerError("collector_panicked", "go runtime"),
    )
    with _patch_broker(broker):
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 502
    assert resp.json()["error"] == "collector_panicked"


# ---------------------------------------------------------------- auto


def test_pref_auto_active_healthy_with_capability_uses_agent(authed_client, db, host):
    _set_transport(db, host, pref="auto", agent_status="active")
    broker = _FakeBroker(
        health=TunnelHealth(
            system_id=host.id, state="healthy", capabilities=("facts",)
        ),
        facts=BrokerFactsResult(
            outcome="success",
            facts={
                "schema_version": 1,
                "collected_at": "2026-05-01T12:00:00Z",
                "cpu_cores": 2,
            },
            partial_errors=[],
        ),
    )
    with _patch_broker(broker), _patch_ssh(_fake_ingest_result()) as ssh_mock:
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 200, resp.text
    assert resp.json()["source_transport"] == "agent"
    # SSH path NOT taken when auto + agent healthy.
    assert ssh_mock.call_count == 0


def test_pref_auto_falls_back_to_ssh_when_agent_disabled(authed_client, db, host):
    _set_transport(db, host, pref="auto", agent_status="disabled")
    # agent_status disabled → auto skips agent entirely (no broker
    # query needed for capability gate).
    broker = _FakeBroker(
        health=TunnelHealth(
            system_id=host.id, state="healthy", capabilities=("facts",)
        ),
    )
    with _patch_broker(broker), _patch_ssh(_fake_ingest_result()) as ssh_mock:
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 200, resp.text
    assert resp.json()["source_transport"] == "ssh"
    assert ssh_mock.call_count == 1


def test_pref_auto_falls_back_to_ssh_when_tunnel_stale(authed_client, db, host):
    _set_transport(db, host, pref="auto", agent_status="active")
    broker = _FakeBroker(
        health=TunnelHealth(system_id=host.id, state="stale", capabilities=("facts",)),
    )
    with _patch_broker(broker), _patch_ssh(_fake_ingest_result()) as ssh_mock:
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 200, resp.text
    assert resp.json()["source_transport"] == "ssh"
    assert ssh_mock.call_count == 1


def test_pref_auto_falls_back_to_ssh_when_agent_op_errors(authed_client, db, host):
    """auto-mode + healthy agent + facts cap, but the broker reports
    an op-level error mid-flight → fall back to SSH instead of
    surfacing the agent error to the caller."""
    _set_transport(db, host, pref="auto", agent_status="active")
    broker = _FakeBroker(
        health=TunnelHealth(
            system_id=host.id, state="healthy", capabilities=("facts",)
        ),
        facts_error=BrokerError("collector_panicked", "x"),
    )
    with _patch_broker(broker), _patch_ssh(_fake_ingest_result()) as ssh_mock:
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 200, resp.text
    assert resp.json()["source_transport"] == "ssh"
    assert ssh_mock.call_count == 1


# ---------------------------------------------------------------- misc


def test_unknown_system_returns_404(authed_client):
    resp = authed_client.post("/systems/999999/facts/refresh")
    assert resp.status_code == 404


def test_ssh_path_transport_failure_returns_502(authed_client, db, host):
    _set_transport(db, host, pref="ssh", agent_status="not_enrolled")

    def _boom(*_a, **_kw):
        raise ssh_facts_collector_service.SshFactsCollectionError("auth failed")

    with patch(
        "app.services.ssh_facts_collector_service.collect_and_ingest", new=_boom
    ):
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 502
    assert resp.json()["error"] == "ssh_collector_failed"


def test_response_shape(authed_client, db, host):
    _set_transport(db, host, pref="ssh", agent_status="not_enrolled")
    result = _fake_ingest_result(status="upserted")
    with _patch_ssh(result):
        resp = authed_client.post(f"/systems/{host.id}/facts/refresh")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {
        "status",
        "source_transport",
        "collected_at",
        "partial_error_count",
    }
    assert body["status"] == "upserted"
    assert body["source_transport"] == "ssh"
    assert body["collected_at"] == "2026-05-01T12:00:00Z"
    assert body["partial_error_count"] == 0
