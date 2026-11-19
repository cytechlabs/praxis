"""PRA-337: revocation against the real identity row and persisted audit.

Uses the DB-backed ``System`` row, the production ``make_db_validator`` and the
production per-session authorizer, so the committed ``agent_status`` is the
authority the broker acts on. Only the eviction HTTP signal and the agent
socket are stubbed.
"""

from __future__ import annotations

import asyncio
import json
from datetime import date
from types import SimpleNamespace

import pytest

from app.broker.handlers import _make_authorizer, make_db_validator
from app.broker.ops import AgentNotAuthorized, OperationManager
from app.broker.registry import AgentRegistry, TunnelEntry
from app.db.access_models import AuditEvent
from app.db.models import Credential, Distro, Group, System
from app.services import agent_identity_service as ais
from app.services.agent_identity_service import AgentIdentityService
from app.services.broker_client import EvictOutcome

SERIAL = "aabbccdd"
FINGERPRINT = "fp-337"


class _SharedSession:
    """Lets the production validator read through the test's session, which
    holds the uncommitted-to-the-outside fixture rows."""

    def __init__(self, db):
        self._db = db

    def query(self, *a, **k):
        return self._db.query(*a, **k)

    def close(self):
        pass


@pytest.fixture
def system_row(db):
    group = db.query(Group).filter_by(name="Default").first()
    if group is None:
        group = Group(name="Default")
        db.add(group)
        db.flush()
    cred = Credential(
        name="pra337-cred", auth_method="password", username="root", vault_path="v/337"
    )
    distro = Distro(
        name="Ubuntu",
        version="22.04",
        release_date=date(2022, 4, 21),
        end_of_life_date=date(2027, 4, 21),
    )
    db.add_all([cred, distro])
    db.flush()
    row = System(
        hostname="pra337-host",
        ip_address="10.9.3.7",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
        agent_status="active",
        agent_cert_serial=SERIAL,
        agent_cert_fingerprint=FINGERPRINT,
    )
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def authorizer(db, system_row):
    validator = make_db_validator(lambda: _SharedSession(db))
    identity = SimpleNamespace(
        system_id=system_row.id, serial_hex=SERIAL, fingerprint_sha256=FINGERPRINT
    )
    return _make_authorizer(validator, identity)


@pytest.fixture
def signals(monkeypatch):
    sent = []

    def fake(system_id, reason, **_kw):
        sent.append((system_id, reason))
        return EvictOutcome(delivered=True, result="evicted")

    monkeypatch.setattr(ais, "signal_eviction", fake)
    return sent


def _events(db, action):
    return db.query(AuditEvent).filter(AuditEvent.action == action).all()


def test_authorizer_follows_the_committed_row(db, system_row, authorizer, signals):
    svc = AgentIdentityService(db)
    assert authorizer() is None
    svc.disable(system_row.id, reason="maintenance")
    assert authorizer() == "system_not_active"
    assert signals == [(system_row.id, "disabled")]
    svc.enable(system_row.id)
    assert authorizer() is None  # re-enable needs no re-enrolment
    system_row.agent_cert_serial = "112233"
    db.flush()
    assert authorizer() not in (None, "system_not_active")  # identity changed
    system_row.agent_cert_serial = SERIAL
    db.flush()
    svc.revoke(system_row.id, reason="decommissioned")
    assert authorizer() == "system_not_active"


def test_unreadable_row_is_unverifiable_not_active(db, system_row, authorizer):
    db.delete(system_row)
    db.flush()
    assert authorizer() == "system_not_active"  # missing row is a refusal
    broken = _make_authorizer(
        make_db_validator(lambda: (_ for _ in ()).throw(RuntimeError("db down"))),
        SimpleNamespace(system_id=1, serial_hex=SERIAL, fingerprint_sha256=FINGERPRINT),
    )
    assert broken() == "identity_unverifiable"


@pytest.mark.asyncio
async def test_dispatch_refused_after_real_disable_and_audit_is_persisted(
    db, system_row, authorizer, signals
):
    class Ws:
        def __init__(self):
            self.sent = []

        async def send(self, m):
            self.sent.append(json.loads(m))

        async def close(self, **_):
            pass

    registry = AgentRegistry()
    ws = Ws()
    entry = TunnelEntry(
        system_id=system_row.id,
        tunnel_session_id="S",
        ws=ws,  # type: ignore[arg-type]
        identity=SimpleNamespace(),  # type: ignore[arg-type]
        capabilities=[],
        agent_version="t",
        authorize=authorizer,
    )
    await registry.register(entry)
    manager = OperationManager(registry, audit_emit=lambda **_k: None)

    op, _ = await manager.create_and_dispatch(system_row.id, "exec", {"cmd": "id"})
    assert op.operation_id and [m["type"] for m in ws.sent] == [
        "op_request",
        "op_nonce",
    ]

    AgentIdentityService(db).revoke(system_row.id, reason="compromised")
    before = len(ws.sent)
    with pytest.raises(AgentNotAuthorized) as err:
        await manager.create_and_dispatch(system_row.id, "exec", {"cmd": "touch x"})
    assert err.value.code == "system_not_active"
    assert len(ws.sent) == before  # nothing reached the agent

    rows = _events(db, "agent.cert.revoked")
    assert len(rows) == 1 and rows[0].target_system_id == system_row.id
    assert not _events(db, "agent.tunnel.evict_failed")  # delivery succeeded
    await asyncio.sleep(0)


def test_failed_signal_leaves_commit_and_persists_failure_audit(
    db, system_row, monkeypatch
):
    monkeypatch.setattr(
        ais,
        "signal_eviction",
        lambda *_a, **_k: EvictOutcome(delivered=False, error="ConnectError"),
    )
    svc = AgentIdentityService(db)
    result = svc.revoke(system_row.id, reason="compromised")
    db.expire_all()
    assert result.agent_status == "revoked"
    assert svc.last_eviction.delivered is False
    (failed,) = _events(db, "agent.tunnel.evict_failed")
    assert failed.outcome == "failure"
    assert failed.target_system_id == system_row.id
    assert _events(db, "agent.cert.revoked")
