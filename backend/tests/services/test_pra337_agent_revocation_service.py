"""PRA-337: backend side of live agent disable / revoke.

* commit-before-signal ordering and the failure semantics of the eviction
  signal (never undoes the committed status; failure is audited)
* eviction signal client (auth header, payload, failure classification)
* dispatch refusal surfaced as an unavailable transport, never SSH
* in-flight interruption text never claims a stop that was not confirmed
* transport selection is unchanged (pinned)
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from app.services import agent_identity_service as ais
from app.services import audit_event_service, broker_client
from app.services.agent_identity_service import AgentIdentityService
from app.services.broker_client import (
    BrokerClient,
    BrokerError,
    BrokerExecResult,
    EvictOutcome,
    TunnelHealth,
    signal_eviction,
)
from app.services.transport.agent import AgentTransport
from app.services.transport.base import TransportError, TransportUnavailable
from app.services.transport.factory import get_transport

# ---------------------------------------------------------------------------
# Identity service: ordering and failure semantics
# ---------------------------------------------------------------------------


class _Db:
    def __init__(self, system, log):
        self.system = system
        self.log = log

    def query(self, *_a):
        return self

    def filter(self, *_a):
        return self

    def first(self):
        return self.system

    def commit(self):
        self.log.append("commit")


def _system(status="active"):
    return SimpleNamespace(
        id=5,
        hostname="h",
        agent_status=status,
        agent_status_reason=None,
        agent_revoked_at=None,
        agent_revocation_reason=None,
        agent_cert_serial="aa:bb",
    )


@pytest.fixture
def svc_env(monkeypatch):
    log = []

    def fake_emit(**kw):
        log.append(("audit", kw["action"], kw.get("outcome", "success")))

    monkeypatch.setattr(audit_event_service, "safe_emit", fake_emit)
    monkeypatch.setattr(ais, "VaultService", lambda db: object())

    def make(status="active", signal=None):
        system = _system(status)
        calls = []

        def fake_signal(system_id, reason, **_kw):
            log.append("signal")
            calls.append((system_id, reason))
            if signal is None:
                return EvictOutcome(delivered=True, result="evicted")
            if isinstance(signal, Exception):
                raise signal
            return signal

        monkeypatch.setattr(ais, "signal_eviction", fake_signal)
        return AgentIdentityService(_Db(system, log)), system, log, calls

    return make


def test_disable_commits_audits_then_signals(svc_env):
    svc, system, log, calls = svc_env("active")
    svc.disable(5, reason="compromised", actor_user_id=1)
    assert system.agent_status == "disabled"
    assert log == ["commit", ("audit", "agent.disabled", "success"), "signal"]
    assert calls == [(5, "disabled")]
    assert svc.last_eviction.delivered is True


def test_revoke_commits_audits_then_signals(svc_env):
    svc, system, log, calls = svc_env("active")
    svc.revoke(5, reason="decommissioned", actor_user_id=1)
    assert system.agent_status == "revoked"
    assert log == ["commit", ("audit", "agent.cert.revoked", "success"), "signal"]
    assert calls == [(5, "revoked")]


@pytest.mark.parametrize(
    "signal",
    [
        EvictOutcome(delivered=False, error="ConnectError"),
        EvictOutcome(delivered=False, error="http_503"),
        RuntimeError("boom"),
    ],
)
def test_undelivered_signal_keeps_commit_and_is_audited(svc_env, signal):
    svc, system, log, _calls = svc_env("active", signal=signal)
    result = svc.revoke(5, reason="r", actor_user_id=1)
    # Committed state stands and the call still returns it.
    assert result is system and system.agent_status == "revoked"
    assert svc.last_eviction.delivered is False
    assert ("audit", "agent.tunnel.evict_failed", "failure") in log
    assert log.index("commit") < log.index(
        ("audit", "agent.tunnel.evict_failed", "failure")
    )


def test_repeating_revoke_resignals_without_new_commit(svc_env):
    svc, _, log, calls = svc_env("revoked")
    svc.revoke(5, reason="again", actor_user_id=1)
    assert log == ["signal"]  # no commit, no duplicate revoke audit
    assert calls == [(5, "revoked")]


def test_disable_when_already_disabled_resignals(svc_env):
    svc, _s, _log, calls = svc_env("disabled")
    svc.disable(5, reason="x", actor_user_id=1)
    assert calls == [(5, "disabled")]


def test_enable_does_not_signal(svc_env):
    svc, system, _log, calls = svc_env("disabled")
    svc.enable(5, actor_user_id=1)
    assert system.agent_status == "active"
    assert calls == []


# ---------------------------------------------------------------------------
# Eviction signal client
# ---------------------------------------------------------------------------


def _client(handler):
    return httpx.Client(
        transport=httpx.MockTransport(handler), base_url="http://broker:8444"
    )


def test_signal_eviction_posts_reason_and_session():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["body"] = request.read()
        return httpx.Response(200, json={"result": "evicted", "ops": {}})

    out = signal_eviction(
        9, "revoked", expected_session_id="S1", client=_client(handler)
    )
    assert seen["path"] == "/internal/agent/sessions/9/evict"
    assert b'"reason":"revoked"' in seen["body"].replace(b" ", b"")
    assert b"S1" in seen["body"]
    assert out.delivered and out.result == "evicted"


def test_signal_eviction_sends_internal_auth_header(monkeypatch):
    captured = {}

    class Spy(httpx.Client):
        def __init__(self, **kw):
            captured.update(kw)
            super().__init__(
                base_url=kw["base_url"],
                transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})),
            )

    monkeypatch.setattr(broker_client.httpx, "Client", Spy)
    monkeypatch.setattr(
        broker_client, "_auth_headers", lambda: {"x-praxis-internal-auth": "tok"}
    )
    assert signal_eviction(9, "disabled").delivered
    assert captured["headers"] == {"x-praxis-internal-auth": "tok"}


@pytest.mark.parametrize("status", [401, 422, 500, 503])
def test_signal_eviction_non_2xx_is_not_delivered(status):
    out = signal_eviction(
        9, "disabled", client=_client(lambda r: httpx.Response(status))
    )
    assert out.delivered is False and out.error == f"http_{status}"


def test_signal_eviction_network_error_is_not_delivered_and_does_not_raise():
    def handler(_request):
        raise httpx.ConnectError("no route")

    out = signal_eviction(9, "disabled", client=_client(handler))
    assert out.delivered is False and out.error == "ConnectError"


# ---------------------------------------------------------------------------
# Transport mapping
# ---------------------------------------------------------------------------


def _transport(result=None, exc=None):
    class Fake:
        @staticmethod
        async def exec(*_a, **_k):
            if exc is not None:
                raise exc
            return result

    return AgentTransport(SimpleNamespace(id=5), Fake())  # type: ignore[arg-type]


@pytest.mark.parametrize("reason", ["agent_not_active", "identity_unverifiable"])
def test_refused_dispatch_is_transport_unavailable_not_a_fallback(reason):
    t = _transport(exc=BrokerError(reason, "x"))
    with pytest.raises(TransportUnavailable) as err:
        asyncio.run(t.run_command(["id"]))
    assert reason in str(err.value)


@pytest.mark.parametrize(
    "termination,must_say,must_not_say",
    [
        ("confirmed", "verified gone", "could not be confirmed"),
        ("not_started", "had not started", "verified gone"),
        ("unconfirmed", "could not be confirmed", "verified gone"),
    ],
)
def test_interrupted_command_reports_only_known_termination(
    termination, must_say, must_not_say
):
    reason = (
        "agent_revoked_unconfirmed" if termination == "unconfirmed" else "agent_revoked"
    )
    result = BrokerExecResult(
        outcome="cancelled",
        exit_code=None,
        stdout=b"",
        stderr=b"",
        duration_ms=1,
        error={"reason": reason, "termination": termination, "cause": "revoked"},
    )
    t = _transport(result=result)
    with pytest.raises(TransportError) as err:
        asyncio.run(t.run_command(["sleep", "60"]))
    text = str(err.value)
    assert must_say in text and must_not_say not in text
    assert "not undone" in text  # never implies side effects were rolled back
    assert not isinstance(err.value, TransportUnavailable)


def test_file_get_refusal_keeps_the_broker_reason():
    def handler(request):
        return httpx.Response(
            403,
            json={"outcome": "error", "error": {"reason": "agent_not_active"}},
        )

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://broker"
        ) as http:
            bc = BrokerClient(client=http)
            with pytest.raises(BrokerError) as err:
                await bc.file_get(5, "/etc/hostname")
            return err.value

    assert asyncio.run(run()).reason == "agent_not_active"


@pytest.mark.parametrize("body", [b"<html>gateway</html>", b"", b"[1, 2]"])
def test_file_get_malformed_refusal_still_surfaces_agent_not_active(body):
    exits = []

    class _StreamCtx:
        async def __aenter__(self):
            return httpx.Response(403, content=body)

        async def __aexit__(self, *exc):
            exits.append(exc)

    class _FakeClient:
        @staticmethod
        def stream(*_a, **_k):
            return _StreamCtx()

    async def run():
        bc = BrokerClient(client=_FakeClient())  # type: ignore[arg-type]
        with pytest.raises(BrokerError) as err:
            await bc.file_get(5, "/etc/hostname")
        return err.value

    err = asyncio.run(run())
    assert err.reason == "agent_not_active"
    assert exits == [(None, None, None)]  # the refused response was released


# ---------------------------------------------------------------------------
# Transport selection is unchanged
# ---------------------------------------------------------------------------


class _Health:
    def __init__(self, state):
        self._h = TunnelHealth(system_id=5, state=state)

    async def health(self, _system_id):
        return self._h


def _sys(pref, status="disabled"):
    return SimpleNamespace(id=5, transport_preference=pref, agent_status=status)


def test_selection_pref_agent_never_falls_back_to_ssh():
    with pytest.raises(TransportUnavailable):
        asyncio.run(get_transport(_sys("agent"), _Health("unregistered"), ssh_service=object()))  # type: ignore[arg-type]


def test_selection_follows_tunnel_health_not_status_so_dispatch_is_the_gate():
    # While the broker still reports a healthy tunnel, selection picks the
    # agent even for a disabled identity; the broker refuses at dispatch.
    got = asyncio.run(get_transport(_sys("agent"), _Health("healthy"), ssh_service=object()))  # type: ignore[arg-type]
    assert got.name == "agent"
    got = asyncio.run(get_transport(_sys("auto"), _Health("healthy"), ssh_service=object()))  # type: ignore[arg-type]
    assert got.name == "agent"


def test_selection_auto_uses_existing_down_tunnel_fallback_once_evicted():
    got = asyncio.run(get_transport(_sys("auto"), _Health("unregistered"), ssh_service=object()))  # type: ignore[arg-type]
    assert got.name == "ssh"
