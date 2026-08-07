"""PRA-305: ad-hoc command execution 500 from SlowAPI request binding.

`POST /command-execution/execute` used to return HTTP 500 before any route logic
ran, because the endpoint named the Starlette ``Request`` ``http_request`` and bound
the Pydantic body to ``request`` — but SlowAPI's ``@limiter.limit`` resolves the
rate-limit key by looking up a parameter named exactly ``request`` typed as a
Starlette ``Request``, and raises otherwise.

The limiter is DISABLED under ``TESTING`` (so suite runs aren't throttled), which is
why a normal test would not reproduce the bug — SlowAPI skips param resolution when
disabled. These tests explicitly ENABLE the limiter so the SlowAPI binding path runs;
with the pre-fix signature they fail with a 500, and with the fix the request reaches
route logic (authorization, 404, audit).
"""

from __future__ import annotations

import pytest

from app.core.rate_limit import limiter
from app.db.access_models import AuditEvent
from app.db.models import Credential, Group, System
from app.services.command_execution_service import CommandExecutionService

# --------------------------------------------------------------------- helpers


@pytest.fixture
def limiter_enabled(monkeypatch):
    """Enable SlowAPI for the duration of the test so the rate-limit binding path
    actually runs (it is disabled under TESTING). This is what exercises — and would
    trip — the ``request`` parameter resolution that PRA-305 fixes."""
    monkeypatch.setattr(limiter, "enabled", True)
    yield


def _system(db, seed_distro, hostname):
    g = db.query(Group).filter_by(name="pra305-grp").first()
    if not g:
        g = Group(name="pra305-grp", description="x")
        db.add(g)
        db.flush()
    c = Credential(
        name=f"pra305-cred-{hostname}", auth_method="ssh_key", username="root"
    )
    db.add(c)
    db.flush()
    s = System(
        hostname=hostname,
        ip_address="10.30.5.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=c.id,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


# ------------------------------------------------------------------ regression


def test_execute_reaches_route_logic_with_limiter_enabled(
    db, client, admin_user, limiter_enabled
):
    """The core regression: with the limiter ENABLED, a valid authenticated request
    reaches route logic instead of being 500'd by SlowAPI. A nonexistent system_id
    resolves to the route's own 404 — with the pre-PRA-305 signature this same call
    returned 500 (``parameter `request` must be an instance of ...Request``)."""
    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute",
        json={"system_id": 999999, "command": "echo hi"},
    )
    assert res.status_code == 404, res.text
    assert "System not found" in res.text
    assert "starlette.requests.Request" not in res.text


def test_execute_authz_denies_before_execution_and_audits(
    db, client, maintainer_user, seed_distro, limiter_enabled, monkeypatch
):
    """Fleet-scope authorization still runs BEFORE execution (the executor is never
    reached on denial) and the denial audit is emitted with the actor IP wired from
    the Starlette request — both downstream of the fixed request binding.

    The actor-IP VALUE is asserted via a spy on ``safe_emit`` rather than the stored
    row's value: this Starlette TestClient transport does not populate
    ``request.client`` (so the peer IP is ``None`` here), but the endpoint still
    derives ``actor_ip`` from ``request.client`` and passes it to the audit — which is
    the wiring PRA-305 must not regress. In a real deployment ``request.client`` is
    populated and carries the peer IP."""
    s = _system(db, seed_distro, "pra305-denied")

    called = {"n": 0}

    def _boom(self, **kwargs):  # pragma: no cover - must never run on denial
        called["n"] += 1
        return {}

    monkeypatch.setattr(CommandExecutionService, "execute_command", _boom)

    import app.services.audit_event_service as aes

    emits = []
    real_safe_emit = aes.safe_emit

    def _spy(**kwargs):
        emits.append(kwargs)
        return real_safe_emit(**kwargs)

    monkeypatch.setattr(aes, "safe_emit", _spy)

    # maintainer holds no grant on this system -> enforce_action denies.
    _login(client, maintainer_user)
    res = client.post(
        "/command-execution/execute",
        json={"system_id": s.id, "command": "echo hi"},
    )
    assert res.status_code == 403, res.text
    assert called["n"] == 0, "authorization must run before command execution"

    denials = [
        e
        for e in emits
        if e.get("action") == "command.exec" and e.get("outcome") == "denied"
    ]
    assert denials, "denial must be audited"
    ev = denials[-1]
    assert ev["target_system_id"] == s.id
    # actor_ip is wired from the Starlette request (request.client); the key must be
    # passed through even when the test transport leaves the peer address unset.
    assert "actor_ip" in ev

    # The denial row is also persisted.
    row = (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "command.exec", AuditEvent.outcome == "denied")
        .order_by(AuditEvent.id.desc())
        .first()
    )
    assert row is not None and row.target_system_id == s.id


def test_execute_still_works_with_limiter_disabled(db, client, admin_user):
    """Sanity: the normal TESTING path (limiter disabled) also reaches route logic —
    the fix does not depend on the limiter being enabled."""
    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute",
        json={"system_id": 999999, "command": "echo hi"},
    )
    assert res.status_code == 404, res.text
