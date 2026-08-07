"""PRA-159 #3: route smoke tests for POST /systems/{id}/content-profile/apply.

Covers HTTP status mapping (200/409/502) by stubbing the orchestrator;
end-to-end orchestrator behaviour is covered in
``test_pra159_content_profile_apply.py``.
"""

from __future__ import annotations

import pytest

from app.db.models import Credential, Group, System
from app.services.content_profile_apply import ApplyOutcome


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="apply-route-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="apply-route-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="apply-route.example.com",
        ip_address="10.71.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _stub_orchestrator(monkeypatch, outcome: ApplyOutcome):
    """Replace orchestrator + transport-construction deps so the
    route handler doesn't try to open a real SSH/agent transport
    or talk to the broker.
    """
    from unittest.mock import MagicMock

    from app.api.routes import content_profile_apply as route_module

    async def _fake_apply(*_a, **_k):
        return outcome

    async def _fake_get_transport(*_a, **_k):
        return object()

    class _FakeBroker:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(route_module, "apply_content_profile_to_host", _fake_apply)
    monkeypatch.setattr(route_module, "get_transport", _fake_get_transport)
    monkeypatch.setattr(route_module, "BrokerClient", lambda: _FakeBroker())
    monkeypatch.setattr(route_module, "SSHService", lambda db: MagicMock())


def test_apply_200_on_applied(authed_client, host, monkeypatch):
    _stub_orchestrator(
        monkeypatch,
        ApplyOutcome(
            state="applied",
            profile_slug="prod",
            written_paths=["/etc/x.list"],
            removed_paths=[],
            trust_installed_for_mirrors=[],
            credentials_issued_for_mirrors=["m1"],
        ),
    )
    res = authed_client.post(f"/systems/{host.id}/content-profile/apply")
    assert res.status_code == 200
    body = res.json()
    assert body["state"] == "applied"
    assert body["profile_slug"] == "prod"
    assert body["written_paths"] == ["/etc/x.list"]


def test_apply_200_on_noop(authed_client, host, monkeypatch):
    _stub_orchestrator(
        monkeypatch,
        ApplyOutcome(state="noop", profile_slug="prod"),
    )
    res = authed_client.post(f"/systems/{host.id}/content-profile/apply")
    assert res.status_code == 200
    assert res.json()["state"] == "noop"


def test_apply_409_on_no_profile(authed_client, host, monkeypatch):
    _stub_orchestrator(
        monkeypatch,
        ApplyOutcome(state="refused_no_profile"),
    )
    res = authed_client.post(f"/systems/{host.id}/content-profile/apply")
    assert res.status_code == 409
    assert res.json()["state"] == "refused_no_profile"


def test_apply_409_on_conflict(authed_client, host, monkeypatch):
    _stub_orchestrator(
        monkeypatch,
        ApplyOutcome(state="refused_conflict"),
    )
    res = authed_client.post(f"/systems/{host.id}/content-profile/apply")
    assert res.status_code == 409
    assert res.json()["state"] == "refused_conflict"


def test_apply_502_on_failed(authed_client, host, monkeypatch):
    _stub_orchestrator(
        monkeypatch,
        ApplyOutcome(state="failed", error_text="sudo password required"),
    )
    res = authed_client.post(f"/systems/{host.id}/content-profile/apply")
    assert res.status_code == 502
    body = res.json()
    assert body["state"] == "failed"
    assert "sudo password required" in body["error_text"]


def test_apply_404_unknown_system(authed_client):
    res = authed_client.post("/systems/999999/content-profile/apply")
    assert res.status_code == 404


def test_apply_requires_admin_or_maintainer(client, db, seed_roles, host):
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="aud-pra159-apply",
        email="aud@x",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    res = client.post(
        "/auth/login", data={"username": "aud-pra159-apply", "password": "testpass123"}
    )
    token = res.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    res = client.post(f"/systems/{host.id}/content-profile/apply")
    assert res.status_code == 403
