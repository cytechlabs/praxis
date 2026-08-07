"""Route-level tests for /agent endpoints (PRA-150).

Stubs SSHService.test_connection and AgentIdentityService._sign so the
test stays in-process. Validates auth gating, SSH-success-only bootstrap
proof, and the response shapes of every endpoint.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.models import Credential, Distro, Group, System


@pytest.fixture
def system_row(db):
    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if distro is None:
        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()
    group = db.query(Group).filter_by(name="Default").first()
    if group is None:
        group = Group(name="Default")
        db.add(group)
        db.flush()
    cred = db.query(Credential).filter_by(name="route-cred").first()
    if cred is None:
        cred = Credential(
            name="route-cred",
            auth_method="password",
            username="root",
            vault_path="v/route",
        )
        db.add(cred)
        db.flush()
    s = System(
        hostname="route-host",
        ip_address="10.10.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _ssh_ok(*_, **__):
    return {"status": "success", "message": "ok"}


def _ssh_warn(*_, **__):
    return {"status": "warning", "message": "Authentication failed"}


def _stub_sign_response(serial="serial-route", expires_in=timedelta(hours=1)):
    def _impl(self, system, csr_pem):  # noqa: ARG001
        return {
            "certificate": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
            "serial_number": serial,
            "fingerprint": "fp-route",
            "expires_at": datetime.utcnow() + expires_in,
            "ca_chain": ["ca-pem"],
            "issuing_ca": "ca-pem",
        }

    return _impl


# ---------------------------------------------------------------------------
# auth gating
# ---------------------------------------------------------------------------


def test_bootstrap_requires_admin_auth(client, system_row):
    res = client.post(f"/agent/bootstrap/{system_row.id}", json={"csr_pem": "csr"})
    assert res.status_code in (401, 403)


def test_status_returns_404_for_unknown_system(authed_client):
    res = authed_client.get("/agent/status/9999")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------


def test_bootstrap_rejects_when_ssh_warning(authed_client, system_row):
    with patch(
        "app.api.routes.agent.SSHService.test_connection", side_effect=_ssh_warn
    ):
        res = authed_client.post(
            f"/agent/bootstrap/{system_row.id}", json={"csr_pem": "csr"}
        )
    assert res.status_code == 502
    assert "Authentication failed" in res.json()["detail"]


def test_bootstrap_signs_and_returns_cert(authed_client, system_row):
    with patch(
        "app.api.routes.agent.SSHService.test_connection", side_effect=_ssh_ok
    ), patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign_response(),
    ):
        res = authed_client.post(
            f"/agent/bootstrap/{system_row.id}", json={"csr_pem": "csr"}
        )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["serial_number"] == "serial-route"
    assert body["agent_status"] == "active"
    assert body["fingerprint"] == "fp-route"


# ---------------------------------------------------------------------------
# disable / enable / revoke + status
# ---------------------------------------------------------------------------


def test_disable_enable_revoke_round_trip(authed_client, system_row):
    # First enroll
    with patch(
        "app.api.routes.agent.SSHService.test_connection", side_effect=_ssh_ok
    ), patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign_response(),
    ):
        bootstrap = authed_client.post(
            f"/agent/bootstrap/{system_row.id}", json={"csr_pem": "csr"}
        )
        assert bootstrap.status_code == 200, bootstrap.text

    # Disable
    res = authed_client.post(
        f"/agent/disable/{system_row.id}", json={"reason": "scheduled maintenance"}
    )
    assert res.status_code == 200
    assert res.json()["agent_status"] == "disabled"
    assert res.json()["agent_status_reason"] == "scheduled maintenance"

    # Enable
    res = authed_client.post(f"/agent/enable/{system_row.id}")
    assert res.status_code == 200
    assert res.json()["agent_status"] == "active"
    assert res.json()["agent_status_reason"] is None

    # Revoke (terminal)
    res = authed_client.post(
        f"/agent/revoke/{system_row.id}", json={"reason": "key compromise"}
    )
    assert res.status_code == 200
    assert res.json()["agent_status"] == "revoked"
    assert res.json()["agent_revocation_reason"] == "key compromise"
    assert res.json()["agent_revoked_at"] is not None

    # Status reflects revoked
    status_res = authed_client.get(f"/agent/status/{system_row.id}")
    assert status_res.status_code == 200
    assert status_res.json()["agent_status"] == "revoked"


def test_revoke_requires_reason(authed_client, system_row):
    res = authed_client.post(f"/agent/revoke/{system_row.id}", json={})
    assert res.status_code == 422


def test_renew_admin_gated_and_calls_service(authed_client, system_row):
    with patch(
        "app.api.routes.agent.SSHService.test_connection", side_effect=_ssh_ok
    ), patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign_response(serial="boot-1"),
    ):
        authed_client.post(f"/agent/bootstrap/{system_row.id}", json={"csr_pem": "csr"})

    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign_response(serial="renewed-2"),
    ):
        res = authed_client.post(
            f"/agent/renew/{system_row.id}", json={"csr_pem": "csr2"}
        )
    assert res.status_code == 200, res.text
    assert res.json()["serial_number"] == "renewed-2"


def test_renew_denied_when_not_active(authed_client, system_row):
    # Never enrolled — renewal should be 400
    res = authed_client.post(f"/agent/renew/{system_row.id}", json={"csr_pem": "csr"})
    assert res.status_code == 400
    assert "renewal denied" in res.json()["detail"]


# ---------------------------------------------------------------------------
# /agent/ca-bundle (PRA-151 task #19)
# ---------------------------------------------------------------------------


def test_ca_bundle_anonymous_returns_both_roots(client, monkeypatch, tmp_path):
    """Anonymous endpoint, no auth header. Returns both CA PEMs."""
    from app.api.routes import agent as agent_route

    agent_pem = "-----BEGIN CERTIFICATE-----\nAGENT_CA\n-----END CERTIFICATE-----\n"
    broker_pem = "-----BEGIN CERTIFICATE-----\nBROKER_CA\n-----END CERTIFICATE-----\n"
    a = tmp_path / "agent-ca.pem"
    b = tmp_path / "broker-ca.pem"
    a.write_text(agent_pem)
    b.write_text(broker_pem)
    monkeypatch.setenv("PRAXIS_AGENT_CA_CERT", str(a))
    monkeypatch.setenv("PRAXIS_BROKER_CA_CERT", str(b))
    agent_route._invalidate_ca_bundle_cache()

    # No Authorization header on `client` — proves the bypass works.
    res = client.get("/agent/ca-bundle")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body == {"agent_ca": agent_pem, "broker_ca": broker_pem}


def test_ca_bundle_503_when_files_missing(client, monkeypatch, tmp_path):
    """Both files must exist; partial bundle = silent misconfig =
    angry agents. 503 instead."""
    from app.api.routes import agent as agent_route

    a = tmp_path / "agent-ca.pem"
    a.write_text("-----BEGIN CERTIFICATE-----\nAGENT\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("PRAXIS_AGENT_CA_CERT", str(a))
    monkeypatch.setenv("PRAXIS_BROKER_CA_CERT", str(tmp_path / "does_not_exist.pem"))
    agent_route._invalidate_ca_bundle_cache()

    res = client.get("/agent/ca-bundle")
    assert res.status_code == 503
    assert "broker" in res.json()["detail"].lower()


def test_ca_bundle_caches_within_window(client, monkeypatch, tmp_path):
    """Second hit within the cache window does not re-read disk."""
    from app.api.routes import agent as agent_route

    a = tmp_path / "agent-ca.pem"
    b = tmp_path / "broker-ca.pem"
    a.write_text("v1-agent")
    b.write_text("v1-broker")
    monkeypatch.setenv("PRAXIS_AGENT_CA_CERT", str(a))
    monkeypatch.setenv("PRAXIS_BROKER_CA_CERT", str(b))
    agent_route._invalidate_ca_bundle_cache()

    res1 = client.get("/agent/ca-bundle")
    assert res1.json()["agent_ca"] == "v1-agent"

    # Mutate the file but DON'T invalidate the cache. Second hit should
    # still see the cached value.
    a.write_text("v2-agent")
    res2 = client.get("/agent/ca-bundle")
    assert res2.json()["agent_ca"] == "v1-agent"

    # After invalidation we read fresh.
    agent_route._invalidate_ca_bundle_cache()
    res3 = client.get("/agent/ca-bundle")
    assert res3.json()["agent_ca"] == "v2-agent"


def test_other_agent_routes_still_require_auth(client, system_row):
    """Defensive: the auth bypass is exact-path /agent/ca-bundle only.
    Every other /agent/* route must still 401/403 unauthenticated."""
    paths = [
        ("POST", f"/agent/bootstrap/{system_row.id}"),
        ("POST", f"/agent/renew/{system_row.id}"),
        ("POST", f"/agent/disable/{system_row.id}"),
        ("POST", f"/agent/enable/{system_row.id}"),
        ("POST", f"/agent/revoke/{system_row.id}"),
        ("GET", f"/agent/status/{system_row.id}"),
    ]
    for method, path in paths:
        res = client.request(method, path, json={})
        assert res.status_code in (401, 403), f"{method} {path} → {res.status_code}"
