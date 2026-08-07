"""PRA-180 Remediation 2A (PRA-219): unified audit events for secret/Vault/PKI.

Proves the newly covered sensitive actions emit AuditEvent rows (which fan out
to external sinks via the existing pipeline) and that no secret value lands in
the event context.
"""

import json

import pytest

from app.db.access_models import AuditEvent
from app.db.models import Credential


def _events(db, action):
    return db.query(AuditEvent).filter(AuditEvent.action == action).all()


def _context_blob(db, action):
    """Concatenated context_json of all events for an action (redaction check)."""
    return " ".join((e.context_json or "") for e in _events(db, action))


# ── Credential actions (mock_vault patches credentials.VaultService) ───────


def test_credential_reveal_emits_audit_without_secret(authed_client, mock_vault, db):
    vault_path = "praxis/credentials/revealme"
    mock_vault.secrets[vault_path] = {"username": "svc", "password": "hunter2-secret"}
    cred = Credential(
        name="revealme",
        auth_method="password",
        username="svc",
        vault_path=vault_path,
    )
    db.add(cred)
    db.flush()

    res = authed_client.get(f"/credentials/{cred.id}/secret")
    assert res.status_code == 200, res.text
    # The endpoint DOES return the secret to the caller...
    assert res.json()["data"]["password"] == "hunter2-secret"

    events = _events(db, "credential.secret.reveal")
    assert len(events) == 1
    ev = events[0]
    assert ev.target_kind == "credential"
    assert ev.target_id == str(cred.id)
    assert ev.actor_username == "admintest"
    # ...but the secret must NOT be in the audit context.
    assert "hunter2-secret" not in (ev.context_json or "")
    ctx = json.loads(ev.context_json or "{}")
    assert ctx["name"] == "revealme"
    assert "password" not in ctx


def test_credential_create_emits_audit_without_secret(authed_client, mock_vault, db):
    res = authed_client.post(
        "/credentials",
        json={
            "name": "newcred",
            "auth_method": "password",
            "username": "svc",
            "password": "topsecret-pw",
        },
    )
    assert res.status_code == 201, res.text

    blob = _context_blob(db, "credential.create")
    assert blob, "expected a credential.create audit event"
    assert "topsecret-pw" not in blob


def test_credential_delete_emits_audit(authed_client, mock_vault, db):
    cred = Credential(
        name="deleteme",
        auth_method="password",
        username="svc",
        vault_path="praxis/credentials/deleteme",
    )
    db.add(cred)
    db.flush()
    cred_id = cred.id

    res = authed_client.delete(f"/credentials/{cred_id}")
    assert res.status_code == 204, res.text

    events = _events(db, "credential.delete")
    assert any(e.target_id == str(cred_id) for e in events)


# ── Direct Vault secret actions (stub VaultService at the route) ───────────


class _StubVault:
    """Minimal VaultService stand-in for the vault secrets routes."""

    def __init__(self, db):
        self._db = db

    def read_secret(self, path):
        return {"password": "vault-secret-value"}

    def read_secret_metadata(self, path):
        return {"current_version": 1, "versions": {"1": {"created_time": "t"}}}

    def write_secret(self, path, data):
        return True

    def delete_secret(self, path):
        return True

    def update_secret_password(self, path, username, new_password):
        return True


class _StubVaultNoMeta(_StubVault):
    """Value read succeeds but metadata lookup fails (PRA-219 ordering fix)."""

    def read_secret_metadata(self, path):
        return None


@pytest.fixture
def _stub_vault_secrets_route(monkeypatch):
    monkeypatch.setattr("app.api.routes.vault.secrets.VaultService", _StubVault)


def test_vault_secret_read_emits_audit_without_value(
    authed_client, _stub_vault_secrets_route, db
):
    res = authed_client.get("/vault/secrets/secret", params={"path": "praxis/foo"})
    assert res.status_code == 200, res.text

    events = _events(db, "vault.secret.read")
    assert len(events) == 1
    ev = events[0]
    assert ev.target_kind == "vault_secret"
    assert ev.target_id == "praxis/foo"
    assert "vault-secret-value" not in (ev.context_json or "")


def test_vault_secret_write_and_delete_emit_audit(
    authed_client, _stub_vault_secrets_route, db
):
    res = authed_client.post(
        "/vault/secrets/secret",
        json={"path": "praxis/bar", "data": {"password": "should-not-log"}},
    )
    assert res.status_code == 201, res.text
    assert _events(db, "vault.secret.write")
    assert "should-not-log" not in _context_blob(db, "vault.secret.write")

    res = authed_client.request(
        "DELETE", "/vault/secrets/secret", params={"path": "praxis/bar"}
    )
    assert res.status_code == 200, res.text
    assert _events(db, "vault.secret.delete")


# ── SSH CA lifecycle (stub the service so no real Vault/SSH pool work) ─────


def test_vault_secret_read_audited_even_if_metadata_fails(
    authed_client, monkeypatch, db
):
    """PRA-219 review fix: a successful secret-value read is audited even if the
    later metadata lookup fails and the request errors out.

    (The endpoint's pre-existing broad ``except`` re-wraps the not-found as 500;
    that 404-vs-500 quirk is out of PRA-219 scope. What matters here is that the
    audit event fired *before* the failing metadata step.)"""
    monkeypatch.setattr("app.api.routes.vault.secrets.VaultService", _StubVaultNoMeta)
    res = authed_client.get("/vault/secrets/secret", params={"path": "praxis/meta"})
    assert res.status_code >= 400, res.text
    events = _events(db, "vault.secret.read")
    assert len(events) == 1, "secret value was accessed; it must be audited"
    assert events[0].target_id == "praxis/meta"


def test_vault_secret_password_update_emits_audit(
    authed_client, _stub_vault_secrets_route, db
):
    res = authed_client.patch(
        "/vault/secrets/secret/password",
        json={
            "path": "praxis/pw",
            "username": "svc",
            "new_password": "do-not-log-this",
        },
    )
    assert res.status_code == 200, res.text
    events = _events(db, "vault.secret.password_update")
    assert len(events) == 1
    assert events[0].target_id == "praxis/pw"
    assert "do-not-log-this" not in (events[0].context_json or "")


def test_ca_rotate_emits_audit(authed_client, monkeypatch, db):
    monkeypatch.setattr(
        "app.api.routes.ssh_identity.ca_rotation_service.rotate_ca",
        lambda db, performed_by: {"rotated": True},
    )
    res = authed_client.post("/ssh-identity/rotate-ca")
    assert res.status_code == 200, res.text

    events = _events(db, "ssh.ca.rotate")
    assert len(events) == 1
    assert events[0].target_kind == "ssh_ca"
    assert events[0].actor_username == "admintest"


def test_ca_revoke_user_certs_emits_audit(authed_client, monkeypatch, db):
    monkeypatch.setattr(
        "app.api.routes.ssh_identity.ca_rotation_service.revoke_user_certs",
        lambda db, performed_by: {"revoked": True},
    )
    res = authed_client.post("/ssh-identity/revoke-user-certs")
    assert res.status_code == 200, res.text
    events = _events(db, "ssh.ca.revoke_user_certs")
    assert len(events) == 1
    assert events[0].target_kind == "ssh_ca"


def test_credential_update_emits_audit_without_secret(authed_client, mock_vault, db):
    vault_path = "praxis/credentials/updme"
    mock_vault.secrets[vault_path] = {"username": "svc", "password": "old"}
    cred = Credential(
        name="updme",
        auth_method="password",
        username="svc",
        vault_path=vault_path,
    )
    db.add(cred)
    db.flush()

    res = authed_client.put(
        f"/credentials/{cred.id}",
        json={"password": "new-secret-value"},
    )
    assert res.status_code == 200, res.text
    events = _events(db, "credential.update")
    assert any(e.target_id == str(cred.id) for e in events)
    assert "new-secret-value" not in _context_blob(db, "credential.update")


# ── SSH user-cert signing emission (PRA-219 review fix) ────────────────────


def test_user_cert_sign_helper_emits_without_cert_material(db, admin_user):
    """The shared emitter records a unified ssh.user_cert.sign event and, by
    construction, can only carry non-secret identifiers."""
    from app.services.audit_event_service import emit_user_cert_sign

    # system_id omitted here so the unit test doesn't need a real System row
    # (target_system_id is a FK); the session path passes a valid system.id.
    emit_user_cert_sign(
        db,
        actor_user_id=admin_user.id,
        actor_username=admin_user.username,
        actor_ip="10.0.0.9",
        login="root",
        ttl_s=300,
        key_id="praxis-session-1-42-1700000000",
        purpose="session",
    )

    events = _events(db, "ssh.user_cert.sign")
    assert len(events) == 1
    ev = events[0]
    assert ev.target_kind == "ssh_user_cert"
    assert ev.actor_username == admin_user.username
    ctx = json.loads(ev.context_json or "{}")
    assert ctx == {
        "login": "root",
        "ttl_s": 300,
        "cert_serial": "praxis-session-1-42-1700000000",
        "purpose": "session",
    }
