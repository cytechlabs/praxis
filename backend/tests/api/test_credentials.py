"""Integration tests for the credentials CRUD routes.

Covers both credential creation modes:
- managed: inline secret in request → backend writes to Vault
- linked:  vault_path only → backend reads existing Vault secret, skips write
"""

from app.db.models import Credential


def _create_managed(client, **overrides):
    body = {
        "name": "prod-root",
        "auth_method": "password",
        "username": "root",
        "password": "s3cret",
        "sudo_method": "none",
    }
    body.update(overrides)
    return client.post("/credentials", json=body)


def test_create_managed_credential_writes_to_vault(authed_client, mock_vault, db):
    res = _create_managed(authed_client)
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["name"] == "prod-root"
    assert body["auth_method"] == "password"
    assert body["username"] == "root"
    assert body["vault_path"] == "praxis/credentials/prod-root"

    assert mock_vault.secrets["praxis/credentials/prod-root"] == {"password": "s3cret"}

    row = db.query(Credential).filter_by(name="prod-root").one()
    assert row.vault_path == "praxis/credentials/prod-root"


def test_create_managed_requires_username_and_password(authed_client):
    res = authed_client.post(
        "/credentials",
        json={"name": "missing", "auth_method": "password", "sudo_method": "none"},
    )
    assert res.status_code == 422
    detail = res.json()["detail"]
    assert any("password" in d["loc"] for d in detail)
    assert any("username" in d["loc"] for d in detail)


def test_create_ssh_key_credential(authed_client, mock_vault):
    res = authed_client.post(
        "/credentials",
        json={
            "name": "ci-bot",
            "auth_method": "ssh_key",
            "username": "ci",
            "ssh_key": "-----BEGIN TEST KEY-----\nblah\n-----END TEST KEY-----",
        },
    )
    assert res.status_code == 201, res.text
    assert "ssh_key" in mock_vault.secrets["praxis/credentials/ci-bot"]


def test_create_linked_credential_reads_existing_secret(authed_client, mock_vault):
    """Vault secret already exists; create credential should not overwrite."""
    mock_vault.secrets["praxis/prefilled"] = {
        "username": "svc",
        "password": "from-vault",
    }

    res = authed_client.post(
        "/credentials",
        json={
            "name": "prefilled-cred",
            "auth_method": "password",
            "vault_path": "praxis/prefilled",
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["username"] == "svc", "username pulled from vault secret"
    assert body["vault_path"] == "praxis/prefilled"
    # Secret data unchanged (no overwrite)
    assert mock_vault.secrets["praxis/prefilled"] == {
        "username": "svc",
        "password": "from-vault",
    }


def test_create_linked_credential_rejects_missing_vault_secret(
    authed_client, mock_vault
):
    res = authed_client.post(
        "/credentials",
        json={
            "name": "orphan",
            "auth_method": "password",
            "vault_path": "praxis/does-not-exist",
        },
    )
    assert res.status_code == 400
    assert "Vault secret not found" in res.json()["detail"]


def test_create_linked_credential_rejects_secret_missing_password_key(
    authed_client, mock_vault
):
    mock_vault.secrets["praxis/keyless"] = {"username": "svc"}
    res = authed_client.post(
        "/credentials",
        json={
            "name": "keyless",
            "auth_method": "password",
            "vault_path": "praxis/keyless",
        },
    )
    assert res.status_code == 400
    assert "missing the 'password' key" in res.json()["detail"]


def test_create_duplicate_name_rejected(authed_client, mock_vault):
    _create_managed(authed_client, name="dupe")
    res = _create_managed(authed_client, name="dupe")
    assert res.status_code == 400
    assert "already exists" in res.json()["detail"]


def test_list_credentials_returns_created(authed_client, mock_vault):
    _create_managed(authed_client, name="listtest")
    res = authed_client.get("/credentials")
    assert res.status_code == 200
    names = [c["name"] for c in res.json()]
    assert "listtest" in names


def test_get_credential_by_id(authed_client, mock_vault):
    created = _create_managed(authed_client, name="getbyid").json()
    res = authed_client.get(f"/credentials/{created['id']}")
    assert res.status_code == 200
    assert res.json()["name"] == "getbyid"


def test_get_credential_404(authed_client):
    res = authed_client.get("/credentials/99999")
    assert res.status_code == 404


def test_delete_credential(authed_client, mock_vault, db):
    created = _create_managed(authed_client, name="deletable").json()
    res = authed_client.delete(f"/credentials/{created['id']}")
    assert res.status_code in (200, 204)
    assert db.query(Credential).filter_by(id=created["id"]).first() is None


def test_create_requires_write_role(client, auditor_user, mock_vault):
    """Auditor role should not be able to create credentials."""
    res = client.post(
        "/auth/login",
        data={"username": auditor_user.username, "password": "testpass123"},
    )
    token = res.json()["access_token"]
    res = client.post(
        "/credentials",
        json={
            "name": "forbidden",
            "auth_method": "password",
            "username": "x",
            "password": "y",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
