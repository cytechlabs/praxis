"""PRA-158 #4a: /mirror-upstream-keys CRUD route tests."""

from __future__ import annotations

import pytest

from app.db.models import MirrorUpstreamKey
from app.services.mirror_gpg import (
    ephemeral_gnupg_home,
    export_public_armored,
    generate_keypair,
    gpg_available,
)

skip_without_gpg = pytest.mark.skipif(
    not gpg_available(),
    reason="needs gpg on PATH (present in backend image; absent on hosted CI)",
)


def _real_armored(slug: str) -> tuple[str, str]:
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, slug)
        return fpr, export_public_armored(home, fpr)


# ---------------------------------------------------------------------------
# GET /mirror-upstream-keys
# ---------------------------------------------------------------------------


def test_list_empty_when_none_imported(authed_client):
    res = authed_client.get("/mirror-upstream-keys")
    assert res.status_code == 200
    assert res.json() == {"keys": []}


@skip_without_gpg
def test_list_returns_imported_keys(authed_client, db):
    fpr_a, armored_a = _real_armored("list-a")
    fpr_b, armored_b = _real_armored("list-b")
    db.add_all(
        [
            MirrorUpstreamKey(
                name="Bravo",
                gpg_fingerprint=fpr_a,
                armored_public_key=armored_a,
            ),
            MirrorUpstreamKey(
                name="Alpha",
                gpg_fingerprint=fpr_b,
                armored_public_key=armored_b,
            ),
        ]
    )
    db.commit()

    res = authed_client.get("/mirror-upstream-keys")
    assert res.status_code == 200
    body = res.json()
    assert len(body["keys"]) == 2
    # Ordered alphabetically by name.
    assert [k["name"] for k in body["keys"]] == ["Alpha", "Bravo"]


def test_list_requires_auth(client):
    res = client.get("/mirror-upstream-keys")
    assert res.status_code == 401


# ---------------------------------------------------------------------------
# POST /mirror-upstream-keys
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_create_imports_armored_and_returns_metadata(authed_client):
    fpr, armored = _real_armored("create-test")
    res = authed_client.post(
        "/mirror-upstream-keys",
        json={
            "name": "Test Archive Key",
            "armored_public_key": armored,
            "notes": "imported during slice 4 testing",
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["name"] == "Test Archive Key"
    assert body["gpg_fingerprint"] == fpr
    assert body["armored_public_key"] == armored
    assert body["notes"] == "imported during slice 4 testing"
    assert "id" in body and "created_at" in body


@skip_without_gpg
def test_create_400_on_malformed_body(authed_client):
    res = authed_client.post(
        "/mirror-upstream-keys",
        json={"name": "Bogus", "armored_public_key": "not a real key"},
    )
    assert res.status_code == 400
    assert "import" in res.json()["detail"].lower()


def test_create_400_on_empty_name(authed_client):
    res = authed_client.post(
        "/mirror-upstream-keys",
        json={"name": "", "armored_public_key": "irrelevant"},
    )
    assert res.status_code == 400


@skip_without_gpg
def test_create_409_on_duplicate_fingerprint(authed_client):
    _, armored = _real_armored("dup-route")
    first = authed_client.post(
        "/mirror-upstream-keys",
        json={"name": "First", "armored_public_key": armored},
    )
    assert first.status_code == 201

    second = authed_client.post(
        "/mirror-upstream-keys",
        json={"name": "Second", "armored_public_key": armored},
    )
    assert second.status_code == 409
    assert "already imported" in second.json()["detail"]


def test_create_403_for_auditor(client, db, seed_roles):
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="upstream-auditor",
        email="upstream-auditor@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    login = client.post(
        "/auth/login",
        data={"username": "upstream-auditor", "password": "testpass123"},
    )
    token = login.json()["access_token"]
    res = client.post(
        "/mirror-upstream-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Auditor", "armored_public_key": "irrelevant"},
    )
    assert res.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /mirror-upstream-keys/{id}
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_delete_returns_204_and_removes_row(authed_client, db):
    fpr, armored = _real_armored("delete-route")
    row = MirrorUpstreamKey(
        name="Delete Me",
        gpg_fingerprint=fpr,
        armored_public_key=armored,
    )
    db.add(row)
    db.commit()
    row_id = row.id

    res = authed_client.delete(f"/mirror-upstream-keys/{row_id}")
    assert res.status_code == 204
    assert (
        db.query(MirrorUpstreamKey).filter(MirrorUpstreamKey.id == row_id).one_or_none()
        is None
    )


def test_delete_404_on_missing(authed_client):
    res = authed_client.delete("/mirror-upstream-keys/99999")
    assert res.status_code == 404


def test_delete_403_for_auditor(client, db, seed_roles):
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="upstream-auditor-del",
        email="upstream-auditor-del@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    login = client.post(
        "/auth/login",
        data={"username": "upstream-auditor-del", "password": "testpass123"},
    )
    token = login.json()["access_token"]
    res = client.delete(
        "/mirror-upstream-keys/1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
