"""PRA-158 slice #1: signing-key API route tests.

Surface under test:
  * ``POST /mirrors/{id}/signing-key`` — bootstrap, idempotent
  * ``GET  /mirrors/{id}/signing-key`` — read active

Locks asserted here:
  * Status field is exactly ``no_key_yet`` or ``key_ready`` — never
    ``trusted`` / ``signed_ok`` (slice #2 wires real signing).
  * Response NEVER includes private key material.
  * RBAC: bootstrap requires admin or maintainer.
"""

from __future__ import annotations

import pytest

from app.db.models import MirrorRepo
from app.services import mirror_signing_key_service as svc_module
from tests.helpers.armor import pgp_private_block

_TEST_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"


@pytest.fixture
def patch_gpg(monkeypatch):
    """Same fake-gpg shim as the service-level test, scoped here so
    the route tests never spawn a real subprocess.
    """

    def fake_generate(home, slug):
        return _TEST_FPR

    def fake_export_secret(home, fpr):
        return pgp_private_block(f"FAKE-SECRET-{fpr}")

    def fake_export_public(home, fpr):
        return (
            f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUBLIC-{fpr}\n-----END-----\n"
        )

    monkeypatch.setattr(svc_module.mirror_gpg, "generate_keypair", fake_generate)
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_secret_armored", fake_export_secret
    )
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_public_armored", fake_export_public
    )


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="test-ubuntu-jammy",
        display_name="Test Ubuntu Jammy",
        package_family="deb",
        upstream_url="http://example.com/ubuntu",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


# ---------------------------------------------------------------------------
# POST /mirrors/{id}/signing-key — idempotent bootstrap
# ---------------------------------------------------------------------------


def test_bootstrap_creates_key_first_call(authed_client, patch_gpg, mirror):
    res = authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["created"] is True
    assert body["mirror_signing_status"] == "key_ready"
    key = body["key"]
    assert key["status"] == "active"
    assert key["gpg_fingerprint"] == _TEST_FPR
    assert "Praxis Mirror Signing test-ubuntu-jammy" in key["key_uid"]
    assert "BEGIN PGP PUBLIC KEY BLOCK" in key["public_key_armored"]


def test_bootstrap_is_idempotent(authed_client, patch_gpg, mirror):
    first = authed_client.post(f"/mirrors/{mirror.id}/signing-key").json()
    second = authed_client.post(f"/mirrors/{mirror.id}/signing-key").json()
    assert first["created"] is True
    assert second["created"] is False
    assert second["mirror_signing_status"] == "key_ready"
    assert first["key"]["id"] == second["key"]["id"]
    assert first["key"]["gpg_fingerprint"] == second["key"]["gpg_fingerprint"]


def test_bootstrap_404_on_missing_mirror(authed_client, patch_gpg):
    res = authed_client.post("/mirrors/99999/signing-key")
    assert res.status_code == 404


def test_bootstrap_404_on_soft_deleted_mirror(authed_client, patch_gpg, db, mirror):
    from datetime import datetime

    mirror.deleted_at = datetime.utcnow()
    db.commit()
    res = authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    assert res.status_code == 404


def test_bootstrap_response_has_no_private_material(authed_client, patch_gpg, mirror):
    """Belt-and-suspenders: assert the exact field shape so a future
    schema regression that adds ``private_armored`` (or similar) would
    break the test.
    """
    res = authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    body = res.json()
    serialized = res.text.lower()
    assert "private" not in serialized or "begin pgp public" in serialized
    # Stronger: the key block in the response is exactly the public set.
    expected_keys = {
        "id",
        "mirror_repo_id",
        "status",
        "gpg_fingerprint",
        "key_uid",
        "cutover_at",
        "retired_at",
        "created_at",
        "public_key_armored",
    }
    assert set(body["key"].keys()) == expected_keys


def test_bootstrap_status_field_is_locked_vocabulary(authed_client, patch_gpg, mirror):
    """Locked vocabulary: status must be no_key_yet|key_ready until the
    signing engine lands. Reject any stray "trusted" or "signed_ok"
    wording.
    """
    res = authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    body = res.json()
    assert body["mirror_signing_status"] in {"no_key_yet", "key_ready"}
    assert "trusted" not in res.text.lower()
    assert "signed_ok" not in res.text.lower()


# ---------------------------------------------------------------------------
# GET /mirrors/{id}/signing-key — read active or 404
# ---------------------------------------------------------------------------


def test_get_active_404_when_no_key(authed_client, mirror):
    res = authed_client.get(f"/mirrors/{mirror.id}/signing-key")
    assert res.status_code == 404
    assert "no_key_yet" in res.json()["detail"]


def test_get_active_returns_metadata_and_public_armored(
    authed_client, patch_gpg, mirror
):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    res = authed_client.get(f"/mirrors/{mirror.id}/signing-key")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "active"
    assert body["gpg_fingerprint"] == _TEST_FPR
    assert "BEGIN PGP PUBLIC KEY BLOCK" in body["public_key_armored"]
    assert "private" not in body or "BEGIN PGP PUBLIC" in body.get(
        "public_key_armored", ""
    )


# ---------------------------------------------------------------------------
# RBAC — bootstrap is admin/maintainer only; read is any auth'd user
# ---------------------------------------------------------------------------


def test_bootstrap_requires_maintainer_or_admin(
    client, patch_gpg, mirror, db, seed_roles
):
    """Auditor (read-only role) cannot bootstrap a signing key."""
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="route-auditor",
        email="route-auditor@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    login = client.post(
        "/auth/login",
        data={"username": "route-auditor", "password": "testpass123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    res = client.post(
        f"/mirrors/{mirror.id}/signing-key",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403


def test_get_active_open_to_any_authed_user(
    client, patch_gpg, mirror, authed_client, db, seed_roles
):
    """Auditor can read the active key (it's public material)."""
    from app.core.auth import get_password_hash
    from app.db.models import User

    # Bootstrap as admin first.
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")

    auditor = User(
        username="route-auditor-read",
        email="route-auditor-read@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    login = client.post(
        "/auth/login",
        data={"username": "route-auditor-read", "password": "testpass123"},
    )
    token = login.json()["access_token"]
    res = client.get(
        f"/mirrors/{mirror.id}/signing-key",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
