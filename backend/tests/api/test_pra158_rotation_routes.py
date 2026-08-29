"""PRA-158 #5b: rotation endpoint tests.

Surface under test:
  * POST /mirrors/{id}/signing-key/rotate-prepare
  * GET  /mirrors/{id}/signing-key/cutover-preview
  * POST /mirrors/{id}/signing-key/cutover  (body: {force?})
  * POST /mirrors/{id}/signing-key/retire/{key_id}

Locks asserted:
  * RBAC: admin/maintainer for all four. Auditor → 403.
  * 409 with structured ``{detail, preview}`` body when cutover would
    block (the preview shape the UI renders pre-action).
  * Force-cutover threads ``current_user.id`` to the service so the
    audit event captures the actor.
  * Retire returns 404 vs 409 distinguishing "not found / wrong
    mirror" from "wrong source status".
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.db.models import (
    Credential,
    Group,
    HostMirrorTrust,
    MirrorRepo,
    MirrorSigningKey,
    System,
)
from app.services import mirror_signing_key_service as svc_module
from tests.helpers.armor import pgp_private_block

_ACTIVE_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
_PENDING_FPR = "B" * 40


@pytest.fixture
def patch_gpg(monkeypatch):
    fingerprints = iter([_ACTIVE_FPR, _PENDING_FPR, "C" * 40, "D" * 40])

    def fake_generate(home, slug):
        return next(fingerprints)

    def fake_export_secret(home, fpr):
        return pgp_private_block(f"FAKE-{fpr}")

    def fake_export_public(home, fpr):
        return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-{fpr}\n-----END-----\n"

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
        slug="rotate-routes",
        display_name="Rotate Routes",
        package_family="deb",
        upstream_url="http://example.com/ubuntu",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        verify_upstream_signature=False,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _make_host(db, seed_distro, hostname: str) -> System:
    grp = Group(name=f"rt-grp-{hostname}", description="rotation routes")
    db.add(grp)
    db.flush()
    cred = Credential(
        name=f"rt-cred-{hostname}", auth_method="ssh_key", username="root"
    )
    db.add(cred)
    db.flush()
    h = System(
        hostname=hostname,
        ip_address="10.0.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(h)
    db.commit()
    db.refresh(h)
    return h


# ---------------------------------------------------------------------------
# POST /signing-key/rotate-prepare
# ---------------------------------------------------------------------------


def test_rotate_prepare_201_creates_pending(
    authed_client, mock_vault, patch_gpg, mirror
):
    # Bootstrap an active key first.
    boot = authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    assert boot.status_code == 200

    res = authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["status"] == "pending_cutover"
    assert body["gpg_fingerprint"] == _PENDING_FPR
    assert "BEGIN PGP PUBLIC KEY BLOCK" in body["public_key_armored"]


def test_rotate_prepare_409_when_pending_already_exists(
    authed_client, mock_vault, patch_gpg, mirror
):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    first = authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")
    assert first.status_code == 201
    second = authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")
    assert second.status_code == 409
    assert "already has a pending_cutover" in second.json()["detail"]


def test_rotate_prepare_404_on_missing_mirror(authed_client, patch_gpg):
    res = authed_client.post("/mirrors/99999/signing-key/rotate-prepare")
    assert res.status_code == 404


def test_rotate_prepare_403_for_auditor(client, db, seed_roles, patch_gpg, mirror):
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="rot-auditor",
        email="rot-auditor@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    login = client.post(
        "/auth/login", data={"username": "rot-auditor", "password": "testpass123"}
    )
    token = login.json()["access_token"]
    res = client.post(
        f"/mirrors/{mirror.id}/signing-key/rotate-prepare",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403


# ---------------------------------------------------------------------------
# GET /signing-key/cutover-preview
# ---------------------------------------------------------------------------


def test_cutover_preview_409_without_pending(
    authed_client, mock_vault, patch_gpg, mirror
):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    res = authed_client.get(f"/mirrors/{mirror.id}/signing-key/cutover-preview")
    assert res.status_code == 409
    assert "no pending_cutover" in res.json()["detail"]


def test_cutover_preview_returns_structured_buckets(
    authed_client, db, mock_vault, patch_gpg, mirror, seed_distro
):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")
    h = _make_host(db, seed_distro, "lagging.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR],
        )
    )
    db.commit()

    res = authed_client.get(f"/mirrors/{mirror.id}/signing-key/cutover-preview")
    assert res.status_code == 200
    body = res.json()
    assert body["pending_fingerprint"] == _PENDING_FPR
    assert body["hosts_missing_pending"] == [h.id]
    assert body["hosts_never_installed"] == []
    assert body["hosts_stale_trust_record"] == []


# ---------------------------------------------------------------------------
# POST /signing-key/cutover
# ---------------------------------------------------------------------------


def test_cutover_promotes_when_all_hosts_ready(
    authed_client, db, mock_vault, patch_gpg, mirror, seed_distro
):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")
    h = _make_host(db, seed_distro, "ready.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR, _PENDING_FPR],
        )
    )
    db.commit()

    res = authed_client.post(
        f"/mirrors/{mirror.id}/signing-key/cutover", json={"force": False}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "active"
    assert body["gpg_fingerprint"] == _PENDING_FPR


def test_cutover_409_with_structured_preview_when_blocked(
    authed_client, db, mock_vault, patch_gpg, mirror, seed_distro
):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")
    h = _make_host(db, seed_distro, "lagging.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR],
        )
    )
    db.commit()

    res = authed_client.post(
        f"/mirrors/{mirror.id}/signing-key/cutover", json={"force": False}
    )
    assert res.status_code == 409
    body = res.json()
    # Flattened to match the declared
    # CutoverBlockedResponse schema — top-level ``detail`` and
    # ``preview`` keys, no FastAPI nesting.
    assert "detail" in body
    assert "preview" in body
    assert body["preview"]["pending_fingerprint"] == _PENDING_FPR
    assert body["preview"]["hosts_missing_pending"] == [h.id]
    assert body["preview"]["hosts_never_installed"] == []
    assert body["preview"]["hosts_stale_trust_record"] == []


def test_cutover_force_overrides_and_emits_audit_with_actor(
    authed_client, admin_user, db, mock_vault, patch_gpg, mirror, seed_distro
):
    """force=True threads current_user.id into the service so the
    audit row records the actor of the override.
    """
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")
    h = _make_host(db, seed_distro, "lagging-forced.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR],
        )
    )
    db.commit()

    with patch("app.services.audit_event_service.safe_emit") as mock_audit:
        res = authed_client.post(
            f"/mirrors/{mirror.id}/signing-key/cutover", json={"force": True}
        )
    assert res.status_code == 200
    mock_audit.assert_called_once()
    kwargs = mock_audit.call_args.kwargs
    # ``authed_client`` is logged in as ``admin_user``; the service
    # must receive that user's id as the actor.
    assert kwargs["actor_user_id"] == admin_user.id
    assert kwargs["context"]["hosts_missing_pending_count"] == 1


def test_cutover_409_without_pending(authed_client, mock_vault, patch_gpg, mirror):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    res = authed_client.post(
        f"/mirrors/{mirror.id}/signing-key/cutover", json={"force": False}
    )
    assert res.status_code == 409
    assert "no pending_cutover" in res.json()["detail"]


def test_cutover_403_for_auditor(client, db, seed_roles, mirror):
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="cut-auditor",
        email="cut-auditor@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()
    login = client.post(
        "/auth/login", data={"username": "cut-auditor", "password": "testpass123"}
    )
    token = login.json()["access_token"]
    res = client.post(
        f"/mirrors/{mirror.id}/signing-key/cutover",
        headers={"Authorization": f"Bearer {token}"},
        json={"force": False},
    )
    assert res.status_code == 403


# ---------------------------------------------------------------------------
# POST /signing-key/retire/{key_id}
# ---------------------------------------------------------------------------


def test_retire_demotes_rotating_out_to_retired(
    authed_client, db, mock_vault, patch_gpg, mirror, seed_distro
):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")
    h = _make_host(db, seed_distro, "ready-retire.example.com")
    db.add(
        HostMirrorTrust(
            host_id=h.id,
            mirror_id=mirror.id,
            installed_fingerprints=[_ACTIVE_FPR, _PENDING_FPR],
        )
    )
    db.commit()
    authed_client.post(
        f"/mirrors/{mirror.id}/signing-key/cutover", json={"force": False}
    )

    rotating = (
        db.query(MirrorSigningKey)
        .filter_by(mirror_repo_id=mirror.id, status="rotating_out")
        .one()
    )

    res = authed_client.post(f"/mirrors/{mirror.id}/signing-key/retire/{rotating.id}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "retired"
    assert body["gpg_fingerprint"] == _ACTIVE_FPR


def test_retire_409_on_active_key(authed_client, mock_vault, patch_gpg, mirror, db):
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    active = (
        db.query(MirrorSigningKey)
        .filter_by(mirror_repo_id=mirror.id, status="active")
        .one()
    )
    res = authed_client.post(f"/mirrors/{mirror.id}/signing-key/retire/{active.id}")
    assert res.status_code == 409
    assert "rotating_out" in res.json()["detail"]


def test_retire_404_on_unknown_key(authed_client, mirror):
    res = authed_client.post(f"/mirrors/{mirror.id}/signing-key/retire/99999")
    assert res.status_code == 404


def test_retire_404_on_cross_mirror_key(
    authed_client, db, mock_vault, patch_gpg, mirror
):
    """A key id valid for mirror A must 404 (not 200, not 409) when
    addressed via mirror B's URL — service-layer message does not leak
    cross-mirror existence.
    """
    other = MirrorRepo(
        slug="other-rotate-routes",
        display_name="Other",
        package_family="deb",
        upstream_url="http://example.com",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        verify_upstream_signature=False,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(other)
    db.commit()
    db.refresh(other)

    # Bootstrap a key on the OTHER mirror.
    authed_client.post(f"/mirrors/{other.id}/signing-key")
    other_active = (
        db.query(MirrorSigningKey)
        .filter_by(mirror_repo_id=other.id, status="active")
        .one()
    )

    # Try to retire it via the FIRST mirror's URL.
    res = authed_client.post(
        f"/mirrors/{mirror.id}/signing-key/retire/{other_active.id}"
    )
    assert res.status_code == 404


def test_retire_403_for_auditor(client, db, seed_roles, mirror):
    from app.core.auth import get_password_hash
    from app.db.models import User

    auditor = User(
        username="ret-auditor",
        email="ret-auditor@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    login = client.post(
        "/auth/login", data={"username": "ret-auditor", "password": "testpass123"}
    )
    token = login.json()["access_token"]
    res = client.post(
        f"/mirrors/{mirror.id}/signing-key/retire/1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
