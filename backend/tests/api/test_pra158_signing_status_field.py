"""PRA-158 #5c: ``signing_status`` derived field on MirrorRepoRead.

Locked vocabulary: no_key_yet, key_ready, rotation_in_progress,
signed_ok, signing_failed, upstream_invalid. Drives the trust-badge
column on the mirror list page.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import MirrorRepo, MirrorSigningKey, MirrorSyncRun
from app.services import mirror_signing_key_service as svc_module
from app.services.mirror_signing_key_service import vault_path_for
from tests.helpers.armor import pgp_private_block

_ACTIVE_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
_PENDING_FPR = "B" * 40


@pytest.fixture
def patch_gpg(monkeypatch):
    fingerprints = iter([_ACTIVE_FPR, _PENDING_FPR, "C" * 40])

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


def _make_mirror(db, slug: str = "status-test") -> MirrorRepo:
    m = MirrorRepo(
        slug=slug,
        display_name=slug,
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
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _add_run(db, mirror, *, status, error_text=None, signed=True):
    """Insert a sync run row. ``signed`` controls whether
    signed_with_key_id points at the active key for ``mirror`` (a real
    FK target — placing literal id=1 would violate the FK).
    """
    signed_with_key_id = None
    if signed:
        active = (
            db.query(MirrorSigningKey)
            .filter_by(mirror_repo_id=mirror.id, status="active")
            .first()
        )
        if active is not None:
            signed_with_key_id = active.id

    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow() - timedelta(minutes=5),
        finished_at=datetime.utcnow(),
        status=status,
        run_kind="sync",
        manifest_sha256="0" * 64 if status == "ok" else None,
        manifest_path="/tmp/m.json" if status == "ok" else None,
        signed_with_key_id=signed_with_key_id,
        error_text=error_text,
    )
    db.add(run)
    db.commit()
    return run


def test_no_key_yet_when_no_active_signing_key(authed_client, db):
    mirror = _make_mirror(db)
    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.status_code == 200
    assert res.json()["signing_status"] == "no_key_yet"


def test_rotation_in_progress_takes_precedence(
    authed_client, db, mock_vault, patch_gpg
):
    """Pending_cutover is the most operationally significant state —
    surfaces over signed_ok/key_ready even when those would otherwise
    apply.
    """
    mirror = _make_mirror(db)
    # Bootstrap active.
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    # Add an ok signed run so the mirror would otherwise be signed_ok.
    active = (
        db.query(MirrorSigningKey)
        .filter_by(mirror_repo_id=mirror.id, status="active")
        .one()
    )
    _add_run(db, mirror, status="ok")
    # Now prepare a rotation.
    authed_client.post(f"/mirrors/{mirror.id}/signing-key/rotate-prepare")

    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "rotation_in_progress"
    # Prevent unused warning.
    assert active is not None


def test_key_ready_when_active_but_no_signed_run(
    authed_client, db, mock_vault, patch_gpg
):
    mirror = _make_mirror(db)
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "key_ready"


def test_key_ready_when_run_predates_signing(authed_client, db, mock_vault, patch_gpg):
    """Pre-PRA-158 runs have signed_with_key_id=NULL; an active key
    plus only NULL-signed runs is bootstrap state, not signed_ok.
    """
    mirror = _make_mirror(db)
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    _add_run(db, mirror, status="ok", signed=False)
    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "key_ready"


def test_signed_ok_when_most_recent_run_signed_and_ok(
    authed_client, db, mock_vault, patch_gpg
):
    mirror = _make_mirror(db)
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    _add_run(db, mirror, status="ok", signed=True)
    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "signed_ok"


def test_signing_failed_when_most_recent_run_failed_with_signing_error(
    authed_client, db, mock_vault, patch_gpg
):
    mirror = _make_mirror(db)
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    _add_run(
        db,
        mirror,
        status="failed",
        signed=True,
        error_text="signing failed: gpg --sign rc=1",
    )
    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "signing_failed"


def test_upstream_invalid_when_most_recent_run_failed_upstream_verify(
    authed_client, db, mock_vault, patch_gpg
):
    mirror = _make_mirror(db)
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")
    _add_run(
        db,
        mirror,
        status="failed",
        signed=True,
        error_text="upstream signature invalid: bad signature",
    )
    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "upstream_invalid"


def test_failed_run_classified_even_when_signed_with_key_id_is_null(
    authed_client, db, mock_vault, patch_gpg
):
    """Real PRA-158 failure paths generally don't set
    signed_with_key_id — upstream-verify fails BEFORE signing, and
    signing/promote failures call _finalize_failed without copying
    sign_outcome.signed_with_key_id onto the run. Status must be
    checked first; the NULL-signed_with_key_id rule is reserved for
    pre-#2c ok runs only.
    """
    mirror = _make_mirror(db)
    authed_client.post(f"/mirrors/{mirror.id}/signing-key")

    # Failed run with NULL signed_with_key_id (the realistic shape) +
    # upstream-invalid error_text → upstream_invalid badge, NOT
    # key_ready.
    _add_run(
        db,
        mirror,
        status="failed",
        signed=False,
        error_text="upstream signature invalid: no public key",
    )
    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "upstream_invalid"

    # And a generic failed run with NULL signed_with_key_id →
    # signing_failed, not key_ready.
    db.query(MirrorSyncRun).delete()
    db.commit()
    _add_run(
        db,
        mirror,
        status="failed",
        signed=False,
        error_text="rsync exited rc=23",
    )
    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "signing_failed"


def test_signing_status_appears_on_list_endpoint(
    authed_client, db, mock_vault, patch_gpg
):
    """The badge column on /mirrors/all consumes ``signing_status``
    from the list response, not detail.
    """
    a = _make_mirror(db, slug="list-a")
    b = _make_mirror(db, slug="list-b")
    authed_client.post(f"/mirrors/{a.id}/signing-key")  # → key_ready

    res = authed_client.get("/mirrors")
    assert res.status_code == 200
    by_slug = {m["slug"]: m for m in res.json()}
    assert by_slug["list-a"]["signing_status"] == "key_ready"
    assert by_slug["list-b"]["signing_status"] == "no_key_yet"


def test_retired_keys_do_not_count_as_active(authed_client, db, mock_vault, patch_gpg):
    """A retired key alone leaves the mirror back at no_key_yet.
    Defensive: confirms the active-key probe filters out retired rows.
    """
    mirror = _make_mirror(db)
    db.add(
        MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="retired",
            gpg_fingerprint="9" * 40,
            key_uid="retired",
            vault_path=vault_path_for(mirror.slug, "9" * 40),
            armored_public_key="x",
            retired_at=datetime.utcnow(),
        )
    )
    db.commit()

    res = authed_client.get(f"/mirrors/{mirror.id}")
    assert res.json()["signing_status"] == "no_key_yet"
