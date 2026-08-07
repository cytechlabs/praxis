"""PRA-158 #2c: end-to-end sync flow with fence-ordered signing.

Drives ``perform_sync_for_mirror`` against a fake SyncEngine that lays
down a tiny apt tree, asserts the run row carries
``manifest_signature_path`` + ``signed_with_key_id``, and confirms
``snapshots/<run_id>.manifest.json.sig`` lands beside the manifest
JSON. Failure-path tests confirm staging cleanup and ``live/``
preservation when signing fails.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from app.db.models import MirrorRepo, MirrorSigningKey, MirrorSyncRun
from app.services import mirror_disk
from app.services import mirror_signing_key_service as svc_module
from app.services.mirror_gpg import gpg_available
from app.services.mirror_sync import SyncResult

skip_without_gpg = pytest.mark.skipif(
    not gpg_available(),
    reason="needs gpg on PATH (present in backend image; absent on hosted CI)",
)

_TEST_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"


@pytest.fixture
def patch_gpg(monkeypatch):
    """Replace gpg gen/export with deterministic fakes; let real gpg
    handle clearsign/detached_sign/import_and_verify when present.

    Tests that only need the orchestrator wiring (not crypto) call
    this; tests that need real signature verification skip without
    gpg.
    """

    def fake_generate(home, slug):
        return _TEST_FPR

    def fake_export_secret(home, fpr):
        return f"-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE-{fpr}\n-----END-----\n"

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
def isolate_mirror_root(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    return tmp_path


def _make_mirror(db, slug="test-fence", package_family="deb") -> MirrorRepo:
    m = MirrorRepo(
        slug=slug,
        display_name=f"Fence {slug}",
        package_family=package_family,
        upstream_url="http://example.com/upstream",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        # PRA-158 #4b: these tests exercise the signing fence and
        # sign-current paths, not the upstream-verify gate. Disable
        # verification so the gate (which would refuse the sync with
        # "no upstream trust anchors" because we don't seed any) gets
        # out of the way. Dedicated upstream-verify coverage lives in
        # tests/services/test_pra158_upstream_verify.py.
        verify_upstream_signature=False,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _make_running_run(db, mirror_id) -> MirrorSyncRun:
    run = MirrorSyncRun(
        mirror_repo_id=mirror_id,
        started_at=datetime.utcnow(),
        status="running",
        run_kind="sync",
    )
    db.add(run)
    db.flush()
    return run


def _patch_orchestrator_engine(monkeypatch, build_apt_tree=True):
    """Stub out engine + free-space gate so the orchestrator runs end
    to end against an in-memory minimal mirror tree.
    """

    class _Engine:
        def sync(self, mirror, work_dir):
            work_dir.mkdir(parents=True, exist_ok=True)
            if build_apt_tree:
                dist = work_dir / "dists" / "jammy"
                dist.mkdir(parents=True)
                (dist / "Release").write_bytes(
                    b"Origin: Test\nLabel: Test\nSuite: jammy\nArchitectures: amd64\n"
                )
                (work_dir / "x.deb").write_bytes(b"hi")
            return SyncResult(ok=True)

        def estimate_sync_bytes(self, mirror):
            return None

    monkeypatch.setattr(
        "app.services.mirror_sync.service.engine_for", lambda m: _Engine()
    )
    monkeypatch.setattr(
        "app.services.mirror_sync.service.check_free_space_gate",
        lambda **_kw: mirror_disk.GateDecision(
            allowed=True, reason="", estimate_unavailable=False
        ),
    )


# ---------------------------------------------------------------------------
# Happy path: sync writes signed artifacts + manifest+sig
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_sync_signs_native_metadata_and_manifest(
    db, mock_vault, isolate_mirror_root, monkeypatch
):
    """End-to-end: signed Release artifacts land in live/, manifest+sig
    land in snapshots/, and the run row carries the new fields.

    Real gpg is needed top-to-bottom — orchestrator generates a real
    key, signs, verifies. Deliberately does NOT use ``patch_gpg``;
    every gpg call goes through the real binary.
    """
    from app.services.mirror_sync.service import perform_sync_for_mirror

    _patch_orchestrator_engine(monkeypatch)

    mirror = _make_mirror(db, slug="test-sign-flow")

    run = _make_running_run(db, mirror.id)
    ok, events = perform_sync_for_mirror(db, mirror, run, prior_status="idle")
    db.commit()

    assert ok, run.error_text
    assert run.status == "ok"
    assert run.run_kind == "sync"
    assert run.manifest_path is not None
    assert run.manifest_signature_path is not None
    assert run.signed_with_key_id is not None

    manifest_path = Path(run.manifest_path)
    sig_path = Path(run.manifest_signature_path)
    assert manifest_path.is_file()
    assert sig_path.is_file()
    assert sig_path.parent == manifest_path.parent
    assert "snapshots" in str(manifest_path)
    assert "snapshots-staging" not in str(manifest_path)

    # Live tree got signed: InRelease + Release.gpg present.
    live = isolate_mirror_root / mirror.slug / "live"
    assert (live / "dists" / "jammy" / "InRelease").is_file()
    assert (live / "dists" / "jammy" / "Release.gpg").is_file()

    # Per-run staging dir was cleaned up after promote.
    staging = isolate_mirror_root / mirror.slug / "snapshots-staging" / str(run.id)
    assert not staging.exists()


# ---------------------------------------------------------------------------
# Failure path: signing failure leaves live/ untouched + cleans staging
# ---------------------------------------------------------------------------


def test_signing_failure_cleans_staging_and_preserves_live(
    db, mock_vault, isolate_mirror_root, monkeypatch, patch_gpg
):
    """If signing fails, the run finalizes failed AND live/ is never
    written AND staging dir is gone.
    """
    from app.services.mirror_sync import service as svc

    _patch_orchestrator_engine(monkeypatch)

    # Force the signing fence to fail.
    def fake_sign(db_, mirror_, run_, work_):
        # Touch staging so we can verify cleanup actually fires.
        from app.services.mirror_paths import staged_manifest_dir, staged_manifest_path

        staged_manifest_dir(mirror_.slug, run_.id).mkdir(parents=True, exist_ok=True)
        staged_manifest_path(mirror_.slug, run_.id).write_bytes(b'{"fake":1}')
        return svc._SignOutcome(ok=False, error_text="forced signing failure")

    monkeypatch.setattr(svc, "_sign_run_in_work", fake_sign)

    mirror = _make_mirror(db, slug="test-sign-fail")
    run = _make_running_run(db, mirror.id)

    ok, events = svc.perform_sync_for_mirror(db, mirror, run, prior_status="idle")
    db.commit()

    assert ok is False
    assert run.status == "failed"
    assert "forced signing failure" in (run.error_text or "")
    # No promote happened — live/ never created.
    live = isolate_mirror_root / mirror.slug / "live"
    assert not live.exists() or not any(live.iterdir())
    # Staging dir cleaned up.
    staging = isolate_mirror_root / mirror.slug / "snapshots-staging" / str(run.id)
    assert not staging.exists()


# ---------------------------------------------------------------------------
# sign-current — service-level test
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_sign_current_signs_existing_live_tree(
    db, mock_vault, isolate_mirror_root, monkeypatch
):
    """sign-current pulls no upstream — pre-populate live/ with a tree,
    invoke the service, assert sign_only run row + native sigs on disk.

    Deliberately does NOT use ``patch_gpg``; the service generates a
    real key on first invocation.
    """
    from app.services.mirror_sign_current import perform_sign_current_for_mirror

    mirror = _make_mirror(db, slug="test-sign-current")

    # Pre-populate live/ with a minimal apt tree (no work/ involvement
    # — sign-current operates on whatever is currently published).
    live = isolate_mirror_root / mirror.slug / "live"
    dist = live / "dists" / "jammy"
    dist.mkdir(parents=True)
    (dist / "Release").write_bytes(
        b"Origin: Test\nLabel: Test\nSuite: jammy\nArchitectures: amd64\n"
    )

    # Insert the running sign_only row the service expects the caller
    # (claim_and_sign_current) to pre-insert.
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        status="running",
        run_kind="sign_only",
    )
    db.add(run)
    db.commit()

    result = perform_sign_current_for_mirror(db, mirror)
    db.commit()
    db.refresh(run)

    assert result.ok, result.error_text
    assert run.status == "ok"
    assert run.run_kind == "sign_only"
    assert run.manifest_path is not None
    assert run.manifest_signature_path is not None
    assert run.signed_with_key_id is not None
    # mirror.last_sync_status is NOT mutated by sign_only.
    assert mirror.last_sync_status == "idle"

    assert (dist / "InRelease").is_file()
    assert (dist / "Release.gpg").is_file()


def test_sign_current_refuses_when_live_empty(
    db, mock_vault, isolate_mirror_root, patch_gpg
):
    """live/ missing or empty → run_kind=sign_only finalizes failed
    with a clear error.
    """
    from app.services.mirror_sign_current import perform_sign_current_for_mirror

    mirror = _make_mirror(db, slug="test-empty-live")
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        status="running",
        run_kind="sign_only",
    )
    db.add(run)
    db.commit()

    result = perform_sign_current_for_mirror(db, mirror)
    db.commit()
    db.refresh(run)

    assert result.ok is False
    assert run.status == "failed"
    assert "live/ for mirror" in (run.error_text or "")


# ---------------------------------------------------------------------------
# sign-current — endpoint
# ---------------------------------------------------------------------------


def test_sign_current_endpoint_queues_and_returns_202(authed_client, db):
    """POST /mirrors/{id}/sign-current returns 202 with run_kind in the
    body. The actual claim+dispatch runs in BackgroundTasks; we just
    assert the queue handoff is shaped right.
    """
    mirror = _make_mirror(db, slug="test-sc-endpoint")
    res = authed_client.post(f"/mirrors/{mirror.id}/sign-current")
    assert res.status_code == 202, res.text
    body = res.json()
    assert body["run_kind"] == "sign_only"
    assert body["queued"] is True
    assert body["mirror_repo_id"] == mirror.id


def test_sign_current_endpoint_404_on_missing_mirror(authed_client):
    res = authed_client.post("/mirrors/99999/sign-current")
    assert res.status_code == 404


def test_sign_current_endpoint_409_when_sync_running(authed_client, db):
    mirror = _make_mirror(db, slug="test-sc-running")
    mirror.last_sync_status = "running"
    db.commit()
    res = authed_client.post(f"/mirrors/{mirror.id}/sign-current")
    assert res.status_code == 409
    assert "sync in progress" in res.json()["detail"]


def test_sign_current_endpoint_403_for_auditor(client, db, seed_roles):
    from app.core.auth import get_password_hash
    from app.db.models import User

    mirror = _make_mirror(db, slug="test-sc-rbac")
    auditor = User(
        username="sc-auditor",
        email="sc-auditor@praxis.example.com",
        hashed_password=get_password_hash("testpass123"),
        is_active=True,
    )
    auditor.roles.append(seed_roles["auditor"])
    db.add(auditor)
    db.commit()

    login = client.post(
        "/auth/login",
        data={"username": "sc-auditor", "password": "testpass123"},
    )
    token = login.json()["access_token"]
    res = client.post(
        f"/mirrors/{mirror.id}/sign-current",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403


# ---------------------------------------------------------------------------
# Schema regression — run row response shape
# ---------------------------------------------------------------------------


def test_run_read_includes_pra158_signing_fields(authed_client, db):
    """GET /mirrors/{id}/runs/{run_id} surfaces the new fields. Pre-PRA-158
    runs (manifest_signature_path/signed_with_key_id NULL) still serialize.
    """
    mirror = _make_mirror(db, slug="test-run-shape")
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        status="ok",
        run_kind="sync",
        manifest_sha256="0" * 64,
        manifest_path="/tmp/fake.json",
        finished_at=datetime.utcnow(),
        byte_count=0,
        package_count=0,
    )
    db.add(run)
    db.commit()

    res = authed_client.get(f"/mirrors/{mirror.id}/runs/{run.id}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["run_kind"] == "sync"
    assert "manifest_signature_path" in body
    assert "signed_with_key_id" in body
    assert body["manifest_signature_path"] is None
    assert body["signed_with_key_id"] is None
