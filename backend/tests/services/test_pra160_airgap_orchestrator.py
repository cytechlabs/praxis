"""PRA-160 slice #1-c: orchestrator failure-path coverage.

Most of the orchestrator surface is already covered by the route
end-to-end tests. This file holds the cases that are awkward to
drive through the route — specifically the
``bundle_descriptor_path`` nulling behavior on transition to
``failed``.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    AirgapBundle,
    AirgapBundleSigningKey,
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    MirrorRepo,
    MirrorSigningKey,
    MirrorSyncRun,
)
from app.services.airgap import descriptor_signer as ds_module
from app.services.airgap import orchestrator as orch_module
from app.services.airgap import signing_key_service as sk_module
from app.services.airgap.orchestrator import AirgapExportOrchestrator

_FPR = "AB00000000000000000000000000000000000001"


@pytest.fixture
def patch_gpg(monkeypatch):
    def fake_generate(home, slug):
        return _FPR

    def fake_export_secret(home, fpr):
        return (
            f"-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE-PRIV-{fpr}\n-----END-----\n"
        )

    def fake_export_public(home, fpr):
        return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUB-{fpr}\n-----END-----\n"

    def fake_import_and_verify(home, armored, expected):
        if expected != _FPR:
            raise AssertionError(f"unexpected fingerprint {expected}")

    def fake_detached_sign(home, fingerprint, body):
        return b"-----BEGIN PGP SIGNATURE-----\nFAKE-SIG\n-----END-----\n"

    monkeypatch.setattr(sk_module.mirror_gpg, "generate_keypair", fake_generate)
    monkeypatch.setattr(
        sk_module.mirror_gpg, "export_secret_armored", fake_export_secret
    )
    monkeypatch.setattr(
        sk_module.mirror_gpg, "export_public_armored", fake_export_public
    )
    monkeypatch.setattr(
        ds_module.mirror_gpg, "import_and_verify", fake_import_and_verify
    )
    monkeypatch.setattr(ds_module.mirror_gpg, "detached_sign", fake_detached_sign)


def _seed_one_profile(db) -> None:
    mirror = MirrorRepo(
        slug="ubuntu-orch",
        display_name="Ubuntu Orch",
        package_family="deb",
        upstream_url="http://example.com/ubuntu",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="ok",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.commit()
    db.refresh(mirror)
    db.add(
        MirrorSyncRun(
            mirror_repo_id=mirror.id,
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow() + timedelta(seconds=5),
            status="ok",
            run_kind="sync",
            byte_count=1,
            package_count=1,
            manifest_sha256="a" * 64,
            manifest_path=f"/snapshots/run-{mirror.id}.manifest.json",
        )
    )
    profile = ContentProfile(
        slug="orch-prof", display_name="orch", package_family="deb"
    )
    channel = ContentChannel(
        slug="orch-chan", display_name="orch", package_family="deb"
    )
    db.add(profile)
    db.add(channel)
    db.commit()
    db.refresh(profile)
    db.refresh(channel)
    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(ContentChannelRepo(channel_id=channel.id, mirror_id=mirror.id))
    db.add(
        MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="active",
            gpg_fingerprint="EE" + "0" * 38,
            key_uid=f"Praxis Mirror Signing {mirror.slug} EE" + "0" * 38,
            vault_path=f"praxis/mirror-signing-keys/{mirror.slug}/EE" + "0" * 38,
            armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n",
        )
    )
    db.commit()


def test_failed_descriptor_sign_nulls_bundle_descriptor_path(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """When the orchestrator transitions a row to
    ``failed`` because descriptor signing raised, the row's
    ``bundle_descriptor_path`` is None — a pointer to a missing path
    would be more misleading than helpful."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    _seed_one_profile(db)

    def boom(*args, **kwargs):
        raise RuntimeError("simulated descriptor sign failure")

    monkeypatch.setattr(orch_module, "sign_and_write_descriptor", boom)

    orchestrator = AirgapExportOrchestrator(db)
    with pytest.raises(RuntimeError, match="simulated descriptor sign failure"):
        orchestrator.create_descriptor_export(
            profile_slugs=["orch-prof"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            actor_user_id=None,
        )

    rows = db.query(AirgapBundle).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.status == "failed"
    assert row.bundle_descriptor_path is None
    assert row.error_text and "simulated descriptor sign failure" in row.error_text
    assert row.finished_at is not None


def test_planner_refusal_creates_no_row(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Re-cover the locked behavior at orchestrator level (route test
    covers it via the API). Verifies ``ensure_active`` did run before
    planning so a signing-key row exists; the export row does NOT."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    orchestrator = AirgapExportOrchestrator(db)
    from app.services.airgap.planner import UnknownProfile

    with pytest.raises(UnknownProfile):
        orchestrator.create_descriptor_export(
            profile_slugs=["nope"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="full",
            parent_bundle_id=None,
            actor_user_id=None,
        )
    assert db.query(AirgapBundle).count() == 0
    assert db.query(AirgapBundleSigningKey).count() == 1


# ---------------------------------------------------------------------------
# Slice #2: build_bundle_payload
# ---------------------------------------------------------------------------


def _seed_mirror_disk_tree(mirror_root, slug: str, run_id: int) -> None:
    """Seed the on-disk mirror layout the tar assembler walks."""
    from pathlib import Path as _Path

    mirror_dir = _Path(mirror_root) / slug
    snaps = mirror_dir / "snapshots"
    snaps.mkdir(parents=True, exist_ok=True)
    (snaps / f"{run_id}.manifest.json").write_bytes(b'{"manifest_sha256":"a"}')
    (snaps / f"{run_id}.manifest.json.sig").write_bytes(
        b"-----BEGIN PGP SIGNATURE-----\nFAKE\n-----END-----\n"
    )
    live = mirror_dir / "live"
    live.mkdir(parents=True, exist_ok=True)
    (live / "Release").write_bytes(b"Suite: jammy\n")
    (live / "main").mkdir(parents=True, exist_ok=True)
    (live / "main" / "Packages").write_bytes(b"Package: hello\n")


def test_build_bundle_payload_descriptor_ready_to_ok(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Happy path: descriptor_ready row → ok with bundle_path,
    payload_sha256, byte_count populated and the tar on disk."""
    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    _seed_one_profile(db)
    # Seed the on-disk tree the tar assembler expects. Mirror slug
    # and run_id come from _seed_one_profile.
    mirror_id = db.query(MirrorRepo).filter_by(slug="ubuntu-orch").one().id
    run_id = db.query(MirrorSyncRun).filter_by(mirror_repo_id=mirror_id).one().id
    _seed_mirror_disk_tree(mirror_root, "ubuntu-orch", run_id)

    orchestrator = AirgapExportOrchestrator(db)
    row = orchestrator.create_descriptor_export(
        profile_slugs=["orch-prof"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    assert row.status == "descriptor_ready"

    built = orchestrator.build_bundle_payload(
        bundle_id=row.bundle_id, actor_user_id=None
    )
    assert built.status == "ok"
    assert built.bundle_path
    assert built.payload_sha256 and len(built.payload_sha256) == 64
    assert built.byte_count and built.byte_count > 0
    assert built.finished_at is not None

    from pathlib import Path as _Path

    final_tar = _Path(built.bundle_path)
    assert final_tar.exists()
    assert not (final_tar.parent / f"{built.bundle_id}.tar.tmp").exists()


def test_build_bundle_payload_idempotent_on_ok(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """A second call after status='ok' returns the row unchanged
    (no re-build, no double-tar, no audit re-emission concerns)."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(tmp_path / "bundles"))
    _seed_one_profile(db)
    run_id = db.query(MirrorSyncRun).one().id
    _seed_mirror_disk_tree(tmp_path / "mirrors", "ubuntu-orch", run_id)

    orchestrator = AirgapExportOrchestrator(db)
    row = orchestrator.create_descriptor_export(
        profile_slugs=["orch-prof"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    first = orchestrator.build_bundle_payload(
        bundle_id=row.bundle_id, actor_user_id=None
    )
    second = orchestrator.build_bundle_payload(
        bundle_id=row.bundle_id, actor_user_id=None
    )
    assert first.id == second.id
    assert first.payload_sha256 == second.payload_sha256
    assert first.bundle_path == second.bundle_path


def test_build_bundle_payload_payload_index_failure_preserves_descriptor(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Payload_index failure preserves the slice-#1
    descriptor pointer (the descriptor on disk is still valid). Only
    bundle_path is nulled."""
    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    _seed_one_profile(db)
    # Don't seed the disk tree — payload index will fail.

    orchestrator = AirgapExportOrchestrator(db)
    row = orchestrator.create_descriptor_export(
        profile_slugs=["orch-prof"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    assert row.bundle_descriptor_path  # set by slice #1
    descriptor_path_before = row.bundle_descriptor_path

    from app.services.airgap.tar_assembler import PayloadIndexError

    with pytest.raises(PayloadIndexError):
        orchestrator.build_bundle_payload(bundle_id=row.bundle_id, actor_user_id=None)

    db.refresh(row)
    assert row.status == "failed"
    # Descriptor pointer PRESERVED — payload_index
    # failure didn't touch the on-disk descriptor.
    assert row.bundle_descriptor_path == descriptor_path_before
    # bundle_path stays None — there's no usable tar.
    assert row.bundle_path is None
    assert row.error_text and "no live tree" in row.error_text
    assert row.finished_at is not None


def test_build_bundle_payload_descriptor_resign_failure_nulls_descriptor(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Descriptor_resign failure DOES null the
    descriptor pointer because the atomic-dir promotion may have
    left the canonical path empty in its worst-case branch."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(tmp_path / "bundles"))
    _seed_one_profile(db)
    run_id = db.query(MirrorSyncRun).one().id
    _seed_mirror_disk_tree(tmp_path / "mirrors", "ubuntu-orch", run_id)

    orchestrator = AirgapExportOrchestrator(db)
    row = orchestrator.create_descriptor_export(
        profile_slugs=["orch-prof"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )

    # Force the slice-#2 re-sign to fail after the slice-#1 sign
    # already succeeded. The test fixture's fake detached_sign is
    # replaced with one that raises on the next call.
    def boom(*args, **kwargs):
        raise RuntimeError("simulated re-sign failure")

    monkeypatch.setattr(ds_module.mirror_gpg, "detached_sign", boom)

    with pytest.raises(RuntimeError, match="simulated re-sign failure"):
        orchestrator.build_bundle_payload(bundle_id=row.bundle_id, actor_user_id=None)

    db.refresh(row)
    assert row.status == "failed"
    # descriptor_resign IS in the invalidating-stages set → nulled.
    assert row.bundle_descriptor_path is None
    assert row.bundle_path is None
    assert row.error_text and "re-sign failed" in row.error_text


def test_build_bundle_payload_idempotent_verifies_disk(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Idempotent ok-short-circuit verifies bundle_path
    exists AND its sha matches payload_sha256. Missing/mutated file →
    transition to failed."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(tmp_path / "bundles"))
    _seed_one_profile(db)
    run_id = db.query(MirrorSyncRun).one().id
    _seed_mirror_disk_tree(tmp_path / "mirrors", "ubuntu-orch", run_id)

    orchestrator = AirgapExportOrchestrator(db)
    row = orchestrator.create_descriptor_export(
        profile_slugs=["orch-prof"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    built = orchestrator.build_bundle_payload(
        bundle_id=row.bundle_id, actor_user_id=None
    )
    assert built.status == "ok"

    # Mutate the bundle file on disk.
    from pathlib import Path as _Path

    _Path(built.bundle_path).write_bytes(b"corrupted")

    with pytest.raises(RuntimeError, match="payload_sha256 mismatch"):
        orchestrator.build_bundle_payload(bundle_id=row.bundle_id, actor_user_id=None)
    db.refresh(built)
    assert built.status == "failed"
    assert built.bundle_path is None
    assert built.error_text and "sha256" in built.error_text


def test_build_bundle_payload_idempotent_detects_missing_bundle_file(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Bundle file deleted between builds → idempotent re-call
    transitions row to failed instead of returning stale ok."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(tmp_path / "bundles"))
    _seed_one_profile(db)
    run_id = db.query(MirrorSyncRun).one().id
    _seed_mirror_disk_tree(tmp_path / "mirrors", "ubuntu-orch", run_id)

    orchestrator = AirgapExportOrchestrator(db)
    row = orchestrator.create_descriptor_export(
        profile_slugs=["orch-prof"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    built = orchestrator.build_bundle_payload(
        bundle_id=row.bundle_id, actor_user_id=None
    )
    from pathlib import Path as _Path

    _Path(built.bundle_path).unlink()

    with pytest.raises(RuntimeError, match="bundle_path missing"):
        orchestrator.build_bundle_payload(bundle_id=row.bundle_id, actor_user_id=None)
    db.refresh(built)
    assert built.status == "failed"
    assert built.bundle_path is None


def test_build_bundle_payload_refuses_unknown_bundle(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    orchestrator = AirgapExportOrchestrator(db)
    with pytest.raises(RuntimeError, match="not found"):
        orchestrator.build_bundle_payload(bundle_id="ghost-bundle", actor_user_id=None)


def test_build_bundle_payload_refuses_when_status_failed(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """A row already at status='failed' cannot be re-driven; operator
    must POST a new export."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(tmp_path / "bundles"))
    _seed_one_profile(db)
    # Don't seed the disk tree — first build fails and lands the row
    # at status='failed'.
    orchestrator = AirgapExportOrchestrator(db)
    row = orchestrator.create_descriptor_export(
        profile_slugs=["orch-prof"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    from app.services.airgap.tar_assembler import PayloadIndexError

    with pytest.raises(PayloadIndexError):
        orchestrator.build_bundle_payload(bundle_id=row.bundle_id, actor_user_id=None)
    db.refresh(row)
    assert row.status == "failed"

    with pytest.raises(RuntimeError, match="requires status='descriptor_ready'"):
        orchestrator.build_bundle_payload(bundle_id=row.bundle_id, actor_user_id=None)
