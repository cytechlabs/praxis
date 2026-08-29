"""PRA-160 slice #3: importer end-to-end tests.

Strategy: build a real bundle tar via the slice #2 export
orchestrator (with faked GPG primitives), then run slice #3's
importer against it. This exercises real tar I/O, real DB,
real sha256 verification, real path-safety checks — only the
GPG signing/verification is faked.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.db.models import (
    AirgapImport,
    AirgapImportTrustKey,
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    MirrorRepo,
    MirrorSigningKey,
    MirrorSyncRun,
)
from app.services.airgap import descriptor_signer as ds_module
from app.services.airgap import importer as imp_module
from app.services.airgap import signing_key_service as sk_module
from app.services.airgap.importer import (
    AirgapImportOrchestrator,
    BundleAlreadyImported,
    BundleSignatureInvalid,
    PayloadIntegrityFailure,
    SlugCollision,
    TarPathOutsideStaging,
)
from app.services.airgap.orchestrator import AirgapExportOrchestrator
from tests.helpers.armor import pgp_private_block

_FPR = "AB00000000000000000000000000000000000001"


# ---------------------------------------------------------------------------
# Fixtures: faked GPG + real tar build
# ---------------------------------------------------------------------------


@pytest.fixture
def patch_gpg(monkeypatch):
    """Fake GPG primitives across export AND import paths.

    Export:
      * generate_keypair, export_secret_armored, export_public_armored
        for slice #1 signing-key bootstrap.
      * detached_sign for slice #2 descriptor sign + per-mirror
        manifest sig (test seeds a real sidecar file).
    Import:
      * import_armored_public + verify_detached as no-ops so trust
        + manifest verification succeed against any input.
      * import_public_and_extract_fingerprint for trust pin.
    """

    def fake_generate(home, slug):
        return _FPR

    def fake_export_secret(home, fpr):
        return pgp_private_block(f"FAKE-PRIV-{fpr}")

    def fake_export_public(home, fpr):
        return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUB-{fpr}\n-----END-----\n"

    def fake_import_and_verify(home, armored, expected):
        if expected != _FPR:
            raise AssertionError(f"unexpected fingerprint {expected}")

    def fake_detached_sign(home, fingerprint, body):
        return b"-----BEGIN PGP SIGNATURE-----\nFAKE-SIG\n-----END-----\n"

    def fake_import_public(home, armored):
        # No-op for the importer; the verify_detached fake below
        # accepts everything.
        return None

    def fake_verify_detached(home, sig_path, body_path):
        # Always succeed for unit tests. Real-gpg integration
        # rides on PRA-158 mirror_gpg tests.
        return None

    def fake_import_extract(home, armored):
        # The importer now requires imported
        # fingerprints to match the descriptor's declared set. The
        # export side seeds MirrorSigningKey with fingerprint
        # 'DD' + '0' * 38 and armored 'FAKE'; the trust pin uses
        # armored 'TRUST'. Discriminate by content.
        if "TRUST" in armored:
            return "TRUSTKEY" + "0" * 32
        if "FAKE" in armored:
            return "DD" + "0" * 38
        return "UNKNOWN" + "0" * 33

    def fake_run_gpg(home, args, **_):
        class Result:
            stdout = b""

        return Result()

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
    monkeypatch.setattr(
        imp_module.mirror_gpg, "import_armored_public", fake_import_public
    )
    monkeypatch.setattr(imp_module.mirror_gpg, "verify_detached", fake_verify_detached)
    # Trust service shares mirror_gpg.
    from app.services.airgap import import_trust_service as ts_module

    monkeypatch.setattr(
        ts_module.mirror_gpg,
        "import_public_and_extract_fingerprint",
        fake_import_extract,
    )
    monkeypatch.setattr(ts_module.mirror_gpg, "_run_gpg", fake_run_gpg)


def _seed_export_side(db) -> tuple[str, MirrorSyncRun]:
    """Seed the DB rows required for a slice-#2 export to succeed."""
    mirror = MirrorRepo(
        slug="ubuntu-jammy",
        display_name="Ubuntu Jammy",
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
    run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow() + timedelta(seconds=5),
        status="ok",
        run_kind="sync",
        byte_count=4096,
        package_count=12,
        manifest_sha256="a" * 64,
        manifest_path=f"/snapshots/run-{mirror.id}.manifest.json",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    profile = ContentProfile(
        slug="prod-base", display_name="prod-base", package_family="deb"
    )
    channel = ContentChannel(slug="base", display_name="base", package_family="deb")
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
            gpg_fingerprint="DD" + "0" * 38,
            key_uid=f"Praxis Mirror Signing {mirror.slug}",
            vault_path=f"praxis/mirror-signing-keys/{mirror.slug}/DD" + "0" * 38,
            armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n",
        )
    )
    db.commit()
    return "ubuntu-jammy", run


def _seed_export_disk(mirror_root: Path, slug: str, run_id: int) -> None:
    mirror_dir = mirror_root / slug
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


def _build_bundle(db, tmp_path: Path) -> Path:
    """Run the slice-#2 export end-to-end. Returns the final tar path."""
    slug, run = _seed_export_side(db)
    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    import os

    os.environ["PRAXIS_MIRROR_ROOT"] = str(mirror_root)
    os.environ["PRAXIS_AIRGAP_BUNDLE_ROOT"] = str(bundle_root)
    _seed_export_disk(mirror_root, slug, run.id)

    orchestrator = AirgapExportOrchestrator(db)
    row = orchestrator.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    built = orchestrator.build_bundle_payload(
        bundle_id=row.bundle_id, actor_user_id=None
    )
    return Path(built.bundle_path)


def _pin_trust_key(db) -> AirgapImportTrustKey:
    """Pin a trust key so the importer's trust check has at least
    one active row. Bytes are arbitrary (faked GPG accepts
    anything)."""
    from app.services.airgap.import_trust_service import ImportTrustKeyService

    return ImportTrustKeyService(db).add_armored_public_key(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nTRUST\n-----END-----\n"
    )


def _move_to_import_staging(bundle_path: Path, import_staging: Path) -> Path:
    """Copy the bundle tar into the import-staging directory and
    return the new path."""
    import shutil

    import_staging.mkdir(parents=True, exist_ok=True)
    dest = import_staging / bundle_path.name
    shutil.copy2(bundle_path, dest)
    return dest


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_import_happy_path_creates_imported_offline_mirror(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    # Mirror root for imported_offline payloads — separate from the
    # export side's tree.
    import_mirror_root = tmp_path / "import-mirrors"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(import_mirror_root))

    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    orchestrator = AirgapImportOrchestrator(db)
    row = orchestrator.run_import(
        path=str(staged_tar),
        force=False,
        actor_user_id=None,
    )

    assert row.status == "ok"
    assert row.payload_sha256 and len(row.payload_sha256) == 64
    assert row.byte_count and row.byte_count > 0
    assert len(row.target_mirror_slugs) == 1
    target_mirror_slug = row.target_mirror_slugs[0]
    assert target_mirror_slug.startswith("imported-")
    assert target_mirror_slug.endswith("-ubuntu-jammy")

    # MirrorRepo created with imported_offline mode.
    repo = db.query(MirrorRepo).filter_by(slug=target_mirror_slug).one()
    assert repo.source_mode == "imported_offline"
    assert repo.enabled is False
    assert repo.package_family == "deb"

    # MirrorSyncRun row with run_kind='import'.
    runs = db.query(MirrorSyncRun).filter_by(mirror_repo_id=repo.id).all()
    assert len(runs) == 1
    assert runs[0].run_kind == "import"
    assert runs[0].status == "ok"
    assert runs[0].manifest_sha256 == "a" * 64

    # ContentChannel + ContentProfile created with prefixed slug.
    chan = (
        db.query(ContentChannel)
        .filter(ContentChannel.slug.like("imported-%-base"))
        .one()
    )
    prof = (
        db.query(ContentProfile)
        .filter(ContentProfile.slug.like("imported-%-prod-base"))
        .one()
    )
    repo_link = db.query(ContentChannelRepo).filter_by(channel_id=chan.id).one()
    assert repo_link.mirror_id == repo.id
    assert (
        db.query(ContentProfileChannel)
        .filter_by(profile_id=prof.id, channel_id=chan.id)
        .one()
        is not None
    )

    # On-disk: imported live tree exists.
    imported_live = import_mirror_root / target_mirror_slug / "live"
    assert (imported_live / "Release").exists()
    assert (imported_live / "main" / "Packages").exists()
    # praxis-mirror.json layout descriptor written.
    assert (import_mirror_root / "praxis-mirror.json").exists()
    # Staging cleaned up.
    assert not (import_staging / row.bundle_id).exists()


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


def test_import_refuses_when_no_trust_pin(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    # NO trust pin.

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(BundleSignatureInvalid) as exc_info:
        orchestrator.run_import(path=str(staged_tar), force=False, actor_user_id=None)
    assert "no_active_trust_keys" in str(exc_info.value.context)


def test_import_refuses_path_outside_staging(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    bundle_path = _build_bundle(db, tmp_path)
    # Don't move it into staging.
    import_staging = tmp_path / "import-staging"
    import_staging.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    _pin_trust_key(db)

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(TarPathOutsideStaging):
        orchestrator.run_import(
            path=str(bundle_path),  # outside staging
            force=False,
            actor_user_id=None,
        )


def test_import_refuses_already_imported_without_force(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    orchestrator = AirgapImportOrchestrator(db)
    first = orchestrator.run_import(
        path=str(staged_tar), force=False, actor_user_id=None
    )
    assert first.status == "ok"

    with pytest.raises(BundleAlreadyImported) as exc_info:
        orchestrator.run_import(path=str(staged_tar), force=False, actor_user_id=None)
    assert exc_info.value.context["bundle_id"] == first.bundle_id


def test_import_refuses_slug_collision(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    # Pre-seed a mirror with the prefix the importer would derive.
    # Read bundle to get bundle_id so we can synthesize the prefix.
    from app.services.airgap.importer import _read_descriptor_pair, derive_imported_slug
    from app.services.airgap.schema import deserialize_descriptor

    body, _ = _read_descriptor_pair(staged_tar)
    preview = deserialize_descriptor(body)
    expected_slug = derive_imported_slug(preview.bundle_id, "ubuntu-jammy")
    db.add(
        MirrorRepo(
            slug=expected_slug,
            display_name="pre-existing",
            package_family="deb",
            upstream_url="http://example.com",
            distribution="jammy",
            components="[]",
            architectures='["amd64"]',
            sync_schedule_cron="0 0 * * *",
            last_sync_status="idle",
            current_disk_bytes=0,
        )
    )
    db.commit()

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(SlugCollision) as exc_info:
        orchestrator.run_import(path=str(staged_tar), force=False, actor_user_id=None)
    conflicts = exc_info.value.context["conflicts"]
    assert any(c["slug"] == expected_slug for c in conflicts)


def test_import_payload_sha_mismatch_raises(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Tampered tar member sha → PayloadIntegrityFailure.

    Strategy: build a real bundle, then rewrite a payload member's
    bytes inside the tar before re-importing. Easiest path: extract
    the tar, mutate one file, re-tar.
    """
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    _pin_trust_key(db)

    # Re-pack the tar with a corrupted live file.
    import tarfile

    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    with tarfile.open(bundle_path, "r") as src:
        src.extractall(extract_dir)
    # Mutate Release.
    release_files = list(extract_dir.rglob("Release"))
    assert release_files, "expected at least one Release member"
    release_files[0].write_bytes(b"TAMPERED")

    tampered_path = import_staging / "tampered.tar"
    import_staging.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tampered_path, "w", format=tarfile.PAX_FORMAT) as out:
        for path in sorted(extract_dir.rglob("*"), key=lambda p: p.as_posix()):
            if path.is_file():
                out.add(
                    str(path),
                    arcname=str(path.relative_to(extract_dir)).replace("\\", "/"),
                )

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(PayloadIntegrityFailure):
        orchestrator.run_import(
            path=str(tampered_path), force=False, actor_user_id=None
        )

    # Failed-row landed.
    rows = db.query(AirgapImport).all()
    assert len(rows) == 1
    assert rows[0].status == "failed"
    assert rows[0].error_text


# ---------------------------------------------------------------------------
# Slug derivation
# ---------------------------------------------------------------------------


def test_derive_imported_slug_format():
    from app.services.airgap.importer import derive_imported_slug

    out = derive_imported_slug("11111111-2222-3333-4444-555555555555", "ubuntu-jammy")
    assert out == "imported-11111111-ubuntu-jammy"


# ---------------------------------------------------------------------------
# #3-a coverage
# ---------------------------------------------------------------------------


def test_descriptor_validation_rejects_non_uuid_bundle_id():
    """Bundle_id must be UUIDv4-shaped before any
    path or DB use."""
    from app.services.airgap.importer import (
        InvalidBundleDescriptor,
        _validate_descriptor_ids,
    )
    from app.services.airgap.schema import BUNDLE_SCHEMA_VERSION, BundleDescriptor

    bad = BundleDescriptor(
        bundle_version=BUNDLE_SCHEMA_VERSION,
        bundle_id="../../etc/passwd",
        kind="full",
        parent_bundle_id=None,
        created_at="2026-05-06T00:00:00Z",
        praxis_instance_signing_fingerprint=_FPR,
        profiles=[],
        channels=[],
        mirrors=[],
    )
    with pytest.raises(InvalidBundleDescriptor) as exc_info:
        _validate_descriptor_ids(bad)
    assert exc_info.value.context["reason"] == "bundle_id_not_uuid"


def test_descriptor_validation_rejects_non_slug_mirror():
    from app.services.airgap.importer import (
        InvalidBundleDescriptor,
        _validate_descriptor_ids,
    )
    from app.services.airgap.schema import (
        BUNDLE_SCHEMA_VERSION,
        BundleDescriptor,
        MirrorRunDescriptor,
    )

    bad = BundleDescriptor(
        bundle_version=BUNDLE_SCHEMA_VERSION,
        bundle_id="11111111-2222-3333-4444-555555555555",
        kind="full",
        parent_bundle_id=None,
        created_at="2026-05-06T00:00:00Z",
        praxis_instance_signing_fingerprint=_FPR,
        profiles=[],
        channels=[],
        mirrors=[
            MirrorRunDescriptor(
                mirror_slug="../escape",
                package_family="deb",
                distribution="jammy",
                components=["main"],
                architectures=["amd64"],
                run_id=1,
                manifest_sha256="a" * 64,
                manifest_path="/x",
                byte_count=None,
                package_count=None,
                signing_key_fingerprints=["DD" + "0" * 38],
                signing_keys_armored=["arm"],
            )
        ],
    )
    with pytest.raises(InvalidBundleDescriptor) as exc_info:
        _validate_descriptor_ids(bad)
    assert exc_info.value.context["reason"] == "mirror_slug_invalid"


def test_descriptor_self_consistency_refuses_orphan_channel_repo():
    from app.services.airgap.importer import (
        InvalidBundleDescriptor,
        _validate_descriptor_self_consistency,
    )
    from app.services.airgap.schema import (
        BUNDLE_SCHEMA_VERSION,
        BundleDescriptor,
        ChannelDescriptor,
        ChannelRepoDescriptor,
    )

    bad = BundleDescriptor(
        bundle_version=BUNDLE_SCHEMA_VERSION,
        bundle_id="11111111-2222-3333-4444-555555555555",
        kind="full",
        parent_bundle_id=None,
        created_at="2026-05-06T00:00:00Z",
        praxis_instance_signing_fingerprint=_FPR,
        profiles=[],
        channels=[
            ChannelDescriptor(
                slug="base",
                display_name="base",
                package_family="deb",
                description=None,
                repos=[
                    ChannelRepoDescriptor(
                        mirror_slug="ghost-mirror",
                        suite_override=None,
                        pinned_run_id=None,
                        pinned_manifest_sha256=None,
                    )
                ],
            )
        ],
        mirrors=[],
    )
    with pytest.raises(InvalidBundleDescriptor) as exc_info:
        _validate_descriptor_self_consistency(bad)
    assert exc_info.value.context["reason"] == "channel_repo_mirror_orphaned"


def test_force_refused_on_completed_import(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Force=True does NOT cascade-replace a
    completed import. ok rows refuse with structured reason."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    orchestrator = AirgapImportOrchestrator(db)
    first = orchestrator.run_import(
        path=str(staged_tar), force=False, actor_user_id=None
    )
    assert first.status == "ok"

    # force=True still refuses because existing.status='ok'.
    with pytest.raises(BundleAlreadyImported) as exc_info:
        orchestrator.run_import(path=str(staged_tar), force=True, actor_user_id=None)
    assert exc_info.value.context["reason"] == "force_refused_on_completed_import"


def test_force_reuses_failed_row(db, mock_vault, patch_gpg, tmp_path, monkeypatch):
    """Force=True on a failed row reuses it for retry."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    # First attempt: monkeypatch ingest_staged_bundle to raise so the
    # row lands at failed.
    from app.services.airgap import importer as imp_module

    real_ingest = imp_module.ingest_staged_bundle

    def fail_once(*args, **kwargs):
        fail_once.calls += 1
        if fail_once.calls == 1:
            raise RuntimeError("simulated ingest failure")
        return real_ingest(*args, **kwargs)

    fail_once.calls = 0
    monkeypatch.setattr(imp_module, "ingest_staged_bundle", fail_once)

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(RuntimeError, match="simulated ingest failure"):
        orchestrator.run_import(path=str(staged_tar), force=False, actor_user_id=None)
    rows = db.query(AirgapImport).all()
    assert len(rows) == 1
    assert rows[0].status == "failed"

    # force=True reuses the failed row.
    second = orchestrator.run_import(
        path=str(staged_tar), force=True, actor_user_id=None
    )
    assert second.status == "ok"
    rows_after = db.query(AirgapImport).all()
    assert len(rows_after) == 1  # same row, not a new one
    assert rows_after[0].id == rows[0].id


def test_imported_channel_repo_is_pinned_to_import_run(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Imported ContentChannelRepo rows auto-pin to
    the new MirrorSyncRun(run_kind='import') row id."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    row = AirgapImportOrchestrator(db).run_import(
        path=str(staged_tar), force=False, actor_user_id=None
    )
    target_slug = row.target_mirror_slugs[0]
    repo = db.query(MirrorRepo).filter_by(slug=target_slug).one()
    import_run = (
        db.query(MirrorSyncRun)
        .filter_by(mirror_repo_id=repo.id, run_kind="import")
        .one()
    )
    chan_repo = db.query(ContentChannelRepo).filter_by(mirror_id=repo.id).one()
    assert chan_repo.pinned_run_id == import_run.id


def test_verify_phase_broad_exception_terminalizes_row(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Tarfile / OSError / assertion failures during
    verify must transition the row to failed (not bubble through
    BackgroundTasks unhandled)."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    from app.services.airgap import importer as imp_module

    def boom(*args, **kwargs):
        raise OSError("simulated tar I/O failure")

    monkeypatch.setattr(imp_module, "verify_and_stage", boom)

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(OSError, match="simulated tar I/O failure"):
        orchestrator.run_import(path=str(staged_tar), force=False, actor_user_id=None)
    rows = db.query(AirgapImport).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.status == "failed"
    assert row.error_text and "verify failed" in row.error_text


def test_pre_flight_check_creates_row_synchronously(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Pre_flight_check is the row-creation path.

    Returns a row at status='verifying' so an immediate poll sees
    real state instead of a synthesized placeholder.
    """
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    orchestrator = AirgapImportOrchestrator(db)
    row = orchestrator.pre_flight_check(
        path=str(staged_tar), force=False, actor_user_id=None
    )
    assert row.status == "verifying"
    assert row.path == str(staged_tar)
    # No mirrors imported yet — execute_import hasn't run.
    assert row.target_mirror_slugs == []
    assert row.payload_sha256 is None

    # Polling the row at this point sees verifying.
    found = db.query(AirgapImport).filter_by(bundle_id=row.bundle_id).one()
    assert found.status == "verifying"

    # execute_import then walks it to ok.
    final = orchestrator.execute_import(row=row, actor_user_id=None)
    assert final.status == "ok"


def test_preflight_corrupt_tar_returns_unreadable_refusal(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Tarfile.ReadError in pre-flight returns a
    structured BundleDescriptorUnreadable refusal with stable
    reason='tar_corrupt'."""
    import_staging = tmp_path / "import-staging"
    import_staging.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    _pin_trust_key(db)

    # Write a non-tar file at a staging-allowed path.
    bad_path = import_staging / "garbage.tar"
    bad_path.write_bytes(b"this is not a tar file at all")

    from app.services.airgap.importer import BundleDescriptorUnreadable

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(BundleDescriptorUnreadable) as exc_info:
        orchestrator.pre_flight_check(
            path=str(bad_path), force=False, actor_user_id=None
        )
    # No row created on pre-flight refusal.
    assert db.query(AirgapImport).count() == 0
    ctx = exc_info.value.context
    assert ctx["path"] == str(bad_path)
    assert ctx["reason"] == "tar_corrupt"
    # Raw exception type stays in a debug field (audit-readable, not
    # the primary discriminator).
    assert "exception_type" in ctx


def test_preflight_io_error_uses_tar_io_error_reason(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Bare OSError (not a tarfile.TarError) maps to
    reason='tar_io_error' so the CLI can distinguish "your tar is
    malformed" from "the OS couldn't read it"."""
    import_staging = tmp_path / "import-staging"
    import_staging.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    _pin_trust_key(db)

    # Build a real bundle so _resolve_tar_path passes; then patch
    # _read_descriptor_pair to raise OSError after path resolution.
    bundle_path = _build_bundle(db, tmp_path)
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)

    from app.services.airgap import importer as imp_module

    def fake_read(*args, **kwargs):
        raise OSError("EIO simulated")

    monkeypatch.setattr(imp_module, "_read_descriptor_pair", fake_read)

    from app.services.airgap.importer import BundleDescriptorUnreadable

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(BundleDescriptorUnreadable) as exc_info:
        orchestrator.pre_flight_check(
            path=str(staged_tar), force=False, actor_user_id=None
        )
    assert exc_info.value.context["reason"] == "tar_io_error"
    assert exc_info.value.context["exception_type"] == "OSError"


def test_preflight_malformed_descriptor_returns_unreadable_refusal(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """A tar whose ``bundle.json`` has the right
    ``bundle_version`` but is missing required fields (or has a
    wrong-shape ``profiles``) raises ``KeyError`` / ``TypeError``
    out of ``deserialize_descriptor``. Pre-flight must convert that
    into a structured ``BundleDescriptorUnreadable`` refusal with
    ``reason='descriptor_malformed'`` so POST returns flat 422
    instead of bubbling a 500. No row is created."""
    import io
    import tarfile

    import_staging = tmp_path / "import-staging"
    import_staging.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    _pin_trust_key(db)

    # Build a minimal tar with bundle.json + bundle.json.sig where
    # the descriptor has the right version but is otherwise
    # missing required fields (raises KeyError on data["profiles"]).
    bad_tar = import_staging / "malformed.tar"
    body = b'{"bundle_version": "v1", "bundle_id": "x"}'
    sig = b"sig"
    with tarfile.open(bad_tar, mode="w") as tar:
        for name, payload in (("bundle.json", body), ("bundle.json.sig", sig)):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

    from app.services.airgap.importer import BundleDescriptorUnreadable

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(BundleDescriptorUnreadable) as exc_info:
        orchestrator.pre_flight_check(
            path=str(bad_tar), force=False, actor_user_id=None
        )
    # No row created on pre-flight refusal.
    assert db.query(AirgapImport).count() == 0
    ctx = exc_info.value.context
    assert ctx["reason"] == "descriptor_malformed"
    assert ctx["path"] == str(bad_tar)
    # Raw exception type stays in a debug field so the audit row
    # captures whether it was KeyError vs TypeError.
    assert ctx["exception_type"] in {"KeyError", "TypeError", "ValueError"}


def test_preflight_descriptor_wrong_shape_returns_unreadable_refusal(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """``profiles`` as a string instead of a list raises
    ``TypeError`` from list iteration; same flat refusal surface as
    the missing-field case."""
    import io
    import tarfile

    import_staging = tmp_path / "import-staging"
    import_staging.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    _pin_trust_key(db)

    bad_tar = import_staging / "wrong-shape.tar"
    body = (
        b'{"bundle_version": "v1", "bundle_id": "x", '
        b'"profiles": "not-a-list", "channels": [], "mirrors": []}'
    )
    sig = b"sig"
    with tarfile.open(bad_tar, mode="w") as tar:
        for name, payload in (("bundle.json", body), ("bundle.json.sig", sig)):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

    from app.services.airgap.importer import BundleDescriptorUnreadable

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(BundleDescriptorUnreadable) as exc_info:
        orchestrator.pre_flight_check(
            path=str(bad_tar), force=False, actor_user_id=None
        )
    assert db.query(AirgapImport).count() == 0
    assert exc_info.value.context["reason"] == "descriptor_malformed"


def test_post_verify_descriptor_rebind_mismatch_terminalizes_row(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Rebind happens INSIDE verify_and_stage
    BEFORE staging paths are composed. A swapped tar with a different
    bundle_id raises BundleDescriptorRebindMismatch and the staging
    dir for the swapped id is never created."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    orchestrator = AirgapImportOrchestrator(db)
    row = orchestrator.pre_flight_check(
        path=str(staged_tar), force=False, actor_user_id=None
    )
    assert row.status == "verifying"

    # Patch deserialize_descriptor at the importer-module level so
    # verify_and_stage's deserialize call returns a descriptor with
    # a swapped bundle_id. The rebind check inside verify_and_stage
    # should fire BEFORE _staging_root_for is composed.
    from app.services.airgap import importer as imp_module
    from app.services.airgap.schema import deserialize_descriptor as real_deser

    swapped_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"

    def fake_deserialize(body):
        d = real_deser(body)
        d.bundle_id = swapped_id
        return d

    monkeypatch.setattr(imp_module, "deserialize_descriptor", fake_deserialize)

    from app.services.airgap.importer import BundleDescriptorRebindMismatch

    with pytest.raises(BundleDescriptorRebindMismatch) as exc_info:
        orchestrator.execute_import(row=row, actor_user_id=None)

    db.refresh(row)
    assert row.status == "failed"
    assert exc_info.value.context["expected_bundle_id"] == row.bundle_id
    assert exc_info.value.context["verified_bundle_id"] == swapped_id

    # Staging dir for the SWAPPED id was never
    # composed/created — the rebind check fired first.
    swapped_staging = import_staging / swapped_id
    assert not swapped_staging.exists(), (
        f"swapped staging dir was created at {swapped_staging}; rebind "
        "check fired AFTER _staging_root_for"
    )


def test_in_progress_refusal_includes_reason(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Existing.status='verifying' refusal carries
    reason='import_in_progress' so CLI copy can differ from the
    'already done' case."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    orchestrator = AirgapImportOrchestrator(db)
    row = orchestrator.pre_flight_check(
        path=str(staged_tar), force=False, actor_user_id=None
    )
    assert row.status == "verifying"

    # Second POST with same tar (force=False) should refuse with
    # in-progress reason, not the "already done" wording.
    with pytest.raises(BundleAlreadyImported) as exc_info:
        orchestrator.pre_flight_check(
            path=str(staged_tar), force=False, actor_user_id=None
        )
    assert exc_info.value.context["reason"] == "import_in_progress"
    assert exc_info.value.context["existing_status"] == "verifying"


def test_delta_export_refuses_missing_parent(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """PRA-160 slice #4: planner refuses kind='delta' when
    parent_bundle_id resolves to no airgap_bundles row."""
    # Seed export side just enough to reach the planner.
    _seed_export_side(db)
    _seed_export_disk(
        tmp_path / "mirrors",
        "ubuntu-jammy",
        db.query(MirrorSyncRun).one().id,
    )
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(tmp_path / "bundles"))

    from app.services.airgap.orchestrator import AirgapExportOrchestrator
    from app.services.airgap.planner import DeltaParentMissing

    with pytest.raises(DeltaParentMissing):
        AirgapExportOrchestrator(db).create_descriptor_export(
            profile_slugs=["prod-base"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="delta",
            parent_bundle_id="00000000-0000-0000-0000-000000000000",
            actor_user_id=None,
        )


def test_delta_export_refuses_parent_status_not_ok(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Parent row exists but isn't status='ok' → DeltaParentNotOk."""
    from app.db.models import AirgapBundle

    _seed_export_side(db)
    run_id = db.query(MirrorSyncRun).one().id
    _seed_export_disk(tmp_path / "mirrors", "ubuntu-jammy", run_id)
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(tmp_path / "bundles"))

    # Pre-seed an airgap_bundles row at status='failed' for the
    # parent_bundle_id we'll point at.
    parent_id = "11111111-2222-3333-4444-555555555555"
    db.add(
        AirgapBundle(
            bundle_id=parent_id,
            kind="full",
            status="failed",
            started_at=datetime.utcnow(),
        )
    )
    db.commit()

    from app.services.airgap.orchestrator import AirgapExportOrchestrator
    from app.services.airgap.planner import DeltaParentNotOk

    with pytest.raises(DeltaParentNotOk):
        AirgapExportOrchestrator(db).create_descriptor_export(
            profile_slugs=["prod-base"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="delta",
            parent_bundle_id=parent_id,
            actor_user_id=None,
        )


def test_delta_round_trip_creates_assembled_mirror(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Build full A; mutate live; build delta B (parent=A); import
    A; import B. B's imported live tree should contain parent files
    + delta overlay; descriptor manifest sha must match the assembled
    sha (post-assembly verification)."""
    from pathlib import Path as _Path

    from app.services.airgap import importer as imp_module
    from app.services.airgap.orchestrator import AirgapExportOrchestrator

    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))

    # Build full A.
    slug, run = _seed_export_side(db)
    _seed_export_disk(mirror_root, slug, run.id)
    orchestrator_export = AirgapExportOrchestrator(db)
    full = orchestrator_export.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    full_built = orchestrator_export.build_bundle_payload(
        bundle_id=full.bundle_id, actor_user_id=None
    )
    assert full_built.status == "ok"

    # Mutate the export's live tree: add a new file and modify
    # an existing one. Then build delta B.
    live = mirror_root / slug / "live"
    (live / "main" / "binary-amd64").mkdir(parents=True, exist_ok=True)
    (live / "main" / "binary-amd64" / "Packages.NEW").write_bytes(
        b"Package: brand-new\n"
    )
    (live / "Release").write_bytes(b"Suite: jammy\nUpdated: yes\n")

    delta_row = orchestrator_export.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="delta",
        parent_bundle_id=full.bundle_id,
        actor_user_id=None,
    )
    delta_built = orchestrator_export.build_bundle_payload(
        bundle_id=delta_row.bundle_id, actor_user_id=None
    )
    assert delta_built.status == "ok"

    # Verify the delta carries only the diff: modified file
    # (Release) + new file (Packages.NEW), and NOT the unchanged
    # parent file (main/Packages).
    import tarfile as _tarfile

    with _tarfile.open(delta_built.bundle_path, "r:") as t:
        delta_names = set(t.getnames())
    delta_live = {n for n in delta_names if "/live/" in n}
    assert "mirrors/ubuntu-jammy/live/Release" in delta_live
    assert "mirrors/ubuntu-jammy/live/main/binary-amd64/Packages.NEW" in delta_live
    # Unchanged file from parent NOT in the delta tar.
    assert "mirrors/ubuntu-jammy/live/main/Packages" not in delta_live

    # Stub the assembled-manifest hasher so the delta-assembly
    # check doesn't compare against a synthetic "a"*64 fixture
    # value (the seed sets manifest_sha256='a'*64). The test seed
    # uses a placeholder; the planner stamps that placeholder onto
    # descriptor.mirror.manifest_sha256 for both A and B, so a
    # successful assembly must produce that placeholder. Patch
    # _compute_assembled_manifest_sha to return whatever the
    # descriptor declared so we exercise the wiring rather than
    # the manifest-fingerprint subtlety (which is covered by the
    # mismatch test below).
    def fake_sha(*args, **kwargs):
        return "a" * 64

    monkeypatch.setattr(imp_module, "_compute_assembled_manifest_sha", fake_sha)

    # Import A, then B.
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    full_in_staging = _move_to_import_staging(
        _Path(full_built.bundle_path), import_staging
    )
    delta_in_staging = _move_to_import_staging(
        _Path(delta_built.bundle_path), import_staging
    )
    _pin_trust_key(db)

    importer = AirgapImportOrchestrator(db)
    importer.run_import(path=str(full_in_staging), force=False, actor_user_id=None)
    delta_imported = importer.run_import(
        path=str(delta_in_staging), force=False, actor_user_id=None
    )
    assert delta_imported.status == "ok"
    assert len(delta_imported.target_mirror_slugs) == 1
    delta_target = delta_imported.target_mirror_slugs[0]

    # The imported delta's live tree should contain BOTH parent
    # files (from copy) and delta overlays (overwrites + new).
    import_mirror_root = tmp_path / "import-mirrors"
    delta_live = import_mirror_root / delta_target / "live"
    assert (delta_live / "Release").exists()
    # New file from delta only.
    assert (delta_live / "main" / "binary-amd64" / "Packages.NEW").exists()
    # Modified file: overlaid bytes win.
    assert b"Updated: yes" in (delta_live / "Release").read_bytes()


def test_delta_import_refuses_missing_parent_chain(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Import a delta whose parent isn't in airgap_imports →
    ParentBundleMissing."""
    from pathlib import Path as _Path

    from app.services.airgap.orchestrator import AirgapExportOrchestrator

    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))

    slug, run = _seed_export_side(db)
    _seed_export_disk(mirror_root, slug, run.id)
    orch_export = AirgapExportOrchestrator(db)
    full = orch_export.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    orch_export.build_bundle_payload(bundle_id=full.bundle_id, actor_user_id=None)

    (mirror_root / slug / "live" / "Release").write_bytes(b"changed\n")
    delta = orch_export.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="delta",
        parent_bundle_id=full.bundle_id,
        actor_user_id=None,
    )
    delta_built = orch_export.build_bundle_payload(
        bundle_id=delta.bundle_id, actor_user_id=None
    )

    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    delta_in_staging = _move_to_import_staging(
        _Path(delta_built.bundle_path), import_staging
    )
    _pin_trust_key(db)

    # NOTE: NOT importing A first → delta has no parent on the
    # import side.
    from app.services.airgap.importer import ParentBundleMissing

    with pytest.raises(ParentBundleMissing) as exc_info:
        AirgapImportOrchestrator(db).run_import(
            path=str(delta_in_staging), force=False, actor_user_id=None
        )
    assert exc_info.value.context["missing_parent_bundle_id"] == full.bundle_id
    # Row terminalized as failed.
    delta_row = db.query(AirgapImport).filter_by(bundle_id=delta.bundle_id).one()
    assert delta_row.status == "failed"


def test_delta_export_refuses_deletions(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Delta export refuses if a parent live path
    is absent from the current tree (would be a deletion)."""
    from pathlib import Path as _Path

    from app.services.airgap.orchestrator import AirgapExportOrchestrator
    from app.services.airgap.tar_assembler import DeltaDeletionsUnsupported

    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))

    slug, run = _seed_export_side(db)
    _seed_export_disk(mirror_root, slug, run.id)
    orch = AirgapExportOrchestrator(db)
    full = orch.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    orch.build_bundle_payload(bundle_id=full.bundle_id, actor_user_id=None)

    # Remove a parent live file before building the delta.
    (mirror_root / slug / "live" / "main" / "Packages").unlink()

    delta_row = orch.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="delta",
        parent_bundle_id=full.bundle_id,
        actor_user_id=None,
    )
    # build_bundle_payload should land the row at failed because
    # the deletion check raises during compute_delta_payload_index.
    with pytest.raises(Exception):
        orch.build_bundle_payload(bundle_id=delta_row.bundle_id, actor_user_id=None)
    db.refresh(delta_row)
    assert delta_row.status == "failed"
    assert "DeltaDeletionsUnsupported" in (delta_row.error_text or "")


def test_delta_export_refuses_new_mirror_in_scope(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Delta planner refuses if current scope adds a
    mirror not in the parent. Profile-slug check passes (same
    profile), but the mirror set drifted post-export."""
    from app.services.airgap.orchestrator import AirgapExportOrchestrator
    from app.services.airgap.planner import DeltaParentScopeMismatch

    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))

    slug, run = _seed_export_side(db)
    _seed_export_disk(mirror_root, slug, run.id)
    orch = AirgapExportOrchestrator(db)
    full = orch.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    orch.build_bundle_payload(bundle_id=full.bundle_id, actor_user_id=None)

    # Add a new mirror to the SAME profile post-export; build a
    # delta and the planner should refuse because the current
    # scope contains a mirror that wasn't in the parent.
    new_mirror = MirrorRepo(
        slug="ubuntu-noble",
        display_name="Ubuntu Noble",
        package_family="deb",
        upstream_url="http://example.com/noble",
        distribution="noble",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="ok",
        current_disk_bytes=0,
    )
    db.add(new_mirror)
    db.commit()
    db.refresh(new_mirror)
    db.add(
        MirrorSyncRun(
            mirror_repo_id=new_mirror.id,
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow() + timedelta(seconds=1),
            status="ok",
            run_kind="sync",
            byte_count=64,
            package_count=1,
            manifest_sha256="b" * 64,
            manifest_path=f"/snapshots/run-{new_mirror.id}.manifest.json",
        )
    )
    db.add(
        MirrorSigningKey(
            mirror_repo_id=new_mirror.id,
            status="active",
            gpg_fingerprint="EE" + "0" * 38,
            key_uid=f"Praxis Mirror Signing {new_mirror.slug}",
            vault_path=f"praxis/mirror-signing-keys/{new_mirror.slug}/EE" + "0" * 38,
            armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n",
        )
    )
    # Wire the new mirror into the existing channel.
    chan = db.query(ContentChannel).filter_by(slug="base").one()
    db.add(ContentChannelRepo(channel_id=chan.id, mirror_id=new_mirror.id))
    db.commit()
    _seed_export_disk(
        mirror_root,
        "ubuntu-noble",
        db.query(MirrorSyncRun).filter_by(mirror_repo_id=new_mirror.id).one().id,
    )

    with pytest.raises(DeltaParentScopeMismatch) as exc_info:
        orch.create_descriptor_export(
            profile_slugs=["prod-base"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="delta",
            parent_bundle_id=full.bundle_id,
            actor_user_id=None,
        )
    assert exc_info.value.context["reason"] == "new_mirror_in_delta_scope"
    assert "ubuntu-noble" in exc_info.value.context["new_mirror_slugs"]


def test_force_reuse_refuses_kind_divergence(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Force-reuse with a tar whose kind/parent
    differs from the existing row's metadata refuses with
    BundleAlreadyImported(reason='force_reuse_kind_mismatch')."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    importer = AirgapImportOrchestrator(db)
    # Simulate a previously-failed import row with kind='delta' for
    # the same bundle_id.
    from app.services.airgap.importer import _read_descriptor_pair, _resolve_tar_path
    from app.services.airgap.schema import deserialize_descriptor as real_deser

    body, _ = _read_descriptor_pair(_resolve_tar_path(str(staged_tar)))
    preview = real_deser(body)
    db.add(
        AirgapImport(
            bundle_id=preview.bundle_id,
            parent_bundle_id="ffffffff-ffff-ffff-ffff-ffffffffffff",
            kind="delta",
            status="failed",
            path=str(staged_tar),
            target_mirror_slugs=[],
            started_at=datetime.utcnow(),
        )
    )
    db.commit()

    with pytest.raises(BundleAlreadyImported) as exc_info:
        importer.pre_flight_check(path=str(staged_tar), force=True, actor_user_id=None)
    assert exc_info.value.context["reason"] == "force_reuse_kind_mismatch"


def test_delta_narrowed_scope_does_not_trip_deletion_check(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Parent had two profiles (A + B) covering
    different mirrors; current delta narrows to A only. The other
    profile's parent live files should NOT be flagged as deletions.
    """
    from app.services.airgap.orchestrator import AirgapExportOrchestrator

    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))

    # Seed two mirrors + two profiles + two channels.
    _seed_export_side(db)  # creates ubuntu-jammy + prod-base + base
    extra_mirror = MirrorRepo(
        slug="ubuntu-noble",
        display_name="Ubuntu Noble",
        package_family="deb",
        upstream_url="http://example.com/noble",
        distribution="noble",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="ok",
        current_disk_bytes=0,
    )
    db.add(extra_mirror)
    db.commit()
    db.refresh(extra_mirror)
    extra_run = MirrorSyncRun(
        mirror_repo_id=extra_mirror.id,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow() + timedelta(seconds=1),
        status="ok",
        run_kind="sync",
        byte_count=64,
        package_count=1,
        manifest_sha256="b" * 64,
        manifest_path=f"/snapshots/run-{extra_mirror.id}.manifest.json",
    )
    db.add(extra_run)
    db.add(
        MirrorSigningKey(
            mirror_repo_id=extra_mirror.id,
            status="active",
            gpg_fingerprint="EE" + "0" * 38,
            key_uid="extra",
            vault_path=f"praxis/mirror-signing-keys/{extra_mirror.slug}/EE" + "0" * 38,
            armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n",
        )
    )
    extra_channel = ContentChannel(
        slug="extra", display_name="extra", package_family="deb"
    )
    db.add(extra_channel)
    db.commit()
    db.refresh(extra_channel)
    db.add(ContentChannelRepo(channel_id=extra_channel.id, mirror_id=extra_mirror.id))
    extra_profile = ContentProfile(
        slug="prod-extra", display_name="prod-extra", package_family="deb"
    )
    db.add(extra_profile)
    db.commit()
    db.refresh(extra_profile)
    db.add(
        ContentProfileChannel(profile_id=extra_profile.id, channel_id=extra_channel.id)
    )
    db.commit()

    _seed_export_disk(
        mirror_root,
        "ubuntu-jammy",
        db.query(MirrorSyncRun)
        .filter_by(
            mirror_repo_id=db.query(MirrorRepo).filter_by(slug="ubuntu-jammy").one().id
        )
        .one()
        .id,
    )
    _seed_export_disk(mirror_root, "ubuntu-noble", extra_run.id)

    # Build parent FULL covering BOTH profiles.
    orch = AirgapExportOrchestrator(db)
    full = orch.create_descriptor_export(
        profile_slugs=["prod-base", "prod-extra"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    full_built = orch.build_bundle_payload(bundle_id=full.bundle_id, actor_user_id=None)
    assert full_built.status == "ok"

    # Tweak ubuntu-jammy live to give the delta something to ship.
    (mirror_root / "ubuntu-jammy" / "live" / "Release").write_bytes(b"v2\n")

    # Build delta narrowed to ONLY prod-base. The deletion check
    # should ignore ubuntu-noble's parent paths because that
    # mirror is no longer in the current descriptor's scope.
    delta = orch.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="delta",
        parent_bundle_id=full.bundle_id,
        actor_user_id=None,
    )
    delta_built = orch.build_bundle_payload(
        bundle_id=delta.bundle_id, actor_user_id=None
    )
    assert delta_built.status == "ok", delta_built.error_text


def test_delta_with_empty_current_scope_refuses_with_parent_context(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Empty current mirror scope on a delta refuses
    with DeltaParentScopeMismatch(reason='all_mirrors_dropped'),
    NOT EmptyProfile."""
    from app.services.airgap.orchestrator import AirgapExportOrchestrator
    from app.services.airgap.planner import DeltaParentScopeMismatch

    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))

    slug, run = _seed_export_side(db)
    _seed_export_disk(mirror_root, slug, run.id)
    orch = AirgapExportOrchestrator(db)
    full = orch.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    orch.build_bundle_payload(bundle_id=full.bundle_id, actor_user_id=None)

    # Drop the channel-mirror link so the profile resolves to no
    # mirrors. Profile still exists; parent's scope still has 1
    # mirror. Delta should refuse with all_mirrors_dropped.
    db.query(ContentChannelRepo).delete()
    db.commit()

    with pytest.raises(DeltaParentScopeMismatch) as exc_info:
        orch.create_descriptor_export(
            profile_slugs=["prod-base"],
            snapshot_selector_base="latest",
            snapshot_overrides=None,
            kind="delta",
            parent_bundle_id=full.bundle_id,
            actor_user_id=None,
        )
    assert exc_info.value.context["reason"] == "all_mirrors_dropped"
    assert "ubuntu-jammy" in exc_info.value.context["parent_mirror_slugs"]


def test_post_verify_kind_rebind_mismatch(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Tar swap that flips kind between pre-flight
    and verify is caught by the rebind check on kind."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    importer = AirgapImportOrchestrator(db)
    row = importer.pre_flight_check(
        path=str(staged_tar), force=False, actor_user_id=None
    )
    assert row.kind == "full"

    # Patch deserialize so verify_and_stage's deserialize returns a
    # delta-shaped descriptor (same bundle_id, swapped kind).
    from app.services.airgap import importer as imp_module
    from app.services.airgap.schema import deserialize_descriptor as real_deser

    def fake_deserialize(body):
        d = real_deser(body)
        d.kind = "delta"
        d.parent_bundle_id = "11111111-1111-1111-1111-111111111111"
        return d

    monkeypatch.setattr(imp_module, "deserialize_descriptor", fake_deserialize)

    from app.services.airgap.importer import BundleDescriptorRebindMismatch

    with pytest.raises(BundleDescriptorRebindMismatch) as exc_info:
        importer.execute_import(row=row, actor_user_id=None)
    assert exc_info.value.context["reason"] == "kind_mismatch"


def test_delta_import_refuses_assembly_sha_mismatch(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """If the assembled manifest sha doesn't match the descriptor's
    declared sha (e.g. parent drifted on disk) → DeltaAssemblyMismatch."""
    from pathlib import Path as _Path

    from app.services.airgap import importer as imp_module
    from app.services.airgap.importer import DeltaAssemblyMismatch
    from app.services.airgap.orchestrator import AirgapExportOrchestrator

    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))

    slug, run = _seed_export_side(db)
    _seed_export_disk(mirror_root, slug, run.id)
    orch_export = AirgapExportOrchestrator(db)
    full = orch_export.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    orch_export.build_bundle_payload(bundle_id=full.bundle_id, actor_user_id=None)
    (mirror_root / slug / "live" / "Release").write_bytes(b"v2\n")
    delta = orch_export.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="delta",
        parent_bundle_id=full.bundle_id,
        actor_user_id=None,
    )
    delta_built = orch_export.build_bundle_payload(
        bundle_id=delta.bundle_id, actor_user_id=None
    )

    # Force the assembled sha to NOT match the descriptor's claim.
    monkeypatch.setattr(
        imp_module,
        "_compute_assembled_manifest_sha",
        lambda *a, **kw: "0" * 64,
    )

    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    full_in_staging = _move_to_import_staging(
        _Path(
            orch_export.build_bundle_payload(
                bundle_id=full.bundle_id, actor_user_id=None
            ).bundle_path
        ),
        import_staging,
    )
    delta_in_staging = _move_to_import_staging(
        _Path(delta_built.bundle_path), import_staging
    )
    _pin_trust_key(db)

    importer = AirgapImportOrchestrator(db)
    importer.run_import(path=str(full_in_staging), force=False, actor_user_id=None)
    with pytest.raises(DeltaAssemblyMismatch) as exc_info:
        importer.run_import(path=str(delta_in_staging), force=False, actor_user_id=None)
    assert exc_info.value.context["assembled_sha256"] == "0" * 64


def test_fingerprint_match_refuses_when_armored_fp_not_declared(
    db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """Imported fingerprint not in declared set → refuse."""
    bundle_path = _build_bundle(db, tmp_path)
    import_staging = tmp_path / "import-staging"
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "import-mirrors"))
    staged_tar = _move_to_import_staging(bundle_path, import_staging)
    _pin_trust_key(db)

    # Override the importer's extract to return a fingerprint that
    # doesn't match the descriptor's declared set.
    from app.services.airgap import importer as imp_module

    def divergent_extract(home, armored):
        if "TRUST" in armored:
            return "TRUSTKEY" + "0" * 32
        return "ZZ" + "0" * 38  # not the declared DD-fingerprint

    monkeypatch.setattr(
        imp_module.mirror_gpg,
        "import_public_and_extract_fingerprint",
        divergent_extract,
    )

    from app.services.airgap.importer import ManifestSignatureInvalid

    orchestrator = AirgapImportOrchestrator(db)
    with pytest.raises(ManifestSignatureInvalid) as exc_info:
        orchestrator.run_import(path=str(staged_tar), force=False, actor_user_id=None)
    assert exc_info.value.context["reason"] == "fingerprint_not_declared"
