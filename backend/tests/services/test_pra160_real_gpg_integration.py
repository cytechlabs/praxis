"""PRA-160 slice #5: real-gpg integration test for airgap export+import.

Builds a bundle with REAL gpg signatures, pins the real public key,
and runs the full slice-#3 importer end-to-end. This is the
acceptance gate that catches:

  * A Dockerfile change that drops the ``gpg`` binary.
  * A drift between export-side signing and import-side
    verification (e.g. canonical-bytes mismatch).
  * Per-mirror manifest signature handling against real keys
    (the unit tests fake import_armored_public + verify_detached).

Hosted CI (which runs pytest directly, no backend image) doesn't
have ``gpg`` and skips this whole module. Cold-rebuild inside the
backend container sets ``PRAXIS_REQUIRE_AIRGAP_TOOL_TESTS=1`` so a
future Dockerfile that drops ``gpg`` fails loudly at module import
instead of silently green-skipping.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.db.models import (
    AirgapImport,
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    MirrorRepo,
    MirrorSigningKey,
    MirrorSyncRun,
)
from app.services import mirror_gpg
from app.services.airgap.import_trust_service import ImportTrustKeyService
from app.services.airgap.importer import AirgapImportOrchestrator
from app.services.airgap.orchestrator import AirgapExportOrchestrator

# Mark slow — generating real gpg keys takes seconds.
pytestmark = pytest.mark.slow

# Same pattern as PRA-157 #6-c real-subprocess gate. Cold-rebuild
# sets PRAXIS_REQUIRE_AIRGAP_TOOL_TESTS=1 so missing gpg fails loud.
_REQUIRE_AIRGAP_TOOLS = os.environ.get("PRAXIS_REQUIRE_AIRGAP_TOOL_TESTS") == "1"

if _REQUIRE_AIRGAP_TOOLS and shutil.which("gpg") is None:
    raise RuntimeError(
        "PRAXIS_REQUIRE_AIRGAP_TOOL_TESTS=1 but the gpg binary is missing. "
        "Cold-rebuild gate requires the backend image to ship gnupg — "
        "check the Dockerfile."
    )

_HAS_GPG = shutil.which("gpg") is not None
skip_without_gpg = pytest.mark.skipif(
    not _HAS_GPG, reason="gpg binary not available on this host"
)


def _seed_export_side(db) -> tuple[str, MirrorSyncRun, MirrorSigningKey]:
    """Seed an export-side mirror + profile + channel + signing key
    using REAL gpg key generation.

    Distinct from the unit-test seed because the mirror signing key's
    armored_public_key must be a real PGP block that gpg can import +
    fingerprint-extract on the import side.
    """
    # Generate a real per-mirror signing key.
    with mirror_gpg.ephemeral_gnupg_home() as home:
        fingerprint = mirror_gpg.generate_keypair(home, "ubuntu-jammy")
        public_armored = mirror_gpg.export_public_armored(home, fingerprint)
        # The export-side service would persist the private half to
        # Vault; for this test we don't persist it because we only
        # need the public for the descriptor. The bundle-signing key
        # is generated separately by AirgapBundleSigningKeyService
        # below via real gpg.

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
        finished_at=datetime.utcnow() + timedelta(seconds=1),
        status="ok",
        run_kind="sync",
        byte_count=128,
        package_count=2,
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
    signing_key = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status="active",
        gpg_fingerprint=fingerprint,
        key_uid=f"Praxis Mirror Signing {mirror.slug} {fingerprint}",
        vault_path=f"praxis/mirror-signing-keys/{mirror.slug}/{fingerprint}",
        armored_public_key=public_armored,
    )
    db.add(signing_key)
    db.commit()
    db.refresh(signing_key)
    return "ubuntu-jammy", run, signing_key


def _seed_export_disk(
    mirror_root: Path,
    slug: str,
    run_id: int,
    *,
    signing_key: MirrorSigningKey,
) -> None:
    """Seed live tree + a REAL signed manifest sidecar at
    snapshots/<run_id>.manifest.json{,.sig}."""
    mirror_dir = mirror_root / slug
    snaps = mirror_dir / "snapshots"
    snaps.mkdir(parents=True, exist_ok=True)
    manifest_path = snaps / f"{run_id}.manifest.json"
    manifest_body = b'{"manifest_sha256":"a"}'
    manifest_path.write_bytes(manifest_body)

    # Real-sign the manifest with the per-mirror key. We need the
    # private half — re-generate one in an ephemeral home, but
    # to keep the descriptor's declared fingerprint matching, we
    # import the previously-exported public into a fresh home
    # alongside a freshly-generated private with the same uid.
    # Simpler path: regenerate a key and re-export public, then
    # update the signing_key row to match. The descriptor reads
    # signing_key.armored_public_key via planner so this stays
    # consistent.
    with mirror_gpg.ephemeral_gnupg_home() as home:
        fpr = mirror_gpg.generate_keypair(home, slug)
        new_public = mirror_gpg.export_public_armored(home, fpr)
        sig_bytes = mirror_gpg.detached_sign(home, fpr, manifest_body)
    (manifest_path.with_suffix(".json.sig")).write_bytes(sig_bytes)
    # Update signing key row's armored + fingerprint to the one
    # that actually signed the manifest, otherwise the importer's
    # fingerprint-match check refuses.
    signing_key.gpg_fingerprint = fpr
    signing_key.armored_public_key = new_public

    live = mirror_dir / "live"
    live.mkdir(parents=True, exist_ok=True)
    (live / "Release").write_bytes(b"Suite: jammy\n")


def _pin_bundle_trust_key(db, fingerprint: str, armored: str) -> None:
    """Inject the bundle signing key directly into
    airgap_import_trust_keys (bypass the service's GPG re-import,
    which would refuse multi-primary armor in some real keys).
    Production path goes through ImportTrustKeyService which
    extracts the fingerprint via gpg; here we already know it.
    """
    from app.db.models import AirgapImportTrustKey

    db.add(
        AirgapImportTrustKey(
            gpg_fingerprint=fingerprint,
            key_uid=f"Praxis Airgap Bundle Signing {fingerprint}",
            armored_public_key=armored,
        )
    )
    db.commit()


@skip_without_gpg
def test_real_gpg_round_trip(db, mock_vault, tmp_path, monkeypatch):
    """Full export → import with REAL gpg signatures and fingerprint
    extraction. Catches drift between export-side signing and
    import-side verification."""
    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))

    slug, run, signing_key = _seed_export_side(db)
    _seed_export_disk(mirror_root, slug, run.id, signing_key=signing_key)
    db.commit()

    orch = AirgapExportOrchestrator(db)
    full = orch.create_descriptor_export(
        profile_slugs=["prod-base"],
        snapshot_selector_base="latest",
        snapshot_overrides=None,
        kind="full",
        parent_bundle_id=None,
        actor_user_id=None,
    )
    built = orch.build_bundle_payload(bundle_id=full.bundle_id, actor_user_id=None)
    assert built.status == "ok"

    # Pin the bundle-signing key for the import side. Pull the
    # public + fingerprint from the AirgapBundleSigningKey row the
    # export side just created.
    from app.db.models import AirgapBundleSigningKey

    bundle_key = db.query(AirgapBundleSigningKey).filter_by(status="active").one()
    _pin_bundle_trust_key(
        db,
        fingerprint=bundle_key.gpg_fingerprint,
        armored=bundle_key.armored_public_key,
    )

    # Move the bundle into import staging, then import.
    import_staging = tmp_path / "import-staging"
    import_staging.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PRAXIS_AIRGAP_IMPORT_STAGING", str(import_staging))
    import_mirror_root = tmp_path / "import-mirrors"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(import_mirror_root))

    staged_tar = import_staging / Path(built.bundle_path).name
    shutil.copy2(built.bundle_path, staged_tar)

    importer = AirgapImportOrchestrator(db)
    row = importer.run_import(path=str(staged_tar), force=False, actor_user_id=None)
    assert row.status == "ok", row.error_text
    assert len(row.target_mirror_slugs) == 1
    target_slug = row.target_mirror_slugs[0]
    target_mirror = db.query(MirrorRepo).filter_by(slug=target_slug).one()
    assert target_mirror.source_mode == "imported_offline"
    assert target_mirror.enabled is False

    # On-disk live tree assembled from the verified payload.
    assert (import_mirror_root / target_slug / "live" / "Release").exists()
    # The praxis-mirror.json layout descriptor was written.
    assert (import_mirror_root / "praxis-mirror.json").exists()
