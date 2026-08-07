"""PRA-160 slice #1: airgap export route — descriptor-only end-to-end.

Surface under test:
  * ``POST /airgap/exports`` — happy path lands as
    ``status='descriptor_ready'`` with the bundle descriptor +
    signature on disk.
  * Planner refusals → 422 with ``code`` + ``context`` in the body.
  * Schema validation: bad selector / missing parent for delta /
    duplicate profile slugs → 422 from Pydantic.

GPG primitives are monkeypatched (signing_key_service AND
descriptor_signer module both reach into ``mirror_gpg``). The route
test uses the in-memory mock_vault for private material.
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
from app.services.airgap import signing_key_service as sk_module

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


@pytest.fixture
def patch_background_build(monkeypatch, db):
    """Run the BackgroundTasks build inline on the test session.

    The production ``run_build_in_background`` opens its own
    ``SessionLocal()``, which lives outside the test's savepoint
    transaction and therefore can't see the test-committed seed
    data. For route tests we substitute an inline runner that
    reuses the test ``db`` session — same code path through
    ``build_bundle_payload`` but visible to assertions.

    The orchestrator unit tests (``test_pra160_airgap_orchestrator.py``)
    cover ``build_bundle_payload`` directly without
    BackgroundTasks; this fixture lets the route end-to-end test
    assert that the route DOES schedule the build and that it
    transitions the row to ``status='ok'`` in the same request
    cycle.
    """
    from app.api.routes import airgap as route_module
    from app.services.airgap.orchestrator import AirgapExportOrchestrator

    def fake_run(bundle_id: str, actor_user_id) -> None:
        AirgapExportOrchestrator(db).build_bundle_payload(
            bundle_id=bundle_id, actor_user_id=actor_user_id
        )

    monkeypatch.setattr(route_module, "run_build_in_background", fake_run)


def _seed_profile_with_synced_mirror(db) -> tuple[ContentProfile, MirrorSyncRun]:
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
        slug="prod-base",
        display_name="prod-base",
        package_family="deb",
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    channel = ContentChannel(
        slug="base",
        display_name="base",
        package_family="deb",
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)

    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(ContentChannelRepo(channel_id=channel.id, mirror_id=mirror.id))
    db.commit()

    # Planner refuses unless every in-scope mirror has a
    # usable armored public key declared.
    db.add(
        MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="active",
            gpg_fingerprint="DD" + "0" * 38,
            key_uid=f"Praxis Mirror Signing {mirror.slug} DD" + "0" * 38,
            vault_path=f"praxis/mirror-signing-keys/{mirror.slug}/DD" + "0" * 38,
            armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n",
        )
    )
    db.commit()

    return profile, run


def _seed_mirror_disk_tree(mirror_root, slug: str, run_id: int) -> None:
    """Seed the on-disk layout the slice-#2 tar assembler walks."""
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


def test_create_export_full_pipeline_to_ok(
    authed_client,
    db,
    mock_vault,
    patch_gpg,
    patch_background_build,
    tmp_path,
    monkeypatch,
):
    """Full slice-#1 + slice-#2 pipeline: POST returns
    descriptor_ready synchronously; BackgroundTasks runs the build
    inline under TestClient and the row reaches status='ok' with
    bundle_path / payload_sha256 / byte_count populated by the time
    the assertions execute."""
    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    _, run = _seed_profile_with_synced_mirror(db)
    _seed_mirror_disk_tree(mirror_root, "ubuntu-jammy", run.id)

    res = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["prod-base"],
            "snapshot_selector": {"base": "latest"},
            "kind": "full",
        },
    )
    assert res.status_code == 201, res.text
    body = res.json()
    bundle_id = body["bundle_id"]
    # The synchronous POST returns descriptor_ready.
    assert body["status"] == "descriptor_ready"
    assert body["bundle_descriptor_path"]

    # BackgroundTasks ran before the test continues. Re-query the
    # row to observe the post-build state.
    db.expire_all()
    row = db.query(AirgapBundle).filter(AirgapBundle.bundle_id == bundle_id).one()
    assert row.status == "ok", row.error_text
    assert row.bundle_path
    assert row.payload_sha256 and len(row.payload_sha256) == 64
    assert row.byte_count and row.byte_count > 0

    from pathlib import Path

    final_tar = Path(row.bundle_path)
    assert final_tar.exists()
    assert not (final_tar.parent / f"{bundle_id}.tar.tmp").exists()


def test_get_export_returns_row(
    authed_client,
    db,
    mock_vault,
    patch_gpg,
    patch_background_build,
    tmp_path,
    monkeypatch,
):
    """GET /airgap/exports/{bundle_id} returns the row state for
    polling. Returns 404 for unknown ids."""
    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    _, run = _seed_profile_with_synced_mirror(db)
    _seed_mirror_disk_tree(mirror_root, "ubuntu-jammy", run.id)

    post = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["prod-base"],
            "snapshot_selector": {"base": "latest"},
            "kind": "full",
        },
    )
    assert post.status_code == 201
    bundle_id = post.json()["bundle_id"]

    got = authed_client.get(f"/airgap/exports/{bundle_id}")
    assert got.status_code == 200
    body = got.json()
    assert body["bundle_id"] == bundle_id
    assert body["status"] == "ok"
    assert body["bundle_path"]
    assert body["payload_sha256"]


def test_get_export_unknown_bundle_returns_404(
    authed_client, db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    res = authed_client.get("/airgap/exports/does-not-exist")
    assert res.status_code == 404


def test_planner_refusal_returns_422_no_row(
    authed_client, db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    res = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["does-not-exist"],
            "snapshot_selector": {"base": "latest"},
            "kind": "full",
        },
    )
    assert res.status_code == 422, res.text
    # Planner-refusal body is flat (not nested under
    # "detail"). The CLI/operator scripts read the top-level "code"
    # to branch on refusal types.
    body = res.json()
    assert "detail" not in body, body
    assert body["code"] == "unknown_profile"
    assert "does-not-exist" in body["context"]["missing"]
    # Locked: no row created on planner refusal.
    assert db.query(AirgapBundle).count() == 0
    # But a signing key row exists — ensure_active runs before planning.
    assert db.query(AirgapBundleSigningKey).count() == 1


def test_delta_kind_requires_parent_at_schema_layer(
    authed_client, db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    res = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["any"],
            "snapshot_selector": {"base": "latest"},
            "kind": "delta",
            # parent_bundle_id intentionally missing
        },
    )
    assert res.status_code == 422, res.text


def test_full_kind_rejects_parent_at_schema_layer(
    authed_client, db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    res = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["any"],
            "snapshot_selector": {"base": "latest"},
            "kind": "full",
            "parent_bundle_id": "bogus",
        },
    )
    assert res.status_code == 422, res.text


def test_invalid_selector_base_returns_422(
    authed_client, db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    res = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["any"],
            "snapshot_selector": {"base": "ancient"},
            "kind": "full",
        },
    )
    assert res.status_code == 422


def test_duplicate_profile_slugs_returns_422(
    authed_client, db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    res = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["dup", "dup"],
            "snapshot_selector": {"base": "latest"},
            "kind": "full",
        },
    )
    assert res.status_code == 422


def test_unauthenticated_rejected(client, patch_gpg):
    res = client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["any"],
            "snapshot_selector": {"base": "latest"},
            "kind": "full",
        },
    )
    assert res.status_code in (401, 403)


# ---------------------------------------------------------------------------
# PRA-198: bounded historical-byte policy for pinned exports.
#
# 1.0 keeps mirror bytes live-only (no per-run byte store). A channel pin is a
# manifest/tracking pin, not a byte freeze. So a "pinned" export whose pinned
# run is byte-EQUIVALENT to the current live/latest-ok run canonicalizes to
# latest-ok and exports; a pin whose manifest DIFFERS from live fails closed
# with the stable ``historical_bytes_unavailable`` code rather than silently
# exporting the wrong (current) bytes.
# ---------------------------------------------------------------------------


def _seed_pinned_profile(db, *, pinned_manifest_sha: str, latest_manifest_sha: str):
    """Seed a profile whose channel pins mirror ``ubuntu-jammy`` to an OLDER ok
    run, with a NEWER ok run as latest-ok. Manifest shas are caller-controlled
    so one helper drives both the byte-equivalent and stale-non-equivalent
    cases. Returns ``(mirror, pinned_run, latest_run)``."""
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

    base_time = datetime.utcnow()
    pinned_run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=base_time - timedelta(hours=1),
        finished_at=base_time - timedelta(hours=1) + timedelta(seconds=5),
        status="ok",
        run_kind="sync",
        byte_count=4096,
        package_count=12,
        manifest_sha256=pinned_manifest_sha,
        manifest_path=f"/snapshots/run-old-{mirror.id}.manifest.json",
    )
    db.add(pinned_run)
    db.commit()
    db.refresh(pinned_run)

    latest_run = MirrorSyncRun(
        mirror_repo_id=mirror.id,
        started_at=base_time,
        finished_at=base_time + timedelta(seconds=5),
        status="ok",
        run_kind="sync",
        byte_count=4096,
        package_count=12,
        manifest_sha256=latest_manifest_sha,
        manifest_path=f"/snapshots/run-new-{mirror.id}.manifest.json",
    )
    db.add(latest_run)
    db.commit()
    db.refresh(latest_run)

    profile = ContentProfile(
        slug="prod-base", display_name="prod-base", package_family="deb"
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    channel = ContentChannel(slug="base", display_name="base", package_family="deb")
    db.add(channel)
    db.commit()
    db.refresh(channel)

    db.add(ContentProfileChannel(profile_id=profile.id, channel_id=channel.id))
    db.add(
        ContentChannelRepo(
            channel_id=channel.id,
            mirror_id=mirror.id,
            pinned_run_id=pinned_run.id,
        )
    )
    db.add(
        MirrorSigningKey(
            mirror_repo_id=mirror.id,
            status="active",
            gpg_fingerprint="DD" + "0" * 38,
            key_uid=f"Praxis Mirror Signing {mirror.slug} DD" + "0" * 38,
            vault_path=f"praxis/mirror-signing-keys/{mirror.slug}/DD" + "0" * 38,
            armored_public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END-----\n",
        )
    )
    db.commit()
    return mirror, pinned_run, latest_run


def test_stale_pinned_export_refused_422(
    authed_client, db, mock_vault, patch_gpg, tmp_path, monkeypatch
):
    """A ``pinned`` export whose pinned run's manifest differs from current live
    fails closed with ``historical_bytes_unavailable`` — the planner refuses
    rather than exporting the wrong (current) bytes. Real planner path."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    mirror, pinned_run, latest_run = _seed_pinned_profile(
        db, pinned_manifest_sha="a" * 64, latest_manifest_sha="b" * 64
    )

    res = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["prod-base"],
            "snapshot_selector": {"base": "pinned"},
            "kind": "full",
        },
    )
    assert res.status_code == 422, res.text
    body = res.json()
    # Flat refusal body (not nested under "detail"); operators branch on code.
    assert "detail" not in body, body
    assert body["code"] == "historical_bytes_unavailable"
    ctx = body["context"]
    assert ctx["mirror_slug"] == mirror.slug
    assert ctx["requested_run_id"] == pinned_run.id
    assert ctx["current_live_run_id"] == latest_run.id
    assert ctx["requested_manifest_sha256"] == "a" * 64
    assert ctx["current_live_manifest_sha256"] == "b" * 64
    assert ctx["reason"]
    # Locked: no bundle row created on a planner refusal.
    assert db.query(AirgapBundle).count() == 0


def test_byte_equivalent_pinned_export_canonicalizes_and_exports(
    authed_client,
    db,
    mock_vault,
    patch_gpg,
    patch_background_build,
    tmp_path,
    monkeypatch,
):
    """A ``pinned`` export whose pinned run is byte-EQUIVALENT to latest-ok
    (same manifest sha) is accepted: the planner canonicalizes to latest-ok and
    the bundle builds. Proves the pin refusal is byte-aware, not pin-blind."""
    mirror_root = tmp_path / "mirrors"
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(mirror_root))
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    _, _pinned_run, latest_run = _seed_pinned_profile(
        db, pinned_manifest_sha="a" * 64, latest_manifest_sha="a" * 64
    )
    # Live tree + manifest sidecar reflect the canonical (latest-ok) run.
    _seed_mirror_disk_tree(mirror_root, "ubuntu-jammy", latest_run.id)

    res = authed_client.post(
        "/airgap/exports",
        json={
            "profile_slugs": ["prod-base"],
            "snapshot_selector": {"base": "pinned"},
            "kind": "full",
        },
    )
    assert res.status_code == 201, res.text
    assert res.json()["status"] == "descriptor_ready"
