"""PRA-158 #4b: upstream-verify primitive + orchestrator integration."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from app.db.models import MirrorRepo, MirrorUpstreamKey
from app.services import mirror_disk
from app.services.mirror_alerts import EVENT_UPSTREAM_INVALID
from app.services.mirror_gpg import (
    clearsign,
    detached_sign,
    ephemeral_gnupg_home,
    export_public_armored,
    generate_keypair,
    gpg_available,
)
from app.services.mirror_sync import SyncResult
from app.services.mirror_upstream_verify import verify_upstream_signatures

skip_without_gpg = pytest.mark.skipif(
    not gpg_available(),
    reason="needs gpg on PATH (present in backend image; absent on hosted CI)",
)


def _make_mirror(
    db, *, slug: str, package_family: str = "deb", verify: bool = True
) -> MirrorRepo:
    m = MirrorRepo(
        slug=slug,
        display_name=slug,
        package_family=package_family,
        upstream_url="http://example.com/upstream",
        distribution="jammy" if package_family == "deb" else "9",
        components='["main"]' if package_family == "deb" else "[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        verify_upstream_signature=verify,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _seed_upstream_key(db, *, name: str, fpr: str, armored: str) -> MirrorUpstreamKey:
    row = MirrorUpstreamKey(
        name=name,
        gpg_fingerprint=fpr,
        armored_public_key=armored,
    )
    db.add(row)
    db.commit()
    return row


# ---------------------------------------------------------------------------
# Empty-keyring + missing-artifact failure modes (no gpg needed)
# ---------------------------------------------------------------------------


def test_verify_refuses_when_no_upstream_keys(db, tmp_path):
    mirror = _make_mirror(db, slug="empty-keyring", package_family="deb")
    work = tmp_path / "work"
    (work / "dists" / "jammy").mkdir(parents=True)
    (work / "dists" / "jammy" / "InRelease").write_text("fake")

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok is False
    assert "no upstream trust anchors" in (result.error_text or "")


@skip_without_gpg
def test_verify_refuses_deb_with_no_signed_artifacts(db, tmp_path):
    """A dists/<suite>/ present in work/ but missing both InRelease
    and Release+Release.gpg is a per-suite verification failure.
    The structured error names the suite directory.
    """
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "anchor")
        armored = export_public_armored(home, fpr)

    _seed_upstream_key(db, name="anchor", fpr=fpr, armored=armored)
    mirror = _make_mirror(db, slug="no-sigs", package_family="deb")

    work = tmp_path / "work"
    (work / "dists" / "jammy").mkdir(parents=True)
    # No InRelease, no Release.gpg.
    (work / "dists" / "jammy" / "Release").write_text("Origin: Test\n")

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok is False
    # Per-suite enforcement: the structured failure
    # names the suite explicitly.
    assert "no signed upstream artifact" in (result.error_text or "")
    assert "jammy" in (result.error_text or "")


# ---------------------------------------------------------------------------
# Real-gpg roundtrip: sign with the trusted key, verify, then break it
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_verify_deb_inrelease_succeeds_when_anchor_matches(db, tmp_path):
    """Sign an InRelease body with key K, register K as upstream anchor,
    and the gate accepts.
    """
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "ubuntu-archive-test")
        armored_pub = export_public_armored(home, fpr)
        body = b"Origin: Test\nLabel: Test\nSuite: jammy\nArchitectures: amd64\n"
        inrelease_bytes = clearsign(home, fpr, body)

    _seed_upstream_key(db, name="Ubuntu Archive", fpr=fpr, armored=armored_pub)
    mirror = _make_mirror(db, slug="deb-ok", package_family="deb")

    work = tmp_path / "work"
    suite = work / "dists" / "jammy"
    suite.mkdir(parents=True)
    (suite / "InRelease").write_bytes(inrelease_bytes)

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok, result.error_text
    assert len(result.verified_paths) == 1
    assert result.verified_paths[0].name == "InRelease"


@skip_without_gpg
def test_verify_deb_release_gpg_detached_succeeds(db, tmp_path):
    """Older mirrors only ship Release + Release.gpg (no InRelease).
    Verify the detached pair against the anchor.
    """
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "release-detached")
        armored_pub = export_public_armored(home, fpr)
        body = b"Origin: Test\nSuite: jammy\n"
        sig = detached_sign(home, fpr, body)

    _seed_upstream_key(db, name="Detached", fpr=fpr, armored=armored_pub)
    mirror = _make_mirror(db, slug="deb-detached", package_family="deb")

    work = tmp_path / "work"
    suite = work / "dists" / "jammy"
    suite.mkdir(parents=True)
    (suite / "Release").write_bytes(body)
    (suite / "Release.gpg").write_bytes(sig)
    # Deliberately NO InRelease — engine emits detached-only.

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok, result.error_text
    assert result.verified_paths[0].name == "Release.gpg"


@skip_without_gpg
def test_verify_deb_refuses_when_one_suite_unsigned(db, tmp_path):
    """A multi-suite mirror where one suite has a valid
    InRelease and another has no signed artifact MUST fail. Silently
    letting the unsigned suite pass to Praxis re-signing was the
    vulnerability.
    """
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "anchor")
        armored_pub = export_public_armored(home, fpr)
        body = b"Origin: Test\nSuite: jammy\n"
        inrelease_bytes = clearsign(home, fpr, body)

    _seed_upstream_key(db, name="Anchor", fpr=fpr, armored=armored_pub)
    mirror = _make_mirror(db, slug="multi-suite", package_family="deb")

    work = tmp_path / "work"
    # Signed suite: jammy.
    jammy = work / "dists" / "jammy"
    jammy.mkdir(parents=True)
    (jammy / "InRelease").write_bytes(inrelease_bytes)
    # Unsigned suite: noble (present but no InRelease, no Release.gpg).
    noble = work / "dists" / "noble"
    noble.mkdir(parents=True)
    (noble / "Release").write_text("Origin: Test\n")  # body but no sig

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok is False
    assert "noble" in (result.error_text or "")
    assert "no signed upstream artifact" in (result.error_text or "")


@skip_without_gpg
def test_verify_deb_inrelease_preferred_over_release_gpg(db, tmp_path):
    """When both InRelease and Release.gpg exist, InRelease wins."""
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "prefer-inrelease")
        armored_pub = export_public_armored(home, fpr)
        body = b"Origin: Test\nSuite: jammy\n"
        inrelease_bytes = clearsign(home, fpr, body)
        detached = detached_sign(home, fpr, body)

    _seed_upstream_key(db, name="Anchor", fpr=fpr, armored=armored_pub)
    mirror = _make_mirror(db, slug="deb-both", package_family="deb")

    work = tmp_path / "work"
    suite = work / "dists" / "jammy"
    suite.mkdir(parents=True)
    (suite / "Release").write_bytes(body)
    (suite / "Release.gpg").write_bytes(detached)
    (suite / "InRelease").write_bytes(inrelease_bytes)

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok
    assert [p.name for p in result.verified_paths] == ["InRelease"]


@skip_without_gpg
def test_verify_deb_refuses_when_anchor_does_not_match(db, tmp_path):
    """Sign with key A, register key B as the anchor — verification fails."""
    with ephemeral_gnupg_home() as home_a:
        fpr_a = generate_keypair(home_a, "signer-a")
        body = b"Origin: Test\nSuite: jammy\n"
        inrelease_bytes = clearsign(home_a, fpr_a, body)

    with ephemeral_gnupg_home() as home_b:
        fpr_b = generate_keypair(home_b, "signer-b")
        armored_b = export_public_armored(home_b, fpr_b)

    _seed_upstream_key(db, name="Wrong Anchor", fpr=fpr_b, armored=armored_b)
    mirror = _make_mirror(db, slug="deb-mismatch", package_family="deb")

    work = tmp_path / "work"
    suite = work / "dists" / "jammy"
    suite.mkdir(parents=True)
    (suite / "InRelease").write_bytes(inrelease_bytes)

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok is False
    assert "verification failed" in (result.error_text or "")
    # gpg diagnostic legitimately surfaces the signing-key fingerprint
    # ("RSA key <fpr>: No public key") — fingerprints are public, not
    # key material. We don't try to scrub them here.


@skip_without_gpg
def test_verify_rpm_repomd_succeeds(db, tmp_path):
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "rocky-archive")
        armored_pub = export_public_armored(home, fpr)
        body = b"<?xml version='1.0' ?>\n<repomd>fake</repomd>\n"
        sig = detached_sign(home, fpr, body)

    _seed_upstream_key(db, name="Rocky", fpr=fpr, armored=armored_pub)
    mirror = _make_mirror(db, slug="rpm-ok", package_family="rpm")

    work = tmp_path / "work"
    repodata = work / "BaseOS" / "repodata"
    repodata.mkdir(parents=True)
    (repodata / "repomd.xml").write_bytes(body)
    (repodata / "repomd.xml.asc").write_bytes(sig)

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok, result.error_text
    assert result.verified_paths[0].name == "repomd.xml.asc"


@skip_without_gpg
def test_verify_rpm_refuses_when_repomd_asc_missing(db, tmp_path):
    """A repodata/ without an ``.asc`` is a verification failure when
    verify_upstream_signature=true.
    """
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "rpm-anchor")
        armored_pub = export_public_armored(home, fpr)

    _seed_upstream_key(db, name="Anchor", fpr=fpr, armored=armored_pub)
    mirror = _make_mirror(db, slug="rpm-no-asc", package_family="rpm")

    work = tmp_path / "work"
    repodata = work / "BaseOS" / "repodata"
    repodata.mkdir(parents=True)
    (repodata / "repomd.xml").write_bytes(b"<repomd/>")
    # No .asc.

    result = verify_upstream_signatures(db, mirror, work)
    assert result.ok is False
    assert "verification failed" in (result.error_text or "")


# ---------------------------------------------------------------------------
# Orchestrator integration: gate fires only when conditions are met
# ---------------------------------------------------------------------------


@pytest.fixture
def isolate_mirror_root(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    return tmp_path


def _patch_orchestrator_passthrough(monkeypatch, lay_inrelease: bool = True):
    """Stub disk gate + engine + signing fence so the orchestrator
    runs end-to-end. ``lay_inrelease`` controls whether the engine
    leaves a signed InRelease behind in work/ (used to vary upstream
    presence per test).
    """
    from app.services.mirror_sync import service as svc

    class _Engine:
        def sync(self, mirror, work_dir):
            work_dir.mkdir(parents=True, exist_ok=True)
            if lay_inrelease:
                suite = work_dir / "dists" / "jammy"
                suite.mkdir(parents=True)
                # Body is signed by the test's fixture key — see test
                # bodies. Tests that need a real signed InRelease
                # write it themselves after engine.sync via
                # post_engine hook (handled per-test).
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

    # Stub the signing fence: the upstream-verify test cases don't
    # care about the post-verify path; pass-through with stats.
    def fake_sign(db_, mirror, run, work):
        from app.services.mirror_paths import (
            staged_manifest_dir,
            staged_manifest_path,
            staged_manifest_signature_path,
        )

        staged_manifest_dir(mirror.slug, run.id).mkdir(parents=True, exist_ok=True)
        staged_manifest_path(mirror.slug, run.id).write_bytes(b'{"fake":"manifest"}')
        staged_manifest_signature_path(mirror.slug, run.id).write_bytes(b"fake-sig")
        return svc._SignOutcome(
            ok=True,
            manifest_byte_count=0,
            manifest_package_count=0,
            manifest_sha256_hex="0" * 64,
            signed_with_key_id=None,
        )

    monkeypatch.setattr(svc, "_sign_run_in_work", fake_sign)


def test_orchestrator_skips_verify_for_imported_offline(
    db, isolate_mirror_root, monkeypatch
):
    """imported_offline mirrors don't pull from upstream — gate must
    not run, regardless of verify_upstream_signature.
    """
    from app.db.models import MirrorSyncRun
    from app.services.mirror_sync.service import perform_sync_for_mirror

    _patch_orchestrator_passthrough(monkeypatch)

    m = _make_mirror(db, slug="imported-skip", package_family="deb", verify=True)
    m.source_mode = "imported_offline"
    db.commit()

    run = MirrorSyncRun(
        mirror_repo_id=m.id,
        started_at=datetime.utcnow(),
        status="running",
        run_kind="sync",
    )
    db.add(run)
    db.flush()

    ok, events = perform_sync_for_mirror(db, m, run, prior_status="idle")
    db.commit()

    # No upstream-invalid event because the gate didn't run.
    assert all(e.event_type != EVENT_UPSTREAM_INVALID for e in events)


def test_orchestrator_skips_verify_when_flag_off(db, isolate_mirror_root, monkeypatch):
    """verify_upstream_signature=false → gate must not run."""
    from app.db.models import MirrorSyncRun
    from app.services.mirror_sync.service import perform_sync_for_mirror

    _patch_orchestrator_passthrough(monkeypatch)
    m = _make_mirror(db, slug="verify-off", package_family="deb", verify=False)

    run = MirrorSyncRun(
        mirror_repo_id=m.id,
        started_at=datetime.utcnow(),
        status="running",
        run_kind="sync",
    )
    db.add(run)
    db.flush()

    ok, events = perform_sync_for_mirror(db, m, run, prior_status="idle")
    db.commit()

    assert all(e.event_type != EVENT_UPSTREAM_INVALID for e in events)


@skip_without_gpg
def test_orchestrator_fires_upstream_invalid_event_on_verify_failure(
    db, isolate_mirror_root, monkeypatch
):
    """End-to-end: upstream signed by key A, anchor is key B, sync
    finalizes failed with the canonical alert event in the returned
    events list.
    """
    from app.db.models import MirrorSyncRun
    from app.services.mirror_sync import SyncResult
    from app.services.mirror_sync import service as svc

    # Custom engine that lays a signed InRelease using key A.
    with ephemeral_gnupg_home() as home_a:
        fpr_a = generate_keypair(home_a, "signer-a")
        body = b"Origin: Test\nSuite: jammy\n"
        inrelease = clearsign(home_a, fpr_a, body)
    with ephemeral_gnupg_home() as home_b:
        fpr_b = generate_keypair(home_b, "anchor-b")
        armored_b = export_public_armored(home_b, fpr_b)

    _seed_upstream_key(db, name="Anchor B", fpr=fpr_b, armored=armored_b)
    m = _make_mirror(db, slug="end-to-end-mismatch", package_family="deb")

    class _Engine:
        def sync(self, mirror, work_dir):
            work_dir.mkdir(parents=True, exist_ok=True)
            suite = work_dir / "dists" / "jammy"
            suite.mkdir(parents=True)
            (suite / "InRelease").write_bytes(inrelease)
            return SyncResult(ok=True)

        def estimate_sync_bytes(self, mirror):
            return None

    monkeypatch.setattr(
        "app.services.mirror_sync.service.engine_for", lambda mm: _Engine()
    )
    monkeypatch.setattr(
        "app.services.mirror_sync.service.check_free_space_gate",
        lambda **_kw: mirror_disk.GateDecision(
            allowed=True, reason="", estimate_unavailable=False
        ),
    )

    run = MirrorSyncRun(
        mirror_repo_id=m.id,
        started_at=datetime.utcnow(),
        status="running",
        run_kind="sync",
    )
    db.add(run)
    db.flush()

    ok, events = svc.perform_sync_for_mirror(db, m, run, prior_status="idle")
    db.commit()

    assert ok is False
    db.refresh(run)
    assert run.status == "failed"
    assert "upstream signature invalid" in (run.error_text or "")
    assert any(e.event_type == EVENT_UPSTREAM_INVALID for e in events)
