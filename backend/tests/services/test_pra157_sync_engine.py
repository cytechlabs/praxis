"""PRA-157 slice #2a: deb sync engine + manifest + free-space gate
+ orchestrator tests.

Subprocess execution is mocked for unit coverage; the real-debmirror
integration test is deferred to a #2a-a follow-up (the orchestrator
contract is fully exercised here via mock engines + filesystem).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.db.models import MirrorRepo, MirrorSyncRun
from app.services import mirror_disk, mirror_manifest, mirror_paths
from app.services.mirror_sync import SyncResult, engine_for
from app.services.mirror_sync.deb import (
    DebSyncEngine,
    _build_debmirror_argv,
    _decode_string_list,
)
from app.services.mirror_sync.service import (
    _promote_work_to_live,
    perform_sync_for_mirror,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_mirror(db, **overrides) -> MirrorRepo:
    base = dict(
        slug=f"test-syncengine-{datetime.utcnow().timestamp()}",
        display_name="Test Mirror",
        package_family="deb",
        upstream_url="http://archive.ubuntu.com/ubuntu",
        distribution="jammy",
        components='["main","universe"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        enabled=True,
        source_mode="upstream_sync",
        verify_upstream_signature=True,
        retention_keep_count=10,
        retention_keep_within_days=30,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    base.update(overrides)
    mirror = MirrorRepo(**base)
    db.add(mirror)
    db.flush()
    return mirror


def _running_run(db, mirror_id: int) -> MirrorSyncRun:
    run = MirrorSyncRun(
        mirror_repo_id=mirror_id,
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(run)
    db.flush()
    return run


def _patch_signing_noop(monkeypatch):
    """Replace the orchestrator's PRA-158 signing fence with a noop
    returning a successful ``_SignOutcome`` (mirrors the helper in
    ``test_pra157_mirror_alerts.py``).

    PRA-157 orchestrator tests drive ``perform_sync_for_mirror`` end
    to end without Vault available; the new signing fence (slice #2c)
    would try to load a private key and fail. These tests are about
    sync orchestration, not signing — noop'ing the fence keeps them
    focused.
    """
    from app.services.mirror_sync import service as svc

    def fake_sign(db_, mirror, run, work):  # noqa: ANN001
        # Build the real manifest from work/ so callers that assert
        # on byte_count/package_count/manifest_sha256 see truthful
        # numbers; only the gpg signing step is skipped. Stage the
        # canonical manifest bytes plus a fake .sig so the
        # orchestrator's promote step has both files to mv.
        from app.services.mirror_manifest import build_manifest as _build
        from app.services.mirror_manifest import manifest_sha256, serialize_manifest
        from app.services.mirror_paths import (
            staged_manifest_dir,
            staged_manifest_path,
            staged_manifest_signature_path,
        )

        manifest = _build(
            slug=mirror.slug,
            run_id=run.id,
            package_family=mirror.package_family,
            root=work,
        )
        staged_manifest_dir(mirror.slug, run.id).mkdir(parents=True, exist_ok=True)
        staged_manifest_path(mirror.slug, run.id).write_bytes(
            serialize_manifest(manifest)
        )
        staged_manifest_signature_path(mirror.slug, run.id).write_bytes(b"fake-sig")
        return svc._SignOutcome(
            ok=True,
            manifest_byte_count=manifest.get("byte_count", 0),
            manifest_package_count=manifest.get("package_count", 0),
            manifest_sha256_hex=manifest_sha256(manifest),
            signed_with_key_id=None,
        )

    monkeypatch.setattr(svc, "_sign_run_in_work", fake_sign)

    # PRA-158 #4b: orchestrator now runs the upstream-verify gate
    # before signing when verify_upstream_signature=true. The legacy
    # orchestrator tests don't seed mirror_upstream_keys, so stub the
    # verify call to passthrough — these tests are about sync-state
    # finalization, not upstream verification.
    from app.services import mirror_upstream_verify

    def fake_verify(db_, mirror, work):  # noqa: ANN001
        return mirror_upstream_verify.UpstreamVerifyResult(ok=True)

    monkeypatch.setattr(
        mirror_upstream_verify, "verify_upstream_signatures", fake_verify
    )


# ---------------------------------------------------------------------------
# mirror_disk — free-space gate
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_disk_usage(monkeypatch):
    """Patch shutil.disk_usage so tests control free/total bytes."""
    from collections import namedtuple

    Usage = namedtuple("Usage", "total used free")

    def _set(total: int, free: int):
        monkeypatch.setattr(
            "shutil.disk_usage",
            lambda _path: Usage(total=total, used=total - free, free=free),
        )

    return _set


def test_disk_gate_global_floor_breached_refuses(
    fake_disk_usage, monkeypatch, tmp_path
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_BYTES", "1000000")
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_PERCENT", "0")
    fake_disk_usage(total=10_000_000, free=500_000)  # below 1 MB floor

    decision = mirror_disk.check_free_space_gate(
        estimate_bytes=None,
        mirror_disk_budget=None,
        current_disk_bytes=0,
    )
    assert decision.allowed is False
    assert "global free-space reserve" in decision.reason


def test_disk_gate_percent_floor_can_dominate(fake_disk_usage, monkeypatch, tmp_path):
    """5% of 1 TiB = 51.2 GiB; that's bigger than the 1 MiB bytes
    floor, so gating must use the percent.
    """
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_BYTES", "1000000")
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_PERCENT", "5")
    one_tib = 1024**4
    fake_disk_usage(total=one_tib, free=10 * 1024**3)  # 10 GiB free

    decision = mirror_disk.check_free_space_gate(
        estimate_bytes=None,
        mirror_disk_budget=None,
        current_disk_bytes=0,
    )
    assert decision.allowed is False, "10 GiB free vs 5% of 1 TiB ≈ 51 GiB floor"


def test_disk_gate_no_estimate_proceeds_with_warning(
    fake_disk_usage, monkeypatch, tmp_path
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_BYTES", "1000")
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_PERCENT", "0")
    fake_disk_usage(total=10_000_000, free=5_000_000)

    decision = mirror_disk.check_free_space_gate(
        estimate_bytes=None,
        mirror_disk_budget=None,
        current_disk_bytes=0,
    )
    assert decision.allowed is True
    assert decision.estimate_unavailable is True


def test_disk_gate_estimate_present_and_sufficient(
    fake_disk_usage, monkeypatch, tmp_path
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_BYTES", "1000")
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_PERCENT", "0")
    fake_disk_usage(total=10_000_000, free=5_000_000)

    decision = mirror_disk.check_free_space_gate(
        estimate_bytes=1_000_000,  # 2x = 2_000_000, under 5_000_000 free
        mirror_disk_budget=None,
        current_disk_bytes=0,
    )
    assert decision.allowed is True
    assert decision.estimate_unavailable is False


def test_disk_gate_estimate_too_big_refuses(fake_disk_usage, monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_BYTES", "1000")
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_PERCENT", "0")
    fake_disk_usage(total=10_000_000, free=5_000_000)

    decision = mirror_disk.check_free_space_gate(
        estimate_bytes=3_000_000,  # 2x = 6_000_000, over 5_000_000 free
        mirror_disk_budget=None,
        current_disk_bytes=0,
    )
    assert decision.allowed is False
    assert "estimate gate breached" in decision.reason


def test_disk_gate_no_estimate_with_budget_uses_conservative_fallback(
    fake_disk_usage, monkeypatch, tmp_path
):
    """Operator set a per-mirror budget; we have no estimate. The
    conservative fallback (1.5x current_disk_bytes, floored at
    budget/4) kicks in.
    """
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_BYTES", "1000")
    monkeypatch.setenv("PRAXIS_MIRROR_MIN_FREE_PERCENT", "0")
    fake_disk_usage(total=100_000_000, free=10_000_000)

    decision = mirror_disk.check_free_space_gate(
        estimate_bytes=None,
        mirror_disk_budget=80_000_000,
        current_disk_bytes=20_000_000,
    )
    # current * 1.5 = 30_000_000 > 10_000_000 free → refuse
    assert decision.allowed is False
    assert "conservative fallback" in decision.reason
    assert decision.estimate_unavailable is True


# ---------------------------------------------------------------------------
# mirror_manifest — manifest builder
# ---------------------------------------------------------------------------


def test_manifest_parses_deb_filename_components():
    pkg, ver, arch = mirror_manifest._parse_deb_filename("nginx_1.18.0-6_amd64.deb")
    assert (pkg, ver, arch) == ("nginx", "1.18.0-6", "amd64")


def test_manifest_parses_deb_filename_with_underscore_in_version():
    pkg, ver, arch = mirror_manifest._parse_deb_filename("lib-foo_2.0-3_amd64.deb")
    # Right-split: package=lib-foo, version=2.0-3, arch=amd64.
    assert pkg == "lib-foo"
    assert arch == "amd64"
    assert ver == "2.0-3"


def test_manifest_non_deb_file_parses_as_no_package():
    assert mirror_manifest._parse_deb_filename("Release") == (None, None, None)
    assert mirror_manifest._parse_deb_filename("Packages.xz") == (None, None, None)


def test_manifest_parses_rpm_filename_components():
    """RPM filenames follow ``name-version-release.arch.rpm``.
    ``version`` returned as joined ``version-release`` (matches
    ``dnf info`` UX). Was previously only deb.
    """
    pkg, ver, arch = mirror_manifest._parse_rpm_filename(
        "nginx-1.20.1-14.el9.x86_64.rpm"
    )
    assert pkg == "nginx"
    assert ver == "1.20.1-14.el9"
    assert arch == "x86_64"


def test_manifest_parses_rpm_filename_with_dash_in_name():
    """Package names can contain dashes (``python3-foo``); right-
    anchored split parses correctly.
    """
    pkg, ver, arch = mirror_manifest._parse_rpm_filename(
        "python3-foo-1.0-1.fc39.noarch.rpm"
    )
    assert pkg == "python3-foo"
    assert ver == "1.0-1.fc39"
    assert arch == "noarch"


def test_manifest_skips_source_rpms():
    """Source RPMs (.src.rpm) parse as no-package — Praxis mirrors
    binary content; SRPM lifecycle is a future concern.
    """
    assert mirror_manifest._parse_rpm_filename("nginx-1.20.1-14.el9.src.rpm") == (
        None,
        None,
        None,
    )


def test_manifest_non_rpm_file_parses_as_no_package():
    assert mirror_manifest._parse_rpm_filename("repomd.xml") == (None, None, None)
    assert mirror_manifest._parse_rpm_filename("primary.xml.gz") == (
        None,
        None,
        None,
    )


def test_manifest_rpm_package_count_is_truthful(tmp_path, monkeypatch):
    """RPM mirrors must report package_count > 0 when .rpm files
    are present. Pre-#3-a, build_manifest only counted deb files.
    """
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    slug = "test-rpm-manifest-count"
    live = tmp_path / slug / "live"
    pool = live / "Packages"
    pool.mkdir(parents=True)
    (pool / "nginx-1.20.1-14.el9.x86_64.rpm").write_bytes(b"fake-rpm-content")
    (pool / "python3-foo-1.0-1.fc39.noarch.rpm").write_bytes(b"another-rpm")
    (live / "repodata").mkdir()
    (live / "repodata" / "repomd.xml").write_bytes(b"<metadata/>")

    manifest = mirror_manifest.build_manifest(slug=slug, run_id=1, package_family="rpm")
    assert manifest["package_count"] == 2
    files_by_name = {f["filename"]: f for f in manifest["files"]}
    nginx = files_by_name["Packages/nginx-1.20.1-14.el9.x86_64.rpm"]
    assert nginx["package"] == "nginx"
    assert nginx["version"] == "1.20.1-14.el9"
    assert nginx["arch"] == "x86_64"
    repomd = files_by_name["repodata/repomd.xml"]
    assert repomd["package"] is None


def test_manifest_build_walks_live_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    slug = "test-manifest-walk"
    live = tmp_path / slug / "live"
    live.mkdir(parents=True)

    pool = live / "pool" / "main" / "n" / "nginx"
    pool.mkdir(parents=True)
    (pool / "nginx_1.18.0_amd64.deb").write_bytes(b"fake-deb-content")
    (live / "Release").write_bytes(b"Origin: Praxis Test")

    manifest = mirror_manifest.build_manifest(
        slug=slug, run_id=42, package_family="deb"
    )
    assert manifest["praxis_mirror_manifest"] == "v1"
    assert manifest["mirror_slug"] == slug
    assert manifest["run_id"] == 42
    assert manifest["package_count"] == 1  # only the .deb counts
    assert manifest["byte_count"] == len(b"fake-deb-content") + len(
        b"Origin: Praxis Test"
    )
    files_by_name = {f["filename"]: f for f in manifest["files"]}
    deb = files_by_name["pool/main/n/nginx/nginx_1.18.0_amd64.deb"]
    assert deb["package"] == "nginx"
    assert deb["version"] == "1.18.0"
    assert deb["arch"] == "amd64"
    assert deb["sha256"] == hashlib.sha256(b"fake-deb-content").hexdigest()
    rel = files_by_name["Release"]
    assert rel["package"] is None


def test_manifest_sha256_is_deterministic(tmp_path):
    """Same files → same manifest_sha256 regardless of walk order or
    when the manifest was built.
    """
    slug = "test-manifest-determinism"
    live = tmp_path / slug / "live"
    live.mkdir(parents=True)
    (live / "a.deb").write_bytes(b"a")
    (live / "b.deb").write_bytes(b"b")

    m1 = mirror_manifest.build_manifest(
        slug=slug, run_id=1, package_family="deb", root=live
    )
    m2 = mirror_manifest.build_manifest(
        slug=slug, run_id=1, package_family="deb", root=live
    )
    assert mirror_manifest.manifest_sha256(m1) == mirror_manifest.manifest_sha256(m2)


def test_manifest_sha256_is_stable_across_run_ids(tmp_path):
    """Two ok runs over the same content (different run_id +
    generated_at) MUST produce the same manifest_sha256 — this is
    the content fingerprint PRA-158 will sign and PRA-160 will use
    as the bundle index. P2 fix on f20b5b5.
    """
    slug = "test-manifest-stable-id"
    live = tmp_path / slug / "live"
    live.mkdir(parents=True)
    (live / "x.deb").write_bytes(b"identical-bytes")
    (live / "y.deb").write_bytes(b"more-bytes")

    m_run_1 = mirror_manifest.build_manifest(
        slug=slug, run_id=1, package_family="deb", root=live
    )
    m_run_99 = mirror_manifest.build_manifest(
        slug=slug, run_id=99, package_family="deb", root=live
    )

    # Volatile fields differ — that's expected and present for forensics.
    assert m_run_1["run_id"] != m_run_99["run_id"]

    # Content hash is identical.
    assert mirror_manifest.manifest_sha256(m_run_1) == mirror_manifest.manifest_sha256(
        m_run_99
    )


def test_manifest_sha256_is_stable_across_mirror_slug(tmp_path):
    """Same content under two different slugs hashes to the same
    fingerprint. Slug is volatile (slugs can be renamed); content
    fingerprint must not depend on it.
    """
    live_a = tmp_path / "alpha" / "live"
    live_b = tmp_path / "beta" / "live"
    live_a.mkdir(parents=True)
    live_b.mkdir(parents=True)
    (live_a / "x.deb").write_bytes(b"shared")
    (live_b / "x.deb").write_bytes(b"shared")

    m_a = mirror_manifest.build_manifest(
        slug="alpha", run_id=1, package_family="deb", root=live_a
    )
    m_b = mirror_manifest.build_manifest(
        slug="beta", run_id=1, package_family="deb", root=live_b
    )
    assert mirror_manifest.manifest_sha256(m_a) == mirror_manifest.manifest_sha256(m_b)


def test_manifest_sha256_changes_when_content_changes(tmp_path):
    """Adding a file flips the content fingerprint."""
    slug = "test-manifest-content-flip"
    live = tmp_path / slug / "live"
    live.mkdir(parents=True)
    (live / "x.deb").write_bytes(b"x")

    m_before = mirror_manifest.build_manifest(
        slug=slug, run_id=1, package_family="deb", root=live
    )
    (live / "y.deb").write_bytes(b"y")
    m_after = mirror_manifest.build_manifest(
        slug=slug, run_id=1, package_family="deb", root=live
    )
    assert mirror_manifest.manifest_sha256(m_before) != mirror_manifest.manifest_sha256(
        m_after
    )


def test_serialize_manifest_includes_volatile_fields_for_forensics(tmp_path):
    """The on-disk JSON keeps run_id / generated_at / mirror_slug so
    an operator inspecting snapshots/<run_id>.manifest.json can see
    which run produced it. Only ``manifest_sha256`` excludes them.
    """
    slug = "test-manifest-forensics"
    live = tmp_path / slug / "live"
    live.mkdir(parents=True)
    (live / "x.deb").write_bytes(b"x")

    manifest = mirror_manifest.build_manifest(
        slug=slug, run_id=42, package_family="deb", root=live
    )
    body = json.loads(mirror_manifest.serialize_manifest(manifest))
    assert body["run_id"] == 42
    assert body["mirror_slug"] == slug
    assert "generated_at" in body


def test_manifest_write_round_trips(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    slug = "test-manifest-write"
    live = mirror_paths.live_dir(slug)
    live.mkdir(parents=True)
    (live / "x.deb").write_bytes(b"x")

    manifest = mirror_manifest.build_manifest(slug=slug, run_id=7, package_family="deb")
    path = mirror_manifest.write_manifest(manifest, slug, 7)
    assert path == mirror_paths.snapshot_manifest_path(slug, 7)
    loaded = json.loads(path.read_bytes())
    assert loaded["mirror_slug"] == slug
    assert loaded["run_id"] == 7


# ---------------------------------------------------------------------------
# mirror_sync.deb — DebSyncEngine argv + subprocess wiring
# ---------------------------------------------------------------------------


def test_deb_argv_has_mandatory_pieces(db, tmp_path):
    mirror = _make_mirror(db, slug="test-argv-basic")
    argv = _build_debmirror_argv(mirror, tmp_path / "work")
    assert argv[0] == "debmirror"
    assert str(tmp_path / "work") in argv
    assert "--host=archive.ubuntu.com" in argv
    assert "--root=/ubuntu" in argv
    assert "--dist=jammy" in argv
    assert "--method=http" in argv
    assert "--section=main,universe" in argv
    assert "--arch=amd64" in argv


def test_deb_argv_omits_section_when_components_empty(db, tmp_path):
    mirror = _make_mirror(db, slug="test-argv-no-comp", components="[]")
    argv = _build_debmirror_argv(mirror, tmp_path / "work")
    assert not any(a.startswith("--section=") for a in argv)


def test_deb_argv_passes_ignore_release_gpg_when_unverified(db, tmp_path):
    mirror = _make_mirror(
        db, slug="test-argv-no-verify", verify_upstream_signature=False
    )
    argv = _build_debmirror_argv(mirror, tmp_path / "work")
    assert "--ignore-release-gpg" in argv

    mirror.verify_upstream_signature = True
    argv2 = _build_debmirror_argv(mirror, tmp_path / "work")
    assert "--ignore-release-gpg" not in argv2


def test_deb_argv_rejects_no_architectures(db, tmp_path):
    mirror = _make_mirror(db, slug="test-argv-no-arch", architectures="[]")
    with pytest.raises(ValueError, match="architecture"):
        _build_debmirror_argv(mirror, tmp_path / "work")


def test_deb_argv_rejects_invalid_upstream_url(db, tmp_path):
    mirror = _make_mirror(db, slug="test-argv-bad-url", upstream_url="not-a-url")
    with pytest.raises(ValueError, match="scheme or host"):
        _build_debmirror_argv(mirror, tmp_path / "work")


def test_decode_string_list_rejects_non_string_items():
    with pytest.raises(ValueError, match="JSON array of strings"):
        _decode_string_list("[1,2,3]", "components")


def test_deb_engine_returns_failed_when_subprocess_rc_nonzero(db, tmp_path):
    mirror = _make_mirror(db, slug="test-engine-rc-fail")
    engine = DebSyncEngine()

    fake_proc = MagicMock(returncode=2, stderr=b"upstream broken", stdout=b"")
    with patch("app.services.mirror_sync.subprocess.run", return_value=fake_proc):
        result = engine.sync(mirror, tmp_path / "work")

    assert result.ok is False
    assert "rc=2" in (result.error_text or "")
    assert "upstream broken" in (result.error_text or "")


def test_deb_engine_handles_missing_debmirror_binary(db, tmp_path):
    mirror = _make_mirror(db, slug="test-engine-missing-bin")
    engine = DebSyncEngine()

    with patch(
        "app.services.mirror_sync.subprocess.run", side_effect=FileNotFoundError
    ):
        result = engine.sync(mirror, tmp_path / "work")
    assert result.ok is False
    assert "debmirror not found" in (result.error_text or "")


def test_deb_engine_estimate_returns_none(db):
    """v1 engine doesn't compute estimates; the gate handles None."""
    mirror = _make_mirror(db, slug="test-engine-estimate")
    assert DebSyncEngine().estimate_sync_bytes(mirror) is None


def test_engine_for_dispatches_on_package_family(db):
    from app.services.mirror_sync.rpm import RpmSyncEngine

    deb_mirror = _make_mirror(db, slug="test-dispatch-deb", package_family="deb")
    assert isinstance(engine_for(deb_mirror), DebSyncEngine)

    rpm_mirror = _make_mirror(db, slug="test-dispatch-rpm", package_family="rpm")
    assert isinstance(engine_for(rpm_mirror), RpmSyncEngine)


# ---------------------------------------------------------------------------
# mirror_sync.rpm — RpmSyncEngine argv + subprocess wiring
# ---------------------------------------------------------------------------


def test_rpm_argv_has_mandatory_pieces(db, tmp_path):
    from app.services.mirror_sync.rpm import _build_dnf_reposync_argv

    mirror = _make_mirror(
        db,
        slug="test-rpm-argv",
        package_family="rpm",
        upstream_url="https://download.example.com/rocky/9/BaseOS/x86_64/os/",
        distribution="el9",
        components="[]",
        architectures='["x86_64"]',
    )
    argv = _build_dnf_reposync_argv(mirror, tmp_path / "work")
    assert argv[0] == "dnf"
    assert argv[1] == "reposync"
    assert "--releasever=praxis" in argv
    assert any(
        a.startswith("--repofrompath=test-rpm-argv,https://download.example.com")
        for a in argv
    )
    assert "--repo=test-rpm-argv" in argv
    assert "--download-metadata" in argv
    assert "--norepopath" in argv
    assert "--delete" in argv
    assert "-p" in argv
    assert str(tmp_path / "work") in argv
    # -a is repeated per arch; noarch is auto-appended.
    arch_indices = [i for i, a in enumerate(argv) if a == "-a"]
    assert arch_indices, "expected at least one -a flag"
    arch_values = [argv[i + 1] for i in arch_indices]
    assert arch_values == ["x86_64", "noarch"]


def test_rpm_argv_repeats_arch_for_multi_arch(db, tmp_path):
    from app.services.mirror_sync.rpm import _build_dnf_reposync_argv

    mirror = _make_mirror(
        db,
        slug="test-rpm-multiarch",
        package_family="rpm",
        upstream_url="https://download.example.com/fedora/39/Everything/",
        distribution="f39",
        architectures='["x86_64","aarch64"]',
    )
    argv = _build_dnf_reposync_argv(mirror, tmp_path / "work")
    arch_values = [argv[i + 1] for i, a in enumerate(argv) if a == "-a"]
    # noarch is auto-appended for RPM mirrors so the
    # operator's binary archs do not silently exclude noarch packages.
    assert arch_values == ["x86_64", "aarch64", "noarch"]


def test_rpm_argv_auto_appends_noarch_to_single_arch(db, tmp_path):
    """One binary arch → emit `-a x86_64 -a noarch`. dnf reposync's
    --arch filter does NOT make noarch implicit; without this the
    one-arch mirror would download incomplete content while
    --download-metadata preserves metadata referencing absent
    noarch RPMs.
    """
    from app.services.mirror_sync.rpm import _build_dnf_reposync_argv

    mirror = _make_mirror(
        db,
        slug="test-rpm-one-arch-noarch",
        package_family="rpm",
        upstream_url="https://example.com/repo/",
        distribution="el9",
        architectures='["x86_64"]',
    )
    argv = _build_dnf_reposync_argv(mirror, tmp_path / "work")
    arch_values = [argv[i + 1] for i, a in enumerate(argv) if a == "-a"]
    assert arch_values == ["x86_64", "noarch"]


def test_rpm_argv_does_not_double_noarch_when_explicit(db, tmp_path):
    """If the operator already lists noarch, don't duplicate it."""
    from app.services.mirror_sync.rpm import _build_dnf_reposync_argv

    mirror = _make_mirror(
        db,
        slug="test-rpm-explicit-noarch",
        package_family="rpm",
        upstream_url="https://example.com/repo/",
        distribution="el9",
        architectures='["x86_64","noarch"]',
    )
    argv = _build_dnf_reposync_argv(mirror, tmp_path / "work")
    arch_values = [argv[i + 1] for i, a in enumerate(argv) if a == "-a"]
    assert arch_values == ["x86_64", "noarch"]
    assert arch_values.count("noarch") == 1


def test_rpm_argv_rejects_unresolved_dnf_repo_variables(db, tmp_path):
    """``$releasever`` / ``$basearch`` / ``$arch`` in upstream_url
    are rejected at argv-build time. The contract says RPM mirrors
    use already-release-resolved URLs; an unresolved variable would
    expand against the sentinel and 404 opaquely.
    """
    from app.services.mirror_sync.rpm import _build_dnf_reposync_argv

    for bad_url in (
        "https://example.com/repo/$releasever/x86_64/",
        "https://example.com/repo/9/$basearch/",
        "https://example.com/$arch/repo/",
    ):
        mirror = _make_mirror(
            db,
            slug=f"test-rpm-var-{datetime.utcnow().timestamp()}",
            package_family="rpm",
            upstream_url=bad_url,
            distribution="el9",
            architectures='["x86_64"]',
        )
        with pytest.raises(ValueError, match="DNF repo variable"):
            _build_dnf_reposync_argv(mirror, tmp_path / "work")


def test_rpm_argv_passes_nogpgcheck_when_unverified(db, tmp_path):
    from app.services.mirror_sync.rpm import _build_dnf_reposync_argv

    mirror = _make_mirror(
        db,
        slug="test-rpm-no-verify",
        package_family="rpm",
        upstream_url="https://example.com/repo/",
        distribution="el9",
        architectures='["x86_64"]',
        verify_upstream_signature=False,
    )
    argv = _build_dnf_reposync_argv(mirror, tmp_path / "work")
    assert "--nogpgcheck" in argv

    mirror.verify_upstream_signature = True
    argv2 = _build_dnf_reposync_argv(mirror, tmp_path / "work")
    assert "--nogpgcheck" not in argv2


def test_rpm_argv_rejects_no_architectures(db, tmp_path):
    from app.services.mirror_sync.rpm import _build_dnf_reposync_argv

    mirror = _make_mirror(
        db,
        slug="test-rpm-no-arch",
        package_family="rpm",
        upstream_url="https://example.com/repo/",
        distribution="el9",
        architectures="[]",
    )
    with pytest.raises(ValueError, match="architecture"):
        _build_dnf_reposync_argv(mirror, tmp_path / "work")


def test_rpm_argv_rejects_invalid_upstream_scheme(db, tmp_path):
    """rsync:// is OK for deb but dnf reposync only takes
    http/https/ftp; the schema layer accepts rsync but the engine
    refuses to build argv. Caller surfaces this as a sync failure.
    """
    from app.services.mirror_sync.rpm import _build_dnf_reposync_argv

    mirror = _make_mirror(
        db,
        slug="test-rpm-bad-scheme",
        package_family="rpm",
        upstream_url="rsync://example.com/repo/",
        distribution="el9",
        architectures='["x86_64"]',
    )
    with pytest.raises(ValueError, match="http"):
        _build_dnf_reposync_argv(mirror, tmp_path / "work")


def test_rpm_engine_returns_failed_when_subprocess_rc_nonzero(db, tmp_path):
    from app.services.mirror_sync.rpm import RpmSyncEngine

    mirror = _make_mirror(
        db,
        slug="test-rpm-rc-fail",
        package_family="rpm",
        upstream_url="https://example.com/repo/",
        distribution="el9",
        architectures='["x86_64"]',
    )
    fake_proc = MagicMock(returncode=1, stderr=b"upstream 404", stdout=b"")
    with patch("app.services.mirror_sync.subprocess.run", return_value=fake_proc):
        result = RpmSyncEngine().sync(mirror, tmp_path / "work")
    assert result.ok is False
    assert "rc=1" in (result.error_text or "")
    assert "upstream 404" in (result.error_text or "")
    assert "dnf reposync" in (result.error_text or "")


def test_rpm_engine_handles_missing_dnf_binary(db, tmp_path):
    from app.services.mirror_sync.rpm import RpmSyncEngine

    mirror = _make_mirror(
        db,
        slug="test-rpm-missing-bin",
        package_family="rpm",
        upstream_url="https://example.com/repo/",
        distribution="el9",
        architectures='["x86_64"]',
    )
    with patch(
        "app.services.mirror_sync.subprocess.run", side_effect=FileNotFoundError
    ):
        result = RpmSyncEngine().sync(mirror, tmp_path / "work")
    assert result.ok is False
    assert "dnf not found" in (result.error_text or "")


def test_rpm_engine_estimate_returns_none(db):
    """v1 rpm engine doesn't compute estimates either."""
    from app.services.mirror_sync.rpm import RpmSyncEngine

    mirror = _make_mirror(
        db,
        slug="test-rpm-estimate",
        package_family="rpm",
        upstream_url="https://example.com/repo/",
        distribution="el9",
        architectures='["x86_64"]',
    )
    assert RpmSyncEngine().estimate_sync_bytes(mirror) is None


# ---------------------------------------------------------------------------
# mirror_sync.service — orchestrator
# ---------------------------------------------------------------------------


class _FakeEngine:
    """Subclass of SyncEngine for orchestrator tests. By default
    succeeds and writes a small file into work/ so the manifest
    builder has something to walk.
    """

    def __init__(
        self,
        ok: bool = True,
        error_text: str = "",
        estimate: int | None = None,
        produce_files: dict[str, bytes] | None = None,
    ):
        self._ok = ok
        self._error_text = error_text
        self._estimate = estimate
        self._produce_files = (
            produce_files
            if produce_files is not None
            else {"foo_1.0_amd64.deb": b"fake-deb"}
        )

    def sync(self, mirror, work_dir: Path) -> SyncResult:
        work_dir.mkdir(parents=True, exist_ok=True)
        if self._ok:
            for relpath, content in self._produce_files.items():
                target = work_dir / relpath
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            return SyncResult(ok=True)
        return SyncResult(ok=False, error_text=self._error_text)

    def estimate_sync_bytes(self, mirror):
        return self._estimate


@pytest.fixture
def patch_disk_gate(monkeypatch):
    """Force the free-space gate to return ``allowed=True`` so
    orchestrator tests don't have to fake disk_usage globally.
    """

    def _do(allowed: bool = True, estimate_unavailable: bool = False):
        monkeypatch.setattr(
            "app.services.mirror_sync.service.check_free_space_gate",
            lambda **_kw: mirror_disk.GateDecision(
                allowed=allowed,
                reason="" if allowed else "test-disabled",
                estimate_unavailable=estimate_unavailable,
            ),
        )

    return _do


def test_orchestrator_finalizes_ok_on_full_happy_path(
    db, tmp_path, monkeypatch, patch_disk_gate
):
    """Engine succeeds, promotion succeeds, manifest written, run row
    finalized as ok with manifest fields populated, mirror state
    advanced.
    """
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    patch_disk_gate(allowed=True)
    _patch_signing_noop(monkeypatch)
    mirror = _make_mirror(db, slug="test-orch-ok")
    db.commit()
    run = _running_run(db, mirror.id)
    db.commit()

    engine = _FakeEngine(produce_files={"hello_1.0_amd64.deb": b"world"})
    with patch("app.services.mirror_sync.service.engine_for", return_value=engine):
        ok, _events = perform_sync_for_mirror(db, mirror, run, now=datetime.utcnow())
    db.commit()

    assert ok is True
    db.refresh(run)
    assert run.status == "ok"
    assert run.manifest_sha256 is not None
    assert run.manifest_path is not None
    assert run.byte_count == len(b"world")
    assert run.package_count == 1
    db.refresh(mirror)
    assert mirror.last_sync_status == "ok"
    assert mirror.last_sync_error is None
    assert mirror.current_disk_bytes == len(b"world")
    # Manifest landed on disk.
    assert Path(run.manifest_path).exists()
    # live/ has the file (promotion ran).
    assert (mirror_paths.live_dir(mirror.slug) / "hello_1.0_amd64.deb").exists()


def test_orchestrator_refuses_on_disk_gate_breach(
    db, tmp_path, monkeypatch, patch_disk_gate
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    patch_disk_gate(allowed=False)
    mirror = _make_mirror(db, slug="test-orch-disk-refuse")
    db.commit()
    run = _running_run(db, mirror.id)
    db.commit()

    engine = _FakeEngine()
    with patch("app.services.mirror_sync.service.engine_for", return_value=engine):
        ok, events = perform_sync_for_mirror(db, mirror, run, now=datetime.utcnow())
    db.commit()

    assert ok is False
    db.refresh(run)
    assert run.status == "failed"
    assert "free-space gate" in (run.error_text or "")
    db.refresh(mirror)
    assert mirror.last_sync_status == "failed"
    assert mirror.last_sync_error is not None
    # PRA-157 #2b-a: orchestrator returns events for the caller to
    # dispatch on a fresh session. Disk-gate refusal builds a
    # disk_pressure event.
    assert any(e.event_type == "mirror_disk_pressure" for e in events)


def test_orchestrator_finalizes_failed_when_engine_fails(
    db, tmp_path, monkeypatch, patch_disk_gate
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    patch_disk_gate(allowed=True)
    mirror = _make_mirror(db, slug="test-orch-engine-fail")
    db.commit()
    run = _running_run(db, mirror.id)
    db.commit()

    engine = _FakeEngine(ok=False, error_text="upstream timeout")
    with patch("app.services.mirror_sync.service.engine_for", return_value=engine):
        ok, events = perform_sync_for_mirror(db, mirror, run, now=datetime.utcnow())
    db.commit()

    assert ok is False
    db.refresh(run)
    assert run.status == "failed"
    assert "upstream timeout" in (run.error_text or "")
    # live/ wasn't promoted — failure path leaves it untouched.
    assert not mirror_paths.live_dir(mirror.slug).exists() or not any(
        mirror_paths.live_dir(mirror.slug).iterdir()
    )
    # PRA-157 #2b-a: engine failure builds a sync_failed event.
    assert any(e.event_type == "mirror_sync_failed" for e in events)


def test_orchestrator_records_estimate_unavailable_warning(
    db, tmp_path, monkeypatch, patch_disk_gate
):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    patch_disk_gate(allowed=True, estimate_unavailable=True)
    _patch_signing_noop(monkeypatch)
    mirror = _make_mirror(db, slug="test-orch-est-warn")
    db.commit()
    run = _running_run(db, mirror.id)
    db.commit()

    engine = _FakeEngine()
    with patch("app.services.mirror_sync.service.engine_for", return_value=engine):
        perform_sync_for_mirror(db, mirror, run, now=datetime.utcnow())  # noqa: F841
    db.commit()

    db.refresh(run)
    assert run.estimate_unavailable is True


def test_promote_work_to_live_copies_contents_and_deletes_extras(tmp_path):
    """rsync --delete must add new files AND remove files in live/
    that are no longer in work/.
    """
    work = tmp_path / "work"
    live = tmp_path / "live"
    work.mkdir()
    live.mkdir()

    (work / "new.deb").write_bytes(b"new")
    (live / "stale.deb").write_bytes(b"stale")  # must be removed
    (live / "still.deb").write_bytes(b"old")  # will be replaced

    (work / "still.deb").write_bytes(b"new-version")

    result = _promote_work_to_live(work, live)
    assert result.ok is True
    assert (live / "new.deb").read_bytes() == b"new"
    assert (live / "still.deb").read_bytes() == b"new-version"
    assert not (live / "stale.deb").exists()


def test_promote_fails_if_work_missing(tmp_path):
    work = tmp_path / "missing"
    live = tmp_path / "live"
    result = _promote_work_to_live(work, live)
    assert result.ok is False
    assert "work dir" in (result.error_text or "")
