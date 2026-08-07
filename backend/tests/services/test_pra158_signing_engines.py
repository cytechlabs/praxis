"""PRA-158 #2b: SigningEngine tests (deb + rpm) + manifest stage/promote.

Real-gpg integration tests build a minimal apt or rpm metadata tree
under tmp_path, run the signing engine, and verify the resulting
artifacts with ``gpg --verify``. Skip when gpg is absent (hosted CI);
cold-rebuild's PRAXIS_REQUIRE_MIRROR_TOOL_TESTS=1 promotes the
missing-binary case to a hard import failure (see
test_pra157_real_subprocess).
"""

from __future__ import annotations

import subprocess

import pytest

from app.services.mirror_gpg import (
    ephemeral_gnupg_home,
    generate_keypair,
    gpg_available,
)
from app.services.mirror_signing import engine_for
from app.services.mirror_signing.deb import DebSigningEngine
from app.services.mirror_signing.manifest import (
    cleanup_staged,
    promote_staged_manifest,
    stage_signed_manifest,
)
from app.services.mirror_signing.rpm import RpmSigningEngine

skip_without_gpg = pytest.mark.skipif(
    not gpg_available(),
    reason="needs gpg on PATH (present in backend image; absent on hosted CI)",
)


# ---------------------------------------------------------------------------
# Fixture trees
# ---------------------------------------------------------------------------


def _make_apt_tree(work_dir, suites=("jammy",)):
    """Lay down a minimal apt mirror tree under ``work_dir``.

    Each suite gets a dists/<suite>/Release file with a plausible
    body. A pool/ dir with a fake .deb proves the signing engine
    only touches dists/.
    """
    for suite in suites:
        dist = work_dir / "dists" / suite
        dist.mkdir(parents=True)
        (dist / "Release").write_bytes(
            f"Origin: Test\nLabel: Test\nSuite: {suite}\nArchitectures: amd64\n".encode()
        )
    pool = work_dir / "pool" / "main"
    pool.mkdir(parents=True)
    (pool / "fake_1.0_amd64.deb").write_bytes(b"not a real deb but won't be touched")


def _make_rpm_tree(work_dir, repos=("BaseOS",)):
    """Lay down a minimal rpm mirror tree under ``work_dir``."""
    for repo in repos:
        repodata = work_dir / repo / "repodata"
        repodata.mkdir(parents=True)
        (repodata / "repomd.xml").write_bytes(
            b"<?xml version='1.0' ?>\n<repomd>fake</repomd>\n"
        )
    # A package that should NOT be touched by the signer.
    pkg_dir = work_dir / "Packages"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "fake-1.0-1.noarch.rpm").write_bytes(b"not a real rpm")


def _verify_gpg(home, sig_path, body_path=None):
    """Helper: run gpg --verify; return True on rc=0."""
    args = ["gpg", "--homedir", str(home), "--verify", str(sig_path)]
    if body_path is not None:
        args.append(str(body_path))
    result = subprocess.run(args, capture_output=True, check=False)
    return result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# engine_for dispatch
# ---------------------------------------------------------------------------


def test_engine_for_dispatches_on_package_family():
    class FakeMirror:
        package_family = "deb"

    assert isinstance(engine_for(FakeMirror()), DebSigningEngine)
    FakeMirror.package_family = "rpm"
    assert isinstance(engine_for(FakeMirror()), RpmSigningEngine)


def test_engine_for_unknown_family_raises():
    class FakeMirror:
        package_family = "snap"

    with pytest.raises(NotImplementedError):
        engine_for(FakeMirror())


# ---------------------------------------------------------------------------
# DebSigningEngine — real gpg
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_deb_engine_signs_release_per_suite(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    _make_apt_tree(work, suites=("jammy", "noble"))

    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        result = DebSigningEngine().sign_native(work, fpr, home)

    assert result.ok, result.error_text
    # 2 suites × 2 artifacts (InRelease + Release.gpg) = 4 files.
    assert len(result.signed_files) == 4

    for suite in ("jammy", "noble"):
        dist = work / "dists" / suite
        assert (dist / "InRelease").is_file()
        assert (dist / "Release.gpg").is_file()
        # InRelease must contain the body inline.
        inrelease = (dist / "InRelease").read_text()
        assert f"Suite: {suite}" in inrelease
        # Release.gpg must NOT contain the body (detached).
        release_gpg = (dist / "Release.gpg").read_text()
        assert "Suite:" not in release_gpg
    # Cryptographic verification lives in
    # ``test_deb_engine_signatures_verify`` below — single-suite there
    # so we don't pay 4× verify subprocess cost in this assertion-rich
    # test.


@skip_without_gpg
def test_deb_engine_signatures_verify(tmp_path):
    """End-to-end: signed artifacts pass ``gpg --verify`` against the
    same key. Catches a regression where we change flags in a way
    that produces a syntactically-valid but semantically-broken sig.
    """
    work = tmp_path / "work"
    work.mkdir()
    _make_apt_tree(work, suites=("jammy",))

    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        result = DebSigningEngine().sign_native(work, fpr, home)
        assert result.ok

        dist = work / "dists" / "jammy"
        # Detached signature verifies against the body file.
        ok, stderr = _verify_gpg(home, dist / "Release.gpg", dist / "Release")
        assert ok, stderr
        # InRelease verifies on its own (clearsign carries the body).
        ok, stderr = _verify_gpg(home, dist / "InRelease")
        assert ok, stderr


@skip_without_gpg
def test_deb_engine_idempotent_overwrite(tmp_path):
    """A second sign over the same tree overwrites the prior sigs
    (e.g. after a key rotation) without errors.
    """
    work = tmp_path / "work"
    work.mkdir()
    _make_apt_tree(work, suites=("jammy",))

    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        DebSigningEngine().sign_native(work, fpr, home)
        first_inrelease = (work / "dists" / "jammy" / "InRelease").read_bytes()
        # Sign a second time — should succeed and produce a (possibly
        # byte-different due to gpg timestamp) artifact.
        result = DebSigningEngine().sign_native(work, fpr, home)
        assert result.ok
        second_inrelease = (work / "dists" / "jammy" / "InRelease").read_bytes()
        assert second_inrelease  # non-empty
        # We don't assert byte-equality — gpg embeds a timestamp.


def test_deb_engine_empty_tree_returns_ok_with_no_files(tmp_path):
    """A work dir with no dists/ is treated as nothing-to-sign rather
    than an error — signing engine doesn't decide whether an empty
    sync should fail; that's the orchestrator's call.
    """
    work = tmp_path / "work"
    work.mkdir()

    # Doesn't even need gpg — should return early.
    with ephemeral_gnupg_home() as home:
        fpr = "A" * 40
        result = DebSigningEngine().sign_native(work, fpr, home)
    assert result.ok
    assert result.signed_files == []


@skip_without_gpg
def test_deb_engine_does_not_touch_pool(tmp_path):
    """Pool/ files (.deb packages) must not be modified — apt anchors
    their integrity through Release hashes, not separate sigs.
    """
    work = tmp_path / "work"
    work.mkdir()
    _make_apt_tree(work)
    deb_path = work / "pool" / "main" / "fake_1.0_amd64.deb"
    original = deb_path.read_bytes()

    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        DebSigningEngine().sign_native(work, fpr, home)

    assert deb_path.read_bytes() == original
    # And no Packages.gpg or pool/<x>.gpg appeared.
    assert not (deb_path.with_suffix(".gpg")).exists()


# ---------------------------------------------------------------------------
# RpmSigningEngine — real gpg
# ---------------------------------------------------------------------------


@skip_without_gpg
def test_rpm_engine_signs_repomd_per_repo(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    _make_rpm_tree(work, repos=("BaseOS", "AppStream"))

    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        result = RpmSigningEngine().sign_native(work, fpr, home)

    assert result.ok, result.error_text
    # 2 repos × 2 artifacts (.asc + .key) = 4 files.
    assert len(result.signed_files) == 4

    for repo in ("BaseOS", "AppStream"):
        repodata = work / repo / "repodata"
        assert (repodata / "repomd.xml.asc").is_file()
        assert (repodata / "repomd.xml.key").is_file()
        key_text = (repodata / "repomd.xml.key").read_text()
        assert "BEGIN PGP PUBLIC KEY BLOCK" in key_text


@skip_without_gpg
def test_rpm_engine_signatures_verify(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    _make_rpm_tree(work, repos=("BaseOS",))

    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        RpmSigningEngine().sign_native(work, fpr, home)

        repodata = work / "BaseOS" / "repodata"
        ok, stderr = _verify_gpg(
            home, repodata / "repomd.xml.asc", repodata / "repomd.xml"
        )
        assert ok, stderr


def test_rpm_engine_empty_tree_returns_ok_with_no_files(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    with ephemeral_gnupg_home() as home:
        fpr = "A" * 40
        result = RpmSigningEngine().sign_native(work, fpr, home)
    assert result.ok
    assert result.signed_files == []


@skip_without_gpg
def test_rpm_engine_does_not_touch_packages(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    _make_rpm_tree(work)
    rpm_path = work / "Packages" / "fake-1.0-1.noarch.rpm"
    original = rpm_path.read_bytes()

    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        RpmSigningEngine().sign_native(work, fpr, home)

    assert rpm_path.read_bytes() == original


# ---------------------------------------------------------------------------
# Manifest stage + promote
# ---------------------------------------------------------------------------


def _fake_manifest():
    return {
        "praxis_mirror_manifest": "v1",
        "mirror_slug": "test-mirror",
        "run_id": 7,
        "package_family": "deb",
        "generated_at": "2026-05-03T00:00:00+00:00",
        "byte_count": 0,
        "package_count": 0,
        "files": [],
    }


@skip_without_gpg
def test_stage_signed_manifest_writes_both_files(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        manifest_path, sig_path = stage_signed_manifest(
            slug="test-mirror",
            run_id=7,
            manifest=_fake_manifest(),
            key_fingerprint=fpr,
            gnupg_home=home,
        )

    assert manifest_path.is_file()
    assert sig_path.is_file()
    assert manifest_path.parent == sig_path.parent
    assert "snapshots-staging" in str(manifest_path)
    assert manifest_path.parent.name == "7"


@skip_without_gpg
def test_promote_staged_manifest_moves_to_snapshots(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        stage_signed_manifest(
            slug="test-mirror",
            run_id=7,
            manifest=_fake_manifest(),
            key_fingerprint=fpr,
            gnupg_home=home,
        )

    final_manifest, final_sig = promote_staged_manifest("test-mirror", 7)
    assert final_manifest.is_file()
    assert final_sig.is_file()
    assert "snapshots-staging" not in str(final_manifest)
    assert final_manifest.parent.name == "snapshots"
    # Per-run staging dir is gone.
    assert not (tmp_path / "test-mirror" / "snapshots-staging" / "7").exists()


@skip_without_gpg
def test_promote_staged_manifest_signature_verifies_against_promoted_body(
    monkeypatch, tmp_path
):
    """End-to-end: the signature that lands in snapshots/ verifies
    against the manifest JSON that lands beside it. Catches a
    regression where the promote step might desync the two files.
    """
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        stage_signed_manifest(
            slug="test-mirror",
            run_id=7,
            manifest=_fake_manifest(),
            key_fingerprint=fpr,
            gnupg_home=home,
        )
        manifest_path, sig_path = promote_staged_manifest("test-mirror", 7)
        ok, stderr = _verify_gpg(home, sig_path, manifest_path)
        assert ok, stderr


def test_promote_staged_manifest_raises_when_nothing_staged(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        promote_staged_manifest("never-staged", 99)


@skip_without_gpg
def test_promote_staged_manifest_rolls_back_on_sig_failure(monkeypatch, tmp_path):
    """If the signature mv fails after the
    manifest mv succeeds, the manifest must NOT remain in snapshots/.
    Slice ships paired artifacts or none.
    """
    from app.services.mirror_paths import (
        snapshot_manifest_path,
        snapshot_manifest_signature_path,
    )
    from app.services.mirror_signing import manifest as manifest_mod

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        stage_signed_manifest(
            slug="test-mirror",
            run_id=7,
            manifest=_fake_manifest(),
            key_fingerprint=fpr,
            gnupg_home=home,
        )

    # Pre-create the sig destination as a non-empty dir → Path.replace
    # of a file onto a non-empty dir raises OSError, exercising the
    # rollback path.
    sig_dst = snapshot_manifest_signature_path("test-mirror", 7)
    sig_dst.mkdir(parents=True)
    (sig_dst / "wedge").write_text("not a file")

    with pytest.raises(OSError):
        manifest_mod.promote_staged_manifest("test-mirror", 7)

    # The manifest must NOT be visible at the snapshots/ destination —
    # rollback either restored it to staging or unlinked it. Either
    # way, no orphan unsigned manifest is published.
    assert not snapshot_manifest_path("test-mirror", 7).is_file()


def test_cleanup_staged_is_idempotent_when_dir_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    cleanup_staged("never-staged", 99)  # no raise


@skip_without_gpg
def test_cleanup_staged_removes_per_run_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    with ephemeral_gnupg_home() as home:
        fpr = generate_keypair(home, "test-mirror")
        stage_signed_manifest(
            slug="test-mirror",
            run_id=7,
            manifest=_fake_manifest(),
            key_fingerprint=fpr,
            gnupg_home=home,
        )

    cleanup_staged("test-mirror", 7)
    assert not (tmp_path / "test-mirror" / "snapshots-staging" / "7").exists()
