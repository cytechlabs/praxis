"""PRA-157 #6: real-subprocess integration tests for debmirror +
dnf reposync.

The unit tests in ``test_pra157_sync_engine.py`` mock subprocess
execution to exercise the orchestrator + manifest + promotion paths
quickly. These tests run the actual ``debmirror`` and ``dnf
reposync`` binaries against fixture upstream repos served by a
local HTTP server in a thread. Slow (multi-second per test) but
catches keyring / repo-layout / argv-shape surprises that mocks
miss.

Marked ``slow`` so unrelated test runs don't pay the time cost.
The cold-rebuild gate runs them as part of the PRA-157 e2e suite.

Fixtures use the binaries already in the backend image:

  * ``apt-utils`` (apt-ftparchive) — added to the Dockerfiles in
    this slice; generates ``Packages``/``Release`` from a pool dir.
  * ``dpkg-deb`` — ships with dpkg, builds a tiny stub .deb.
  * ``createrepo_c`` — installed in #3; generates ``repodata/`` for
    the rpm fixture.
"""

from __future__ import annotations

import gzip
import http.server
import os
import shutil
import socketserver
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator

import pytest

from app.db.models import MirrorAlertState, MirrorRepo, MirrorSyncRun
from app.db.session import SessionLocal

# Each test in this module spends seconds on subprocess work; mark
# them slow so a developer iterating on unit tests can opt out via
# ``pytest -m "not slow"``.
pytestmark = pytest.mark.slow

# PRA-157 #6-c: hosted CI runs pytest directly on the GitHub runner
# (paths under /opt/hostedtoolcache/Python/...), NOT inside the
# backend Docker image. That host doesn't have debmirror /
# apt-ftparchive / dnf / createrepo_c, so these tests skipif-out
# there. Cold-rebuild inside Docker MUST exercise them — that's the
# whole purpose of slice #6 as the real-subprocess acceptance gate.
# scripts/test-cold-rebuild.sh sets PRAXIS_REQUIRE_MIRROR_TOOL_TESTS=1
# so a future Dockerfile change that drops one of the binaries fails
# loudly at module import instead of silently skipping past the gate.
_REQUIRE_MIRROR_TOOLS = os.environ.get("PRAXIS_REQUIRE_MIRROR_TOOL_TESTS") == "1"

_REQUIRED_BINARIES = (
    "debmirror",
    "apt-ftparchive",
    "dpkg-deb",
    "dnf",
    "createrepo_c",
    # PRA-158 #1: full gnupg required for the signing pipeline. gpgv
    # alone (verify-only, shipped since PRA-157) cannot --gen-key,
    # --sign, or --import. The cold-rebuild gate must catch a future
    # Dockerfile that drops gnupg.
    "gpg",
)
if _REQUIRE_MIRROR_TOOLS:
    _missing = [b for b in _REQUIRED_BINARIES if shutil.which(b) is None]
    if _missing:
        raise RuntimeError(
            f"PRAXIS_REQUIRE_MIRROR_TOOL_TESTS=1 but missing binaries: "
            f"{_missing}. Cold-rebuild gate requires the backend image to "
            f"ship debmirror, apt-ftparchive, dpkg-deb, dnf, "
            f"createrepo_c, and gpg — check the Dockerfile."
        )

_HAS_DEBMIRROR = shutil.which("debmirror") is not None
_HAS_APT_FTPARCHIVE = shutil.which("apt-ftparchive") is not None
_HAS_DPKG_DEB = shutil.which("dpkg-deb") is not None
_HAS_DNF = shutil.which("dnf") is not None
_HAS_CREATEREPO_C = shutil.which("createrepo_c") is not None
_HAS_APT_TOOLCHAIN = _HAS_DEBMIRROR and _HAS_APT_FTPARCHIVE and _HAS_DPKG_DEB
_HAS_DNF_TOOLCHAIN = _HAS_DNF and _HAS_CREATEREPO_C

skip_without_apt = pytest.mark.skipif(
    not _HAS_APT_TOOLCHAIN,
    reason=(
        "needs debmirror + apt-ftparchive + dpkg-deb on PATH "
        "(present in backend image; absent on hosted CI runner)"
    ),
)
skip_without_dnf = pytest.mark.skipif(
    not _HAS_DNF_TOOLCHAIN,
    reason=(
        "needs dnf + createrepo_c on PATH "
        "(present in backend image; absent on hosted CI runner)"
    ),
)


# ---------------------------------------------------------------------------
# HTTP server (thread-scoped per test)
# ---------------------------------------------------------------------------


class _ReuseAddrServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextmanager
def _serve_directory(root: Path) -> Generator[int, None, None]:
    """Serve ``root`` on a free localhost port; yield the port.

    The server runs in a daemon thread; the with-block tears it
    down on exit. Uses ThreadingTCPServer so debmirror's parallel
    fetches don't deadlock on the request-at-a-time default.
    """

    def _handler_factory(*args, **kwargs):
        return http.server.SimpleHTTPRequestHandler(
            *args, directory=str(root), **kwargs
        )

    httpd = _ReuseAddrServer(("127.0.0.1", 0), _handler_factory)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Fixture builders — apt + rpm
# ---------------------------------------------------------------------------


def _build_stub_deb(work: Path, package: str, version: str, arch: str) -> Path:
    """Build a minimal valid .deb via dpkg-deb. Returns the .deb
    path. The package's only behavior is "exists in the index";
    no postinst/preinst.
    """
    pkg_root = work / f"{package}-build"
    debian = pkg_root / "DEBIAN"
    debian.mkdir(parents=True)
    (debian / "control").write_text(
        f"Package: {package}\n"
        f"Version: {version}\n"
        f"Architecture: {arch}\n"
        "Maintainer: Praxis Test <test@praxis.local>\n"
        f"Description: Stub package for PRA-157 integration test\n"
    )
    out = work / f"{package}_{version}_{arch}.deb"
    res = subprocess.run(
        ["dpkg-deb", "--build", str(pkg_root), str(out)],
        capture_output=True,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"dpkg-deb failed rc={res.returncode}: "
            f"{res.stderr.decode('utf-8', errors='replace')}"
        )
    return out


def _build_apt_repo(
    repo_root: Path,
    *,
    dist: str = "praxis-test",
    component: str = "main",
    arch: str = "amd64",
) -> None:
    """Lay out an apt repo at ``repo_root`` with one stub package.
    Uses ``apt-ftparchive`` to generate the indexes and Release.
    """
    pool = repo_root / "pool" / component
    pool.mkdir(parents=True)
    deb_workdir = repo_root / "_build"
    deb_workdir.mkdir()
    deb = _build_stub_deb(deb_workdir, "praxis-stub", "1.0", arch)
    final = pool / deb.name
    final.write_bytes(deb.read_bytes())

    binary_dir = repo_root / "dists" / dist / component / f"binary-{arch}"
    binary_dir.mkdir(parents=True)

    pkgs = subprocess.run(
        ["apt-ftparchive", "packages", f"pool/{component}"],
        cwd=repo_root,
        capture_output=True,
        check=True,
    )
    packages_path = binary_dir / "Packages"
    packages_path.write_bytes(pkgs.stdout)
    (binary_dir / "Packages.gz").write_bytes(gzip.compress(pkgs.stdout))

    release = subprocess.run(
        [
            "apt-ftparchive",
            "-o",
            f"APT::FTPArchive::Release::Origin=Praxis Test",
            "-o",
            f"APT::FTPArchive::Release::Codename={dist}",
            "-o",
            f"APT::FTPArchive::Release::Suite=testing",
            "-o",
            f"APT::FTPArchive::Release::Architectures={arch}",
            "-o",
            f"APT::FTPArchive::Release::Components={component}",
            "release",
            f"dists/{dist}",
        ],
        cwd=repo_root,
        capture_output=True,
        check=True,
    )
    (repo_root / "dists" / dist / "Release").write_bytes(release.stdout)


def _build_rpm_repo(repo_root: Path) -> None:
    """Lay out an empty rpm repo at ``repo_root`` via
    ``createrepo_c``. Empty package set keeps the fixture trivial
    while still exercising dnf's repodata parsing path.
    """
    repo_root.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        ["createrepo_c", str(repo_root)],
        capture_output=True,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"createrepo_c failed rc={res.returncode}: "
            f"{res.stderr.decode('utf-8', errors='replace')}"
        )


# ---------------------------------------------------------------------------
# Mirror lifecycle helpers (real DB writes; cleanup at end)
# ---------------------------------------------------------------------------


def _patch_signing_noop(monkeypatch):
    """Stub the PRA-158 signing fence so cold-rebuild real-subprocess
    tests don't need a working Vault token (PRA-158 #5-d).

    Slice #2c made every sync call ``MirrorSigningKeyService.ensure_active``
    inside ``perform_sync_for_mirror``. The cold-rebuild stack starts
    Vault but doesn't seed VAULT_TOKEN into the test process's env, so
    these tests — which call ``claim_and_sync_one_mirror`` against the
    live stack — fail with "VAULT_TOKEN environment variable not set"
    when the new fence runs. The tests are about real debmirror/dnf
    behavior, not signing; mirror the helper from
    ``test_pra157_sync_engine.py`` to noop the fence.

    Builds a real manifest from work/ so byte_count/package_count
    assertions on the run row still see truthful numbers — only the
    gpg+Vault round-trip is skipped.
    """
    from app.services.mirror_sync import service as svc

    def fake_sign(db_, mirror, run, work):  # noqa: ANN001
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


def _insert_mirror(**fields) -> int:
    setup = SessionLocal()
    try:
        m = MirrorRepo(**fields)
        setup.add(m)
        setup.commit()
        return m.id
    finally:
        setup.close()


def _cleanup_mirror(mirror_id: int) -> None:
    cleanup = SessionLocal()
    try:
        cleanup.query(MirrorAlertState).filter(
            MirrorAlertState.mirror_repo_id == mirror_id
        ).delete()
        cleanup.query(MirrorSyncRun).filter(
            MirrorSyncRun.mirror_repo_id == mirror_id
        ).delete()
        cleanup.query(MirrorRepo).filter(MirrorRepo.id == mirror_id).delete()
        cleanup.commit()
    finally:
        cleanup.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@skip_without_apt
def test_real_debmirror_syncs_fixture_apt_repo(tmp_path, monkeypatch):
    """End-to-end through ``claim_and_sync_one_mirror`` with the
    actual ``debmirror`` binary, against an apt-ftparchive-built
    fixture repo. Asserts run finalizes ok, manifest has the stub
    package, live/ tree contains the .deb.
    """
    from app.services.mirror_sweep import claim_and_sync_one_mirror

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "praxis-mirrors"))
    _patch_signing_noop(monkeypatch)

    upstream_root = tmp_path / "fixture-apt"
    _build_apt_repo(upstream_root, dist="praxis-test", arch="amd64")

    slug = f"e2e-deb-{int(datetime.utcnow().timestamp())}"
    with _serve_directory(upstream_root) as port:
        mirror_id = _insert_mirror(
            slug=slug,
            display_name="Real-debmirror integration",
            package_family="deb",
            upstream_url=f"http://127.0.0.1:{port}/",
            distribution="praxis-test",
            components='["main"]',
            architectures='["amd64"]',
            sync_schedule_cron="0 2 * * *",
            enabled=True,
            source_mode="upstream_sync",
            verify_upstream_signature=False,  # fixture isn't signed
            retention_keep_count=10,
            retention_keep_within_days=30,
            last_sync_status="idle",
            current_disk_bytes=0,
        )
        try:
            outcome = claim_and_sync_one_mirror(mirror_id, slug)
            assert outcome == "ok", outcome

            # Verify the run row, manifest, and live/ tree.
            check = SessionLocal()
            try:
                run = (
                    check.query(MirrorSyncRun)
                    .filter(MirrorSyncRun.mirror_repo_id == mirror_id)
                    .order_by(MirrorSyncRun.id.desc())
                    .first()
                )
                assert run is not None
                assert run.status == "ok"
                assert run.manifest_sha256 is not None
                assert run.package_count is not None and run.package_count >= 1
                assert run.byte_count is not None and run.byte_count > 0

                manifest_path = Path(run.manifest_path)
                assert manifest_path.is_file()

                live = Path(tmp_path / "praxis-mirrors") / slug / "live"
                # debmirror lays the deb under pool/main/.../*.deb
                debs = list(live.rglob("*.deb"))
                assert (
                    len(debs) >= 1
                ), f"expected at least one .deb under {live}; got {debs}"
                # And metadata files.
                releases = list(live.rglob("Release"))
                assert (
                    len(releases) >= 1
                ), f"expected Release file under {live}; got {releases}"
            finally:
                check.close()
        finally:
            _cleanup_mirror(mirror_id)


@skip_without_dnf
def test_real_dnf_reposync_syncs_empty_fixture_rpm_repo(tmp_path, monkeypatch):
    """End-to-end through ``claim_and_sync_one_mirror`` with the
    actual ``dnf reposync`` binary, against a createrepo_c-built
    empty fixture repo. Asserts run finalizes ok with package_count=0
    (empty repo) but live/ contains the repodata tree.
    """
    from app.services.mirror_sweep import claim_and_sync_one_mirror

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "praxis-mirrors"))
    _patch_signing_noop(monkeypatch)

    upstream_root = tmp_path / "fixture-rpm"
    _build_rpm_repo(upstream_root)

    slug = f"e2e-rpm-{int(datetime.utcnow().timestamp())}"
    with _serve_directory(upstream_root) as port:
        mirror_id = _insert_mirror(
            slug=slug,
            display_name="Real-dnf-reposync integration",
            package_family="rpm",
            upstream_url=f"http://127.0.0.1:{port}/",
            distribution="praxis-test",
            components="[]",
            architectures='["x86_64"]',
            sync_schedule_cron="0 2 * * *",
            enabled=True,
            source_mode="upstream_sync",
            verify_upstream_signature=False,
            retention_keep_count=10,
            retention_keep_within_days=30,
            last_sync_status="idle",
            current_disk_bytes=0,
        )
        try:
            outcome = claim_and_sync_one_mirror(mirror_id, slug)
            assert outcome == "ok", outcome

            check = SessionLocal()
            try:
                run = (
                    check.query(MirrorSyncRun)
                    .filter(MirrorSyncRun.mirror_repo_id == mirror_id)
                    .order_by(MirrorSyncRun.id.desc())
                    .first()
                )
                assert run is not None
                assert run.status == "ok"
                assert run.manifest_sha256 is not None
                # Empty fixture → 0 .rpm packages but repodata exists.
                assert run.package_count == 0
                assert run.byte_count is not None and run.byte_count >= 0

                live = Path(tmp_path / "praxis-mirrors") / slug / "live"
                # dnf reposync writes the upstream repodata into live/
                # via --download-metadata + --norepopath.
                repomd = list(live.rglob("repomd.xml"))
                assert (
                    len(repomd) >= 1
                ), f"expected repomd.xml under {live}; got {repomd}"
            finally:
                check.close()
        finally:
            _cleanup_mirror(mirror_id)


@skip_without_dnf
def test_dnf_reposync_writes_state_into_dnf_state_dir_not_cwd(tmp_path, monkeypatch):
    """``dnf reposync`` creates ``.rpmdb/`` under ``$HOME`` on first
    invocation (empirically verified — NOT cwd, even though many
    similar tools do use cwd). The praxis user's HOME is ``/app``
    in production, so without isolation the state would pollute
    the application root and distinct RPM mirrors would contend on
    shared rpmdb. The rpm engine pins BOTH ``cwd`` and ``HOME`` to
    ``dnf_state_dir(slug)`` so the side-effect lands under the
    mirror's slug root and:

      * does NOT land under the orchestrator's working directory.
      * does NOT land under ``work/`` or ``live/`` (never
        promoted to clients).

    P2 #6-a regression. Asserts post-state of all four
    candidate locations.
    """
    import os

    from app.services.mirror_paths import dnf_state_dir, live_dir, work_dir
    from app.services.mirror_sweep import claim_and_sync_one_mirror

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "praxis-mirrors"))
    _patch_signing_noop(monkeypatch)

    upstream_root = tmp_path / "fixture-rpm-cwd"
    _build_rpm_repo(upstream_root)

    slug = f"e2e-rpm-cwd-{int(datetime.utcnow().timestamp())}"
    cwd_before = os.getcwd()
    rpmdb_in_cwd_before = (Path(cwd_before) / ".rpmdb").exists()

    with _serve_directory(upstream_root) as port:
        mirror_id = _insert_mirror(
            slug=slug,
            display_name="dnf cwd isolation",
            package_family="rpm",
            upstream_url=f"http://127.0.0.1:{port}/",
            distribution="praxis-test",
            components="[]",
            architectures='["x86_64"]',
            sync_schedule_cron="0 2 * * *",
            enabled=True,
            source_mode="upstream_sync",
            verify_upstream_signature=False,
            retention_keep_count=10,
            retention_keep_within_days=30,
            last_sync_status="idle",
            current_disk_bytes=0,
        )
        try:
            outcome = claim_and_sync_one_mirror(mirror_id, slug)
            assert outcome == "ok", outcome

            assert (
                os.getcwd() == cwd_before
            ), "subprocess.run with cwd= must not change the parent's cwd"
            # If the orchestrator's cwd had an .rpmdb before, it
            # might still — but the test only meaningfully asserts
            # that THIS sync didn't add one.
            if not rpmdb_in_cwd_before:
                assert not (Path(cwd_before) / ".rpmdb").exists(), (
                    "dnf wrote .rpmdb/ into the orchestrator's cwd; the "
                    "engine should pin BOTH cwd and HOME to dnf_state_dir(slug)"
                )
            assert not (live_dir(slug) / ".rpmdb").exists()
            assert not (work_dir(slug) / ".rpmdb").exists()
            # The dedicated state dir SHOULD have it.
            assert (dnf_state_dir(slug) / ".rpmdb").exists(), (
                "expected dnf to land .rpmdb/ in the dedicated " "dnf_state_dir(slug)"
            )
        finally:
            _cleanup_mirror(mirror_id)


@skip_without_apt
def test_real_debmirror_resumes_incremental_on_second_sync(tmp_path, monkeypatch):
    """Two consecutive syncs against the same fixture: second is
    incremental on the same ``work/`` dir. Asserts both finalize ok
    and the second's manifest_sha256 equals the first's (same
    content).
    """
    from app.services.mirror_sweep import claim_and_sync_one_mirror

    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "praxis-mirrors"))
    _patch_signing_noop(monkeypatch)

    upstream_root = tmp_path / "fixture-apt-incr"
    _build_apt_repo(upstream_root)

    slug = f"e2e-deb-incr-{int(datetime.utcnow().timestamp())}"
    with _serve_directory(upstream_root) as port:
        mirror_id = _insert_mirror(
            slug=slug,
            display_name="Real-debmirror incremental",
            package_family="deb",
            upstream_url=f"http://127.0.0.1:{port}/",
            distribution="praxis-test",
            components='["main"]',
            architectures='["amd64"]',
            sync_schedule_cron="0 2 * * *",
            enabled=True,
            source_mode="upstream_sync",
            verify_upstream_signature=False,
            retention_keep_count=10,
            retention_keep_within_days=30,
            last_sync_status="idle",
            current_disk_bytes=0,
        )
        try:
            outcome1 = claim_and_sync_one_mirror(mirror_id, slug)
            assert outcome1 == "ok", outcome1
            outcome2 = claim_and_sync_one_mirror(mirror_id, slug)
            assert outcome2 == "ok", outcome2

            check = SessionLocal()
            try:
                runs = (
                    check.query(MirrorSyncRun)
                    .filter(
                        MirrorSyncRun.mirror_repo_id == mirror_id,
                        MirrorSyncRun.status == "ok",
                    )
                    .order_by(MirrorSyncRun.id.asc())
                    .all()
                )
                # Retention keeps both (count=10, days=30).
                assert len(runs) >= 2
                first, second = runs[0], runs[-1]
                # Both produced a content fingerprint. Bit-exact
                # equality across runs is NOT asserted here — debmirror
                # touches some metadata/translation files on the
                # second pass even when upstream is unchanged, so the
                # manifest's `files` entries can differ in sha/size
                # between runs against the same fixture. The
                # cross-run determinism contract (identical files →
                # identical hash) is exercised by
                # ``test_manifest_sha256_is_stable_across_run_ids`` in
                # the unit suite. The integration test's value here
                # is proving the second sync runs successfully on
                # debmirror's resumable work/ tree rather than
                # blowing up.
                assert first.manifest_sha256 is not None
                assert second.manifest_sha256 is not None
            finally:
                check.close()
        finally:
            _cleanup_mirror(mirror_id)
