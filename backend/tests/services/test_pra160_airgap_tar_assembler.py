"""PRA-160 slice #2: tar assembler unit tests.

Covers:
  * plan_payload_members layout (manifest + sidecar + live tree).
  * compute_payload_index hashes deterministically; raises on
    missing source files.
  * assemble_bundle_tar produces a deterministic tar (zeroed mtime
    + uid/gid), atomic .tmp → final rename, payload_sha256 matches
    a separate sha256 of the final file.
  * Tar member layout includes bundle.json + sig at the root and
    every payload member at the declared path_in_tar.
"""

from __future__ import annotations

import hashlib
import tarfile
from pathlib import Path

import pytest

from app.services.airgap.schema import (
    BUNDLE_SCHEMA_VERSION,
    BundleDescriptor,
    ChannelDescriptor,
    MirrorRunDescriptor,
    ProfileDescriptor,
)
from app.services.airgap.tar_assembler import (
    PayloadIndexError,
    assemble_bundle_tar,
    compute_payload_index,
    plan_payload_members,
)

_FPR = "AA00000000000000000000000000000000000001"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_descriptor(slug: str, run_id: int) -> BundleDescriptor:
    return BundleDescriptor(
        bundle_version=BUNDLE_SCHEMA_VERSION,
        bundle_id="bundle-test-1",
        kind="full",
        parent_bundle_id=None,
        created_at="2026-05-06T00:00:00Z",
        praxis_instance_signing_fingerprint=_FPR,
        profiles=[
            ProfileDescriptor(
                slug="prod",
                display_name="prod",
                package_family="deb",
                description=None,
                channel_slugs=["base"],
            )
        ],
        channels=[
            ChannelDescriptor(
                slug="base",
                display_name="base",
                package_family="deb",
                description=None,
                repos=[],
            )
        ],
        mirrors=[
            MirrorRunDescriptor(
                mirror_slug=slug,
                package_family="deb",
                distribution="jammy",
                components=["main"],
                architectures=["amd64"],
                run_id=run_id,
                manifest_sha256="a" * 64,
                manifest_path="/data/praxis/mirrors/x/snapshots/x.manifest.json",
                byte_count=None,
                package_count=None,
                signing_key_fingerprints=["BB" + "0" * 38],
                signing_keys_armored=["-----BEGIN PGP PUBLIC KEY BLOCK-----\n"],
            )
        ],
    )


def _seed_mirror_tree(
    mirror_root: Path,
    slug: str,
    run_id: int,
    *,
    live_files: dict[str, bytes] | None = None,
    manifest_body: bytes = b'{"manifest_sha256":"a"}',
    manifest_sig: bytes = b"-----BEGIN PGP SIGNATURE-----\nFAKE\n-----END-----\n",
) -> None:
    mirror_dir = mirror_root / slug
    snapshots = mirror_dir / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    (snapshots / f"{run_id}.manifest.json").write_bytes(manifest_body)
    (snapshots / f"{run_id}.manifest.json.sig").write_bytes(manifest_sig)

    live = mirror_dir / "live"
    live.mkdir(parents=True, exist_ok=True)
    files = live_files or {
        "Release": b"Suite: jammy\n",
        "main/binary-amd64/Packages": b"Package: hello\n",
    }
    for rel, body in files.items():
        target = live / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)


# ---------------------------------------------------------------------------
# plan_payload_members
# ---------------------------------------------------------------------------


def test_plan_payload_members_layout(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    _seed_mirror_tree(tmp_path, "ubuntu-jammy", 42)
    descriptor = _make_descriptor("ubuntu-jammy", 42)

    plans = plan_payload_members(descriptor)
    paths = [p.path_in_tar for p in plans]
    assert "mirrors/ubuntu-jammy/snapshots/42.manifest.json" in paths
    assert "mirrors/ubuntu-jammy/snapshots/42.manifest.json.sig" in paths
    assert "mirrors/ubuntu-jammy/live/Release" in paths
    assert "mirrors/ubuntu-jammy/live/main/binary-amd64/Packages" in paths
    # Manifest pair lands BEFORE the live tree files.
    manifest_idx = paths.index("mirrors/ubuntu-jammy/snapshots/42.manifest.json")
    live_idx = paths.index("mirrors/ubuntu-jammy/live/Release")
    assert manifest_idx < live_idx


def test_plan_refuses_symlinks_in_live(tmp_path, monkeypatch):
    """V1 refuses mirrors with symlinks in the live
    tree. PRA-157 ``rsync -a`` preserves symlinks, and the manifest
    walker follows file symlinks when hashing — silently skipping
    here would create a signed manifest claiming a file exists
    while the exported tar omits it. Schema needs symlink-aware
    semantics before we can include them safely."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    _seed_mirror_tree(tmp_path, "syml", 1)
    live = tmp_path / "syml" / "live"
    target = live / "Release"
    link = live / "Release.symlink"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    descriptor = _make_descriptor("syml", 1)
    with pytest.raises(PayloadIndexError, match="symlink"):
        plan_payload_members(descriptor)


def test_plan_refuses_missing_live_tree(tmp_path, monkeypatch):
    """Missing live/ → hard PayloadIndexError, not
    silent empty payload."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    # Seed manifest sidecars but NOT live/.
    snapshots = tmp_path / "noLive" / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    (snapshots / "1.manifest.json").write_bytes(b'{"x":true}')
    (snapshots / "1.manifest.json.sig").write_bytes(b"sig")
    descriptor = _make_descriptor("noLive", 1)
    with pytest.raises(PayloadIndexError, match="no live tree"):
        plan_payload_members(descriptor)


def test_plan_refuses_live_path_that_is_not_a_directory(tmp_path, monkeypatch):
    """live/ exists but is a regular file, not a directory."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    mirror_dir = tmp_path / "filelive"
    snapshots = mirror_dir / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    (snapshots / "1.manifest.json").write_bytes(b'{"x":true}')
    (snapshots / "1.manifest.json.sig").write_bytes(b"sig")
    (mirror_dir / "live").write_bytes(b"not a dir")
    descriptor = _make_descriptor("filelive", 1)
    with pytest.raises(PayloadIndexError, match="not a directory"):
        plan_payload_members(descriptor)


# ---------------------------------------------------------------------------
# compute_payload_index
# ---------------------------------------------------------------------------


def test_compute_payload_index_hashes_match_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    _seed_mirror_tree(
        tmp_path,
        "ubuntu-hash",
        7,
        live_files={"Release": b"hello-bytes\n"},
    )
    descriptor = _make_descriptor("ubuntu-hash", 7)

    index, plans = compute_payload_index(descriptor)
    by_path = {e.path_in_tar: e for e in index}
    release_entry = by_path["mirrors/ubuntu-hash/live/Release"]
    assert release_entry.sha256 == hashlib.sha256(b"hello-bytes\n").hexdigest()
    assert release_entry.byte_count == len(b"hello-bytes\n")
    # Index covers every plan member.
    assert len(index) == len(plans)


def test_compute_payload_index_raises_when_manifest_missing(tmp_path, monkeypatch):
    """Manifest sidecar missing but live/ exists → PayloadIndexError
    from the per-member existence check inside compute_payload_index."""
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path))
    # Seed live/ but NOT the manifest sidecars.
    live = tmp_path / "noManifest" / "live"
    live.mkdir(parents=True, exist_ok=True)
    (live / "Release").write_bytes(b"R")
    descriptor = _make_descriptor("noManifest", 1)

    with pytest.raises(PayloadIndexError, match="payload member missing"):
        compute_payload_index(descriptor)


# ---------------------------------------------------------------------------
# assemble_bundle_tar
# ---------------------------------------------------------------------------


def _write_descriptor_pair(staging: Path) -> tuple[Path, Path]:
    body = staging / "bundle.json"
    sig = staging / "bundle.json.sig"
    body.parent.mkdir(parents=True, exist_ok=True)
    body.write_bytes(b'{"bundle_version":"v1","stub":true}')
    sig.write_bytes(b"-----BEGIN PGP SIGNATURE-----\nFAKE\n-----END-----\n")
    return body, sig


def test_assemble_bundle_tar_writes_atomic_pair(tmp_path, monkeypatch):
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    _seed_mirror_tree(
        tmp_path / "mirrors",
        "ubuntu-asm",
        9,
        live_files={"Release": b"r1", "Packages": b"p1"},
    )
    descriptor = _make_descriptor("ubuntu-asm", 9)
    index, plans = compute_payload_index(descriptor)
    staging = tmp_path / "stage"
    body_path, sig_path = _write_descriptor_pair(staging)

    final_path, payload_sha, byte_count = assemble_bundle_tar(
        bundle_id=descriptor.bundle_id,
        descriptor_body_path=body_path,
        descriptor_signature_path=sig_path,
        member_plans=plans,
        payload_index=index,
    )

    # Final file exists; tmp doesn't.
    assert final_path.exists()
    assert not (bundle_root / f"{descriptor.bundle_id}.tar.tmp").exists()
    # Reported byte_count + payload_sha256 match a fresh hash of
    # the final file on disk.
    actual_sha = hashlib.sha256(final_path.read_bytes()).hexdigest()
    assert payload_sha == actual_sha
    assert byte_count == final_path.stat().st_size


def test_assemble_bundle_tar_member_layout(tmp_path, monkeypatch):
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    _seed_mirror_tree(
        tmp_path / "mirrors",
        "ubuntu-layout",
        12,
        live_files={"Release": b"R", "main/binary-amd64/Packages": b"P"},
    )
    descriptor = _make_descriptor("ubuntu-layout", 12)
    index, plans = compute_payload_index(descriptor)
    staging = tmp_path / "stage"
    body_path, sig_path = _write_descriptor_pair(staging)

    final_path, _, _ = assemble_bundle_tar(
        bundle_id=descriptor.bundle_id,
        descriptor_body_path=body_path,
        descriptor_signature_path=sig_path,
        member_plans=plans,
        payload_index=index,
    )

    with tarfile.open(final_path, "r") as tar:
        names = tar.getnames()
    # Trust anchor pair lands FIRST.
    assert names[0] == "bundle.json"
    assert names[1] == "bundle.json.sig"
    # Then mirror payload.
    assert "mirrors/ubuntu-layout/snapshots/12.manifest.json" in names
    assert "mirrors/ubuntu-layout/snapshots/12.manifest.json.sig" in names
    assert "mirrors/ubuntu-layout/live/Release" in names
    assert "mirrors/ubuntu-layout/live/main/binary-amd64/Packages" in names


def test_assemble_bundle_tar_is_deterministic(tmp_path, monkeypatch):
    """Two assemblies of the same content tree produce identical
    payload_sha256. mtime/uid/gid must be normalized."""
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    _seed_mirror_tree(
        tmp_path / "mirrors",
        "ubuntu-det",
        1,
        live_files={"Release": b"deterministic"},
    )
    descriptor = _make_descriptor("ubuntu-det", 1)
    index, plans = compute_payload_index(descriptor)
    staging = tmp_path / "stage"
    body_path, sig_path = _write_descriptor_pair(staging)

    final1, sha1, _ = assemble_bundle_tar(
        bundle_id="det-run-1",
        descriptor_body_path=body_path,
        descriptor_signature_path=sig_path,
        member_plans=plans,
        payload_index=index,
    )

    # Touch the source files (advance their mtime); content
    # unchanged. Re-assemble under a different bundle_id.
    import os
    import time

    new_mtime = time.time() + 5
    for plan in plans:
        os.utime(plan.source_path, (new_mtime, new_mtime))

    index2, plans2 = compute_payload_index(descriptor)
    final2, sha2, _ = assemble_bundle_tar(
        bundle_id="det-run-2",
        descriptor_body_path=body_path,
        descriptor_signature_path=sig_path,
        member_plans=plans2,
        payload_index=index2,
    )
    # bundle_id differs, but the payload-bytes hashes are equal
    # because mtime is normalized in the tar headers and bundle.json
    # is the same body.
    assert sha1 == sha2
    assert final1 != final2


def test_assemble_bundle_tar_refuses_when_source_grew_with_same_prefix(
    tmp_path, monkeypatch
):
    """Source file grew after index, but the prefix
    matches the signed sha. Without the pre-stat check the
    sha-tracking reader would only consume the signed-length prefix
    and falsely sign off, silently truncating the now-longer source
    in the tar."""
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    _seed_mirror_tree(
        tmp_path / "mirrors",
        "ubuntu-append",
        4,
        live_files={"Release": b"original-prefix"},
    )
    descriptor = _make_descriptor("ubuntu-append", 4)
    index, plans = compute_payload_index(descriptor)
    staging = tmp_path / "stage"
    body_path, sig_path = _write_descriptor_pair(staging)

    # Append bytes to the live file. Original prefix stays intact —
    # so a tracker that only reads expected.byte_count would compute
    # the same sha and the build would silently truncate.
    last_plan = plans[-1]  # the live "Release" file
    last_plan.source_path.write_bytes(b"original-prefix" + b"-extra")

    from app.services.airgap.tar_assembler import PayloadIntegrityError

    with pytest.raises(PayloadIntegrityError, match="size changed on disk"):
        assemble_bundle_tar(
            bundle_id="append",
            descriptor_body_path=body_path,
            descriptor_signature_path=sig_path,
            member_plans=plans,
            payload_index=index,
        )
    assert not (bundle_root / "append.tar.tmp").exists()
    assert not (bundle_root / "append.tar").exists()


def test_assemble_bundle_tar_refuses_when_source_grows_mid_write(tmp_path, monkeypatch):
    """File grows AFTER the pre-add fstat but before
    or during tar.addfile. The post-addfile fstat re-check catches
    it — closes the open-fd race window the path-level pre-stat
    couldn't cover."""
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    _seed_mirror_tree(
        tmp_path / "mirrors",
        "ubuntu-mid",
        6,
        live_files={"Release": b"original"},
    )
    descriptor = _make_descriptor("ubuntu-mid", 6)
    index, plans = compute_payload_index(descriptor)
    staging = tmp_path / "stage"
    body_path, sig_path = _write_descriptor_pair(staging)

    # Synthetic exercise of the post-add fstat recheck. The
    # real-world race (concurrent writer extends the inode while
    # tarfile reads exactly the signed prefix) is hard to reproduce
    # deterministically; monkeypatching ``os.fstat`` per-fd
    # call-count returns the expected size on the first call (pre-
    # add) and a grown size on the second call (post-add), so the
    # pre-add fstat passes and the post-add fstat fires.
    from app.services.airgap import tar_assembler as ta

    real_fstat = ta.os.fstat
    target_size = len(b"original")
    target_match_count = {"n": 0}

    class _Stub:
        def __init__(self, size):
            self.st_size = size

    def fake_fstat(fd):
        actual = real_fstat(fd)
        # Pre-add and post-add fstats are paired per member. The
        # Release file (target_size bytes) is the only one of size
        # 8 in this fixture; manifest + sig are larger. So the
        # first fstat that returns target_size is the pre-add for
        # Release; the second is the post-add. Mutate the second.
        if actual.st_size == target_size:
            target_match_count["n"] += 1
            if target_match_count["n"] == 2:
                return _Stub(actual.st_size + 6)
        return actual

    monkeypatch.setattr("os.fstat", fake_fstat)

    from app.services.airgap.tar_assembler import PayloadIntegrityError

    with pytest.raises(PayloadIntegrityError, match="size changed during"):
        assemble_bundle_tar(
            bundle_id="mid",
            descriptor_body_path=body_path,
            descriptor_signature_path=sig_path,
            member_plans=plans,
            payload_index=index,
        )
    assert not (bundle_root / "mid.tar.tmp").exists()
    assert not (bundle_root / "mid.tar").exists()


def test_assemble_bundle_tar_refuses_when_member_size_changes(tmp_path, monkeypatch):
    """Source file shrinks/grows between index hash
    and tar write → byte_count mismatch → PayloadIntegrityError."""
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    _seed_mirror_tree(
        tmp_path / "mirrors", "ubuntu-grow", 3, live_files={"Release": b"original"}
    )
    descriptor = _make_descriptor("ubuntu-grow", 3)
    index, plans = compute_payload_index(descriptor)
    staging = tmp_path / "stage"
    body_path, sig_path = _write_descriptor_pair(staging)

    # Grow the file between index and assembly.
    plans[-1].source_path.write_bytes(b"now longer than before")

    from app.services.airgap.tar_assembler import PayloadIntegrityError

    # The pre-stat check fires first now (size mismatch),
    # before the in-tar sha comparison. Either error correctly
    # refuses the build; we accept either match.
    with pytest.raises(
        PayloadIntegrityError, match="size changed on disk|sha256 mismatch"
    ):
        assemble_bundle_tar(
            bundle_id="grow",
            descriptor_body_path=body_path,
            descriptor_signature_path=sig_path,
            member_plans=plans,
            payload_index=index,
        )
    assert not (bundle_root / "grow.tar.tmp").exists()


def test_assemble_bundle_tar_cleans_tmp_on_failure(tmp_path, monkeypatch):
    """If the tar writer raises mid-build, the .tmp sibling is
    cleaned up so a retry isn't blocked by leftover bytes."""
    bundle_root = tmp_path / "bundles"
    monkeypatch.setenv("PRAXIS_AIRGAP_BUNDLE_ROOT", str(bundle_root))
    monkeypatch.setenv("PRAXIS_MIRROR_ROOT", str(tmp_path / "mirrors"))
    _seed_mirror_tree(
        tmp_path / "mirrors", "ubuntu-bad", 5, live_files={"Release": b"R"}
    )
    descriptor = _make_descriptor("ubuntu-bad", 5)
    index, plans = compute_payload_index(descriptor)
    staging = tmp_path / "stage"
    body_path, sig_path = _write_descriptor_pair(staging)

    # Simulate failure: mutate one of the source files between
    # index computation and tar assembly. Same length as the
    # original (1 byte) so the size check passes and we exercise
    # the in-tar sha-mismatch refusal.
    plans[-1].source_path.write_bytes(b"X")

    from app.services.airgap.tar_assembler import PayloadIntegrityError

    with pytest.raises(PayloadIntegrityError):
        assemble_bundle_tar(
            bundle_id="bad",
            descriptor_body_path=body_path,
            descriptor_signature_path=sig_path,
            member_plans=plans,
            payload_index=index,
        )

    assert not (bundle_root / "bad.tar.tmp").exists()
    assert not (bundle_root / "bad.tar").exists()
