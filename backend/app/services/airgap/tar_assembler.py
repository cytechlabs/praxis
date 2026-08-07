"""Airgap bundle tar assembly (PRA-160 slice #2).

Two-phase build:

  **Phase 1 — payload index.**
    Walk every mirror's live tree + manifest sidecars, compute
    sha256 + byte_count for each file, return the
    ``List[PayloadIndexEntry]`` keyed by ``path_in_tar`` (the
    canonical layout below). No bytes copied — files are hashed
    in place. The orchestrator stamps the result onto the
    descriptor and re-signs so the bundle-level signature covers
    the populated index.

  **Phase 2 — tar assembly.**
    Open ``<bundle_id>.tar.tmp`` in ``PRAXIS_AIRGAP_BUNDLE_ROOT``,
    write ``bundle.json`` + ``bundle.json.sig`` first (the trust
    anchor pair), then add every payload member at its declared
    ``path_in_tar``. Stream-compute sha256 over the whole tar
    file as it's written. Atomic-rename ``.tmp`` → final on
    success; ``unlink`` the ``.tmp`` on failure so a crashed
    build doesn't leave a half-written file at the canonical path.

Locks (PRA-160 design conversation):
  * Tar layout (locked):
        bundle.json
        bundle.json.sig
        mirrors/<mirror_slug>/snapshots/<run_id>.manifest.json
        mirrors/<mirror_slug>/snapshots/<run_id>.manifest.json.sig
        mirrors/<mirror_slug>/live/...
  * **Plain POSIX tar, uncompressed.** Compression deferred —
    apt/rpm metadata is already gzip/xz, double-compression buys
    little; the operator can gzip on transport if needed. Single
    ``.tar`` file ships to the airgap side.
  * Bundle-level signature (``bundle.json.sig``) covers the
    descriptor body **including** ``payload_index``. Per-member
    sha256 verification at import time chains through that
    signature; armored bytes carried in the tar are NOT trust
    anchors.
  * The descriptor + signature are tar members and live at the
    tar root. They are NOT in ``payload_index`` (the index is the
    list of non-trust-anchor members).
  * ``payload_sha256`` (returned to the orchestrator and stamped
    on the ``airgap_bundles`` row) is sha256 of the **entire**
    tar file. It's an export-side integrity fingerprint — not
    part of the in-bundle trust chain — so it doesn't need to
    appear inside ``bundle.json``.
  * Tarfile members use deterministic metadata:
        - ``mtime`` zeroed (so two byte-identical exports at
          different wall-clock times produce identical tars and
          identical ``payload_sha256``).
        - ``uid``/``gid`` zeroed; ``uname``/``gname`` empty.
        - ``mode`` is 0o644 for files, 0o755 for dirs.
    PRA-157's ``promote rsync --delete`` already strips ownership
    so this matches the on-disk reality.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Tuple

from ..mirror_paths import (
    live_dir,
    snapshot_manifest_path,
    snapshot_manifest_signature_path,
)
from .paths import (
    DESCRIPTOR_FILENAME,
    DESCRIPTOR_SIGNATURE_FILENAME,
    bundle_file_path,
    bundle_file_tmp_path,
    descriptor_path,
    descriptor_signature_path,
)
from .schema import BundleDescriptor, PayloadIndexEntry

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------- buffers

# Stream chunk size for sha256 hashing + tar writes. 1 MiB is a
# common compromise between syscall overhead and memory footprint;
# tarfile.add internally also reads in chunks.
_CHUNK_BYTES = 1024 * 1024


# --------------------------------------------------------------------- types


@dataclass
class _MemberPlan:
    """One file to include in the tar plus its declared ``path_in_tar``.

    ``source_path`` is the on-disk source. ``path_in_tar`` is the
    arcname; the importer's payload-index walk reads this exact
    string out of the descriptor to look up the sha256.
    """

    source_path: Path
    path_in_tar: str


# --------------------------------------------------------------------- plan


def plan_payload_members(descriptor: BundleDescriptor) -> List[_MemberPlan]:
    """Resolve every payload member's (source_path, path_in_tar) pair.

    Layout per mirror:
      * ``mirrors/<slug>/snapshots/<run_id>.manifest.json``
      * ``mirrors/<slug>/snapshots/<run_id>.manifest.json.sig``
      * ``mirrors/<slug>/live/...``  (every file under live/, recursive)

    Source paths come from ``mirror_paths`` so an operator who
    relocated ``PRAXIS_MIRROR_ROOT`` doesn't need a separate
    PRAXIS_AIRGAP_* override. Order is deterministic: mirrors
    sorted by slug, then manifest, manifest.sig, then live tree
    walked in path order.
    """
    plans: List[_MemberPlan] = []
    for mirror in sorted(descriptor.mirrors, key=lambda m: m.mirror_slug):
        slug = mirror.mirror_slug
        manifest_src = snapshot_manifest_path(slug, mirror.run_id)
        manifest_sig_src = snapshot_manifest_signature_path(slug, mirror.run_id)
        plans.append(
            _MemberPlan(
                source_path=manifest_src,
                path_in_tar=(f"mirrors/{slug}/snapshots/{mirror.run_id}.manifest.json"),
            )
        )
        plans.append(
            _MemberPlan(
                source_path=manifest_sig_src,
                path_in_tar=(
                    f"mirrors/{slug}/snapshots/" f"{mirror.run_id}.manifest.json.sig"
                ),
            )
        )
        # Missing/non-directory ``live/`` is a hard
        # error, not a silent empty payload. PRA-157 ``live/`` is
        # always last-promoted; if it's gone the mirror is in an
        # un-exportable state and the importer would receive a tar
        # with manifest sidecars but no payload.
        live_root = live_dir(slug)
        if not live_root.exists():
            raise PayloadIndexError(
                f"mirror '{slug}' has no live tree at {live_root}; "
                "cannot export a bundle without payload bytes"
            )
        if not live_root.is_dir():
            raise PayloadIndexError(
                f"mirror '{slug}' live root {live_root} exists but is "
                "not a directory; cannot export"
            )
        for live_file in _iter_live_files(live_root, mirror_slug=slug):
            relative = live_file.relative_to(live_root).as_posix()
            plans.append(
                _MemberPlan(
                    source_path=live_file,
                    path_in_tar=f"mirrors/{slug}/live/{relative}",
                )
            )
    return plans


def _iter_live_files(live_root: Path, *, mirror_slug: str) -> Iterator[Path]:
    """Walk ``live_root`` recursively, yielding regular files only.

    Symlinks in ``live/`` are a hard refusal in v1.
    PRA-157's ``rsync -a`` preserves symlinks, and the mirror
    manifest walker follows file symlinks when hashing — so a
    silent skip here would produce a signed manifest claiming a
    file exists while the exported tar omits it. Until the
    descriptor schema declares symlink semantics
    (target + relative/absolute marker) we refuse rather than
    drift the trust contract.

    Path order is deterministic (sorted by full POSIX path) so two
    byte-identical exports against the same tree produce identical
    tar member ordering, feeding the deterministic
    ``payload_sha256`` lock.
    """
    # ``rglob('*')`` returns lexicographically-arbitrary order on
    # some filesystems. Stable sort by full POSIX path makes the
    # output deterministic.
    for path in sorted(live_root.rglob("*"), key=lambda p: p.as_posix()):
        if path.is_symlink():
            raise PayloadIndexError(
                f"mirror '{mirror_slug}' live tree contains a symlink at "
                f"{path}; v1 airgap export refuses symlinks until the "
                "descriptor schema declares symlink semantics. Either "
                "replace with a regular file or wait for symlink-aware "
                "export support."
            )
        if path.is_file():
            yield path


# --------------------------------------------------------------------- index


class PayloadIndexError(RuntimeError):
    """A planned payload member is missing on disk.

    Slice #2 raises this from ``compute_payload_index`` when
    ``mirror_paths.live_dir(slug)`` is missing, the manifest
    sidecar is gone, or any individual live file disappeared
    between the planner and the assembler. Surfaces a structured
    failure so the orchestrator can transition the row to
    ``status='failed'`` with usable ``error_text`` instead of a
    bare ``FileNotFoundError``.
    """


class DeltaDeletionsUnsupported(RuntimeError):
    """Parent bundle declared a payload path that's
    absent from the current plan (deletion).

    v1's delta semantics don't carry "remove this file" instructions;
    if we shipped a delta whose parent had a file the current tree
    doesn't, the importer would copy the parent's file forward,
    leaving an obsolete artifact whose sha is in the descriptor's
    declared manifest_sha256 — the post-assembly check would then
    fail with ``DeltaAssemblyMismatch``. Refuse synchronously at
    export so the operator gets a clean signal, not a signed bundle
    that's guaranteed to fail import.
    """


def compute_payload_index(
    descriptor: BundleDescriptor,
) -> Tuple[List[PayloadIndexEntry], List[_MemberPlan]]:
    """Hash every payload member and return ``(index, member_plans)``.

    The orchestrator stamps ``index`` onto ``descriptor.payload_index``
    and ``member_plans`` is fed straight to ``assemble_bundle_tar``
    (saves a second walk).

    Raises ``PayloadIndexError`` for any missing planned member.
    """
    member_plans = plan_payload_members(descriptor)
    index: List[PayloadIndexEntry] = []
    for plan in member_plans:
        if not plan.source_path.exists():
            raise PayloadIndexError(
                f"payload member missing on disk: {plan.source_path} "
                f"(declared path_in_tar={plan.path_in_tar!r})"
            )
        sha, size = _hash_file(plan.source_path)
        index.append(
            PayloadIndexEntry(
                path_in_tar=plan.path_in_tar,
                sha256=sha,
                byte_count=size,
            )
        )
    return index, member_plans


def _hash_file(path: Path) -> Tuple[str, int]:
    """Stream-hash ``path`` in 1 MiB chunks. Returns ``(hex_sha256, size)``."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_BYTES)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def compute_delta_payload_index(
    descriptor: BundleDescriptor,
    parent_descriptor: BundleDescriptor,
) -> Tuple[List[PayloadIndexEntry], List[_MemberPlan]]:
    """Compute the delta-only payload index against the parent.

    PRA-160 slice #4: per-file diff. Walk every payload member the
    current ``descriptor`` would include (manifest sidecar pair +
    live tree); hash each; compare to ``parent_descriptor.payload_index``
    keyed on ``path_in_tar``. Include ONLY entries where:
      * the path is absent from the parent (new file), OR
      * the path's sha256 differs from the parent's.

    Manifest + sidecar pair is always included — it reflects the
    current run, which differs from the parent's run.

    Deletions (paths present in parent's
    payload_index but absent from the current plan) are refused
    with ``DeltaDeletionsUnsupported``. Shipping such a bundle
    would leave the parent's now-obsolete file in place on the
    import side and the post-assembly manifest sha would diverge.
    A future schema version can add a ``removed_paths`` list to
    represent deletions; until then, a removed file forces a full
    re-export.
    """
    parent_by_path = {e.path_in_tar: e for e in parent_descriptor.payload_index}
    full_member_plans = plan_payload_members(descriptor)
    current_paths = {plan.path_in_tar for plan in full_member_plans}

    # Deletion detection. A "deletion" is
    # a parent payload path under ``mirrors/<slug>/live/`` for a
    # mirror in the CURRENT descriptor's scope that's absent from
    # the current plan. Two scoping rules:
    #   1. Restrict to ``mirrors/<slug>/live/`` paths so manifest
    #      sidecar paths (different run_id per export) and any
    #      future top-level tar members aren't false-positives.
    #      Suffix-excluding ``.manifest.json`` would mask a real
    #      live file with that name.
    #   2. Restrict to slugs present in ``descriptor.mirrors``. A
    #      narrowed delta (parent had profiles A+B, current exports
    #      only A) legitimately drops profile B's mirror payload
    #      from scope — those parent paths aren't "deletions",
    #      they're just out-of-scope. Refusing them would block
    #      every legitimate scope-narrow delta.
    current_mirror_slugs = {m.mirror_slug for m in descriptor.mirrors}
    in_scope_live_prefixes = tuple(
        f"mirrors/{slug}/live/" for slug in current_mirror_slugs
    )
    deleted_paths = sorted(
        path
        for path in parent_by_path
        if path not in current_paths
        and any(path.startswith(prefix) for prefix in in_scope_live_prefixes)
    )
    if deleted_paths:
        raise DeltaDeletionsUnsupported(
            f"delta against parent {parent_descriptor.bundle_id!r} would "
            f"need to remove {len(deleted_paths)} path(s) from the "
            "imported tree, but v1 delta semantics don't represent "
            "deletions. Re-export full, or restore the deleted file(s) "
            "before exporting a delta. Affected paths (capped to 25): "
            f"{deleted_paths[:25]!r}"
        )

    delta_index: List[PayloadIndexEntry] = []
    delta_member_plans: List[_MemberPlan] = []
    for plan in full_member_plans:
        if not plan.source_path.exists():
            raise PayloadIndexError(
                f"payload member missing on disk: {plan.source_path} "
                f"(declared path_in_tar={plan.path_in_tar!r})"
            )
        sha, size = _hash_file(plan.source_path)
        # Manifest + sidecar pair always travel: they describe the
        # current run, which is a different run than the parent's.
        if plan.path_in_tar.endswith(".manifest.json") or plan.path_in_tar.endswith(
            ".manifest.json.sig"
        ):
            include = True
        else:
            parent_entry = parent_by_path.get(plan.path_in_tar)
            include = parent_entry is None or parent_entry.sha256 != sha
        if include:
            delta_member_plans.append(plan)
            delta_index.append(
                PayloadIndexEntry(
                    path_in_tar=plan.path_in_tar,
                    sha256=sha,
                    byte_count=size,
                )
            )
    return delta_index, delta_member_plans


# --------------------------------------------------------------------- tar


def _tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Normalize tar member metadata for deterministic output.

    Two byte-identical exports of the same content tree must
    produce identical tar bytes (and therefore identical
    ``payload_sha256``). Without this filter, ``mtime`` /
    ``uid`` / ``gid`` / ``uname`` / ``gname`` from the local
    filesystem would leak into the tar and break determinism.
    """
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if info.isdir():
        info.mode = 0o755
    else:
        info.mode = 0o644
    return info


class PayloadIntegrityError(RuntimeError):
    """A payload member's bytes diverged between index hash and tar write.

    ``compute_payload_index`` hashes each source
    file once. Between that and ``assemble_bundle_tar`` reading the
    same files for tar inclusion, a mirror sync, retention sweep,
    or operator action could mutate the bytes — leaving the signed
    descriptor describing one set of shas while the tar carries
    another. Verification at write-time catches this race so the
    build refuses rather than ship a tar the importer will
    eventually reject.
    """


def assemble_bundle_tar(
    *,
    bundle_id: str,
    descriptor_body_path: Path,
    descriptor_signature_path: Path,
    member_plans: Iterable[_MemberPlan],
    payload_index: Iterable[PayloadIndexEntry],
) -> Tuple[Path, str, int]:
    """Build the bundle tar; return ``(final_path, payload_sha256, byte_count)``.

    Writes to ``<airgap_bundle_root>/<bundle_id>.tar.tmp``, then
    ``os.rename`` to the final path. On failure, deletes the
    ``.tmp`` sibling so a retry isn't blocked by leftover bytes.

    Computes sha256 over the entire tar stream while writing and
    returns the digest plus total byte count.

    Every payload member is hashed AS its bytes
    flow into the tar (via a sha-tracking wrapper around the
    source file handle); the result is compared to the signed
    ``payload_index`` entry for that ``path_in_tar``. Mismatch
    raises ``PayloadIntegrityError`` so we don't ship a tar whose
    contents disagree with what the importer's signed descriptor
    claims. Trust-anchor members (bundle.json, bundle.json.sig)
    are not in ``payload_index`` and aren't verified this way —
    they were just produced by ``sign_and_write_descriptor``.

    Tarfile format is pinned to ``PAX_FORMAT``
    because PRA-159 mirror paths can exceed USTAR's 100-character
    name limit, and PAX is the only standard format that
    extension-encodes long names.
    """
    expected_by_path = {entry.path_in_tar: entry for entry in payload_index}

    final_path = bundle_file_path(bundle_id)
    tmp_path = bundle_file_tmp_path(bundle_id)
    final_path.parent.mkdir(parents=True, exist_ok=True)
    if tmp_path.exists():
        # Stale tmp from a prior crashed build. Clean before reuse.
        tmp_path.unlink()

    hasher = hashlib.sha256()
    byte_count = 0

    try:
        with tmp_path.open("wb") as raw_fh:
            hashing_fh = _HashingFile(raw_fh, hasher)
            with tarfile.open(
                fileobj=hashing_fh, mode="w", format=tarfile.PAX_FORMAT
            ) as tar:
                # 1. Trust anchor pair first: bundle.json + bundle.json.sig.
                tar.add(
                    str(descriptor_body_path),
                    arcname=DESCRIPTOR_FILENAME,
                    filter=_tar_filter,
                )
                tar.add(
                    str(descriptor_signature_path),
                    arcname=DESCRIPTOR_SIGNATURE_FILENAME,
                    filter=_tar_filter,
                )
                # 2. Payload members in plan order (deterministic).
                for plan in member_plans:
                    expected = expected_by_path.get(plan.path_in_tar)
                    if expected is None:
                        raise PayloadIntegrityError(
                            f"plan member {plan.path_in_tar!r} has no "
                            "matching payload_index entry; planner and "
                            "tar assembler are out of sync"
                        )
                    _add_verified_member(tar, plan, expected)
            byte_count = hashing_fh.bytes_written

        os.rename(tmp_path, final_path)
    except Exception:
        # Ensure the tmp doesn't linger — a retry should start clean.
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError as cleanup_err:
                logger.warning(
                    "Failed to remove stale airgap bundle tmp at %s: %s",
                    tmp_path,
                    cleanup_err,
                )
        raise

    payload_sha256 = hasher.hexdigest()
    logger.info(
        "Assembled airgap bundle bundle_id=%s bytes=%d sha256=%s",
        bundle_id,
        byte_count,
        payload_sha256,
    )
    return final_path, payload_sha256, byte_count


def _add_verified_member(
    tar: tarfile.TarFile,
    plan: _MemberPlan,
    expected: PayloadIndexEntry,
) -> None:
    """Add ``plan`` to ``tar`` while re-hashing the source bytes.

    Build the ``TarInfo`` manually (size + normalized metadata) so
    we can hand ``tar.addfile`` a sha-tracking ``fileobj`` wrapper
    around the source file handle. The wrapper hashes every byte
    tarfile reads. After ``addfile`` returns, we compare the
    tracker's digest + byte count against ``expected``; mismatch
    raises ``PayloadIntegrityError`` and the caller's outer
    ``try`` cleans up the .tmp.

    Stat the source's **open file descriptor**
    both BEFORE and AFTER ``tar.addfile``. The sha-tracking reader
    only sees ``info.size`` bytes (tarfile reads exactly that many
    because we set the TarInfo size from the signed index). If the
    source grew after ``compute_payload_index`` but the prefix is
    unchanged, the tracker hashes the matching prefix and signs off
    — silently truncating the now-longer source.

    A path-level ``stat()`` before opening leaves a small race: the
    inode could grow between stat and read. ``os.fstat`` on the
    same fd we read from closes that window. Re-fstating after
    ``addfile`` catches a grow that happened DURING the read.
    """
    info = tarfile.TarInfo(name=plan.path_in_tar)
    info.type = tarfile.REGTYPE
    info.size = expected.byte_count
    info.mtime = 0
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    with plan.source_path.open("rb") as src_fh:
        size_before = os.fstat(src_fh.fileno()).st_size
        if size_before != expected.byte_count:
            raise PayloadIntegrityError(
                f"payload member {plan.path_in_tar!r} size changed on "
                f"disk: signed index expected {expected.byte_count} bytes, "
                f"open file is {size_before}. Source file changed between "
                "index computation and tar assembly."
            )
        tracker = _ShaTrackingReader(src_fh)
        tar.addfile(info, fileobj=tracker)
        size_after = os.fstat(src_fh.fileno()).st_size
        if size_after != expected.byte_count:
            raise PayloadIntegrityError(
                f"payload member {plan.path_in_tar!r} size changed during "
                f"tar.addfile: signed index expected {expected.byte_count} "
                f"bytes, open file is now {size_after}. Source file was "
                "mutated mid-write."
            )
    if tracker.bytes_read != expected.byte_count:
        raise PayloadIntegrityError(
            f"payload member {plan.path_in_tar!r} byte_count mismatch: "
            f"tar wrote {tracker.bytes_read} bytes, signed index expected "
            f"{expected.byte_count}. Source file changed between index "
            "computation and tar assembly."
        )
    if tracker.hexdigest() != expected.sha256:
        raise PayloadIntegrityError(
            f"payload member {plan.path_in_tar!r} sha256 mismatch: "
            f"tar wrote {tracker.hexdigest()}, signed index expected "
            f"{expected.sha256}. Source file changed between index "
            "computation and tar assembly."
        )


class _ShaTrackingReader:
    """Read-side wrapper that streams sha256 over consumed bytes.

    Used by ``tar.addfile`` to verify on write that the source
    file produced the same bytes the payload index hashed earlier.
    Tarfile reads exactly ``info.size`` bytes from
    the fileobj when given an explicit size; we then compare both
    byte count and digest after the call.
    """

    def __init__(self, fh):
        self._fh = fh
        self._hasher = hashlib.sha256()
        self.bytes_read = 0

    def read(self, n: int = -1) -> bytes:  # pragma: no cover — trivial
        data = self._fh.read(n)
        self._hasher.update(data)
        self.bytes_read += len(data)
        return data

    def hexdigest(self) -> str:  # pragma: no cover — trivial
        return self._hasher.hexdigest()


class _HashingFile:
    """Pass-through file wrapper that updates a sha256 hasher on each write.

    Python's ``tarfile`` writes through ``fileobj.write(bytes)`` and
    expects ``tell()`` to report the current write offset (used for
    block alignment). Intercepting at this layer means we hash every
    byte that lands on disk (header bytes + member contents +
    padding) without a second pass over the finished file.
    ``bytes_written`` doubles as the synthetic write offset reported
    via ``tell()``.

    No ``seek()`` — tarfile in write mode never seeks backward in
    the stream. If a future caller needed seekable output, this
    wrapper would need to be reworked to stop streaming-hash and
    fall back to a post-write hash pass.
    """

    def __init__(self, fh, hasher):
        self._fh = fh
        self._hasher = hasher
        self.bytes_written = 0

    def write(self, data: bytes) -> int:  # pragma: no cover — trivial
        self._hasher.update(data)
        self.bytes_written += len(data)
        return self._fh.write(data)

    def tell(self) -> int:  # pragma: no cover — trivial
        return self.bytes_written

    def flush(self) -> None:  # pragma: no cover — trivial
        self._fh.flush()

    def close(self) -> None:  # pragma: no cover — close is owned by caller
        # Caller's ``with`` block on the underlying file handles
        # close; tarfile calls flush() but not close() through the
        # wrapper.
        pass


# --------------------------------------------------------------------- helpers
# (kept module-level so tests can import without instantiating a class)


def descriptor_pair_paths(bundle_id: str) -> Tuple[Path, Path]:
    """Resolve the staging-dir descriptor + signature pair for ``bundle_id``."""
    return descriptor_path(bundle_id), descriptor_signature_path(bundle_id)
