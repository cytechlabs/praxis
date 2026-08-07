"""Airgap bundle importer (PRA-160 slice #3).

Verifies a bundle tar against operator-pinned trust keys, extracts
its payload to staging, then ingests the result as
``imported_offline`` mirrors + content channels + content profiles
with prefixed slugs.

End-to-end flow (top-level ``run_import``):

  1. Idempotency: refuse if ``airgap_imports.bundle_id`` already
     present unless ``force=True``.
  2. Insert ``airgap_imports`` row at ``status='verifying'``.
  3. Verify the bundle (``verify_and_stage``):
       a. Resolve the tar path; refuse if outside the allow-listed
          import staging root.
       b. Read ``bundle.json`` + ``bundle.json.sig`` from the tar.
       c. Verify the sig against operator-pinned trust keys
          (armored bytes inside the tar
          are NOT trust anchors).
       d. ``deserialize_descriptor`` (rejects unknown
          ``bundle_version``).
       e. Walk the tar; for each payload member, validate the
          member name (no traversal), extract to staging while
          streaming-hashing, compare to the descriptor's signed
          ``payload_index`` entry.
       f. Per-mirror manifest signatures verified against the
          descriptor's declared armored keys for that mirror, in
          an ephemeral GNUPGHOME.
  4. Transition row to ``status='extracting'``.
  5. Ingest (``ingest_staged_bundle``):
       a. For each mirror in scope, compute the prefixed slug and
          check collisions across mirror + channel + profile slugs
          (including soft-deleted, slice-#1 lock).
       b. Promote staging/<orig_slug>/{live,snapshots} into the
          canonical mirror root under the prefixed slug via
          ``os.rename`` (cross-FS fallback to ``shutil.move``).
       c. Write ``praxis-mirror.json`` at the mirror volume root if
          missing.
       d. Insert ``MirrorRepo`` (``source_mode='imported_offline'``,
          ``enabled=False``), ``MirrorSyncRun``
          (``run_kind='import'``, ``status='ok'``, manifest_sha256
          from the descriptor).
       e. Insert ``ContentChannel`` + ``ContentChannelRepo`` +
          ``ContentProfile`` + ``ContentProfileChannel`` rows with
          prefixed slugs.
  6. Transition row to ``status='ok'`` with ``payload_sha256`` +
     ``byte_count`` + ``target_mirror_slugs`` populated.

Locks (PRA-160 design conversation + carry-forwards):
  * Trust: only keys in ``airgap_import_trust_keys`` (deleted_at
    IS NULL). Tar-side armor is decoration.
  * Path safety: tar path must resolve under
    ``PRAXIS_AIRGAP_IMPORT_STAGING``. Member names must match the
    locked layout (``bundle.json``, ``bundle.json.sig``,
    ``mirrors/<slug>/snapshots/<run_id>.manifest.json{,.sig}``,
    ``mirrors/<slug>/live/<path>``) and must not contain ``..``
    segments or absolute paths.
  * Slug prefix: ``imported-<bundle_short>-<original_slug>`` for
    mirror, channel, and profile slugs. Bundle short = first 8
    chars of bundle_id sans dashes.
  * Failure path: row → ``failed`` with ``error_text`` populated;
    staging dir cleaned up; partial DB rows rolled back via the
    transaction boundary in ``ingest_staged_bundle``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import tarfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ...db.models import (
    AirgapImport,
    AirgapImportTrustKey,
    ContentChannel,
    ContentChannelRepo,
    ContentProfile,
    ContentProfileChannel,
    MirrorRepo,
    MirrorSyncRun,
)
from .. import mirror_gpg
from ..audit_event_service import safe_emit
from ..mirror_paths import DESCRIPTOR_FILENAME as MIRROR_LAYOUT_DESCRIPTOR_FILENAME
from ..mirror_paths import (
    LAYOUT_VERSION,
    live_dir,
    mirror_repo_root,
    mirror_root,
    snapshots_dir,
)
from .paths import airgap_import_staging_root
from .schema import BundleDescriptor, UnsupportedSchemaVersion, deserialize_descriptor

logger = logging.getLogger(__name__)


# Locked tar layout regex (slice #2). Importer uses these to
# validate member names before extraction.
_BUNDLE_DESCRIPTOR_NAME = "bundle.json"
_BUNDLE_DESCRIPTOR_SIG_NAME = "bundle.json.sig"
_MIRROR_MEMBER_RE = re.compile(
    r"^mirrors/(?P<slug>[a-z0-9_-]+)/"
    r"(?:"
    r"snapshots/(?P<run_id>\d+)\.manifest\.json(?P<sig>\.sig)?"
    r"|"
    r"live/(?P<live_path>[^\\\0]+)"
    r")$"
)
_SLUG_RE = re.compile(r"^[a-z0-9_-]+$")
_CHUNK_BYTES = 1024 * 1024


# ---------------------------------------------------------------------------
# Refusal types
# ---------------------------------------------------------------------------


class ImporterRefusal(Exception):
    """Base class for importer-side refusals.

    ``code`` is a stable string the route handler surfaces in the
    response body so the operator + CLI can branch on it without
    string-matching the message. ``context`` carries structured
    detail.
    """

    code: str = "import_refused"

    def __init__(self, message: str, context: Optional[dict] = None) -> None:
        super().__init__(message)
        self.context = context or {}


class BundleAlreadyImported(ImporterRefusal):
    code = "bundle_already_imported"


class TarPathOutsideStaging(ImporterRefusal):
    code = "tar_path_outside_staging"


class TarFileMissing(ImporterRefusal):
    code = "tar_file_missing"


class BundleSignatureInvalid(ImporterRefusal):
    code = "bundle_signature_invalid"


class BundleDescriptorMissing(ImporterRefusal):
    code = "bundle_descriptor_missing"


class UnsupportedBundleVersion(ImporterRefusal):
    code = "unsupported_bundle_version"


class PayloadMemberInvalid(ImporterRefusal):
    code = "payload_member_invalid"


class PayloadIntegrityFailure(ImporterRefusal):
    code = "payload_integrity_failure"


class ManifestSignatureInvalid(ImporterRefusal):
    code = "manifest_signature_invalid"


class SlugCollision(ImporterRefusal):
    code = "slug_collision"


class InvalidBundleDescriptor(ImporterRefusal):
    """Descriptor field violates a structural invariant.

    Raised when ``bundle_id`` isn't UUID-shaped, a slug fails the
    ``[a-z0-9_-]+`` pattern, or a channel/profile references an
    entity not in the descriptor's declared set. These are
    pre-extraction refusals — no path or DB state is touched.
    """

    code = "invalid_bundle_descriptor"


class BundleDescriptorUnreadable(ImporterRefusal):
    """Tar file is corrupt or unreadable.

    ``_read_descriptor_pair`` can raise ``tarfile.ReadError`` /
    ``OSError`` on a non-tar / truncated / EIO file. Pre-flight
    converts those crashes into a structured refusal so POST
    ``/airgap/imports`` returns a flat 422 body instead of bubbling
    a 500.
    """

    code = "bundle_descriptor_unreadable"


class ParentBundleMissing(ImporterRefusal):
    """Delta bundle's ``parent_bundle_id`` doesn't
    correspond to a row in ``airgap_imports`` on this instance.

    Deltas are applied on top of an already-imported parent. If the
    parent isn't here, the delta has no baseline to overlay onto.
    """

    code = "parent_bundle_missing"


class ParentBundleNotOk(ImporterRefusal):
    """An ancestor in the parent chain isn't
    ``status='ok'``.

    A delta chain is only as trustworthy as its weakest link;
    importing on top of a failed/in-progress parent would leave
    the imported tree in an indeterminate state.
    """

    code = "parent_bundle_not_ok"


class DeltaAssemblyMismatch(ImporterRefusal):
    """The assembled (parent + delta) live tree's
    manifest sha256 doesn't match the descriptor's declared sha.

    The delta's mirror manifest sha is the FINAL post-assembly tree's
    sha (not a delta-only sha). After cp parent → target + overlay
    delta files, recomputing the manifest must match. Mismatch means
    the parent's on-disk state has drifted (was modified after
    import) or the delta was crafted against a different parent
    revision than the operator pointed at.
    """

    code = "delta_assembly_mismatch"


class BundleDescriptorRebindMismatch(ImporterRefusal):
    """Post-verify descriptor differs from the
    row's bundle_id.

    Pre-flight reads the descriptor preview, validates structure,
    and creates the ``airgap_imports`` row keyed on ``bundle_id``.
    If the tar file is replaced between POST and the BG task,
    ``execute_import`` would otherwise verify+stage+ingest a
    different bundle while the row remains keyed to the original
    bundle_id. Refuse loudly to break the swap.
    """

    code = "bundle_descriptor_rebind_mismatch"


# Bundle ids are UUIDv4 from slice #1's planner (str(uuid.uuid4())).
# Strict regex on the canonical 8-4-4-4-12 hex shape (lowercase) to
# block descriptor-driven path traversal before _staging_root_for
# composes a directory name from the field.
_BUNDLE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_DESCRIPTOR_SLUG_MAX_LEN = 64


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------


def _resolve_tar_path(tar_path_str: str) -> Path:
    """Resolve ``tar_path_str`` and require it to live under the
    configured import staging root.

    Symlinks are followed via ``Path.resolve(strict=True)`` so a
    symlink that escapes the staging root is caught here. Raises
    ``TarFileMissing`` if the path doesn't exist; ``TarPathOutsideStaging``
    if it resolves outside the allow-listed root.
    """
    tar_path = Path(tar_path_str)
    if not tar_path.exists():
        raise TarFileMissing(
            f"airgap import path does not exist: {tar_path}",
            {"path": str(tar_path)},
        )
    resolved = tar_path.resolve(strict=True)
    staging = airgap_import_staging_root().resolve()
    try:
        resolved.relative_to(staging)
    except ValueError as exc:
        raise TarPathOutsideStaging(
            f"airgap import path {resolved} resolves outside staging root "
            f"{staging}; refuse to read",
            {"resolved_path": str(resolved), "staging_root": str(staging)},
        ) from exc
    return resolved


# ---------------------------------------------------------------------------
# Descriptor structural validation
# ---------------------------------------------------------------------------


def _validate_descriptor_ids(descriptor: BundleDescriptor) -> None:
    """Refuse if any descriptor identifier violates a structural
    invariant before we use it to build a path or DB row.


      * ``bundle_id`` must be UUIDv4-shaped (8-4-4-4-12 lowercase hex).
        ``_staging_root_for`` and the audit ``target_id`` use this
        verbatim — a malformed value could escape the staging root
        or smuggle metadata through the audit trail.
      * Every mirror/channel/profile slug must match
        ``[a-z0-9_-]+`` and respect the slug length cap. The
        importer composes ``mirrors/<slug>/...`` paths from these
        and persists them as DB slugs, so untrusted shapes need
        early refusal.
    """
    if not _BUNDLE_ID_RE.match(descriptor.bundle_id):
        raise InvalidBundleDescriptor(
            f"bundle_id {descriptor.bundle_id!r} is not UUIDv4-shaped",
            {"reason": "bundle_id_not_uuid", "bundle_id": descriptor.bundle_id},
        )
    for mirror in descriptor.mirrors:
        _assert_slug_shape("mirror", mirror.mirror_slug, descriptor.bundle_id)
    for channel in descriptor.channels:
        _assert_slug_shape("channel", channel.slug, descriptor.bundle_id)
    for profile in descriptor.profiles:
        _assert_slug_shape("profile", profile.slug, descriptor.bundle_id)


def _assert_slug_shape(kind: str, slug: str, bundle_id: str) -> None:
    if (
        not isinstance(slug, str)
        or not slug
        or len(slug) > _DESCRIPTOR_SLUG_MAX_LEN
        or not _SLUG_RE.match(slug)
    ):
        raise InvalidBundleDescriptor(
            f"descriptor {kind} slug {slug!r} violates the "
            "[a-z0-9_-]+ pattern or 64-char length cap",
            {
                "reason": f"{kind}_slug_invalid",
                "kind": kind,
                "slug": slug,
                "bundle_id": bundle_id,
            },
        )


def _validate_descriptor_self_consistency(descriptor: BundleDescriptor) -> None:
    """Refuse if a channel or profile references an entity not in
    the descriptor's declared set.

    For airgap imports, silently dropping orphaned references would
    change the exported profile's content shape — the imported
    profile would compose fewer mirrors than the export side
    intended. Treat this as a hard refusal so the operator gets a
    clear "your bundle is structurally inconsistent; re-export"
    signal.
    """
    declared_mirror_slugs = {m.mirror_slug for m in descriptor.mirrors}
    declared_channel_slugs = {c.slug for c in descriptor.channels}
    for channel in descriptor.channels:
        for repo in channel.repos:
            if repo.mirror_slug not in declared_mirror_slugs:
                raise InvalidBundleDescriptor(
                    f"channel {channel.slug!r} references mirror "
                    f"{repo.mirror_slug!r} which is not in "
                    "descriptor.mirrors",
                    {
                        "reason": "channel_repo_mirror_orphaned",
                        "channel_slug": channel.slug,
                        "mirror_slug": repo.mirror_slug,
                        "declared_mirror_slugs": sorted(declared_mirror_slugs),
                    },
                )
    for profile in descriptor.profiles:
        for chan_slug in profile.channel_slugs:
            if chan_slug not in declared_channel_slugs:
                raise InvalidBundleDescriptor(
                    f"profile {profile.slug!r} references channel "
                    f"{chan_slug!r} which is not in "
                    "descriptor.channels",
                    {
                        "reason": "profile_channel_orphaned",
                        "profile_slug": profile.slug,
                        "channel_slug": chan_slug,
                        "declared_channel_slugs": sorted(declared_channel_slugs),
                    },
                )


# ---------------------------------------------------------------------------
# Verify + stage
# ---------------------------------------------------------------------------


@dataclass
class VerifiedBundle:
    """Output of ``verify_and_stage``.

    ``staging_root`` is a per-import scratch dir under
    ``PRAXIS_AIRGAP_IMPORT_STAGING/<bundle_id>/``. After successful
    ingest the caller ``rmtree``s it; on failure the orchestrator
    cleans up the same path so a retry starts fresh.
    """

    descriptor: BundleDescriptor
    staging_root: Path
    payload_sha256: str
    byte_count: int


def verify_and_stage(
    *,
    tar_path: Path,
    db: Session,
    expected_bundle_id: Optional[str] = None,
    expected_kind: Optional[str] = None,
    expected_parent_bundle_id: Optional[str] = None,
) -> VerifiedBundle:
    """Verify bundle.json.sig + payload_index + per-mirror manifest
    sigs; stream-extract the payload into a staging dir.

    Path-resolved ``tar_path`` is assumed safe (caller already
    validated via ``_resolve_tar_path``).

    ``expected_bundle_id`` is the row's bundle_id
    from pre-flight. After signature verification + deserialize,
    we re-validate descriptor structural invariants AND require
    ``descriptor.bundle_id == expected_bundle_id`` BEFORE composing
    any descriptor-derived path (``_staging_root_for``, per-mirror
    ``mirrors/<slug>/...`` paths). A swapped tar therefore can't
    stage under the wrong bundle id, and a same-bundle descriptor
    with bad slugs can't reach descriptor-derived paths.

    ``expected_kind`` and ``expected_parent_bundle_id``
    extend the rebind to delta metadata. A same-bundle-id tar
    swap that flips kind=full → kind=delta (or alters
    parent_bundle_id) would otherwise pair the row's stale parent
    chain with a verified descriptor that disagrees, and the
    importer would walk the wrong chain. Refuse with
    ``BundleDescriptorRebindMismatch`` when either value differs.
    """
    # ---- Trust keys (operator-pinned) ----------------------------
    trust_keys = (
        db.query(AirgapImportTrustKey)
        .filter(AirgapImportTrustKey.deleted_at.is_(None))
        .all()
    )
    if not trust_keys:
        raise BundleSignatureInvalid(
            "no operator-pinned bundle trust keys are active; "
            "register one via POST /airgap/import-trust before importing",
            {"reason": "no_active_trust_keys"},
        )

    # ---- Read bundle.json + sig from tar (small files; OK to load
    # into memory) ------------------------------------------------
    descriptor_bytes, sig_bytes = _read_descriptor_pair(tar_path)

    # ---- Verify bundle.json.sig against any pinned trust key ----
    _verify_bundle_signature(descriptor_bytes, sig_bytes, trust_keys)

    # ---- Deserialize (rejects unknown bundle_version) -----------
    try:
        descriptor = deserialize_descriptor(descriptor_bytes)
    except ValueError as exc:
        raise UnsupportedBundleVersion(
            str(exc), {"reason": "deserialize_failed"}
        ) from exc

    # ---- rebind + structural validation BEFORE
    # any descriptor-derived path is composed. The descriptor is
    # now signature-verified and is the trusted source of truth;
    # validate its ids before they reach _staging_root_for or
    # per-mirror path construction.
    _validate_descriptor_ids(descriptor)
    _validate_descriptor_self_consistency(descriptor)
    if expected_bundle_id is not None and descriptor.bundle_id != expected_bundle_id:
        raise BundleDescriptorRebindMismatch(
            f"verified bundle_id={descriptor.bundle_id!r} does not match "
            f"expected bundle_id={expected_bundle_id!r}; tar file may "
            "have been replaced between pre-flight and verify",
            {
                "expected_bundle_id": expected_bundle_id,
                "verified_bundle_id": descriptor.bundle_id,
                "reason": "tar_swap_detected",
            },
        )
    # Rebind kind + parent_bundle_id alongside
    # bundle_id so a same-bundle-id tar swap that flipped delta
    # metadata can't smuggle the wrong parent chain into ingest.
    if expected_kind is not None and descriptor.kind != expected_kind:
        raise BundleDescriptorRebindMismatch(
            f"verified kind={descriptor.kind!r} does not match expected "
            f"kind={expected_kind!r}; descriptor metadata diverged from "
            "the row created at POST time",
            {
                "expected_kind": expected_kind,
                "verified_kind": descriptor.kind,
                "reason": "kind_mismatch",
            },
        )
    if expected_parent_bundle_id is not None or descriptor.parent_bundle_id is not None:
        if descriptor.parent_bundle_id != expected_parent_bundle_id:
            raise BundleDescriptorRebindMismatch(
                f"verified parent_bundle_id={descriptor.parent_bundle_id!r} "
                f"does not match expected="
                f"{expected_parent_bundle_id!r}; descriptor's delta lineage "
                "diverged from the row created at POST time",
                {
                    "expected_parent_bundle_id": expected_parent_bundle_id,
                    "verified_parent_bundle_id": descriptor.parent_bundle_id,
                    "reason": "parent_bundle_id_mismatch",
                },
            )

    # ---- Stream-extract + verify per-member sha256 --------------
    staging_root = _staging_root_for(descriptor.bundle_id)
    if staging_root.exists():
        shutil.rmtree(staging_root, ignore_errors=False)
    staging_root.mkdir(parents=True, exist_ok=False)

    expected_by_path = {e.path_in_tar: e for e in descriptor.payload_index}
    seen_paths: set[str] = set()
    total_hasher = hashlib.sha256()
    total_bytes = 0

    with tar_path.open("rb") as raw_fh:
        # Compute payload_sha256 over the full tar in parallel with
        # extraction. Same shape as slice #2 _HashingFile but for
        # reads. ``mode="r|"`` is the streaming form — no backward
        # seeks, which keeps the hash-on-read fileobj wrapper
        # simple and the whole tar walked exactly once.
        hashing_fh = _HashingReader(raw_fh, total_hasher)
        with tarfile.open(fileobj=hashing_fh, mode="r|") as tar:
            for member in tar:
                _validate_member_name(member.name)
                # Trust anchor pair — already verified above.
                if member.name in (
                    _BUNDLE_DESCRIPTOR_NAME,
                    _BUNDLE_DESCRIPTOR_SIG_NAME,
                ):
                    # Extract for ingest convenience (descriptor
                    # text on disk for ops inspection).
                    _extract_to(staging_root, tar, member)
                    continue
                if not member.isfile():
                    raise PayloadMemberInvalid(
                        f"non-regular file in tar: {member.name!r} "
                        f"(type={member.type!r})",
                        {"path_in_tar": member.name, "type": int(member.type)},
                    )
                expected = expected_by_path.get(member.name)
                if expected is None:
                    raise PayloadMemberInvalid(
                        f"tar member {member.name!r} is not declared in "
                        "the signed payload_index",
                        {"path_in_tar": member.name},
                    )
                _extract_and_verify(staging_root, tar, member, expected)
                seen_paths.add(member.name)
        total_bytes = hashing_fh.bytes_read

    missing = sorted(set(expected_by_path) - seen_paths)
    if missing:
        raise PayloadIntegrityFailure(
            f"signed payload_index declares {len(missing)} member(s) "
            "not present in the tar",
            {"missing_paths_in_tar": missing[:25]},  # cap for body size
        )

    # ---- Per-mirror manifest signature verification --------------
    _verify_per_mirror_manifest_sigs(descriptor=descriptor, staging_root=staging_root)

    payload_sha256 = total_hasher.hexdigest()
    return VerifiedBundle(
        descriptor=descriptor,
        staging_root=staging_root,
        payload_sha256=payload_sha256,
        byte_count=total_bytes,
    )


def _read_descriptor_pair(tar_path: Path) -> Tuple[bytes, bytes]:
    """Open the tar, return ``(bundle.json, bundle.json.sig)`` bytes.

    Both are tar root members per the slice-#2 layout. Raises
    ``BundleDescriptorMissing`` if either is absent.
    """
    body: Optional[bytes] = None
    sig: Optional[bytes] = None
    with tarfile.open(tar_path, mode="r") as tar:
        for member in tar:
            if member.name == _BUNDLE_DESCRIPTOR_NAME and member.isfile():
                fh = tar.extractfile(member)
                assert fh is not None
                body = fh.read()
            elif member.name == _BUNDLE_DESCRIPTOR_SIG_NAME and member.isfile():
                fh = tar.extractfile(member)
                assert fh is not None
                sig = fh.read()
            if body is not None and sig is not None:
                break
    if body is None or sig is None:
        raise BundleDescriptorMissing(
            "bundle.json and/or bundle.json.sig missing from tar root",
            {
                "have_bundle_json": body is not None,
                "have_bundle_json_sig": sig is not None,
            },
        )
    return body, sig


def _verify_bundle_signature(
    body: bytes,
    sig: bytes,
    trust_keys: List[AirgapImportTrustKey],
) -> None:
    """Verify ``sig`` over ``body`` against any active trust pin.

    Builds a transient keyring with every pinned armored public
    key and asks gpg --verify to accept the sig if any key matches.
    Refuses ``BundleSignatureInvalid`` if no trusted key signed it.
    """
    with mirror_gpg.ephemeral_gnupg_home() as home:
        for key in trust_keys:
            mirror_gpg.import_armored_public(home, key.armored_public_key)
        # Write body + sig to temp paths; verify_detached takes paths.
        body_path = home / "body"
        sig_path = home / "body.sig"
        body_path.write_bytes(body)
        sig_path.write_bytes(sig)
        try:
            mirror_gpg.verify_detached(home, sig_path, body_path)
        except mirror_gpg.MirrorGPGError as exc:
            raise BundleSignatureInvalid(
                "bundle.json signature does not verify against any "
                "operator-pinned trust key",
                {
                    "active_trust_fingerprints": [
                        k.gpg_fingerprint for k in trust_keys
                    ],
                    "gpg_error": str(exc),
                },
            ) from exc


def _validate_member_name(name: str) -> None:
    """Refuse path-traversal / absolute / unknown-layout member names."""
    if name.startswith("/") or "\\" in name or "\x00" in name:
        raise PayloadMemberInvalid(
            f"tar member name {name!r} has illegal characters",
            {"path_in_tar": name},
        )
    parts = name.split("/")
    if any(p in ("", "..", ".") for p in parts[:-1]) or parts[-1] in (
        "",
        "..",
        ".",
    ):
        raise PayloadMemberInvalid(
            f"tar member name {name!r} has empty / traversal segments",
            {"path_in_tar": name},
        )
    if name in (_BUNDLE_DESCRIPTOR_NAME, _BUNDLE_DESCRIPTOR_SIG_NAME):
        return
    if not _MIRROR_MEMBER_RE.match(name):
        raise PayloadMemberInvalid(
            f"tar member name {name!r} does not match the locked airgap "
            "layout (mirrors/<slug>/snapshots/<run>.manifest.json[.sig] "
            "or mirrors/<slug>/live/<path>)",
            {"path_in_tar": name},
        )


def _extract_to(staging_root: Path, tar, member) -> None:
    """Extract ``member`` to ``staging_root/<member.name>``.

    Member name is already validated; we don't use ``tar.extract``
    because that may follow tarfile's permission/owner side effects.
    Manual fileobj copy is enough for our regular-file payloads.
    """
    dest = staging_root / member.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = tar.extractfile(member)
    assert src is not None
    with dest.open("wb") as out_fh:
        while True:
            chunk = src.read(_CHUNK_BYTES)
            if not chunk:
                break
            out_fh.write(chunk)


def _extract_and_verify(
    staging_root: Path,
    tar,
    member,
    expected,
) -> None:
    """Extract ``member`` to staging while streaming-hashing.

    Compares hash + byte count to the signed ``expected`` entry.
    Mismatch raises ``PayloadIntegrityFailure``.
    """
    dest = staging_root / member.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    n = 0
    src = tar.extractfile(member)
    assert src is not None
    with dest.open("wb") as out_fh:
        while True:
            chunk = src.read(_CHUNK_BYTES)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
            out_fh.write(chunk)
    if n != expected.byte_count:
        raise PayloadIntegrityFailure(
            f"member {member.name!r} byte_count mismatch: tar carried "
            f"{n} bytes, signed payload_index expected "
            f"{expected.byte_count}",
            {
                "path_in_tar": member.name,
                "actual_byte_count": n,
                "expected_byte_count": expected.byte_count,
            },
        )
    if h.hexdigest() != expected.sha256:
        raise PayloadIntegrityFailure(
            f"member {member.name!r} sha256 mismatch: tar carried "
            f"{h.hexdigest()}, signed payload_index expected "
            f"{expected.sha256}",
            {
                "path_in_tar": member.name,
                "actual_sha256": h.hexdigest(),
                "expected_sha256": expected.sha256,
            },
        )


def _verify_per_mirror_manifest_sigs(
    *,
    descriptor: BundleDescriptor,
    staging_root: Path,
) -> None:
    """For each mirror in the descriptor, verify its
    ``<run_id>.manifest.json.sig`` against the descriptor's
    declared armored keys for that mirror.

    Trusts ONLY keys declared in the
    descriptor body (which the bundle-level signature already
    covers).

    Every armored entry must be non-empty,
    importable, and its imported fingerprint must be in the
    declared ``signing_key_fingerprints`` set. After importing
    every entry, the imported-fingerprint set must equal the
    declared-fingerprint set — otherwise the descriptor's
    fingerprint metadata has drifted from its actual verification
    keys and offline reasoning is broken.
    """
    for mirror in descriptor.mirrors:
        manifest_path = (
            staging_root
            / "mirrors"
            / mirror.mirror_slug
            / "snapshots"
            / f"{mirror.run_id}.manifest.json"
        )
        sig_path = manifest_path.with_suffix(manifest_path.suffix + ".sig")
        if not manifest_path.exists() or not sig_path.exists():
            raise PayloadIntegrityFailure(
                f"mirror {mirror.mirror_slug!r} manifest or sig is missing "
                "from staging after extraction",
                {"mirror_slug": mirror.mirror_slug, "run_id": mirror.run_id},
            )
        if not mirror.signing_keys_armored:
            raise ManifestSignatureInvalid(
                f"mirror {mirror.mirror_slug!r} declares no armored "
                "signing keys; cannot verify manifest signature",
                {"mirror_slug": mirror.mirror_slug},
            )
        if len(mirror.signing_keys_armored) != len(mirror.signing_key_fingerprints):
            raise ManifestSignatureInvalid(
                f"mirror {mirror.mirror_slug!r} declared "
                f"{len(mirror.signing_key_fingerprints)} fingerprint(s) but "
                f"{len(mirror.signing_keys_armored)} armored key entrie(s); "
                "each declared fingerprint needs a matching armored entry",
                {
                    "mirror_slug": mirror.mirror_slug,
                    "declared_fingerprints": list(mirror.signing_key_fingerprints),
                    "armored_count": len(mirror.signing_keys_armored),
                    "reason": "fingerprint_armored_count_mismatch",
                },
            )
        declared_fps = {fp.upper() for fp in mirror.signing_key_fingerprints if fp}
        if not declared_fps:
            raise ManifestSignatureInvalid(
                f"mirror {mirror.mirror_slug!r} has no declared "
                "fingerprints; cannot verify manifest signature",
                {"mirror_slug": mirror.mirror_slug},
            )
        imported_fps: set[str] = set()
        with mirror_gpg.ephemeral_gnupg_home() as home:
            for idx, armored in enumerate(mirror.signing_keys_armored):
                if not armored:
                    raise ManifestSignatureInvalid(
                        f"mirror {mirror.mirror_slug!r} armored key entry "
                        f"{idx} is empty",
                        {
                            "mirror_slug": mirror.mirror_slug,
                            "armored_index": idx,
                            "reason": "empty_armored_entry",
                        },
                    )
                try:
                    fp = mirror_gpg.import_public_and_extract_fingerprint(home, armored)
                except mirror_gpg.MirrorGPGError as exc:
                    raise ManifestSignatureInvalid(
                        f"mirror {mirror.mirror_slug!r} armored key entry "
                        f"{idx} failed to import: {exc}",
                        {
                            "mirror_slug": mirror.mirror_slug,
                            "armored_index": idx,
                            "reason": "armored_import_failed",
                            "gpg_error": str(exc),
                        },
                    ) from exc
                fp_upper = fp.upper()
                if fp_upper not in declared_fps:
                    raise ManifestSignatureInvalid(
                        f"mirror {mirror.mirror_slug!r} armored key entry "
                        f"{idx} produced fingerprint {fp_upper} which is "
                        "not in the declared fingerprint set",
                        {
                            "mirror_slug": mirror.mirror_slug,
                            "armored_index": idx,
                            "imported_fingerprint": fp_upper,
                            "declared_fingerprints": sorted(declared_fps),
                            "reason": "fingerprint_not_declared",
                        },
                    )
                imported_fps.add(fp_upper)
            if imported_fps != declared_fps:
                missing = sorted(declared_fps - imported_fps)
                raise ManifestSignatureInvalid(
                    f"mirror {mirror.mirror_slug!r} declared "
                    f"{len(declared_fps)} fingerprint(s) but only "
                    f"{len(imported_fps)} were importable; declared set "
                    "has drifted from actual verification keys",
                    {
                        "mirror_slug": mirror.mirror_slug,
                        "missing_declared_fingerprints": missing,
                        "imported_fingerprints": sorted(imported_fps),
                        "reason": "declared_fingerprint_not_imported",
                    },
                )
            try:
                mirror_gpg.verify_detached(home, sig_path, manifest_path)
            except mirror_gpg.MirrorGPGError as exc:
                raise ManifestSignatureInvalid(
                    f"mirror {mirror.mirror_slug!r} manifest sig does not "
                    "verify against any declared armored key",
                    {
                        "mirror_slug": mirror.mirror_slug,
                        "declared_fingerprints": list(mirror.signing_key_fingerprints),
                        "gpg_error": str(exc),
                    },
                ) from exc


def _staging_root_for(bundle_id: str) -> Path:
    """Return ``<PRAXIS_AIRGAP_IMPORT_STAGING>/<bundle_id>/`` for
    per-import scratch state."""
    return airgap_import_staging_root() / bundle_id


class _HashingReader:
    """Read-side wrapper that streams sha256 over consumed bytes.

    Mirrors slice #2's ``_ShaTrackingReader`` shape but for
    ``tarfile.open(mode="r", fileobj=...)`` use. Tarfile reads
    through the fileobj and tells us the byte count via
    ``bytes_read``.
    """

    def __init__(self, fh, hasher):
        self._fh = fh
        self._hasher = hasher
        self.bytes_read = 0

    def read(self, n: int = -1) -> bytes:  # pragma: no cover — trivial
        data = self._fh.read(n)
        self._hasher.update(data)
        self.bytes_read += len(data)
        return data

    def tell(self) -> int:  # pragma: no cover — trivial
        return self.bytes_read


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


def derive_imported_slug(bundle_id: str, original_slug: str) -> str:
    """Compute the prefixed slug for an imported entity.

    Format: ``imported-<bundle_short>-<original_slug>``. Bundle
    short = first 8 chars of bundle_id with dashes stripped — keeps
    slugs deterministic across re-imports of the same bundle while
    avoiding accidental collisions between unrelated bundles.
    """
    short = bundle_id.replace("-", "")[:8]
    return f"imported-{short}-{original_slug}"


def _check_slug_collision(
    db: Session,
    *,
    mirror_slugs: List[str],
    channel_slugs: List[str],
    profile_slugs: List[str],
) -> None:
    """Refuse if any prefixed slug collides with an existing row.

    Slice-#1 lock: soft-deleted slugs ARE collisions in v1
    (DB unique constraints span deleted rows). The error body lists
    every collision so the operator sees the full picture in one
    request.
    """
    conflicts: List[Dict[str, str]] = []
    if mirror_slugs:
        for row in db.query(MirrorRepo).filter(MirrorRepo.slug.in_(mirror_slugs)).all():
            conflicts.append({"kind": "mirror", "slug": row.slug})
    if channel_slugs:
        for row in (
            db.query(ContentChannel)
            .filter(ContentChannel.slug.in_(channel_slugs))
            .all()
        ):
            conflicts.append({"kind": "channel", "slug": row.slug})
    if profile_slugs:
        for row in (
            db.query(ContentProfile)
            .filter(ContentProfile.slug.in_(profile_slugs))
            .all()
        ):
            conflicts.append({"kind": "profile", "slug": row.slug})
    if conflicts:
        raise SlugCollision(
            f"importer found {len(conflicts)} pre-existing slug(s) "
            "(including soft-deleted) that would collide with the "
            "imported entities; refuse",
            {"conflicts": conflicts},
        )


def _promote_mirror_tree(
    *,
    staging_root: Path,
    original_slug: str,
    target_slug: str,
    run_id: int,
) -> None:
    """Move staging/<orig>/{live,snapshots} → mirror_root/<target>/...

    Uses ``shutil.move`` so cross-FS moves work (staging may be on
    a different volume than the mirror root in production). The
    target dir must not exist (slug-collision check above already
    ensured this for fresh imports).
    """
    src_mirror = staging_root / "mirrors" / original_slug
    dest_root = mirror_repo_root(target_slug)
    dest_root.mkdir(parents=True, exist_ok=True)
    # snapshots/
    src_snap = src_mirror / "snapshots"
    dest_snap = snapshots_dir(target_slug)
    dest_snap.mkdir(parents=True, exist_ok=True)
    # Move the imported manifest+sig pair into snapshots/.
    for child in src_snap.iterdir():
        shutil.move(str(child), str(dest_snap / child.name))
    # live/
    src_live = src_mirror / "live"
    dest_live = live_dir(target_slug)
    if dest_live.exists():
        shutil.rmtree(dest_live, ignore_errors=False)
    shutil.move(str(src_live), str(dest_live))


def _resolve_parent_chain(db: Session, *, head_bundle_id: str) -> List["AirgapImport"]:
    """Walk the parent chain starting from ``head_bundle_id`` (PRA-160 #4).

    Returns the chain in **root → parent → head** order so a caller
    can apply layers in that sequence. Refuses with
    ``ParentBundleMissing`` if any link's row is absent and
    ``ParentBundleNotOk`` if any link isn't ``status='ok'``.

    The head row must already exist (the caller's pre-flight created
    it). It's NOT included in the returned chain — the caller has
    that row directly.

    A row whose ``parent_bundle_id`` is None terminates the walk;
    this is the root full bundle.
    """
    head_row = (
        db.query(AirgapImport)
        .filter(AirgapImport.bundle_id == head_bundle_id)
        .one_or_none()
    )
    if head_row is None:
        # Should never happen — caller's pre-flight ensures the head
        # row exists. Defensive.
        raise ParentBundleMissing(
            f"head airgap_imports row for bundle_id={head_bundle_id!r} "
            "vanished mid-import",
            {"head_bundle_id": head_bundle_id},
        )
    chain: List[AirgapImport] = []
    cursor_parent = head_row.parent_bundle_id
    seen: set[str] = {head_bundle_id}
    while cursor_parent is not None:
        if cursor_parent in seen:
            raise ParentBundleMissing(
                f"parent chain for {head_bundle_id!r} contains a cycle "
                f"at {cursor_parent!r}",
                {
                    "head_bundle_id": head_bundle_id,
                    "cycle_at": cursor_parent,
                },
            )
        seen.add(cursor_parent)
        parent_row = (
            db.query(AirgapImport)
            .filter(AirgapImport.bundle_id == cursor_parent)
            .one_or_none()
        )
        if parent_row is None:
            raise ParentBundleMissing(
                f"parent bundle_id={cursor_parent!r} not found in "
                "airgap_imports; import the parent first",
                {
                    "missing_parent_bundle_id": cursor_parent,
                    "head_bundle_id": head_bundle_id,
                },
            )
        if parent_row.status != "ok":
            raise ParentBundleNotOk(
                f"parent bundle_id={cursor_parent!r} is in "
                f"status={parent_row.status!r}; delta requires every "
                "ancestor to be ok",
                {
                    "parent_bundle_id": cursor_parent,
                    "parent_status": parent_row.status,
                    "head_bundle_id": head_bundle_id,
                },
            )
        chain.append(parent_row)
        cursor_parent = parent_row.parent_bundle_id
    # Walked head → parent → grandparent → ...; reverse for root-first.
    chain.reverse()
    return chain


def _copy_parent_live_to_target(
    *,
    parent_target_mirror_slug: str,
    delta_target_slug: str,
) -> None:
    """Copy a parent-imported mirror's live tree to the delta's
    target live (PRA-160 #4).

    ``shutil.copytree`` with ``dirs_exist_ok=True`` so multiple
    parent layers in a chain can stack cumulatively. Each successive
    layer overlays the previous via the same copytree call.
    """
    src_live = live_dir(parent_target_mirror_slug)
    if not src_live.exists():
        raise ParentBundleNotOk(
            f"parent imported mirror {parent_target_mirror_slug!r} has no "
            f"live tree on disk at {src_live}; delta cannot assemble",
            {
                "parent_target_mirror_slug": parent_target_mirror_slug,
                "missing_path": str(src_live),
                "reason": "parent_live_missing",
            },
        )
    dest_live = live_dir(delta_target_slug)
    dest_live.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src_live, dest_live, dirs_exist_ok=True)


def _overlay_delta_live(
    *,
    staging_root: Path,
    original_slug: str,
    target_slug: str,
) -> None:
    """Overlay staging/<orig>/live/* onto the target's existing live
    tree (PRA-160 #4).

    Used after ``_copy_parent_live_to_target`` populated the target
    with the parent's bytes. Files in the delta replace files at
    the same path; new files are added; v1 does not represent
    deletions.
    """
    src_live = staging_root / "mirrors" / original_slug / "live"
    if not src_live.exists():
        # No diff in this mirror's live tree — descriptor.payload_index
        # may still have included the manifest sidecar pair without
        # any live entries. The parent copy is the final tree.
        return
    dest_live = live_dir(target_slug)
    shutil.copytree(src_live, dest_live, dirs_exist_ok=True)


def _compute_assembled_manifest_sha(
    target_slug: str, *, run_id: int, package_family: str
) -> str:
    """Build a PRA-157 manifest of the assembled live tree and
    return its content-only sha256 (PRA-160 #4).

    Reuses the export-side ``mirror_manifest.build_manifest`` +
    ``manifest_sha256`` so the comparison against the descriptor's
    declared ``mirror.manifest_sha256`` is byte-for-byte against
    the same canonical form. The descriptor's value was produced
    on the export side via the same path against the export's live
    tree — so a successful parent+delta assembly that produces the
    same final tree yields the same sha.
    """
    from .. import mirror_manifest  # pylint: disable=import-outside-toplevel

    manifest = mirror_manifest.build_manifest(
        slug=target_slug,
        run_id=run_id,
        package_family=package_family,
    )
    return mirror_manifest.manifest_sha256(manifest)


def _ensure_mirror_layout_descriptor() -> None:
    """Write ``praxis-mirror.json`` at the volume root if missing.

    The PRA-157 mirror engine writes this on first sync; the
    importer writes it too so an instance whose first mirror is
    imported still gets a correct layout descriptor.
    """
    root = mirror_root()
    descriptor_path = root / MIRROR_LAYOUT_DESCRIPTOR_FILENAME
    if descriptor_path.exists():
        return
    root.mkdir(parents=True, exist_ok=True)
    import json  # pylint: disable=import-outside-toplevel

    descriptor_path.write_text(
        json.dumps(
            {
                "praxis_mirror_layout": LAYOUT_VERSION,
                "written_by": "airgap_importer",
                "written_at": datetime.utcnow().isoformat() + "Z",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def ingest_staged_bundle(
    *,
    db: Session,
    descriptor: BundleDescriptor,
    staging_root: Path,
    payload_sha256: str,
    byte_count: int,
    parent_chain: Optional[List["AirgapImport"]] = None,
) -> List[str]:
    """Promote staging → canonical paths, create DB rows.

    Returns the list of imported (prefixed) mirror slugs the
    caller stamps onto ``airgap_imports.target_mirror_slugs``.

    Slug collision check is collective (every prefixed slug across
    mirror/channel/profile checked first); failure raises
    ``SlugCollision`` and no on-disk state is mutated.

    PRA-160 slice #4: when ``descriptor.kind == 'delta'``, the
    caller passes ``parent_chain`` (root → ... → direct parent,
    every row at ``status='ok'``). For each mirror in scope the
    importer copies each chain layer's live tree to the delta's
    target slug in chain order (cumulative overlay), then overlays
    the delta's extracted live files. After assembly, the final
    manifest sha is recomputed and compared against
    ``descriptor.mirror.manifest_sha256`` — mismatch raises
    ``DeltaAssemblyMismatch`` so a parent that drifted on disk or
    a delta crafted against a different parent revision can't
    silently succeed.
    """
    bundle_id = descriptor.bundle_id
    mirror_target_by_orig: Dict[str, str] = {
        m.mirror_slug: derive_imported_slug(bundle_id, m.mirror_slug)
        for m in descriptor.mirrors
    }
    channel_target_by_orig: Dict[str, str] = {
        c.slug: derive_imported_slug(bundle_id, c.slug) for c in descriptor.channels
    }
    profile_target_by_orig: Dict[str, str] = {
        p.slug: derive_imported_slug(bundle_id, p.slug) for p in descriptor.profiles
    }

    _check_slug_collision(
        db,
        mirror_slugs=list(mirror_target_by_orig.values()),
        channel_slugs=list(channel_target_by_orig.values()),
        profile_slugs=list(profile_target_by_orig.values()),
    )

    _ensure_mirror_layout_descriptor()

    # PRA-160 #4: precompute per-chain-layer parent target slugs
    # for each original mirror_slug so the delta assembly can walk
    # them in root-first order.
    parent_chain = parent_chain or []
    parent_layer_slugs_by_orig: Dict[str, List[str]] = {}
    if descriptor.kind == "delta":
        for mirror_desc in descriptor.mirrors:
            parent_layer_slugs_by_orig[mirror_desc.mirror_slug] = [
                derive_imported_slug(p.bundle_id, mirror_desc.mirror_slug)
                for p in parent_chain
            ]

    # Promote on-disk tree per mirror BEFORE inserting rows. If a
    # promotion fails partway, the airgap_imports row goes to
    # ``failed`` and the staging dir stays for inspection. We do
    # NOT roll the previously-promoted mirrors back to staging in
    # v1 — operator triage is the recovery path.
    target_mirror_slugs: List[str] = []
    for mirror_desc in descriptor.mirrors:
        target_slug = mirror_target_by_orig[mirror_desc.mirror_slug]
        if descriptor.kind == "delta":
            # 1. Move the delta's manifest sidecar pair into the
            #    target's snapshots/.
            src_mirror = staging_root / "mirrors" / mirror_desc.mirror_slug
            mirror_repo_root(target_slug).mkdir(parents=True, exist_ok=True)
            dest_snap = snapshots_dir(target_slug)
            dest_snap.mkdir(parents=True, exist_ok=True)
            for child in (src_mirror / "snapshots").iterdir():
                shutil.move(str(child), str(dest_snap / child.name))
            # 2. Copy each parent-chain layer's live tree onto the
            #    delta's target live (root-first; later layers
            #    overlay earlier ones via dirs_exist_ok=True).
            for parent_target_slug in parent_layer_slugs_by_orig[
                mirror_desc.mirror_slug
            ]:
                _copy_parent_live_to_target(
                    parent_target_mirror_slug=parent_target_slug,
                    delta_target_slug=target_slug,
                )
            # 3. Overlay the delta's live diff (if any).
            _overlay_delta_live(
                staging_root=staging_root,
                original_slug=mirror_desc.mirror_slug,
                target_slug=target_slug,
            )
            # 4. Verify the assembled tree's manifest sha matches
            #    the descriptor's declared sha.
            assembled_sha = _compute_assembled_manifest_sha(
                target_slug,
                run_id=mirror_desc.run_id,
                package_family=mirror_desc.package_family,
            )
            if assembled_sha != mirror_desc.manifest_sha256:
                raise DeltaAssemblyMismatch(
                    f"mirror {mirror_desc.mirror_slug!r} delta assembly "
                    f"sha256 {assembled_sha!r} does not match descriptor's "
                    f"declared sha256 {mirror_desc.manifest_sha256!r}; "
                    "parent on disk may have drifted or the delta was "
                    "crafted against a different parent revision",
                    {
                        "mirror_slug": mirror_desc.mirror_slug,
                        "target_slug": target_slug,
                        "assembled_sha256": assembled_sha,
                        "expected_sha256": mirror_desc.manifest_sha256,
                        "parent_chain_bundle_ids": [p.bundle_id for p in parent_chain],
                    },
                )
        else:
            _promote_mirror_tree(
                staging_root=staging_root,
                original_slug=mirror_desc.mirror_slug,
                target_slug=target_slug,
                run_id=mirror_desc.run_id,
            )
        target_mirror_slugs.append(target_slug)

    # DB rows in a single transaction so a row-insert failure
    # rolls back cleanly. The on-disk promotions above are NOT
    # transactional; an inserted MirrorRepo with no on-disk live
    # dir is the failure mode here, caught by the row-insert
    # exception path in run_import.
    mirror_id_by_orig: Dict[str, int] = {}
    # Track the new MirrorSyncRun(run_kind='import')
    # row id per original mirror slug so the channel-repo loop below
    # can auto-pin to the import run. Bundles are byte-frozen, so
    # auto-pinning preserves profile.pinned predicates across import
    # without requiring the operator to manually re-pin.
    run_id_by_orig: Dict[str, int] = {}
    for mirror_desc in descriptor.mirrors:
        target_slug = mirror_target_by_orig[mirror_desc.mirror_slug]
        repo = MirrorRepo(
            slug=target_slug,
            display_name=f"[imported] {mirror_desc.mirror_slug}",
            package_family=mirror_desc.package_family,
            upstream_url=f"airgap-imported://{bundle_id}/{mirror_desc.mirror_slug}",
            distribution=mirror_desc.distribution,
            components=_json_dumps(mirror_desc.components),
            architectures=_json_dumps(mirror_desc.architectures),
            sync_schedule_cron="0 0 1 1 *",  # @yearly placeholder
            enabled=False,
            source_mode="imported_offline",
            verify_upstream_signature=False,
            last_sync_status="ok",
            current_disk_bytes=0,
        )
        db.add(repo)
        db.flush()
        mirror_id_by_orig[mirror_desc.mirror_slug] = repo.id
        # MirrorSyncRun row capturing the imported snapshot.
        run = MirrorSyncRun(
            mirror_repo_id=repo.id,
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            status="ok",
            run_kind="import",
            byte_count=mirror_desc.byte_count,
            package_count=mirror_desc.package_count,
            manifest_sha256=mirror_desc.manifest_sha256 or None,
            manifest_path=str(
                snapshots_dir(target_slug) / f"{mirror_desc.run_id}.manifest.json"
            ),
            manifest_signature_path=str(
                snapshots_dir(target_slug) / f"{mirror_desc.run_id}.manifest.json.sig"
            ),
        )
        db.add(run)
        db.flush()
        run_id_by_orig[mirror_desc.mirror_slug] = run.id

    channel_id_by_orig: Dict[str, int] = {}
    for chan_desc in descriptor.channels:
        target_slug = channel_target_by_orig[chan_desc.slug]
        chan_row = ContentChannel(
            slug=target_slug,
            display_name=f"[imported] {chan_desc.display_name}",
            package_family=chan_desc.package_family,
            description=chan_desc.description,
        )
        db.add(chan_row)
        db.flush()
        channel_id_by_orig[chan_desc.slug] = chan_row.id
        for repo_desc in chan_desc.repos:
            mirror_id = mirror_id_by_orig.get(repo_desc.mirror_slug)
            if mirror_id is None:
                # Channel references a mirror that's not in scope —
                # shouldn't happen for a self-consistent descriptor
                # but guard against it. Skip the link; a future
                # importer slice can decide whether to refuse.
                logger.warning(
                    "channel %r repo references mirror %r not in bundle "
                    "scope; skipping repo link",
                    chan_desc.slug,
                    repo_desc.mirror_slug,
                )
                continue
            # Auto-pin to the new import-run row.
            # Bundles are byte-frozen, so the imported snapshot IS
            # the only valid pin target on this side; pre-populating
            # ``pinned_run_id`` keeps profile.pinned predicates
            # firing without requiring operator action.
            db.add(
                ContentChannelRepo(
                    channel_id=chan_row.id,
                    mirror_id=mirror_id,
                    suite_override=repo_desc.suite_override,
                    pinned_run_id=run_id_by_orig.get(repo_desc.mirror_slug),
                )
            )

    for prof_desc in descriptor.profiles:
        target_slug = profile_target_by_orig[prof_desc.slug]
        prof_row = ContentProfile(
            slug=target_slug,
            display_name=f"[imported] {prof_desc.display_name}",
            package_family=prof_desc.package_family,
            description=prof_desc.description,
        )
        db.add(prof_row)
        db.flush()
        for orig_chan_slug in prof_desc.channel_slugs:
            chan_id = channel_id_by_orig.get(orig_chan_slug)
            if chan_id is None:
                continue
            db.add(ContentProfileChannel(profile_id=prof_row.id, channel_id=chan_id))

    db.commit()
    # Staging dir is now consumed; remove the per-bundle scratch.
    if staging_root.exists():
        shutil.rmtree(staging_root, ignore_errors=True)
    return target_mirror_slugs


def _json_dumps(value) -> str:
    """Serialize a list/value as compact JSON for the
    ``mirror_repos.components`` / ``mirror_repos.architectures``
    columns (stored as Text per PRA-157)."""
    import json  # pylint: disable=import-outside-toplevel

    return json.dumps(value or [], sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------


class AirgapImportOrchestrator:
    """End-to-end import flow (PRA-160 slice #3)."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def pre_flight_check(
        self,
        *,
        path: str,
        force: bool,
        actor_user_id: Optional[int],
    ) -> AirgapImport:
        """Synchronous pre-flight.

        Steps that the route + the BG runner share, run before the
        heavy verify+ingest:
          1. Resolve + staging-confine the tar path.
          2. Sniff ``bundle.json`` for ``bundle_id`` / ``kind``.
          3. Validate descriptor structural invariants
             (``bundle_id`` UUIDv4 shape, slug shapes, channel/profile
             self-consistency).
          4. Idempotency: refuse re-import of an ``ok`` row even with
             ``force=True`` (true cascade-replace deferred); allow
             ``force=True`` to reuse a ``failed`` row.
          5. Insert / reuse the ``airgap_imports`` row at
             ``status='verifying'``.

        Returns the ready-to-process row. Raises
        ``ImporterRefusal`` on any pre-flight failure (no row
        created/mutated).
        """
        # ---- Path safety ----
        try:
            tar_path = _resolve_tar_path(path)
        except ImporterRefusal as exc:
            self._emit_refusal(
                actor_user_id=actor_user_id,
                code=exc.code,
                context=exc.context,
            )
            raise

        # ---- Descriptor sniff ----
        # Tarfile.ReadError + OSError + similar IO
        # crashes from a corrupt/non-tar/truncated file must surface
        # as a structured refusal so POST returns flat 422 instead
        # of 500. ImporterRefusal bubbles through its existing branch.
        try:
            body, _sig = _read_descriptor_pair(tar_path)
            preview = deserialize_descriptor(body)
        except ImporterRefusal as exc:
            self._emit_refusal(
                actor_user_id=actor_user_id, code=exc.code, context=exc.context
            )
            raise
        except UnsupportedSchemaVersion as exc:
            # Typed exception from schema means the
            # ``bundle_version`` itself is one we don't know. Distinct
            # surface from "shape-broken descriptor" so operators see
            # "upgrade Praxis" rather than a generic malformed
            # message. Caught BEFORE the broader malformed branch
            # (subclass-precedence on ValueError).
            self._emit_refusal(
                actor_user_id=actor_user_id,
                code="unsupported_bundle_version",
                context={"reason": str(exc)},
            )
            raise UnsupportedBundleVersion(
                str(exc), {"reason": "deserialize_failed"}
            ) from exc
        except (ValueError, KeyError, TypeError) as exc:
            # A versioned-but-malformed descriptor raises
            # KeyError (missing required field) or TypeError (wrong
            # field shape) from ``ProfileDescriptor(**p)`` style
            # constructors, plus ValueError from a malformed JSON
            # body. Without this branch the operator-supplied tar
            # crashed pre-flight with a 500 instead of the flat
            # structured-refusal contract PRA-160 locked in.
            self._emit_refusal(
                actor_user_id=actor_user_id,
                code=BundleDescriptorUnreadable.code,
                context={
                    "reason": "descriptor_malformed",
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                    "path": str(tar_path),
                },
            )
            raise BundleDescriptorUnreadable(
                f"descriptor body unreadable: {exc!r}",
                {
                    "reason": "descriptor_malformed",
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                    "path": str(tar_path),
                },
            ) from exc
        except (tarfile.TarError, OSError) as exc:
            # Stable reason strings for CLI/UI copy.
            # tarfile.TarError covers ReadError / CompressionError /
            # StreamError / HeaderError → all "the file is malformed
            # in some way" (tar_corrupt). Bare OSError means the OS
            # couldn't read the bytes (EIO, EACCES, etc.) → tar_io_error.
            # Raw exception type is kept in ``exception_type`` for
            # audit/debug.
            reason = (
                "tar_corrupt" if isinstance(exc, tarfile.TarError) else "tar_io_error"
            )
            ctx = {
                "reason": reason,
                "exception_type": type(exc).__name__,
                "error": str(exc),
                "path": str(tar_path),
            }
            self._emit_refusal(
                actor_user_id=actor_user_id,
                code=BundleDescriptorUnreadable.code,
                context=ctx,
            )
            raise BundleDescriptorUnreadable(
                f"airgap bundle tar at {tar_path} is unreadable: {exc!r}",
                ctx,
            ) from exc

        # ---- Descriptor structural validation ----
        try:
            _validate_descriptor_ids(preview)
            _validate_descriptor_self_consistency(preview)
        except ImporterRefusal as exc:
            self._emit_refusal(
                actor_user_id=actor_user_id,
                code=exc.code,
                context=exc.context,
            )
            raise

        bundle_id = preview.bundle_id

        # ---- Idempotency ----
        existing = (
            self.db.query(AirgapImport)
            .filter(AirgapImport.bundle_id == bundle_id)
            .one_or_none()
        )
        if existing is not None:
            # Discriminate "already done" from
            # "currently running" so CLI copy can differ.
            in_progress = existing.status in ("verifying", "extracting")
            if not force:
                ctx = {
                    "bundle_id": bundle_id,
                    "existing_status": existing.status,
                    "existing_id": existing.id,
                }
                if in_progress:
                    ctx["reason"] = "import_in_progress"
                self._emit_refusal(
                    actor_user_id=actor_user_id,
                    code=BundleAlreadyImported.code,
                    context=ctx,
                )
                raise BundleAlreadyImported(
                    (
                        f"bundle_id={bundle_id!r} import is already in progress "
                        f"(status={existing.status!r}); wait for it to finish"
                        if in_progress
                        else f"bundle_id={bundle_id!r} already imported "
                        f"(status={existing.status!r}); pass force=True to "
                        "retry a failed import"
                    ),
                    ctx,
                )
            # Force=True is NOT a cascade-replace.
            # An ``ok`` row's mirror/channel/profile rows are still
            # present; a re-run would just hit SlugCollision and
            # mark the previously-ok row failed without replacing
            # bytes. Refuse explicitly.
            if existing.status == "ok":
                self._emit_refusal(
                    actor_user_id=actor_user_id,
                    code=BundleAlreadyImported.code,
                    context={
                        "bundle_id": bundle_id,
                        "existing_status": "ok",
                        "existing_id": existing.id,
                        "reason": "force_refused_on_completed_import",
                    },
                )
                raise BundleAlreadyImported(
                    f"bundle_id={bundle_id!r} is already at status='ok' "
                    "and force=True does not cascade-replace imported "
                    "mirror/channel/profile rows in v1; soft-delete "
                    "those entities and re-import, or wait for the "
                    "follow-up cascade-replace path",
                    {
                        "bundle_id": bundle_id,
                        "existing_status": "ok",
                        "existing_id": existing.id,
                        "reason": "force_refused_on_completed_import",
                    },
                )

        # ---- Insert / reuse row ----
        if existing is not None:
            # Force-reuse must require the preview's
            # kind + parent_bundle_id to match the stored row's.
            # Otherwise a force-reuse with a tar that's morphed
            # full → delta (or changed parent_bundle_id) at the
            # same bundle_id would silently bind the row's stale
            # delta lineage to a swapped descriptor. Refuse with
            # a structured reason; operator can re-run with the
            # correct kind/parent or wipe the failed row first.
            if existing.kind != preview.kind:
                self._emit_refusal(
                    actor_user_id=actor_user_id,
                    code=BundleAlreadyImported.code,
                    context={
                        "bundle_id": bundle_id,
                        "existing_kind": existing.kind,
                        "preview_kind": preview.kind,
                        "reason": "force_reuse_kind_mismatch",
                    },
                )
                raise BundleAlreadyImported(
                    f"force-reuse refused: existing row kind="
                    f"{existing.kind!r} but the new tar's preview says "
                    f"kind={preview.kind!r}. Force-reuse must point at the "
                    "same lineage.",
                    {
                        "bundle_id": bundle_id,
                        "existing_kind": existing.kind,
                        "preview_kind": preview.kind,
                        "reason": "force_reuse_kind_mismatch",
                    },
                )
            if existing.parent_bundle_id != preview.parent_bundle_id:
                self._emit_refusal(
                    actor_user_id=actor_user_id,
                    code=BundleAlreadyImported.code,
                    context={
                        "bundle_id": bundle_id,
                        "existing_parent_bundle_id": existing.parent_bundle_id,
                        "preview_parent_bundle_id": preview.parent_bundle_id,
                        "reason": "force_reuse_parent_bundle_id_mismatch",
                    },
                )
                raise BundleAlreadyImported(
                    f"force-reuse refused: existing row parent_bundle_id="
                    f"{existing.parent_bundle_id!r} but the new tar's "
                    f"preview says parent_bundle_id="
                    f"{preview.parent_bundle_id!r}. Force-reuse must point "
                    "at the same lineage.",
                    {
                        "bundle_id": bundle_id,
                        "existing_parent_bundle_id": existing.parent_bundle_id,
                        "preview_parent_bundle_id": preview.parent_bundle_id,
                        "reason": "force_reuse_parent_bundle_id_mismatch",
                    },
                )
            row = existing
            row.status = "verifying"
            row.error_text = None
            row.path = str(tar_path)
            row.payload_sha256 = None
            row.byte_count = None
            row.target_mirror_slugs = []
            row.started_at = datetime.utcnow()
            row.finished_at = None
        else:
            row = AirgapImport(
                bundle_id=bundle_id,
                parent_bundle_id=preview.parent_bundle_id,
                kind=preview.kind,
                status="verifying",
                path=str(tar_path),
                target_mirror_slugs=[],
                started_at=datetime.utcnow(),
            )
            self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def execute_import(
        self,
        *,
        row: AirgapImport,
        actor_user_id: Optional[int],
    ) -> AirgapImport:
        """Run verify + ingest on a row already at ``status='verifying'``.

        Split out from ``run_import`` so the
        route's synchronous pre-flight creates the row and the
        BackgroundTasks runner only does the heavy work.
        """
        if row.status != "verifying":
            raise RuntimeError(
                f"execute_import expected row at status='verifying', "
                f"got {row.status!r}"
            )

        # ---- Verify + stage. Catches broad
        # exceptions so tarfile/OSError failures terminalize the
        # row. Binds row.bundle_id into the verifier
        # so the descriptor's structural validation + rebind check
        # happens BEFORE any descriptor-derived path is composed.
        try:
            verified = verify_and_stage(
                tar_path=Path(row.path),
                db=self.db,
                expected_bundle_id=row.bundle_id,
                expected_kind=row.kind,
                expected_parent_bundle_id=row.parent_bundle_id,
            )
        except ImporterRefusal as exc:
            self._fail_import(
                row=row,
                actor_user_id=actor_user_id,
                stage="verify",
                code=exc.code,
                error_text=str(exc),
                context=exc.context,
            )
            raise
        except Exception as exc:  # pylint: disable=broad-except
            self._fail_import(
                row=row,
                actor_user_id=actor_user_id,
                stage="verify",
                code="verify_failed",
                error_text=f"verify failed: {exc!r}",
                context={"exception_type": type(exc).__name__},
            )
            raise

        row.status = "extracting"
        row.payload_sha256 = verified.payload_sha256
        row.byte_count = verified.byte_count
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)

        # PRA-160 #4: for delta bundles, walk the parent chain in
        # airgap_imports BEFORE the ingest so a missing/non-ok
        # ancestor terminalizes the row at status='failed' with
        # stage='verify' instead of leaving partial state from
        # ingest. Refusals propagate through the existing
        # ImporterRefusal arm in the broader try/except below.
        parent_chain: List[AirgapImport] = []
        if verified.descriptor.kind == "delta":
            try:
                parent_chain = _resolve_parent_chain(
                    self.db, head_bundle_id=row.bundle_id
                )
            except ImporterRefusal as exc:
                self._fail_import(
                    row=row,
                    actor_user_id=actor_user_id,
                    stage="verify",
                    code=exc.code,
                    error_text=str(exc),
                    context=exc.context,
                )
                raise

        try:
            target_slugs = ingest_staged_bundle(
                db=self.db,
                descriptor=verified.descriptor,
                staging_root=verified.staging_root,
                payload_sha256=verified.payload_sha256,
                byte_count=verified.byte_count,
                parent_chain=parent_chain,
            )
        except ImporterRefusal as exc:
            self._fail_import(
                row=row,
                actor_user_id=actor_user_id,
                stage="ingest",
                code=exc.code,
                error_text=str(exc),
                context=exc.context,
            )
            raise
        except Exception as exc:  # pylint: disable=broad-except
            self._fail_import(
                row=row,
                actor_user_id=actor_user_id,
                stage="ingest",
                code="ingest_failed",
                error_text=f"ingest failed: {exc!r}",
                context={"exception_type": type(exc).__name__},
            )
            raise

        row.status = "ok"
        row.target_mirror_slugs = target_slugs
        row.finished_at = datetime.utcnow()
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)

        safe_emit(
            action="airgap_import.ok",
            actor_user_id=actor_user_id,
            target_kind="airgap_import",
            target_id=row.bundle_id,
            context={
                "kind": row.kind,
                "payload_sha256": row.payload_sha256,
                "byte_count": row.byte_count,
                "target_mirror_slugs": list(row.target_mirror_slugs),
            },
        )
        logger.info(
            "Airgap import ok bundle_id=%s mirrors=%d",
            row.bundle_id,
            len(target_slugs),
        )
        return row

    def run_import(
        self,
        *,
        path: str,
        force: bool,
        actor_user_id: Optional[int],
    ) -> AirgapImport:
        """Convenience: pre_flight_check + execute_import.

        The route does these in two phases (sync pre-flight + BG
        execute) so the operator's POST returns honest row state.
        Direct callers (CLI, tests) can use this single-call form.
        """
        row = self.pre_flight_check(path=path, force=force, actor_user_id=actor_user_id)
        return self.execute_import(row=row, actor_user_id=actor_user_id)

    # ------------------------------------------------------------------

    def _fail_import(
        self,
        *,
        row: AirgapImport,
        actor_user_id: Optional[int],
        stage: str,
        code: str,
        error_text: str,
        context: dict,
    ) -> None:
        row.status = "failed"
        row.error_text = error_text
        row.finished_at = datetime.utcnow()
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        # Best-effort staging cleanup.
        staging = _staging_root_for(row.bundle_id)
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        safe_emit(
            action="airgap_import.failed",
            actor_user_id=actor_user_id,
            target_kind="airgap_import",
            target_id=row.bundle_id,
            context={
                "stage": stage,
                "code": code,
                "error_text": error_text,
                **context,
            },
        )

    def _emit_refusal(
        self,
        *,
        actor_user_id: Optional[int],
        code: str,
        context: dict,
    ) -> None:
        """Emit a pre-row refusal audit. Mirrors the slice-#1
        ``airgap_export_refused`` shape — keyed on the request hash
        so dashboards group identical refusals.
        """
        request_hash = hashlib.sha256(
            f"{code}|{sorted(context.items())}".encode("utf-8")
        ).hexdigest()[:32]
        safe_emit(
            action="airgap_import_refused",
            actor_user_id=actor_user_id,
            target_kind="airgap_import_request",
            target_id=request_hash,
            context={"code": code, **context},
        )


def run_execute_in_background(bundle_id: str, actor_user_id: Optional[int]) -> None:
    """Entry point for FastAPI BackgroundTasks.

    The route's synchronous pre-flight has already created/reused
    the ``airgap_imports`` row at ``status='verifying'``. This
    runner just loads it and calls ``execute_import``. Mirrors
    slice #2's ``run_build_in_background`` shape.
    """
    from ...db.session import SessionLocal  # pylint: disable=import-outside-toplevel

    db = SessionLocal()
    try:
        row = (
            db.query(AirgapImport)
            .filter(AirgapImport.bundle_id == bundle_id)
            .one_or_none()
        )
        if row is None:
            logger.error(
                "Airgap import BG task fired for bundle_id=%s but no row "
                "exists; skipping",
                bundle_id,
            )
            return
        if row.status != "verifying":
            logger.warning(
                "Airgap import BG task fired for bundle_id=%s but row is "
                "in status=%s (expected 'verifying'); skipping",
                bundle_id,
                row.status,
            )
            return
        try:
            AirgapImportOrchestrator(db).execute_import(
                row=row, actor_user_id=actor_user_id
            )
        except Exception as exc:  # pylint: disable=broad-except
            # ``_fail_import`` already terminalized the row and
            # emitted the audit before this exception escaped.
            logger.error(
                "Airgap import failed bundle_id=%s: %r",
                bundle_id,
                exc,
            )
    finally:
        db.close()
