"""Bundle descriptor body for airgap export/import (PRA-160 slice #1).

The bundle descriptor is the trust anchor for an airgap bundle. It
declares what's inside (profiles → channels → mirrors → runs), names
the byte locations within the eventual tar (filled in by slice #2),
and embeds the per-mirror signing public-key material the importer
needs to verify each ``<run_id>.manifest.json.sig`` ride-along.

Locks (PRA-160 design conversation):
  * Schema is versioned via ``BUNDLE_SCHEMA_VERSION``. The importer
    refuses unknown versions; bumps require an explicit code change
    on both sides.
  * Per-mirror signing public keys + fingerprints are declared inside
    the descriptor body so the bundle-level signature
    (``bundle.json.sig``) **covers** them. The importer trusts only
    keys declared here, NOT arbitrary armored bytes carried in the
    tar.
  * ``payload_index`` maps tar member paths → declared sha256 → byte
    length. Empty in slice #1 (descriptor-only); slice #2 populates
    after tar assembly and re-signs the descriptor.
  * Subscription tables (``host_content_profile_subscriptions`` etc.)
    are explicitly NOT exported — host bindings are operator policy
    on the airgap side, not portable from the export side.

Canonical-bytes serialization:
  * ``json.dumps`` with ``sort_keys=True``, no whitespace variance,
    UTF-8. Signed bytes are exactly what the importer recomputes
    from the descriptor JSON on disk, so any field ordering drift
    or whitespace mutation invalidates the signature.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import List, Optional

# Bumped only on incompatible structural change. Slice #1 ships v1.
BUNDLE_SCHEMA_VERSION = "v1"


@dataclass
class MirrorRunDescriptor:
    """One mirror's selected snapshot run inside the bundle.

    Slice #1 fills in identity + manifest fields. Slice #2 fills in
    ``manifest_path_in_tar`` + ``live_path_in_tar`` once the tar
    layout is assembled.
    """

    mirror_slug: str
    package_family: str  # 'deb' | 'rpm'
    distribution: str
    components: List[str]
    architectures: List[str]
    run_id: int
    manifest_sha256: str
    manifest_path: str  # absolute path on the export side, audit trace
    byte_count: Optional[int]
    package_count: Optional[int]
    # Per-mirror signing keys whose fingerprints sign this run's
    # ``<run_id>.manifest.json.sig``. Multiple keys may be present
    # (active + rotating_out + pending_cutover) so the importer can
    # accept verifications from any of them.
    signing_key_fingerprints: List[str] = field(default_factory=list)
    signing_keys_armored: List[str] = field(default_factory=list)
    # Tar layout is finalized in slice #2; descriptor-only rows leave
    # these None.
    manifest_path_in_tar: Optional[str] = None
    manifest_signature_path_in_tar: Optional[str] = None
    live_path_in_tar: Optional[str] = None


@dataclass
class ChannelRepoDescriptor:
    """Per-channel mirror entry — denormalized snapshot of
    ``ContentChannelRepo``.
    """

    mirror_slug: str
    suite_override: Optional[str]
    pinned_run_id: Optional[int]
    pinned_manifest_sha256: Optional[str]


@dataclass
class ChannelDescriptor:
    """Denormalized snapshot of ``ContentChannel`` + repo links."""

    slug: str
    display_name: str
    package_family: str
    description: Optional[str]
    repos: List[ChannelRepoDescriptor]


@dataclass
class ProfileDescriptor:
    """Denormalized snapshot of ``ContentProfile`` + channel links."""

    slug: str
    display_name: str
    package_family: str
    description: Optional[str]
    channel_slugs: List[str]


@dataclass
class PayloadIndexEntry:
    """One tar member entry in the payload index (slice #2 populates)."""

    path_in_tar: str
    sha256: str
    byte_count: int


@dataclass
class BundleDescriptor:
    """Top-level bundle descriptor body (PRA-160 slice #1).

    The on-disk JSON file is ``bundle.json`` at the bundle root; its
    detached signature lives at ``bundle.json.sig``. Both are written
    inside ``.airgap-staging/<bundle_id>/`` until slice #2 promotes
    them into the final tar.
    """

    bundle_version: str
    bundle_id: str
    kind: str  # 'full' | 'delta'
    parent_bundle_id: Optional[str]
    created_at: str  # ISO 8601 UTC, with trailing 'Z'
    praxis_instance_signing_fingerprint: str
    profiles: List[ProfileDescriptor]
    channels: List[ChannelDescriptor]
    mirrors: List[MirrorRunDescriptor]
    # Slice #2 populates this once tar assembly is done. Slice #1
    # signs an empty list; slice #2 re-signs the descriptor with the
    # populated index. The importer uses the signed index to validate
    # tar member sha256s during extraction.
    payload_index: List[PayloadIndexEntry] = field(default_factory=list)


def serialize_descriptor(descriptor: BundleDescriptor) -> bytes:
    """Return canonical UTF-8 bytes for a descriptor.

    Used both for signing (so the sig covers an exact byte sequence)
    and for write-to-disk so the importer recomputes the same bytes
    when verifying.

    ``json.dumps(..., sort_keys=True, separators=(',', ':'))`` keeps
    output deterministic across Python versions and dict insertion
    order. Whitespace-free output also makes diffs against tampered
    descriptors trivially line-up-able in audit reviews.
    """
    payload = asdict(descriptor)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class UnsupportedSchemaVersion(ValueError):
    """Raised by ``deserialize_descriptor`` when ``bundle_version`` is
    not one this Praxis knows.

    A typed subclass of ``ValueError`` so the CLI can
    discriminate "future bundle, upgrade Praxis" from "malformed
    descriptor body" without sentinel-string matching, while staying
    backward-compatible with existing ``except ValueError`` callers
    in ``importer.run_import`` and ``planner.delta``.
    """


def deserialize_descriptor(body: bytes) -> BundleDescriptor:
    """Parse canonical bytes back into a ``BundleDescriptor``.

    Slice #3's importer uses this to read ``bundle.json`` from a
    landed bundle. Strict — unknown ``bundle_version`` raises so the
    importer can refuse with a clean error before doing any byte
    work.
    """
    data = json.loads(body)
    version = data.get("bundle_version")
    if version != BUNDLE_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"unsupported bundle_version {version!r}; importer expects "
            f"{BUNDLE_SCHEMA_VERSION!r}"
        )

    profiles = [ProfileDescriptor(**p) for p in data["profiles"]]
    channels = [
        ChannelDescriptor(
            slug=c["slug"],
            display_name=c["display_name"],
            package_family=c["package_family"],
            description=c["description"],
            repos=[ChannelRepoDescriptor(**r) for r in c["repos"]],
        )
        for c in data["channels"]
    ]
    mirrors = [MirrorRunDescriptor(**m) for m in data["mirrors"]]
    payload_index = [PayloadIndexEntry(**e) for e in data.get("payload_index", [])]

    return BundleDescriptor(
        bundle_version=version,
        bundle_id=data["bundle_id"],
        kind=data["kind"],
        parent_bundle_id=data.get("parent_bundle_id"),
        created_at=data["created_at"],
        praxis_instance_signing_fingerprint=data["praxis_instance_signing_fingerprint"],
        profiles=profiles,
        channels=channels,
        mirrors=mirrors,
        payload_index=payload_index,
    )
