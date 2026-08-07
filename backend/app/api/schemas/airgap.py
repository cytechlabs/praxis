"""Pydantic schemas for the airgap export/import surface (PRA-160 slice #1).

The bundle descriptor body itself lives in
``app.services.airgap.schema`` (it's a service-layer artifact —
canonical-bytes serializable, not a request/response shape). What's
here is the operator-facing API:

  * ``SnapshotSelector`` — base ``latest|pinned`` plus per-mirror
    explicit overrides.
  * ``ExportRequest`` / ``ExportResponse`` — slice #1 descriptor-only
    flow.
  * ``BundleSigningKeyBootstrapResponse`` — idempotent bootstrap.

Pydantic V1 (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, validator

VALID_BASE_SELECTORS = {"latest", "pinned"}
VALID_EXPORT_KINDS = {"full", "delta"}

SLUG_MAX_LEN = 64
PROFILE_SLUG_MIN = 1


def _validate_profile_slug(v: str) -> str:
    if not isinstance(v, str):
        raise ValueError("profile slug must be a string")
    v = v.strip()
    if not (PROFILE_SLUG_MIN <= len(v) <= SLUG_MAX_LEN):
        raise ValueError(
            f"profile slug length must be {PROFILE_SLUG_MIN}..{SLUG_MAX_LEN}"
        )
    if v != v.lower():
        raise ValueError("profile slug must be lowercase")
    if not all(c.isalnum() or c in "-_" for c in v):
        raise ValueError(
            "profile slug must contain only [a-z0-9_-] (lowercase "
            "alphanumeric, hyphen, underscore)"
        )
    return v


def _validate_mirror_slug_key(v: str) -> str:
    """Mirror slugs in the override map use the same shape as profile slugs."""
    return _validate_profile_slug(v)


class SnapshotSelector(BaseModel):
    """Per-export snapshot byte-selection policy.

    Locks (PRA-160 design conversation, tightened in #1-a/#1-b/#1-c):
      * ``base`` ∈ ``latest | pinned``. Pinned only falls back to
        latest when NO channel referencing a mirror has any pin set;
        if a pin IS set but the pin row is missing/non-ok or owned
        by a different mirror, the planner refuses with
        ``PinUnusable``. Multiple channel pins for one mirror with
        differing manifest sha256 values refuse with
        ``ConflictingPins``. Equal-sha pins resolve to the
        most-recent ok run.
      * ``overrides`` — explicit ``{mirror_slug: run_id}`` overrides
        layered on top. Format ``--snapshot run:<id>`` was rejected
        in design review as ambiguous for multi-mirror profile
        exports; per-mirror overrides are the locked CLI shape.
      * Validation that ``run_id`` belongs to the named mirror and is
        ``status='ok'`` lives in the planner — schema only enforces
        type + slug shape so a bad request returns a clean 422.
    """

    base: str = "latest"
    overrides: Optional[Dict[str, int]] = None

    @validator("base")
    def _base(cls, v):  # pylint: disable=no-self-argument
        if v not in VALID_BASE_SELECTORS:
            raise ValueError(f"base must be one of: {sorted(VALID_BASE_SELECTORS)}")
        return v

    @validator("overrides")
    def _overrides(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError("overrides must be a {mirror_slug: run_id} mapping")
        out: Dict[str, int] = {}
        for slug, run_id in v.items():
            slug_clean = _validate_mirror_slug_key(slug)
            # Reject bool first — isinstance(True, int) is True in Python.
            if isinstance(run_id, bool) or not isinstance(run_id, int):
                raise ValueError(
                    f"override run_id for mirror '{slug_clean}' must be an " "integer"
                )
            if run_id <= 0:
                raise ValueError(
                    f"override run_id for mirror '{slug_clean}' must be positive"
                )
            if slug_clean in out:
                raise ValueError(f"duplicate override entry for mirror '{slug_clean}'")
            out[slug_clean] = run_id
        return out


class ExportRequest(BaseModel):
    """Operator request to build a bundle.

    ``profile_slugs`` is the operator-facing primitive (see PRA-160
    design conversation Q1). Channels and mirrors are derived by the
    planner from each profile's composition.

    ``parent_bundle_id`` is required iff ``kind='delta'`` (slice #4
    enforces this; slice #1 only accepts ``kind='full'`` since the
    delta planner doesn't exist yet).
    """

    profile_slugs: List[str]
    snapshot_selector: SnapshotSelector = SnapshotSelector()
    kind: str = "full"
    parent_bundle_id: Optional[str] = None

    @validator("profile_slugs")
    def _profile_slugs(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, list):
            raise ValueError("profile_slugs must be a list")
        if not v:
            raise ValueError("at least one profile_slug is required")
        seen: set[str] = set()
        out: List[str] = []
        for slug in v:
            cleaned = _validate_profile_slug(slug)
            if cleaned in seen:
                raise ValueError(f"duplicate profile_slug: {cleaned!r}")
            seen.add(cleaned)
            out.append(cleaned)
        return out

    @validator("kind")
    def _kind(cls, v):  # pylint: disable=no-self-argument
        if v not in VALID_EXPORT_KINDS:
            raise ValueError(f"kind must be one of: {sorted(VALID_EXPORT_KINDS)}")
        return v

    @validator("parent_bundle_id", always=True)
    def _parent_bundle_id(cls, v, values):  # pylint: disable=no-self-argument
        kind = values.get("kind")
        if kind == "delta" and not v:
            raise ValueError("parent_bundle_id is required for delta exports")
        if kind == "full" and v:
            raise ValueError("parent_bundle_id must be omitted for full exports")
        return v


class ExportResponse(BaseModel):
    """Returned for a successful export request.

    Slice #1 returns ``status='descriptor_ready'`` immediately after
    the descriptor + signature land. Slice #2 will extend the flow so
    the same row reaches ``status='ok'`` after tar assembly.
    """

    bundle_id: str
    kind: str
    status: str
    bundle_descriptor_path: Optional[str]
    bundle_path: Optional[str]
    payload_sha256: Optional[str]
    byte_count: Optional[int]
    error_text: Optional[str]
    started_at: datetime
    finished_at: Optional[datetime]


class BundleSigningKeyBootstrapResponse(BaseModel):
    """Idempotent bootstrap response.

    Mirrors ``MirrorSigningKeyBootstrapResponse`` shape so the CLI /
    UI doesn't have to special-case airgap key bootstrap.
    """

    fingerprint: str
    key_uid: str
    status: str
    created: bool


class BundleSigningKeyRead(BaseModel):
    """One bundle signing key for the operator UI (PRA-196).

    ``armored_public_key`` is public material an operator distributes to
    import-side instances. Private key material and the Vault path are NEVER
    serialized into this response.
    """

    id: int
    fingerprint: str
    key_uid: str
    status: str
    armored_public_key: Optional[str]
    created_at: datetime
    updated_at: datetime


class BundleSigningKeyRotateResponse(BaseModel):
    """Result of a bundle signing-key rotation (PRA-196).

    ``old`` is the demoted (``rotating_out``) key, still valid for verifying
    already-exported bundles; ``new`` is the fresh ``active`` key that signs
    bundles produced from now on.
    """

    old: BundleSigningKeyRead
    new: BundleSigningKeyRead


# ---------------------------------------------------------------------------
# Slice #3: import trust keys
# ---------------------------------------------------------------------------


class ImportTrustKeyCreate(BaseModel):
    """Pin a bundle-signing public key for the import path (PRA-160 slice #3).

    Operator pastes the armored public key (received out-of-band
    from the export-side instance). The service derives the
    fingerprint via gpg --import + --list-keys; we don't accept an
    operator-supplied fingerprint to avoid a "trust this fingerprint
    for whatever bytes" footgun.
    """

    armored_public_key: str

    @validator("armored_public_key")
    def _armored(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, str) or "BEGIN PGP PUBLIC KEY BLOCK" not in v:
            raise ValueError("armored_public_key must be a PGP PUBLIC KEY BLOCK string")
        return v


class ImportTrustKeyRead(BaseModel):
    id: int
    gpg_fingerprint: str
    key_uid: str
    added_at: datetime
    deleted_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Slice #3: import request/response
# ---------------------------------------------------------------------------


class ImportRequest(BaseModel):
    """Operator request to import an airgap bundle.

    Locks (PRA-160 slice #3):
      * Path-based v1 — operator mounts the bundle tar (USB, NFS,
        etc.) at a location under ``PRAXIS_AIRGAP_IMPORT_STAGING``
        and passes the absolute path here. Multipart upload deferred.
      * ``force=True`` re-imports a bundle whose ``bundle_id``
        already has an ``airgap_imports`` row (rsync --delete
        replace of the on-disk live tree). Without ``force``,
        re-import refuses with ``BundleAlreadyImported``.
    """

    path: str
    force: bool = False

    @validator("path")
    def _path(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, str) or not v.strip():
            raise ValueError("path must be a non-empty string")
        v = v.strip()
        # Refuse path traversal patterns at the schema layer; the
        # importer also validates that the resolved path is under
        # an allow-listed root.
        if ".." in v.split("/"):
            raise ValueError("path must not contain '..' segments")
        return v


class ImportResponse(BaseModel):
    """AirgapImport row state for the import API."""

    bundle_id: str
    kind: str
    status: str
    path: Optional[str]
    payload_sha256: Optional[str]
    byte_count: Optional[int]
    target_mirror_slugs: List[str]
    error_text: Optional[str]
    started_at: datetime
    finished_at: Optional[datetime]
