"""Pydantic schemas for the mirror engine API (PRA-157 #2b).

DB stores ``components`` and ``architectures`` as JSON-encoded text;
the API exposes them as plain ``list[str]``. Encoding/decoding lives
in the route handlers. ``sync_schedule_cron`` accepts a 5-field cron
string and is validated with APScheduler's parser at write time so
malformed schedules are caught before they reach the runtime sweep.

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md`` — ``@classmethod`` suppresses
validation in the V1 surface this codebase still uses).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel, validator

VALID_PACKAGE_FAMILIES = {"deb", "rpm"}
VALID_SOURCE_MODES = {"upstream_sync", "imported_offline"}
VALID_SYNC_STATUSES = {"idle", "running", "ok", "failed"}

SLUG_MAX_LEN = 64
SLUG_MIN_LEN = 1
DISPLAY_NAME_MAX_LEN = 128
URL_MAX_LEN = 512
DISTRIBUTION_MAX_LEN = 64
CRON_MAX_LEN = 128


def _validate_slug(v: str) -> str:
    if not isinstance(v, str):
        raise ValueError("slug must be a string")
    v = v.strip()
    if not (SLUG_MIN_LEN <= len(v) <= SLUG_MAX_LEN):
        raise ValueError(
            f"slug length must be {SLUG_MIN_LEN}..{SLUG_MAX_LEN} characters"
        )
    if v != v.lower():
        raise ValueError("slug must be lowercase")
    if not all(c.isalnum() or c in "-_" for c in v):
        raise ValueError(
            "slug must contain only [a-z0-9_-] (lowercase alphanumeric, "
            "hyphen, underscore)"
        )
    return v


def _validate_string_list(v) -> List[str]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise ValueError("must be a list of strings")
    out: List[str] = []
    for item in v:
        if isinstance(item, bool) or not isinstance(item, str):
            raise ValueError("each item must be a string")
        item = item.strip()
        if not item:
            raise ValueError("entries must be non-empty")
        out.append(item)
    return out


def _validate_cron(v: str) -> str:
    if not isinstance(v, str):
        raise ValueError("sync_schedule_cron must be a string")
    v = v.strip()
    if not v:
        raise ValueError("sync_schedule_cron is required")
    if len(v) > CRON_MAX_LEN:
        raise ValueError(f"sync_schedule_cron exceeds {CRON_MAX_LEN} characters")
    try:
        CronTrigger.from_crontab(v, timezone="UTC")
    except Exception as exc:  # pylint: disable=broad-except
        raise ValueError(f"invalid cron expression: {exc}") from exc
    return v


# ---------------------------------------------------------------------------
# Create / Update / Read
# ---------------------------------------------------------------------------


class MirrorRepoCreate(BaseModel):
    slug: str
    display_name: str
    package_family: str
    upstream_url: str
    distribution: str
    components: Optional[List[str]] = None
    architectures: List[str]
    sync_schedule_cron: str
    enabled: bool = True
    source_mode: str = "upstream_sync"
    verify_upstream_signature: bool = True
    retention_keep_count: int = 10
    retention_keep_within_days: int = 30
    disk_budget_bytes: Optional[int] = None

    @validator("slug")
    def _slug(cls, v):  # pylint: disable=no-self-argument
        return _validate_slug(v)

    @validator("display_name")
    def _display_name(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, str) or not v.strip():
            raise ValueError("display_name is required")
        if len(v) > DISPLAY_NAME_MAX_LEN:
            raise ValueError(f"display_name exceeds {DISPLAY_NAME_MAX_LEN} characters")
        return v.strip()

    @validator("package_family")
    def _package_family(cls, v):  # pylint: disable=no-self-argument
        if v not in VALID_PACKAGE_FAMILIES:
            raise ValueError(
                f"package_family must be one of: {sorted(VALID_PACKAGE_FAMILIES)}"
            )
        return v

    @validator("upstream_url")
    def _upstream_url(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, str) or not v.strip():
            raise ValueError("upstream_url is required")
        if len(v) > URL_MAX_LEN:
            raise ValueError(f"upstream_url exceeds {URL_MAX_LEN} characters")
        if not v.lower().startswith(("http://", "https://", "rsync://", "ftp://")):
            raise ValueError(
                "upstream_url must be http://, https://, rsync://, or ftp://"
            )
        return v.strip()

    @validator("distribution")
    def _distribution(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, str) or not v.strip():
            raise ValueError("distribution is required")
        if len(v) > DISTRIBUTION_MAX_LEN:
            raise ValueError(f"distribution exceeds {DISTRIBUTION_MAX_LEN} characters")
        return v.strip()

    @validator("components", pre=True)
    def _components(cls, v):  # pylint: disable=no-self-argument
        return _validate_string_list(v)

    @validator("architectures", pre=True)
    def _architectures(cls, v):  # pylint: disable=no-self-argument
        decoded = _validate_string_list(v)
        if not decoded:
            raise ValueError("at least one architecture is required")
        return decoded

    @validator("sync_schedule_cron")
    def _sync_schedule_cron(cls, v):  # pylint: disable=no-self-argument
        return _validate_cron(v)

    @validator("source_mode")
    def _source_mode(cls, v):  # pylint: disable=no-self-argument
        if v not in VALID_SOURCE_MODES:
            raise ValueError(
                f"source_mode must be one of: {sorted(VALID_SOURCE_MODES)}"
            )
        return v

    @validator("retention_keep_count")
    def _retention_keep_count(cls, v):  # pylint: disable=no-self-argument
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ValueError("retention_keep_count must be an integer >= 1")
        return v

    @validator("retention_keep_within_days")
    def _retention_keep_within_days(cls, v):  # pylint: disable=no-self-argument
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError("retention_keep_within_days must be an integer >= 0")
        return v

    @validator("disk_budget_bytes")
    def _disk_budget_bytes(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
            raise ValueError("disk_budget_bytes must be a positive integer or null")
        return v


class MirrorRepoUpdate(BaseModel):
    """All-optional patch body. Slug is immutable after creation —
    rename would break advisory-lock id-keying invariants and confuse
    PRA-160 bundle naming.
    """

    display_name: Optional[str] = None
    upstream_url: Optional[str] = None
    distribution: Optional[str] = None
    components: Optional[List[str]] = None
    architectures: Optional[List[str]] = None
    sync_schedule_cron: Optional[str] = None
    enabled: Optional[bool] = None
    source_mode: Optional[str] = None
    verify_upstream_signature: Optional[bool] = None
    retention_keep_count: Optional[int] = None
    retention_keep_within_days: Optional[int] = None
    disk_budget_bytes: Optional[int] = None

    @validator("display_name")
    def _display_name(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if not isinstance(v, str) or not v.strip():
            raise ValueError("display_name cannot be blank")
        if len(v) > DISPLAY_NAME_MAX_LEN:
            raise ValueError(f"display_name exceeds {DISPLAY_NAME_MAX_LEN} characters")
        return v.strip()

    @validator("upstream_url")
    def _upstream_url(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if not isinstance(v, str) or not v.strip():
            raise ValueError("upstream_url cannot be blank")
        if len(v) > URL_MAX_LEN:
            raise ValueError(f"upstream_url exceeds {URL_MAX_LEN} characters")
        if not v.lower().startswith(("http://", "https://", "rsync://", "ftp://")):
            raise ValueError(
                "upstream_url must be http://, https://, rsync://, or ftp://"
            )
        return v.strip()

    @validator("distribution")
    def _distribution(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if not isinstance(v, str) or not v.strip():
            raise ValueError("distribution cannot be blank")
        if len(v) > DISTRIBUTION_MAX_LEN:
            raise ValueError(f"distribution exceeds {DISTRIBUTION_MAX_LEN} characters")
        return v.strip()

    @validator("components", pre=True)
    def _components(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        return _validate_string_list(v)

    @validator("architectures", pre=True)
    def _architectures(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        decoded = _validate_string_list(v)
        if not decoded:
            raise ValueError("at least one architecture is required")
        return decoded

    @validator("sync_schedule_cron")
    def _sync_schedule_cron(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        return _validate_cron(v)

    @validator("source_mode")
    def _source_mode(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if v not in VALID_SOURCE_MODES:
            raise ValueError(
                f"source_mode must be one of: {sorted(VALID_SOURCE_MODES)}"
            )
        return v

    @validator("retention_keep_count")
    def _retention_keep_count(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ValueError("retention_keep_count must be an integer >= 1")
        return v

    @validator("retention_keep_within_days")
    def _retention_keep_within_days(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError("retention_keep_within_days must be an integer >= 0")
        return v

    @validator("disk_budget_bytes")
    def _disk_budget_bytes(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
            raise ValueError("disk_budget_bytes must be a positive integer or null")
        return v


class MirrorRepoRead(BaseModel):
    id: int
    slug: str
    display_name: str
    package_family: str
    upstream_url: str
    distribution: str
    components: List[str]
    architectures: List[str]
    sync_schedule_cron: str
    enabled: bool
    source_mode: str
    verify_upstream_signature: bool
    retention_keep_count: int
    retention_keep_within_days: int
    disk_budget_bytes: Optional[int]
    last_sync_started_at: Optional[datetime]
    last_sync_finished_at: Optional[datetime]
    last_sync_status: str
    last_sync_error: Optional[str]
    current_disk_bytes: int
    deleted_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    # PRA-158 #5c: derived UI badge state. Locked vocabulary:
    #   no_key_yet            — no active signing key yet
    #   key_ready             — active key, no signed run yet
    #   rotation_in_progress  — pending_cutover key exists
    #   signed_ok             — most recent run finalized ok with a key
    #   signing_failed        — most recent run failed (signing/promote)
    #   upstream_invalid      — most recent run refused by upstream-verify gate
    signing_status: str


class MirrorSyncRunRead(BaseModel):
    id: int
    mirror_repo_id: int
    started_at: datetime
    finished_at: Optional[datetime]
    status: str
    # PRA-158 #2a: sync (full sync from upstream) vs sign_only (retrofit
    # signatures onto current live/ tree). Status semantics unchanged.
    run_kind: str
    byte_count: Optional[int]
    package_count: Optional[int]
    manifest_sha256: Optional[str]
    manifest_path: Optional[str]
    # PRA-158 #2a: detached manifest signature sidecar (NULL on
    # pre-PRA-158 runs).
    manifest_signature_path: Optional[str]
    signed_with_key_id: Optional[int]
    error_text: Optional[str]
    estimate_unavailable: bool
    created_at: datetime


class MirrorSyncQueuedResponse(BaseModel):
    """202 Accepted response for POST /mirrors/{id}/sync."""

    mirror_repo_id: int
    queued: bool
    message: str


class MirrorSignCurrentQueuedResponse(BaseModel):
    """202 Accepted response for POST /mirrors/{id}/sign-current (PRA-158 #2c)."""

    mirror_repo_id: int
    queued: bool
    run_kind: str  # always "sign_only" for this endpoint
    message: str


# ---------------------------------------------------------------------------
# PRA-158 slice #1 — Signing-key surface (metadata only)
# ---------------------------------------------------------------------------
#
# Slice #1 carves the read shape and the bootstrap endpoint. Slice #2 wires
# the signing engine; slice #3 returns the bundle.asc body. Until then the
# UI/API status field MUST be ``no_key_yet`` or ``key_ready``, never
# ``trusted`` or ``signed_ok`` — having a key is not the same as having
# signed anything yet.

VALID_SIGNING_KEY_STATUSES = {
    "active",
    "pending_cutover",
    "rotating_out",
    "retired",
}

VALID_MIRROR_SIGNING_STATUSES = {"no_key_yet", "key_ready"}


class MirrorSigningKeyRead(BaseModel):
    """Public metadata for a single signing key.

    NEVER carries private key material. ``public_key_armored`` is the
    armored public half (safe by definition); slice #1 keeps it out of
    the default response and exposes it only via an explicit field that
    callers opt into. Slice #3 ships the full trust-bundle endpoint.
    """

    id: int
    mirror_repo_id: int
    status: str
    gpg_fingerprint: str
    key_uid: str
    cutover_at: Optional[datetime]
    retired_at: Optional[datetime]
    created_at: datetime


class MirrorSigningKeyDetail(MirrorSigningKeyRead):
    """Like ``MirrorSigningKeyRead`` plus the armored public key.

    Returned by the bootstrap endpoint and by an explicit detail fetch.
    Public material only — NEVER include private. Caller-side guard
    against leaking private material is the route handler, not pydantic.
    """

    public_key_armored: str


# ---------------------------------------------------------------------------
# PRA-158 slice #5b — rotation endpoints
# ---------------------------------------------------------------------------
#
# Three explicit endpoints — no auto-cutover (locked):
#   * POST /mirrors/{id}/signing-key/rotate-prepare
#   * POST /mirrors/{id}/signing-key/cutover
#   * POST /mirrors/{id}/signing-key/retire/{key_id}
# Plus a preview that returns the cutover hard-gate state without
# performing it:
#   * GET /mirrors/{id}/signing-key/cutover-preview


class CutoverPreviewResponse(BaseModel):
    """Hard-gate preview shape (PRA-158 #5b).

    Slice #5a only populates ``hosts_missing_pending``;
    ``hosts_never_installed`` and ``hosts_stale_trust_record`` are
    forward-compatible empty lists until PRA-159's channel work
    creates a per-mirror→hosts relationship the gate can use to
    detect "never installed" and "stale record" cases.
    """

    pending_fingerprint: str
    hosts_missing_pending: List[int]
    hosts_never_installed: List[int]
    hosts_stale_trust_record: List[int]


class CutoverRequest(BaseModel):
    """Body for ``POST /mirrors/{id}/signing-key/cutover``.

    ``force=True`` overrides the hard-gate AND emits an audit event
    with structured counts (per the locked design); the role gate
    (admin/maintainer) is the same on the endpoint either way.
    """

    force: bool = False


class CutoverBlockedResponse(BaseModel):
    """409 body when ``cutover(force=False)`` would leave hosts
    without the pending key. Mirrors ``CutoverPreviewResponse`` so a
    UI can use the same component for the "would-block" preview and
    the "did-block" rejection.
    """

    detail: str
    preview: CutoverPreviewResponse


class MirrorSigningKeyBootstrapResponse(BaseModel):
    """Response for ``POST /mirrors/{id}/signing-key``.

    Idempotent endpoint: ``created`` is true on the call that actually
    generated the key, false on subsequent calls returning the existing
    active key. ``mirror_signing_status`` is the UI-friendly summary
    field locked at ``no_key_yet`` (no active key) or ``key_ready``
    (active key exists, signing engine wiring lands in slice #2).
    """

    created: bool
    mirror_signing_status: str
    key: MirrorSigningKeyDetail


# ---------------------------------------------------------------------------
# PRA-158 slice #3b — trust-bundle distribution
# ---------------------------------------------------------------------------
#
# Trust bundle is the public-key set hosts install to trust this mirror's
# native signatures. Includes ``active`` + ``pending_cutover`` +
# ``rotating_out`` keys (slice #1 ``bundle_public_keys`` lock); NEVER
# includes ``retired``. Two endpoints share the same set:
#
#   * ``GET /mirrors/{id}/trust-bundle``     — JSON, structured
#   * ``GET /mirrors/{id}/trust-bundle.asc`` — concatenated armored bodies
#
# Both authenticated (no anonymous fetch — slice-#1 design lock). Hosts
# pull the bundle through the slice #3c install primitive, not directly.


class TrustBundleEntry(BaseModel):
    """One key inside the trust bundle."""

    id: int  # PRA-158 #5c: UI passes this to the retire endpoint.
    fingerprint: str
    uid: str
    status: str  # active | pending_cutover | rotating_out
    armored: str  # armored public key (PGP PUBLIC KEY BLOCK)


class InstallTrustRequest(BaseModel):
    """Body for ``POST /mirrors/{id}/install-trust`` (PRA-158 #3c).

    Explicit host list — no implicit "all hosts" default to keep the
    blast radius of a misclick small. Operators can compose larger
    fleets client-side from the systems-list endpoint.
    """

    host_ids: List[int]


class HostInstallResultRead(BaseModel):
    """Per-host result inside ``InstallTrustResponse``."""

    host_id: int
    ok: bool
    installed_fingerprints: List[str]
    written_paths: List[str]
    error_text: Optional[str] = None


class InstallTrustResponse(BaseModel):
    """``POST /mirrors/{id}/install-trust`` response.

    ``ok`` is True iff every host succeeded. Per-host detail is in
    ``results``. The endpoint awaits all installs inline (trust
    install is fast — small files, few round-trips); for very large
    fleets a future slice can introduce a queued mode without
    breaking this shape.
    """

    mirror_id: int
    ok: bool
    results: List[HostInstallResultRead]


class TrustBundleResponse(BaseModel):
    """``GET /mirrors/{id}/trust-bundle`` JSON body.

    ``active_fingerprint`` is the fingerprint of the key currently used
    for signing — convenient for installers that want to identify the
    "primary" key without ordering on ``status`` themselves.
    ``keys`` is ordered: active first, then pending_cutover, then
    rotating_out (matches ``MirrorSigningKeyService.bundle_public_keys``).
    """

    mirror_id: int
    mirror_slug: str
    active_fingerprint: Optional[str]
    keys: List[TrustBundleEntry]
