"""Pydantic schemas for content resolution / diff / credential routes
(PRA-159 slice #2).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, validator

# ---------------------------------------------------------------------------
# Resolved mirror entry (profile fan-out)
# ---------------------------------------------------------------------------


class ResolvedMirrorEntryRead(BaseModel):
    channel_id: int
    channel_slug: str
    mirror_id: int
    mirror_slug: str
    package_family: str
    suite: str
    components: List[str]
    architectures: List[str]
    pinned_run_id: Optional[int]
    pinned_manifest_sha256: Optional[str]


class EffectiveProfileBindingSlim(BaseModel):
    """Same shape as the /content-profile resolution response;
    duplicated locally so the resolved-content endpoints don't need
    to import the profile router's schema module."""

    profile_id: int
    profile_slug: str
    profile_display_name: str
    via_kind: Literal["direct", "group", "smart_group"]
    via_id: Optional[int]
    via_label: Optional[str]


class ResolvedContentRead(BaseModel):
    state: Literal["no_profile", "resolved", "conflict"]
    profile: Optional[EffectiveProfileBindingSlim]
    conflict_bindings: List[EffectiveProfileBindingSlim]
    entries: List[ResolvedMirrorEntryRead]


# ---------------------------------------------------------------------------
# Manifest + diff
# ---------------------------------------------------------------------------


class ProfileManifestPackage(BaseModel):
    package: str
    arch: Optional[str]
    version: str


class ProfileManifestRead(BaseModel):
    packages: List[ProfileManifestPackage]
    summary: dict


class ProfileDiffRow(BaseModel):
    package: str
    arch: Optional[str]
    from_version: Optional[str]
    to_version: Optional[str]


class ProfileDiffRead(BaseModel):
    added: List[ProfileDiffRow]
    removed: List[ProfileDiffRow]
    changed: List[ProfileDiffRow]
    summary: dict


# ---------------------------------------------------------------------------
# Mirror serve credential (per-host bearer)
# ---------------------------------------------------------------------------


class MirrorServeCredentialIssueRequest(BaseModel):
    """Operator-driven issuance.

    ``ttl_days`` defaults to 365 (matches the service default). Slice
    #3's apply orchestrator will issue credentials automatically; this
    endpoint exists for manual ops + for tests.
    """

    mirror_id: int
    ttl_days: int = 365

    @validator("mirror_id")
    def _mirror_id(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise ValueError("mirror_id must be a positive integer")
        return v

    @validator("ttl_days")
    def _ttl(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0 or v > 3650:
            raise ValueError("ttl_days must be a positive integer ≤ 3650")
        return v


class MirrorServeCredentialIssueResponse(BaseModel):
    """Returned ONCE at issue. ``plaintext`` is the only opportunity
    to read the bearer token; subsequent reads return only metadata
    (``MirrorServeCredentialRead``).
    """

    credential_id: int
    host_id: int
    mirror_id: int
    plaintext: str
    issued_at: datetime
    expires_at: datetime


class MirrorServeCredentialRead(BaseModel):
    """Metadata-only view (no plaintext, no hash)."""

    id: int
    host_id: int
    mirror_id: int
    mirror_slug: str
    issued_at: datetime
    expires_at: datetime
    last_used_at: Optional[datetime]
    revoked_at: Optional[datetime]
