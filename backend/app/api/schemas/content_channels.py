"""Pydantic schemas for content channels (PRA-159 slice #1).

Channels are pure content composition — a channel bundles N mirrors
of one ``package_family``. Hosts subscribe to ``ContentProfile`` rows,
not channels directly. See ``content_profiles.py`` for the
host-facing layer.

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md``).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, validator

VALID_PACKAGE_FAMILIES = {"deb", "rpm"}

SLUG_MAX_LEN = 64
SLUG_MIN_LEN = 1
DISPLAY_NAME_MAX_LEN = 128
DESCRIPTION_MAX_LEN = 4096
SUITE_MAX_LEN = 64


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


def _validate_display_name(v) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError("display_name is required")
    if len(v) > DISPLAY_NAME_MAX_LEN:
        raise ValueError(f"display_name exceeds {DISPLAY_NAME_MAX_LEN} characters")
    return v.strip()


def _validate_package_family(v: str) -> str:
    if v not in VALID_PACKAGE_FAMILIES:
        raise ValueError(
            f"package_family must be one of: {sorted(VALID_PACKAGE_FAMILIES)}"
        )
    return v


def _validate_description(v):
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError("description must be a string")
    if len(v) > DESCRIPTION_MAX_LEN:
        raise ValueError(f"description exceeds {DESCRIPTION_MAX_LEN} characters")
    return v


def _validate_suite_override(v):
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError("suite_override must be a string")
    v = v.strip()
    if not v:
        # Treat empty string as inherit (NULL); reject explicit empties so
        # the API contract stays "omit OR null OR concrete suite" instead
        # of an undefined "is empty string the same as NULL?" branch.
        raise ValueError("suite_override must be non-empty (omit to inherit)")
    if len(v) > SUITE_MAX_LEN:
        raise ValueError(f"suite_override exceeds {SUITE_MAX_LEN} characters")
    return v


# ---------------------------------------------------------------------------
# Channel CRUD
# ---------------------------------------------------------------------------


class ContentChannelCreate(BaseModel):
    slug: str
    display_name: str
    package_family: str
    description: Optional[str] = None

    @validator("slug")
    def _slug(cls, v):  # pylint: disable=no-self-argument
        return _validate_slug(v)

    @validator("display_name")
    def _display_name(cls, v):  # pylint: disable=no-self-argument
        return _validate_display_name(v)

    @validator("package_family")
    def _package_family(cls, v):  # pylint: disable=no-self-argument
        return _validate_package_family(v)

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _validate_description(v)


class ContentChannelUpdate(BaseModel):
    """Partial update. ``slug`` and ``package_family`` are immutable.

    ``package_family`` is immutable because it shifts the legality of
    every linked ``ContentChannelRepo`` (mirror would no longer match
    the channel) and every parent ``ContentProfile`` (channel would
    no longer match the profile family). Operators wanting a different
    family should create a new channel.
    """

    display_name: Optional[str] = None
    description: Optional[str] = None

    @validator("display_name")
    def _display_name(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        return _validate_display_name(v)

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _validate_description(v)


class ContentChannelRepoRead(BaseModel):
    id: int
    channel_id: int
    mirror_id: int
    mirror_slug: str
    suite_override: Optional[str]
    effective_suite: str
    pinned_run_id: Optional[int]
    pinned_manifest_sha256: Optional[str]
    created_at: datetime
    updated_at: datetime


class ContentChannelRead(BaseModel):
    id: int
    slug: str
    display_name: str
    package_family: str
    description: Optional[str]
    deleted_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    repos: List[ContentChannelRepoRead]


# ---------------------------------------------------------------------------
# Channel↔repo sub-resource
# ---------------------------------------------------------------------------


class ContentChannelRepoAdd(BaseModel):
    """Add a mirror entry to a channel.

    ``suite_override`` may be omitted (inherit the mirror's
    ``distribution``) OR set to a concrete suite (compose multi-suite
    channels of one upstream).

    ``pinned_run_id`` may be omitted (track-live default) OR set to
    a ``mirror_sync_runs.id`` belonging to the same mirror with
    ``status='ok'``. Pin is metadata-only — see
    ``ContentChannelRepo`` docstring.
    """

    mirror_id: int
    suite_override: Optional[str] = None
    pinned_run_id: Optional[int] = None

    @validator("suite_override")
    def _suite_override(cls, v):  # pylint: disable=no-self-argument
        return _validate_suite_override(v)

    @validator("mirror_id")
    def _mirror_id(cls, v):  # pylint: disable=no-self-argument
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise ValueError("mirror_id must be a positive integer")
        return v

    @validator("pinned_run_id")
    def _pinned_run_id(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise ValueError("pinned_run_id must be a positive integer")
        return v


class ContentChannelRepoPinUpdate(BaseModel):
    """Repin (or unpin) a single channel-repo entry.

    ``pinned_run_id=null`` clears the pin (track-live).
    """

    pinned_run_id: Optional[int]

    @validator("pinned_run_id")
    def _pinned_run_id(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise ValueError("pinned_run_id must be a positive integer")
        return v
