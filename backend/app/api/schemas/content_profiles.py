"""Pydantic schemas for content profiles + subscriptions (PRA-159 #1).

Profiles are the host-facing object. Hosts (or groups, or smart
groups) subscribe to a profile; ``ContentProfileService.resolve_effective``
walks the three subscription tables with strict precedence
(direct > static-group > smart-group) and returns one of
``no_profile | resolved | conflict``.

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md``).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, validator

from .content_channels import (
    DESCRIPTION_MAX_LEN,
    DISPLAY_NAME_MAX_LEN,
    SLUG_MAX_LEN,
    SLUG_MIN_LEN,
    VALID_PACKAGE_FAMILIES,
)


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


def _validate_positive_int(v, field: str):
    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return v


# ---------------------------------------------------------------------------
# Profile CRUD
# ---------------------------------------------------------------------------


class ContentProfileCreate(BaseModel):
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


class ContentProfileUpdate(BaseModel):
    """Partial update. ``slug`` and ``package_family`` immutable."""

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


class ChannelLinkRead(BaseModel):
    """Slim channel reference inside a profile read shape."""

    id: int
    channel_id: int
    channel_slug: str
    channel_display_name: str


class ContentProfileRead(BaseModel):
    id: int
    slug: str
    display_name: str
    package_family: str
    description: Optional[str]
    deleted_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    channels: List[ChannelLinkRead]


# ---------------------------------------------------------------------------
# Profile↔channel sub-resource
# ---------------------------------------------------------------------------


class ProfileChannelAdd(BaseModel):
    channel_id: int

    @validator("channel_id")
    def _channel_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_int(v, "channel_id")


# ---------------------------------------------------------------------------
# Subscription sub-resources (one shape per scope)
# ---------------------------------------------------------------------------


class ProfileHostSubscriptionAdd(BaseModel):
    host_id: int

    @validator("host_id")
    def _host_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_int(v, "host_id")


class ProfileGroupSubscriptionAdd(BaseModel):
    group_id: int

    @validator("group_id")
    def _group_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_int(v, "group_id")


class ProfileSmartGroupSubscriptionAdd(BaseModel):
    smart_group_id: int

    @validator("smart_group_id")
    def _smart_group_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_int(v, "smart_group_id")


class SubscriptionRead(BaseModel):
    """Shape returned from any of the three subscription read paths."""

    id: int
    profile_id: int
    scope_kind: Literal["host", "group", "smart_group"]
    scope_id: int
    scope_label: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Effective-profile resolution shape
# ---------------------------------------------------------------------------


class EffectiveProfileBindingRead(BaseModel):
    """One subscription that contributed to (or conflicted at) the
    effective profile resolution."""

    profile_id: int
    profile_slug: str
    profile_display_name: str
    via_kind: Literal["direct", "group", "smart_group"]
    via_id: Optional[int]
    via_label: Optional[str]


class ProfileSubscriberRead(BaseModel):
    """One host whose effective profile resolution lands on this
    profile (PRA-159 #5).

    Used by the profile detail UI's "Subscribers" tab. ``via_kind``
    + ``via_id`` + ``via_label`` describe how the host arrived at
    this profile (parallel to ``EffectiveProfileBindingRead``)."""

    host_id: int
    hostname: str
    via_kind: Literal["direct", "group", "smart_group"]
    via_id: Optional[int]
    via_label: Optional[str]


class EffectiveProfileRead(BaseModel):
    """Three-state result of ``ContentProfileService.resolve_effective``.

    ``state``:
      * ``no_profile`` — host has no subscription at any tier.
      * ``resolved`` — exactly one profile wins at the highest
        non-empty tier; ``profile`` is set, ``conflict_bindings``
        is empty.
      * ``conflict`` — multiple distinct profiles tied at the highest
        non-empty tier; ``profile`` is null, ``conflict_bindings``
        lists each contributor for operator triage. Apply MUST refuse
        in this state.

    Lower-tier subscriptions never appear in ``conflict_bindings``
    when a higher tier is present (precedence is strict; lower tiers
    are simply ignored once a higher one matches).
    """

    state: Literal["no_profile", "resolved", "conflict"]
    profile: Optional[EffectiveProfileBindingRead]
    conflict_bindings: List[EffectiveProfileBindingRead]
