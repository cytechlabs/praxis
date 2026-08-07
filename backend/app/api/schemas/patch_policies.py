"""Pydantic schemas for patch policies (PRA-161 slice 1b).

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md`` — using ``@classmethod`` here
silently disables the validator).

Slug shape mirrors the PRA-159 channel/profile validator (lowercase
alphanumeric + ``-`` / ``_``, length 1..64) so operators don't have
to learn a different rule per surface.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, validator

SLUG_MIN_LEN = 1
SLUG_MAX_LEN = 64
NAME_MAX_LEN = 128
DESCRIPTION_MAX_LEN = 4096
PACKAGE_NAME_MAX_LEN = 255
SCOPE_PACKAGES_MAX = 1024  # generous upper bound; allow/deny lists rarely large
REQUIRED_APPROVALS_MAX = 32

VALID_SCOPE_KINDS = {
    "security_only",
    "full",
    "package_allowlist",
    "package_denylist",
}
VALID_REBOOT_POLICIES = {"never", "if_required", "always"}
VALID_ROLLOUT_CADENCES = {"immediate", "staged"}
VALID_FAILURE_POLICIES = {"continue", "pause_fleet"}


# ---------------------------------------------------------------------------
# Field validators — module-level helpers so Create / Update share them
# ---------------------------------------------------------------------------


def _validate_slug(v):
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


def _validate_name(v):
    if not isinstance(v, str) or not v.strip():
        raise ValueError("name is required")
    if len(v) > NAME_MAX_LEN:
        raise ValueError(f"name exceeds {NAME_MAX_LEN} characters")
    return v.strip()


def _validate_description(v):
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError("description must be a string")
    if len(v) > DESCRIPTION_MAX_LEN:
        raise ValueError(f"description exceeds {DESCRIPTION_MAX_LEN} characters")
    return v


def _validate_scope_kind(v):
    if v not in VALID_SCOPE_KINDS:
        raise ValueError(f"scope_kind must be one of: {sorted(VALID_SCOPE_KINDS)}")
    return v


def _validate_scope_packages(v):
    """List of distinct package-name strings.

    Empty list is the only legal value when ``scope_kind`` is
    ``security_only`` or ``full``; the cross-field check lives in
    the model validator below.
    """
    if v is None:
        return []
    if not isinstance(v, list):
        raise ValueError("scope_packages must be a list of strings")
    if len(v) > SCOPE_PACKAGES_MAX:
        raise ValueError(f"scope_packages exceeds {SCOPE_PACKAGES_MAX} entries")
    cleaned: List[str] = []
    seen = set()
    for entry in v:
        if not isinstance(entry, str):
            raise ValueError("scope_packages entries must be strings")
        s = entry.strip()
        if not s:
            raise ValueError("scope_packages entries must be non-empty strings")
        if len(s) > PACKAGE_NAME_MAX_LEN:
            raise ValueError(f"package name exceeds {PACKAGE_NAME_MAX_LEN} characters")
        if s in seen:
            raise ValueError(f"duplicate package in scope_packages: {s!r}")
        seen.add(s)
        cleaned.append(s)
    return cleaned


def _validate_reboot_policy(v):
    if v not in VALID_REBOOT_POLICIES:
        raise ValueError(
            f"reboot_policy must be one of: {sorted(VALID_REBOOT_POLICIES)}"
        )
    return v


def _validate_rollout_cadence(v):
    if v not in VALID_ROLLOUT_CADENCES:
        raise ValueError(
            f"rollout_cadence must be one of: {sorted(VALID_ROLLOUT_CADENCES)}"
        )
    return v


def _validate_failure_policy(v):
    if v not in VALID_FAILURE_POLICIES:
        raise ValueError(
            f"failure_policy must be one of: {sorted(VALID_FAILURE_POLICIES)}"
        )
    return v


def _validate_required_approvals(v):
    """Reject 0, negatives, bool-as-int (PRA-161 slice 1a lock #4)."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("required_approvals must be an integer >= 1")
    if v < 1:
        raise ValueError("required_approvals must be >= 1")
    if v > REQUIRED_APPROVALS_MAX:
        raise ValueError(f"required_approvals exceeds {REQUIRED_APPROVALS_MAX}")
    return v


def _validate_optional_window_id(v):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("maintenance/reboot window id must be an integer or null")
    if v <= 0:
        raise ValueError("maintenance/reboot window id must be positive")
    return v


# ---------------------------------------------------------------------------
# Create / Update / Read
# ---------------------------------------------------------------------------


class PatchPolicyCreate(BaseModel):
    slug: str
    name: str
    description: Optional[str] = None
    scope_kind: str
    scope_packages: Optional[List[str]] = None
    reboot_policy: str = "if_required"
    reboot_window_id: Optional[int] = None
    maintenance_window_id: Optional[int] = None
    requires_approval: bool = False
    required_approvals: int = 1
    rollout_cadence: str = "immediate"
    failure_policy: str = "pause_fleet"
    enabled: bool = True

    @validator("slug")
    def _slug(cls, v):  # pylint: disable=no-self-argument
        return _validate_slug(v)

    @validator("name")
    def _name(cls, v):  # pylint: disable=no-self-argument
        return _validate_name(v)

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _validate_description(v)

    @validator("scope_kind")
    def _scope_kind(cls, v):  # pylint: disable=no-self-argument
        return _validate_scope_kind(v)

    @validator("scope_packages", always=True)
    def _scope_packages(cls, v, values):  # pylint: disable=no-self-argument
        cleaned = _validate_scope_packages(v)
        scope_kind = values.get("scope_kind")
        if scope_kind in {"security_only", "full"} and cleaned:
            raise ValueError(
                f"scope_packages must be empty when scope_kind={scope_kind!r}"
            )
        if scope_kind in {"package_allowlist", "package_denylist"} and not cleaned:
            raise ValueError(
                f"scope_packages must be non-empty when scope_kind={scope_kind!r}"
            )
        return cleaned

    @validator("reboot_policy")
    def _reboot_policy(cls, v):  # pylint: disable=no-self-argument
        return _validate_reboot_policy(v)

    @validator("reboot_window_id", pre=True)
    def _reboot_window_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_window_id(v)

    @validator("maintenance_window_id", pre=True)
    def _maintenance_window_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_window_id(v)

    # ``pre=True`` is critical: ``int`` field types coerce ``True`` to 1
    # before the validator runs (PRA-161 slice 1a lock #4 — bool-as-int).
    @validator("required_approvals", pre=True)
    def _required_approvals(cls, v):  # pylint: disable=no-self-argument
        return _validate_required_approvals(v)

    @validator("rollout_cadence")
    def _rollout_cadence(cls, v):  # pylint: disable=no-self-argument
        return _validate_rollout_cadence(v)

    @validator("failure_policy")
    def _failure_policy(cls, v):  # pylint: disable=no-self-argument
        return _validate_failure_policy(v)


class PatchPolicyUpdate(BaseModel):
    """All fields optional — partial update. Slug is intentionally
    immutable post-create (mirrors PRA-159 channels)."""

    name: Optional[str] = None
    description: Optional[str] = None
    scope_kind: Optional[str] = None
    scope_packages: Optional[List[str]] = None
    reboot_policy: Optional[str] = None
    reboot_window_id: Optional[int] = None
    maintenance_window_id: Optional[int] = None
    requires_approval: Optional[bool] = None
    required_approvals: Optional[int] = None
    rollout_cadence: Optional[str] = None
    failure_policy: Optional[str] = None
    enabled: Optional[bool] = None

    @validator("name")
    def _name(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_name(v)

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _validate_description(v)

    @validator("scope_kind")
    def _scope_kind(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_scope_kind(v)

    @validator("scope_packages")
    def _scope_packages(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_scope_packages(v)

    @validator("reboot_policy")
    def _reboot_policy(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_reboot_policy(v)

    @validator("reboot_window_id", pre=True)
    def _reboot_window_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_window_id(v)

    @validator("maintenance_window_id", pre=True)
    def _maintenance_window_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_window_id(v)

    # ``pre=True`` so True/False are not silently coerced to 1/0.
    @validator("required_approvals", pre=True)
    def _required_approvals(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_required_approvals(v)

    @validator("rollout_cadence")
    def _rollout_cadence(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_rollout_cadence(v)

    @validator("failure_policy")
    def _failure_policy(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_failure_policy(v)


class PatchPolicyRead(BaseModel):
    id: int
    slug: str
    name: str
    description: Optional[str] = None
    scope_kind: str
    scope_packages: List[str]
    reboot_policy: str
    reboot_window_id: Optional[int] = None
    maintenance_window_id: Optional[int] = None
    requires_approval: bool
    required_approvals: int
    rollout_cadence: str
    failure_policy: str
    enabled: bool
    is_fleet_default: bool = False
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class EffectivePolicyRead(BaseModel):
    """Resolver result returned by ``GET /systems/{id}/patch-policy/effective``.

    ``policy`` is null and ``resolution_kind`` is ``"no_policy"`` when no
    binding tier matches and there is no enabled fleet default.
    Conflict cases never produce this payload — they surface as HTTP 409
    with a structured ``detail``.
    """

    system_id: int
    resolution_kind: str
    policy: Optional[PatchPolicyRead] = None


# ---------------------------------------------------------------------------
# Bindings (slice 1c)
# ---------------------------------------------------------------------------


def _validate_target_id(v):
    """Reject 0, negatives, and bool-as-int for target FKs (host_id /
    group_id / smart_group_id). ``pre=True`` on the validators below
    so True/False are not coerced to 1/0 by Pydantic V1."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("target id must be an integer")
    if v <= 0:
        raise ValueError("target id must be positive")
    return v


class PatchPolicyHostBindingCreate(BaseModel):
    host_id: int

    @validator("host_id", pre=True)
    def _host_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_target_id(v)


class PatchPolicyGroupBindingCreate(BaseModel):
    group_id: int

    @validator("group_id", pre=True)
    def _group_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_target_id(v)


class PatchPolicySmartGroupBindingCreate(BaseModel):
    smart_group_id: int

    @validator("smart_group_id", pre=True)
    def _smart_group_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_target_id(v)


class PatchPolicyHostBindingRead(BaseModel):
    id: int
    policy_id: int
    system_id: int
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchPolicyGroupBindingRead(BaseModel):
    id: int
    policy_id: int
    group_id: int
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchPolicySmartGroupBindingRead(BaseModel):
    id: int
    policy_id: int
    smart_group_id: int
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchPolicyBindingsList(BaseModel):
    """All three binding kinds returned in one envelope, so the UI
    can render a policy detail page without three separate calls."""

    policy_id: int
    hosts: List[PatchPolicyHostBindingRead]
    groups: List[PatchPolicyGroupBindingRead]
    smart_groups: List[PatchPolicySmartGroupBindingRead]


# ---------------------------------------------------------------------------
# Policy → ring-set binding + staged readiness (slice 3)
# ---------------------------------------------------------------------------


class PatchPolicyRingBindingCreate(BaseModel):
    ring_id: int

    @validator("ring_id", pre=True)
    def _ring_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_target_id(v)


class PatchPolicyRingBindingRead(BaseModel):
    """One row of a policy's bound ring set, inlined with enough ring
    metadata that an operator can spot stale or disabled bindings
    without a follow-up call."""

    id: int
    policy_id: int
    ring_id: int
    ring_slug: str
    ring_name: str
    ring_sort_order: int
    ring_enabled: bool
    created_by: int
    created_at: datetime
    updated_at: datetime


class PatchPolicyRingSetList(BaseModel):
    policy_id: int
    rings: List[PatchPolicyRingBindingRead]


class PatchPolicyStagedReadiness(BaseModel):
    """Verdict on whether a staged patch policy is operationally usable.

    ``status`` is one of ``"not_staged"`` / ``"ready"`` /
    ``"missing_ring_set"`` / ``"no_enabled_rings"``. ``message`` is
    populated for non-ready states with operator-actionable text.
    """

    policy_id: int
    policy_slug: str
    rollout_cadence: str
    enabled: bool
    status: str
    ring_count: int
    enabled_ring_count: int
    message: Optional[str] = None
