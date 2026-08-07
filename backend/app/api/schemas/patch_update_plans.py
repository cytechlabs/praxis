"""Pydantic schemas for patch update plans (PRA-164 slice 1).

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md`` — using ``@classmethod`` here
silently disables the validator).

Slice 1 ships the dry-run substrate only. No package selection,
preflight, approval request, or execution fields land here yet.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

NAME_MAX_LEN = 128
DESCRIPTION_MAX_LEN = 4096
TARGET_HOSTS_MAX = 10000


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


def _validate_positive_id(v):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("id must be an integer or null")
    if v <= 0:
        raise ValueError("id must be positive")
    return v


def _validate_required_positive_id(v):
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("id must be an integer")
    if v <= 0:
        raise ValueError("id must be positive")
    return v


def _validate_target_system_ids(v):
    """Allow ``None`` (auto-discover) or a list of distinct positive ints.

    Empty list is allowed by Pydantic but the service treats it as
    "auto-discover" semantically — keep the route surface honest by
    rejecting it here so operators see the difference between
    "auto-select" (omit field) and "explicitly empty" (mistake)."""
    if v is None:
        return None
    if not isinstance(v, list):
        raise ValueError("target_system_ids must be a list of positive integers")
    if not v:
        raise ValueError(
            "target_system_ids cannot be an explicitly empty list; omit "
            "the field to auto-discover hosts whose effective policy "
            "resolves to the requested policy"
        )
    if len(v) > TARGET_HOSTS_MAX:
        raise ValueError(f"target_system_ids exceeds {TARGET_HOSTS_MAX} entries")
    cleaned: List[int] = []
    seen: set[int] = set()
    for entry in v:
        if isinstance(entry, bool) or not isinstance(entry, int):
            raise ValueError("target_system_ids entries must be integers (no bools)")
        if entry <= 0:
            raise ValueError("target_system_ids entries must be positive")
        if entry in seen:
            raise ValueError(f"duplicate target_system_id: {entry}")
        seen.add(entry)
        cleaned.append(entry)
    return cleaned


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


class PatchUpdatePlanCreate(BaseModel):
    """Body for ``POST /patch/update-plans/dry-run``.

    The endpoint is dry-run by intent — the result is a plan
    artifact that is NOT permission to execute. Approval, scheduling,
    and execution are explicit later actions owned by later slices /
    PRAs.
    """

    policy_id: int
    name: str
    description: Optional[str] = None
    target_system_ids: Optional[List[int]] = None
    scheduled_start_at: Optional[datetime] = None
    maintenance_window_id: Optional[int] = None
    reboot_window_id: Optional[int] = None

    @validator("policy_id", pre=True)
    def _policy_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_required_positive_id(v)

    @validator("name")
    def _name(cls, v):  # pylint: disable=no-self-argument
        return _validate_name(v)

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _validate_description(v)

    # ``pre=True`` is critical: ``List[int]`` field types coerce
    # ``True`` -> 1 and ``"5"`` -> 5 *before* the validator runs,
    # which would silently let bool/string entries become audited
    # host ids (Slice 1a fix). Same pattern as the
    # patch_policies bool-as-int trap on ``required_approvals``.
    @validator("target_system_ids", pre=True)
    def _target_system_ids(cls, v):  # pylint: disable=no-self-argument
        return _validate_target_system_ids(v)

    @validator("maintenance_window_id", pre=True)
    def _maintenance_window_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_id(v)

    @validator("reboot_window_id", pre=True)
    def _reboot_window_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_id(v)


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


class PatchUpdatePlanHostRead(BaseModel):
    """Per-host plan row.

    ``state`` is ``planned`` or ``blocked``. ``block_reasons`` is the
    structured list (``[{"code", "details": {...}}]``) the slice 4 UI
    will render. Snapshot columns preserve audit context even after
    later policy / ring / system / profile changes.
    """

    id: int
    plan_id: int
    system_id: Optional[int]
    system_hostname_snapshot: Optional[str]
    policy_id_snapshot: Optional[int]
    policy_slug_snapshot: Optional[str]
    policy_resolution_kind: str
    ring_id_snapshot: Optional[int]
    ring_slug_snapshot: Optional[str]
    ring_name_snapshot: Optional[str]
    ring_sort_order_snapshot: Optional[int]
    ring_source_tier: Optional[str]
    ring_resolution_status: str
    wave_index: int
    content_profile_state: str
    content_profile_id_snapshot: Optional[int]
    content_profile_slug_snapshot: Optional[str]
    content_profile_display_name_snapshot: Optional[str]
    content_profile_package_family_snapshot: Optional[str]
    content_profile_conflict_snapshot: List[Dict[str, Any]] = []
    state: str
    block_reasons: List[Dict[str, Any]] = []
    # Slice 2: per-host count rollup of selection-preview rows.
    # Null for ``blocked`` hosts (selection skipped) and for any
    # host whose system was deleted between create-time and
    # selection (skip-with-null).
    selection_summary: Optional[Dict[str, Any]] = None
    # Slice 3: per-host count rollup of preflight snapshot rows
    # (counts by content_availability_state + installed_drift_count).
    # Null for blocked hosts, hosts whose system was deleted before
    # preflight, and hosts whose Slice 2 selection produced zero rows.
    preflight_summary: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchUpdatePlanPreflightSnapshotRead(BaseModel):
    """One preflight snapshot row (PRA-164 slice 3).

    ``content_availability_state`` is one of ``available`` /
    ``unavailable`` / ``profile_missing`` / ``not_applicable``.
    ``package_manager_family_snapshot`` is one of ``apt`` / ``dnf``
    / ``unknown``. ``installed_version_at_preflight`` is null when
    the package isn't installed at preflight time.
    """

    id: int
    plan_host_id: int
    package_name: str
    installed_version_at_preflight: Optional[str]
    package_manager_family_snapshot: str
    content_availability_state: str
    availability_details: Dict[str, Any] = {}
    evaluated_at: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchUpdatePlanSelectedPackageRead(BaseModel):
    """One selection-preview row (PRA-164 slice 2).

    ``state`` is one of ``selected`` / ``excluded`` /
    ``unresolvable``. ``selection_reason`` follows the seven-value
    enum (six baseline values plus
    ``policy_denylist_default_select`` for non-denylisted packages
    in a ``package_denylist`` plan).
    ``package_name == ""`` is the inventory-missing placeholder
    sentinel.
    """

    id: int
    plan_host_id: int
    package_name: str
    installed_version_snapshot: Optional[str]
    available_version_snapshot: Optional[str]
    advisory_id_snapshot: Optional[int]
    advisory_source_kind_snapshot: Optional[str]
    advisory_class_snapshot: Optional[str]
    advisory_severity_snapshot: Optional[str]
    selection_reason: str
    state: str
    details: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchUpdatePlanRead(BaseModel):
    id: int
    # PRA-355: nullable — an admin deleting a policy whose only remaining links
    # are archived plans detaches those plans (policy_id → NULL); the plan's
    # policy_snapshot preserves the policy identity for the tombstone.
    policy_id: Optional[int]
    name: str
    description: Optional[str]
    state: str
    scheduled_start_at: Optional[datetime]
    maintenance_window_id: Optional[int]
    reboot_window_id: Optional[int]
    policy_snapshot: Dict[str, Any] = {}
    ring_sequence_snapshot: List[Dict[str, Any]] = []
    request_snapshot: Dict[str, Any] = {}
    block_reasons: List[Dict[str, Any]] = []
    created_by: int
    # PRA-355 archive/retire tombstone fields. archived_at != null means the
    # plan is retired (hidden from normal lists, evidence preserved).
    archived_at: Optional[datetime] = None
    archived_by: Optional[int] = None
    archive_reason: Optional[str] = None
    # PRA-355: backend-authoritative cleanup affordances so the UI renders
    # Delete vs Archive from truth, not from ``state`` alone (a blocked plan
    # with approval history is NOT hard-deletable but IS archivable).
    has_lifecycle_history: bool = False
    can_hard_delete: bool = False
    can_archive: bool = False
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchUpdatePlanDetail(PatchUpdatePlanRead):
    """Full plan envelope including host rows. Returned by the
    create / refresh / get-by-id endpoints so a single round-trip
    surfaces the whole audit artifact."""

    hosts: List[PatchUpdatePlanHostRead] = []
    # Slice 4: most recent approval status (link_id + approval_id +
    # requested_by/at + patch_approval_service status snapshot) so the
    # operator UI can render approve/reject controls without a follow-up
    # round trip. Null when no approval has ever been requested for the
    # plan (policy.requires_approval=False or operator hasn't asked yet).
    approval: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Slice 4: approval / schedule / supersede request bodies
# ---------------------------------------------------------------------------


def _validate_optional_comment(v):
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError("comment must be a string")
    if len(v) > DESCRIPTION_MAX_LEN:
        raise ValueError(f"comment exceeds {DESCRIPTION_MAX_LEN} characters")
    return v


class PatchUpdatePlanApprovalRequest(BaseModel):
    """Body for ``POST /patch/update-plans/{plan_id}/approval/request``."""

    expires_at: Optional[datetime] = None
    comment: Optional[str] = None

    @validator("comment")
    def _comment(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_comment(v)


class PatchUpdatePlanApprovalDecision(BaseModel):
    """Body for the direct-approve / vote-approve / vote-reject routes.
    The same shape covers all three so the route layer can disambiguate
    by URL + plan state."""

    comment: Optional[str] = None

    @validator("comment")
    def _comment(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_comment(v)


class PatchUpdatePlanScheduleRequest(BaseModel):
    """Body for ``POST /patch/update-plans/{plan_id}/schedule``."""

    scheduled_start_at: datetime
    maintenance_window_id: Optional[int] = None
    reboot_window_id: Optional[int] = None

    @validator("maintenance_window_id", pre=True)
    def _maintenance_window_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_id(v)

    @validator("reboot_window_id", pre=True)
    def _reboot_window_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_positive_id(v)


class PatchUpdatePlanSupersedeRequest(BaseModel):
    """Body for ``POST /patch/update-plans/{plan_id}/supersede``.
    Slice 4 supersede is explicit-only (operator action); never
    auto-fires on newer-plan approval — a deliberate product
    decision."""

    comment: Optional[str] = None

    @validator("comment")
    def _comment(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_comment(v)


class PatchUpdatePlanArchiveRequest(BaseModel):
    """Body for ``POST /patch/update-plans/{plan_id}/archive`` (PRA-355).

    Admin-only evidence-preserving retire. ``reason`` (aliased ``comment``
    accepted for symmetry with the other lifecycle bodies) is optional and
    recorded on the tombstone."""

    reason: Optional[str] = None

    @validator("reason", pre=True)
    def _reason(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_comment(v)
