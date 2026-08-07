"""Pydantic schemas for patch rings (PRA-162 slice 1).

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md``). ``pre=True`` on every int /
nullable-int validator so ``True`` / ``False`` aren't silently
coerced before the bool-as-int guard fires (carry-forward from
PRA-161 slice 1a lock #4).

Slug shape mirrors the PRA-159 / PRA-161 convention so operators
don't have to learn a different rule per surface.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

SLUG_MIN_LEN = 1
SLUG_MAX_LEN = 64
NAME_MAX_LEN = 128
DESCRIPTION_MAX_LEN = 4096
SORT_ORDER_MAX = 10_000  # generous upper bound; rings are typically <10


# ---------------------------------------------------------------------------
# Field validators
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


def _validate_sort_order(v):
    """Reject 0, negatives, bool-as-int, and absurd ordinals."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("sort_order must be an integer >= 1")
    if v < 1:
        raise ValueError("sort_order must be >= 1")
    if v > SORT_ORDER_MAX:
        raise ValueError(f"sort_order exceeds {SORT_ORDER_MAX}")
    return v


def _validate_target_id(v):
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("target id must be an integer")
    if v <= 0:
        raise ValueError("target id must be positive")
    return v


# ---------------------------------------------------------------------------
# Ring CRUD
# ---------------------------------------------------------------------------


class PatchRingCreate(BaseModel):
    slug: str
    name: str
    description: Optional[str] = None
    sort_order: int
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

    @validator("sort_order", pre=True)
    def _sort_order(cls, v):  # pylint: disable=no-self-argument
        return _validate_sort_order(v)


class PatchRingUpdate(BaseModel):
    """All fields optional — partial update. Slug is intentionally
    immutable post-create (mirrors PRA-159 channels and PRA-161
    policies)."""

    name: Optional[str] = None
    description: Optional[str] = None
    sort_order: Optional[int] = None
    enabled: Optional[bool] = None

    @validator("name")
    def _name(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_name(v)

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _validate_description(v)

    @validator("sort_order", pre=True)
    def _sort_order(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_sort_order(v)


class PatchRingRead(BaseModel):
    id: int
    slug: str
    name: str
    description: Optional[str] = None
    sort_order: int
    enabled: bool
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------


class PatchRingHostBindingCreate(BaseModel):
    host_id: int

    @validator("host_id", pre=True)
    def _host_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_target_id(v)


class PatchRingGroupBindingCreate(BaseModel):
    group_id: int

    @validator("group_id", pre=True)
    def _group_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_target_id(v)


class PatchRingSmartGroupBindingCreate(BaseModel):
    smart_group_id: int

    @validator("smart_group_id", pre=True)
    def _smart_group_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_target_id(v)


class PatchRingHostBindingRead(BaseModel):
    id: int
    ring_id: int
    system_id: int
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchRingGroupBindingRead(BaseModel):
    id: int
    ring_id: int
    group_id: int
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchRingSmartGroupBindingRead(BaseModel):
    id: int
    ring_id: int
    smart_group_id: int
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchRingBindingsList(BaseModel):
    """All three binding kinds returned in one envelope so a ring
    detail page renders without three separate calls."""

    ring_id: int
    hosts: List[PatchRingHostBindingRead]
    groups: List[PatchRingGroupBindingRead]
    smart_groups: List[PatchRingSmartGroupBindingRead]


class EffectiveRingRead(BaseModel):
    """Resolver result returned by ``GET /systems/{id}/patch-ring``.

    ``status`` is one of ``"no_ring"`` / ``"resolved"`` / ``"conflict"``.

    ``ring`` is populated when ``status == "resolved"``.
    ``candidates`` is populated when ``status == "conflict"`` and lists
    the distinct enabled rings that collided at ``source_tier`` so an
    operator can fix the duplicate-binding state.

    ``source_tier`` is one of ``"host"`` / ``"group"`` / ``"smart_group"``
    when ``resolved`` or ``conflict``, and ``null`` when ``no_ring``.

    Conflict cases surface here as state, not as HTTP 409, so a single
    payload shape powers both the host-detail card and the operator
    UI's conflict banner without two error paths.
    """

    system_id: int
    status: str
    source_tier: Optional[str] = None
    ring: Optional[PatchRingRead] = None
    candidates: List[PatchRingRead] = []
    message: Optional[str] = None


# ---------------------------------------------------------------------------
# Promotion gate definitions + stored signals (slice 4)
# ---------------------------------------------------------------------------


SIGNAL_KEY_MAX_LEN = 128
SOURCE_REF_KIND_MAX_LEN = 64
SOURCE_REF_ID_MAX_LEN = 128

VALID_GATE_KINDS = {"boolean", "threshold"}
VALID_COMPARATORS = {"eq", "ne", "gt", "gte", "lt", "lte"}
VALID_SIGNAL_STATUSES = {"pass", "fail"}
VALID_SOURCE_KINDS = {"manual", "execution", "reboot", "probe", "external"}


def _validate_signal_key(v):
    if not isinstance(v, str):
        raise ValueError("signal_key must be a string")
    v = v.strip()
    if not v:
        raise ValueError("signal_key is required")
    if len(v) > SIGNAL_KEY_MAX_LEN:
        raise ValueError(f"signal_key exceeds {SIGNAL_KEY_MAX_LEN} characters")
    if v != v.lower():
        raise ValueError("signal_key must be lowercase")
    if not all(c.isalnum() or c in "-_." for c in v):
        raise ValueError(
            "signal_key must contain only [a-z0-9_.-] (lowercase "
            "alphanumeric, hyphen, underscore, dot)"
        )
    return v


def _validate_gate_kind(v):
    if v not in VALID_GATE_KINDS:
        raise ValueError(f"gate_kind must be one of: {sorted(VALID_GATE_KINDS)}")
    return v


def _validate_comparator(v):
    if v is None:
        return None
    if v not in VALID_COMPARATORS:
        raise ValueError(f"comparator must be one of: {sorted(VALID_COMPARATORS)}")
    return v


def _validate_signal_status(v):
    if v not in VALID_SIGNAL_STATUSES:
        raise ValueError(f"status must be one of: {sorted(VALID_SIGNAL_STATUSES)}")
    return v


def _validate_source_kind(v):
    """Public manual-signal API constraint.

    The DB/service vocabulary admits ``manual`` plus the future-writer
    values (``execution``, ``reboot``, ``probe``, ``external``) so
    PRA-171/172 can attach signals via the lower-level
    ``patch_ring_service.record_gate_signal`` without schema churn.
    But the *public* manual-signal endpoint must not let an operator
    impersonate those writers — promotion readiness ignores
    ``source_kind`` for verdict purposes, so a manual call carrying
    ``source_kind=execution`` would silently misrepresent provenance.

    Reject anything other than ``manual`` at the schema layer; the
    service-side vocabulary stays wider for internal callers.
    """
    if v != "manual":
        raise ValueError(
            'source_kind must be "manual" on this endpoint; future '
            "writer kinds (execution / reboot / probe / external) are "
            "reserved for internal service callers"
        )
    return v


class PatchRingGateDefinitionCreate(BaseModel):
    signal_key: str
    name: str
    description: Optional[str] = None
    gate_kind: str
    comparator: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    required: bool = True
    enabled: bool = True

    @validator("signal_key")
    def _signal_key(cls, v):  # pylint: disable=no-self-argument
        return _validate_signal_key(v)

    @validator("name")
    def _name(cls, v):  # pylint: disable=no-self-argument
        return _validate_name(v)

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _validate_description(v)

    @validator("gate_kind")
    def _gate_kind(cls, v):  # pylint: disable=no-self-argument
        return _validate_gate_kind(v)

    @validator("comparator")
    def _comparator(cls, v):  # pylint: disable=no-self-argument
        return _validate_comparator(v)


class PatchRingGateDefinitionUpdate(BaseModel):
    """Partial update. ``signal_key`` is intentionally immutable
    post-create so stored signals don't lose their definition link
    via a key rename (cleaner to delete + recreate). The field is
    declared here only so the service layer can surface a clear
    "immutable" 422 — Pydantic would otherwise silently drop it."""

    signal_key: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    gate_kind: Optional[str] = None
    comparator: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    required: Optional[bool] = None
    enabled: Optional[bool] = None

    @validator("name")
    def _name(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_name(v)

    @validator("description")
    def _description(cls, v):  # pylint: disable=no-self-argument
        return _validate_description(v)

    @validator("gate_kind")
    def _gate_kind(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        return _validate_gate_kind(v)

    @validator("comparator")
    def _comparator(cls, v):  # pylint: disable=no-self-argument
        return _validate_comparator(v)


class PatchRingGateDefinitionRead(BaseModel):
    id: int
    ring_id: int
    signal_key: str
    name: str
    description: Optional[str] = None
    gate_kind: str
    comparator: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    required: bool
    enabled: bool
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchRingGateSignalCreate(BaseModel):
    signal_key: str
    status: str
    value: Optional[Any] = None
    details: Optional[Dict[str, Any]] = None
    source_kind: str = "manual"
    source_ref_kind: Optional[str] = None
    source_ref_id: Optional[str] = None
    observed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    @validator("signal_key")
    def _signal_key(cls, v):  # pylint: disable=no-self-argument
        return _validate_signal_key(v)

    @validator("status")
    def _status(cls, v):  # pylint: disable=no-self-argument
        return _validate_signal_status(v)

    @validator("source_kind")
    def _source_kind(cls, v):  # pylint: disable=no-self-argument
        return _validate_source_kind(v)

    @validator("source_ref_kind")
    def _source_ref_kind(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("source_ref_kind must be a string")
        if len(v) > SOURCE_REF_KIND_MAX_LEN:
            raise ValueError(
                f"source_ref_kind exceeds {SOURCE_REF_KIND_MAX_LEN} characters"
            )
        return v

    @validator("source_ref_id")
    def _source_ref_id(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("source_ref_id must be a string")
        if len(v) > SOURCE_REF_ID_MAX_LEN:
            raise ValueError(
                f"source_ref_id exceeds {SOURCE_REF_ID_MAX_LEN} characters"
            )
        return v


class PatchRingGateSignalRead(BaseModel):
    id: int
    ring_id: int
    gate_definition_id: Optional[int] = None
    signal_key: str
    status: str
    value: Optional[Any] = None
    details: Optional[Dict[str, Any]] = None
    source_kind: str
    source_ref_kind: Optional[str] = None
    source_ref_id: Optional[str] = None
    observed_at: datetime
    expires_at: Optional[datetime] = None
    created_by: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchRingPromotionGateDetail(BaseModel):
    """Per-gate breakdown returned in the promotion-readiness verdict.

    ``gate_status`` ∈ ``{satisfied, failing, missing, expired,
    disabled, ignored_optional}``. ``signal`` is populated when a
    signal exists (even if expired or stale); ``signal`` is null
    for missing or no-signal states."""

    gate_id: int
    signal_key: str
    name: str
    gate_kind: str
    required: bool
    enabled: bool
    gate_status: str
    message: Optional[str] = None
    signal: Optional[PatchRingGateSignalRead] = None


class PatchRingPromotionReadiness(BaseModel):
    """Verdict on whether a ring is ready to promote.

    ``status`` ∈ ``{ring_disabled, blocked, missing_signal, no_gates,
    ready}``. ``gates`` lists per-gate detail in stable
    ``signal_key`` order so an operator can scan the missing/failing
    rows immediately. Optional gates are reported in ``gates`` but
    do not contribute to ``status`` (only required enabled gates
    drive the verdict)."""

    ring_id: int
    ring_slug: str
    ring_enabled: bool
    status: str
    message: Optional[str] = None
    required_gate_count: int
    enabled_gate_count: int
    gates: List[PatchRingPromotionGateDetail]


class PatchRingSeedDefaultsResult(BaseModel):
    """Summary returned by the canary→pilot→prod seed helper.

    ``created`` lists the slugs newly created during this call;
    ``existing`` lists the slugs that were already present (idempotent
    no-op). The full ring set is returned in ``rings`` so the caller
    can react to the locked sort_order vocabulary without a follow-up
    list call.
    """

    created: List[str]
    existing: List[str]
    rings: List[PatchRingRead]
