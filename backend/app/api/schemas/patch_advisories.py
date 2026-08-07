"""Pydantic schemas for patch advisories (PRA-163 slice 4).

Pydantic V1 syntax (``orm_mode = True``; ``@validator`` without
``@classmethod`` per ``feedback_pydantic_validators.md``).

Read-only schemas — the only mutation surface in this slice is the
operator-triggered host applicability recompute, which takes no
body and returns an :class:`ApplicabilityResultRead`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

# ---------------------------------------------------------------------------
# Core advisory + fixed-package shapes
# ---------------------------------------------------------------------------


class PatchAdvisoryFixedPackageRead(BaseModel):
    """One per-(distro_id, distro_release, package_name) target row
    on a :class:`PatchAdvisory`. ``fixed_version`` is nullable for
    advisories with no published fix.
    """

    id: int
    advisory_id: int
    distro_id: str
    distro_release: str
    package_name: str
    fixed_version: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchAdvisoryRead(BaseModel):
    """Native distribution advisory row.

    ``raw`` carries the original source payload (JSONB) for forensic
    inspection from the detail page; UI list rows omit it via
    ``response_model_exclude``. ``digest`` is the sha256 of the
    canonical-JSON ``raw`` payload — operators rarely look at it but
    it's the no-op-refresh contract from Slice 1.
    """

    id: int
    source_kind: str
    source_advisory_id: str
    advisory_class: str
    severity: str
    title: str
    summary: Optional[str] = None
    distro_family: str
    published_at: Optional[datetime] = None
    source_updated_at: Optional[datetime] = None
    cve_ids: Optional[List[str]] = None
    external_refs: Optional[List[str]] = None
    raw: Optional[Dict[str, Any]] = None
    digest: str
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchAdvisoryDetailRead(PatchAdvisoryRead):
    """Detail-page shape: the advisory plus its fixed-package targets."""

    fixed_packages: List[PatchAdvisoryFixedPackageRead] = []


# ---------------------------------------------------------------------------
# Per-host applicability shapes
# ---------------------------------------------------------------------------


class HostAdvisoryRowRead(BaseModel):
    """One per-(host, advisory, package_name) applicability row joined
    with its source advisory metadata so the per-host card renders
    without a second request.
    """

    id: int
    system_id: int
    advisory_id: int
    fixed_package_id: Optional[int] = None
    package_name: str
    installed_version: Optional[str] = None
    required_version: Optional[str] = None
    state: str
    reason: Optional[str] = None
    evaluated_at: datetime
    advisory: PatchAdvisoryRead

    class Config:
        orm_mode = True


class HostAdvisoryCountsRead(BaseModel):
    """Always returns all four state keys (zero-default per Slice 2
    ``count_host_advisories_by_state`` contract).

    ``host_facts_missing`` (Slice 4-a) is true iff the host has no
    usable ``HostFacts.distro_id_facts`` / ``HostFacts.distro_release``
    — the same predicate the Slice 2 resolver uses to short-circuit
    applicability computation. The per-host card consumes this on
    initial load so the facts-missing callout renders without
    requiring an operator-triggered recompute first.
    """

    system_id: int
    counts: Dict[str, int]
    host_facts_missing: bool


# ---------------------------------------------------------------------------
# Fleet roll-up shape
# ---------------------------------------------------------------------------


class FleetAdvisoryCountsRead(BaseModel):
    """Counts of fleet-wide ``state='applicable'`` advisory rows.

    Always returns one entry per locked severity AND one entry per
    locked advisory_class so the dashboard tile renders the full grid
    even when zero rows exist.
    """

    severity: Dict[str, int]
    advisory_class: Dict[str, int]
    total: int


# ---------------------------------------------------------------------------
# Manual recompute response shape
# ---------------------------------------------------------------------------


class ApplicabilityResultRead(BaseModel):
    """Mirrors :class:`patch_advisory_service.ApplicabilityResult`.
    Surfaced inline to operators after the manual-recompute trigger
    so they see the row delta without a second fetch.
    """

    system_id: int
    counts: Dict[str, int]
    rows_added: int
    rows_updated: int
    rows_removed: int
    advisories_touched: int
    host_facts_missing: bool
    changed: bool


# ---------------------------------------------------------------------------
# Operator-triggered import shapes (PRA-239)
# ---------------------------------------------------------------------------


class PatchAdvisoryImportRunRead(BaseModel):
    """One :class:`patch_advisory_service.PatchAdvisoryImport` row —
    the recorded summary of an import attempt. Operators read these to
    see import history (status, per-action counts, error details)
    without parsing per-advisory audit rows.
    """

    id: int
    source_kind: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    imported_count: int
    refreshed_count: int
    unchanged_count: int
    error_count: int
    error_details: Optional[List[Dict[str, Any]]] = None
    created_by: int
    created_at: datetime

    class Config:
        orm_mode = True


class AdvisoryImportOutcomeRead(BaseModel):
    """Per-payload outcome, mirroring
    :class:`patch_advisory_service.ImportOutcome`. ``action`` is one of
    ``imported`` / ``refreshed`` / ``unchanged`` / ``error``.
    """

    source_advisory_id: str
    action: str
    advisory_id: Optional[int] = None
    error: Optional[str] = None

    class Config:
        orm_mode = True


class AdvisoryImportRequest(BaseModel):
    """Operator import request: a ``source_kind`` plus one raw native
    payload (``payload``) or a list of them (``payloads``). Exactly one
    of the two must be supplied. Raw payloads are normalized server-side
    by the matching source-specific normalizer before import.
    """

    source_kind: str
    payload: Optional[Dict[str, Any]] = None
    payloads: Optional[List[Dict[str, Any]]] = None

    @validator("payloads", always=True)
    def _coalesce_payloads(cls, v, values):  # noqa: N805
        single = values.get("payload")
        if v is None and single is None:
            raise ValueError(
                "provide 'payload' (one raw object) or 'payloads' (a list)"
            )
        if v is not None and single is not None:
            raise ValueError("provide only one of 'payload' or 'payloads'")
        resolved = v if v is not None else [single]
        if not resolved:
            raise ValueError("payloads must not be empty")
        return resolved


class AdvisoryImportResponse(BaseModel):
    """Result of an operator import: the recorded run plus the ordered
    per-payload outcomes.
    """

    run: PatchAdvisoryImportRunRead
    outcomes: List[AdvisoryImportOutcomeRead]
