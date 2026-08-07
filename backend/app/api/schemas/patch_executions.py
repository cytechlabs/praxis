"""Pydantic schemas for patch update executions (PRA-171 slice 1).

Pydantic V1 syntax (``@validator`` without ``@classmethod`` per
``feedback_pydantic_validators.md`` — using ``@classmethod`` here
silently disables the validator).

Slice 1 ships the execution-run substrate + live-progress read
model only. No package execution, no SSH/agent dispatch, no real
host result fields.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

COMMENT_MAX_LEN = 4096


def _validate_required_positive_id(v):
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("id must be an integer")
    if v <= 0:
        raise ValueError("id must be positive")
    return v


def _validate_optional_positive_int(v):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("value must be an integer or null")
    if v <= 0:
        raise ValueError("value must be positive")
    return v


def _validate_optional_threshold(v):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("failure_threshold_percent must be an integer 0-100 or null")
    if v < 0 or v > 100:
        raise ValueError(
            "failure_threshold_percent must be between 0 and 100 inclusive"
        )
    return v


def _validate_optional_text(v):
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError("value must be a string")
    if len(v) > COMMENT_MAX_LEN:
        raise ValueError(f"value exceeds {COMMENT_MAX_LEN} characters")
    return v


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class PatchUpdateExecutionStart(BaseModel):
    """Body for ``POST /patch/update-executions/start``.

    ``plan_id`` is required; ``max_parallel_per_wave`` and
    ``failure_threshold_percent`` are optional overrides over the
    plan's policy snapshot defaults.
    """

    plan_id: int
    max_parallel_per_wave: Optional[int] = None
    failure_threshold_percent: Optional[int] = None

    @validator("plan_id", pre=True)
    def _plan_id(cls, v):  # pylint: disable=no-self-argument
        return _validate_required_positive_id(v)

    @validator("max_parallel_per_wave", pre=True)
    def _max_parallel_per_wave(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_positive_int(v)

    @validator("failure_threshold_percent", pre=True)
    def _failure_threshold_percent(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_threshold(v)


class PatchUpdateExecutionPauseRequest(BaseModel):
    pause_reason: Optional[str] = None

    @validator("pause_reason")
    def _pause_reason(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_text(v)


class PatchUpdateExecutionCancelRequest(BaseModel):
    cancel_reason: Optional[str] = None

    @validator("cancel_reason")
    def _cancel_reason(cls, v):  # pylint: disable=no-self-argument
        return _validate_optional_text(v)


# ---------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------


class PatchUpdateExecutionHostRead(BaseModel):
    """One materialized execution-host row.

    ``state`` is one of ``pending`` / ``running`` / ``succeeded`` /
    ``failed`` / ``skipped`` / ``paused`` / ``canceled``. Slice 1
    only writes ``pending`` / ``skipped`` / ``canceled``;
    other transitions belong to later slices.
    """

    id: int
    execution_id: int
    plan_host_id: int
    system_id_snapshot: Optional[int]
    system_hostname_snapshot: Optional[str]
    wave_index: int
    state: str
    selected_package_count: int
    skip_reasons: List[Dict[str, Any]] = []
    error_details: Dict[str, Any] = {}
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchUpdateExecutionWave(BaseModel):
    wave_index: int
    host_count: int
    selected_package_count: int
    host_counts_by_state: Dict[str, int] = {}


class PatchUpdateExecutionProgress(BaseModel):
    host_count: int
    host_counts_by_state: Dict[str, int] = {}
    selected_package_count: int
    # Slice 2: per-package outcome rollup from
    # patch_update_execution_host_packages. Zero counts before the
    # first dispatch-next call writes any rows.
    package_outcome_counts: Dict[str, int] = {}
    waves: List[PatchUpdateExecutionWave] = []
    # Slice 3: wave indexes that have already had
    # ``patch_update_execution.wave_completed`` emitted. Empty before
    # the first wave finishes.
    completed_wave_indexes: List[int] = []
    # Slice 3: structured context recorded when the dispatcher
    # auto-paused for a failure-threshold breach. Null otherwise.
    threshold_pause: Optional[Dict[str, Any]] = None


class PatchUpdateExecutionRead(BaseModel):
    id: int
    plan_id: int
    state: str
    started_by: int
    started_at: datetime
    completed_at: Optional[datetime]
    paused_at: Optional[datetime]
    canceled_at: Optional[datetime]
    max_parallel_per_wave: int
    failure_threshold_percent: Optional[int]
    pause_reason: Optional[str]
    cancel_reason: Optional[str]
    plan_state_snapshot: str
    policy_snapshot: Dict[str, Any] = {}
    execution_config_snapshot: Dict[str, Any] = {}
    progress_summary: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchUpdateExecutionDetail(PatchUpdateExecutionRead):
    """Full execution envelope including live progress rollup and the
    per-host rows. Returned by the start / get / pause / resume /
    cancel endpoints so a single round-trip surfaces the artifact."""

    progress: PatchUpdateExecutionProgress
    hosts: List[PatchUpdateExecutionHostRead] = []


# ---------------------------------------------------------------------------
# Slice 2: dispatch
# ---------------------------------------------------------------------------


class PatchUpdateExecutionHostPackageRead(BaseModel):
    """One per-package execution result row (PRA-171 slice 2).

    ``outcome`` is one of ``succeeded`` / ``failed`` / ``skipped``
    / ``unknown``. ``installed_version_after`` is null when Slice 2
    cannot reliably observe the post-execution version (typical
    apt/dnf bundle path); a future verification slice may populate
    it.
    """

    id: int
    execution_host_id: int
    package_name: str
    requested_version_snapshot: Optional[str]
    installed_version_before: Optional[str]
    installed_version_after: Optional[str]
    package_manager_family_snapshot: str
    outcome: str
    error_code: Optional[str]
    details: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class PatchUpdateExecutionDispatchHostOutcome(BaseModel):
    """One host-row summary inside a dispatch-next batch result."""

    execution_host_id: int
    system_id: Optional[int] = None
    outcome: str
    exit_code: Optional[int] = None
    transport: Optional[str] = None
    error_code: Optional[str] = None


class PatchUpdateExecutionDispatchResult(BaseModel):
    """Body returned by ``POST /patch/update-executions/{id}/dispatch-next``.

    Slice 2 contract: trigger-based, one bounded batch per call.
    ``no_pending`` is true when no wave had any pending hosts (the
    operator has nothing left to dispatch on this execution).
    ``pause_reason`` is set when the dispatcher aborted mid-batch
    because a concurrent operator paused or canceled the execution
    or because the dispatcher auto-paused for a failure-threshold
    breach (Slice 3).

    Slice 3 lifecycle fields:

    * ``completed_wave_indexes`` — wave indexes that emitted
      ``wave_completed`` during this call (empty when no new wave
      finished).
    * ``threshold_pause`` — structured breach context when the
      dispatcher auto-paused for ``failure_threshold_percent``
      breach during this call.
    * ``finalized_state`` — terminal state the execution flipped to
      during this call (``succeeded`` / ``failed``); null when the
      execution is not yet complete.
    """

    execution_id: int
    wave_index: Optional[int] = None
    dispatched_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    no_pending: bool = False
    pause_reason: Optional[str] = None
    host_outcomes: List[PatchUpdateExecutionDispatchHostOutcome] = []
    completed_wave_indexes: List[int] = []
    threshold_pause: Optional[Dict[str, Any]] = None
    finalized_state: Optional[str] = None
    execution: PatchUpdateExecutionDetail
