"""PRA-178 Slice 1 — patch execution review-period report/export.

Read-only service surface for the manual reporting/export foundation. Slice 1 ships:

* a bounded review-period iterator over ``patch_update_executions``
* a stable export wire shape consumed by both CSV and JSON output
* a post-stream audit emission helper

The substrate is deliberately reusable: later PRA-178 slices that
schedule the same report or expose it through a notification path
should call into these helpers rather than re-deriving the row shape.

Hard boundaries (slice locks):

* No scheduler, worker, queue, broker, or recurring delivery.
* No host mutation, package execution, reboot, rollback, OpenSCAP,
  facts refresh, package scan, raw SSH, or subprocess.
* No notification event expansion or alert delivery retry changes.

The export window guard mirrors the PRA-165 compliance evidence
export: a misclicked unbounded GET cannot dump unbounded history.
``EXPORT_MAX_ROWS`` is an additional soft cap that prevents a single
review-period request from materializing tens of millions of rows in
memory; the route surfaces a 422 with operator-readable text rather
than silently truncating.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from ..db.models import PatchUpdateExecution, PatchUpdatePlan, User
from . import patch_scope
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local error class — route layer maps message containing "not found"
# to 404 and everything else to 422 per the PRA-161/162/164/171 pattern.
# ---------------------------------------------------------------------------


class PatchReportError(ValueError):
    """Raised when an export request is rejected for semantic reasons
    (bad window, unsupported state filter, row cap exceeded, etc.)."""


# ---------------------------------------------------------------------------
# Window + size guards
# ---------------------------------------------------------------------------

# Hard ceiling for the review window. Operators can chunk longer
# ranges through multiple requests; this guard exists so a 1-hour
# misclick cannot dump every patch execution row in the database.
EXPORT_WINDOW_MAX_DAYS = 366

# Default review window when the caller omits both bounds. Matches the
# default-recent-history posture of the PRA-165 evidence export.
EXPORT_DEFAULT_WINDOW_DAYS = 30

# Hard ceiling on the number of rows a single export request will
# materialize. The export response shape is bounded-array JSON / CSV
# rather than NDJSON streaming, so the route fails closed if the filter
# would produce more rows than this cap. Operators can narrow with the
# ``plan_id`` / ``state`` filters to get under the cap.
EXPORT_MAX_ROWS = 50_000

# yield_per chunk for the underlying query; balances memory footprint
# against round-trip overhead per the compliance evidence pattern.
EXPORT_STREAM_CHUNK = 500


# Audit event-type string for the patch execution export. Documented in
# docs/audit-schema.md alongside the other compliance/patch export
# actions.
AUDIT_PATCH_EXECUTION_EXPORT_REQUESTED = "patch_execution_export.requested"


VALID_EXPORT_FORMATS: Tuple[str, ...] = ("csv", "json")


# Stable column order for the CSV export. Pinned so external auditor
# scripts can rely on it.
EXPORT_CSV_COLUMNS: Tuple[str, ...] = (
    "id",
    "plan_id",
    "plan_name_snapshot",
    "policy_slug_snapshot",
    "state",
    "plan_state_snapshot",
    "started_by_user_id",
    "started_by_username",
    "started_at",
    "completed_at",
    "paused_at",
    "canceled_at",
    "max_parallel_per_wave",
    "failure_threshold_percent",
    "pause_reason",
    "cancel_reason",
    "host_count",
    "host_succeeded",
    "host_failed",
    "host_skipped",
    "host_canceled",
    "package_succeeded",
    "package_failed",
    "package_skipped",
    "created_at",
    "updated_at",
)


# ---------------------------------------------------------------------------
# Window resolution + validation
# ---------------------------------------------------------------------------


def resolve_export_window(
    started_after: Optional[datetime],
    started_before: Optional[datetime],
) -> Tuple[datetime, datetime]:
    """Return ``(after, before)`` for the export window after applying
    defaults and validating bounds.

    Defaults to the last :data:`EXPORT_DEFAULT_WINDOW_DAYS` days when
    both bounds are omitted so a casual operator GET does not accidentally
    dump every execution in history. Raises :class:`PatchReportError`
    when the window is inverted or longer than
    :data:`EXPORT_WINDOW_MAX_DAYS`.
    """
    now = datetime.utcnow()
    if started_before is None:
        started_before = now
    if started_after is None:
        started_after = started_before - timedelta(days=EXPORT_DEFAULT_WINDOW_DAYS)
    if started_before <= started_after:
        raise PatchReportError(
            "started_before must be strictly greater than started_after"
        )
    if (started_before - started_after) > timedelta(days=EXPORT_WINDOW_MAX_DAYS):
        raise PatchReportError(
            f"export window must be <= {EXPORT_WINDOW_MAX_DAYS} days"
        )
    return started_after, started_before


def validate_format(fmt: Optional[str]) -> str:
    """Normalize and validate the export format. Returns the lowered
    format string; raises :class:`PatchReportError` for unsupported
    values."""
    if fmt is None or fmt == "":
        return "csv"
    if not isinstance(fmt, str):
        raise PatchReportError("format must be a string")
    lowered = fmt.lower()
    if lowered not in VALID_EXPORT_FORMATS:
        raise PatchReportError(f"format must be one of: {list(VALID_EXPORT_FORMATS)}")
    return lowered


def validate_state(state: Optional[str]) -> Optional[str]:
    """Validate the optional state filter against the execution state
    vocabulary. Returns the validated value (or None)."""
    if state is None:
        return None
    if not isinstance(state, str):
        raise PatchReportError("state must be a string")
    # Import lazily to avoid a circular import on
    # ``patch_execution_service`` (which itself imports a number of
    # plan/policy helpers).
    from .patch_execution_service import VALID_EXECUTION_STATES

    if state not in VALID_EXECUTION_STATES:
        raise PatchReportError(
            f"state must be one of: {sorted(VALID_EXECUTION_STATES)}"
        )
    return state


# ---------------------------------------------------------------------------
# Row materialization
# ---------------------------------------------------------------------------


def _utc_iso(value: Optional[datetime]) -> Optional[str]:
    """Render a naive-UTC datetime as ``...Z`` so consumers cannot
    mistake the value for local time."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat() + "Z"
    return value.isoformat()


def _progress_counts(progress_summary: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """Pull a bounded subset of host/package counts out of the live
    ``progress_summary`` JSONB column. The column shape is owned by
    :mod:`patch_execution_service`; we only read the keys we know are
    stable and default to 0 when they are missing so this surface stays
    forward-compatible with later additions.
    """
    summary = progress_summary or {}
    host_counts: Dict[str, Any] = (
        (summary.get("host_counts_by_state") or {}) if isinstance(summary, dict) else {}
    )
    pkg_counts: Dict[str, Any] = (
        (summary.get("package_outcome_counts") or {})
        if isinstance(summary, dict)
        else {}
    )

    def _int(d: Dict[str, Any], key: str) -> int:
        value = d.get(key)
        try:
            return int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0

    return {
        "host_count": _int(summary, "host_count") if isinstance(summary, dict) else 0,
        "host_succeeded": _int(host_counts, "succeeded"),
        "host_failed": _int(host_counts, "failed"),
        "host_skipped": _int(host_counts, "skipped"),
        "host_canceled": _int(host_counts, "canceled"),
        "package_succeeded": _int(pkg_counts, "succeeded"),
        "package_failed": _int(pkg_counts, "failed"),
        "package_skipped": _int(pkg_counts, "skipped"),
    }


def execution_export_row(
    execution: PatchUpdateExecution,
    *,
    plan_name: Optional[str],
    policy_slug: Optional[str],
    started_by_username: Optional[str],
) -> Dict[str, Any]:
    """Stable wire shape used by both the CSV and JSON exports.

    Pulls denormalized counts out of the live ``progress_summary``
    JSONB; per-host/per-package detail still lives behind the
    execution detail route. The shape is intentionally flat so a CSV
    importer can map columns one-to-one without nested parsing.

    ``policy_slug`` comes from the parent plan's ``policy_snapshot``
    JSONB rather than the live ``patch_policies.slug`` column so the
    export remains faithful to the moment-in-time intent the operator
    approved.
    """
    counts = _progress_counts(execution.progress_summary)
    return {
        "id": execution.id,
        "plan_id": execution.plan_id,
        "plan_name_snapshot": plan_name,
        "policy_slug_snapshot": policy_slug,
        "state": execution.state,
        "plan_state_snapshot": execution.plan_state_snapshot,
        "started_by_user_id": execution.started_by,
        "started_by_username": started_by_username,
        "started_at": _utc_iso(execution.started_at),
        "completed_at": _utc_iso(execution.completed_at),
        "paused_at": _utc_iso(execution.paused_at),
        "canceled_at": _utc_iso(execution.canceled_at),
        "max_parallel_per_wave": execution.max_parallel_per_wave,
        "failure_threshold_percent": execution.failure_threshold_percent,
        "pause_reason": execution.pause_reason,
        "cancel_reason": execution.cancel_reason,
        "host_count": counts["host_count"],
        "host_succeeded": counts["host_succeeded"],
        "host_failed": counts["host_failed"],
        "host_skipped": counts["host_skipped"],
        "host_canceled": counts["host_canceled"],
        "package_succeeded": counts["package_succeeded"],
        "package_failed": counts["package_failed"],
        "package_skipped": counts["package_skipped"],
        "created_at": _utc_iso(execution.created_at),
        "updated_at": _utc_iso(execution.updated_at),
    }


# ---------------------------------------------------------------------------
# Query iterator
# ---------------------------------------------------------------------------


def iter_executions_for_export(
    db: Session,
    *,
    started_after: datetime,
    started_before: datetime,
    plan_id: Optional[int] = None,
    state: Optional[str] = None,
) -> Iterable[Tuple[PatchUpdateExecution, Optional[str], Optional[str], Optional[str]]]:
    """Yield ``(execution, plan_name, plan_slug, username)`` tuples in
    ascending ``started_at`` order over the given review window.

    Uses ``yield_per`` so the backend does not materialize the full
    result set in memory. Plan and user lookups are batched per chunk
    rather than per-row to keep query count bounded.
    """
    q = db.query(PatchUpdateExecution).filter(
        PatchUpdateExecution.started_at >= started_after,
        PatchUpdateExecution.started_at < started_before,
    )
    if plan_id is not None:
        q = q.filter(PatchUpdateExecution.plan_id == plan_id)
    if state is not None:
        q = q.filter(PatchUpdateExecution.state == state)
    q = q.order_by(
        PatchUpdateExecution.started_at.asc(),
        PatchUpdateExecution.id.asc(),
    )

    chunk: List[PatchUpdateExecution] = []
    for execution in q.yield_per(EXPORT_STREAM_CHUNK):
        chunk.append(execution)
        if len(chunk) >= EXPORT_STREAM_CHUNK:
            yield from _materialize_chunk(db, chunk)
            chunk = []
    if chunk:
        yield from _materialize_chunk(db, chunk)


def _materialize_chunk(
    db: Session, chunk: List[PatchUpdateExecution]
) -> Iterable[Tuple[PatchUpdateExecution, Optional[str], Optional[str], Optional[str]]]:
    plan_ids = {e.plan_id for e in chunk if e.plan_id is not None}
    user_ids = {e.started_by for e in chunk if e.started_by is not None}

    plan_map: Dict[int, Tuple[Optional[str], Optional[str]]] = {}
    if plan_ids:
        rows = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id.in_(plan_ids)).all()
        for p in rows:
            policy_slug: Optional[str] = None
            snap = getattr(p, "policy_snapshot", None) or {}
            if isinstance(snap, dict):
                candidate = snap.get("slug")
                if isinstance(candidate, str):
                    policy_slug = candidate
            plan_map[p.id] = (getattr(p, "name", None), policy_slug)

    user_map: Dict[int, Optional[str]] = {}
    if user_ids:
        urows = db.query(User).filter(User.id.in_(user_ids)).all()
        user_map = {u.id: getattr(u, "username", None) for u in urows}

    for execution in chunk:
        name, policy_slug = plan_map.get(execution.plan_id, (None, None))
        yield (
            execution,
            name,
            policy_slug,
            user_map.get(execution.started_by) if execution.started_by else None,
        )


def collect_export_rows(
    db: Session,
    *,
    started_after: datetime,
    started_before: datetime,
    plan_id: Optional[int] = None,
    state: Optional[str] = None,
    scope_system_ids: Optional[Set[int]] = None,
) -> List[Dict[str, Any]]:
    """Materialize the export window into a bounded list of stable
    wire-shape dicts. Raises :class:`PatchReportError` with a 422-shaped
    message when the filter would produce more than :data:`EXPORT_MAX_ROWS`
    rows so the caller does not silently truncate.

    PRA-281: ``scope_system_ids`` restricts the export to executions the caller
    may see. ``None`` = tenant-wide (admin, unchanged); otherwise an execution is
    included only when every one of its materialized target hosts is in scope
    (out-of-scope-only and mixed-scope executions are skipped, so no hidden
    execution row, hostname, package name, or count reaches a scoped caller). An
    empty set yields an empty export.
    """
    out: List[Dict[str, Any]] = []
    for execution, name, policy_slug, username in iter_executions_for_export(
        db,
        started_after=started_after,
        started_before=started_before,
        plan_id=plan_id,
        state=state,
    ):
        if scope_system_ids is not None and not patch_scope.execution_visible_to_scope(
            db, execution.id, scope_system_ids
        ):
            continue
        out.append(
            execution_export_row(
                execution,
                plan_name=name,
                policy_slug=policy_slug,
                started_by_username=username,
            )
        )
        if len(out) > EXPORT_MAX_ROWS:
            raise PatchReportError(
                "patch execution export would exceed "
                f"{EXPORT_MAX_ROWS} rows; narrow the review window or "
                "filter by plan_id / state"
            )
    return out


# ---------------------------------------------------------------------------
# Audit emission — after rows materialize so the row count is accurate.
# ---------------------------------------------------------------------------


def emit_export_requested_audit(
    *,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    export_format: str,
    filters: Dict[str, Any],
    row_count: int,
) -> None:
    """Emit ``patch_execution_export.requested`` after the export
    response is built. Goes through :func:`safe_emit` with no ``db=``
    so the request-scoped session lifetime does not matter — the
    session-boundary lock for "audit AFTER my own commit" applies.
    """
    safe_emit(
        action=AUDIT_PATCH_EXECUTION_EXPORT_REQUESTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_execution_export",
        target_id=None,
        context={
            "format": export_format,
            "filters": filters,
            "row_count": row_count,
        },
    )


def filters_for_audit(
    *,
    started_after: datetime,
    started_before: datetime,
    plan_id: Optional[int],
    state: Optional[str],
) -> Dict[str, Any]:
    """Bounded operator-supplied filter snapshot recorded in the audit
    event ``context`` block. Timestamps are normalized to ``...Z``.
    """
    return {
        "started_after": _utc_iso(started_after),
        "started_before": _utc_iso(started_before),
        "plan_id": plan_id,
        "state": state,
    }
