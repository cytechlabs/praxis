"""PRA-178 Slice 2 — durable report-run lifecycle helpers.

Persists one ``ReportRun`` row per report/export execution and exposes
a bounded read surface for the operator UI and later scheduler slices.
This module sits on top of the Slice 1 export substrate; Slice 2 only
records ``triggered_by='user'`` rows because there is no scheduler yet.

Hard boundaries (slice locks):

* No scheduler, worker, queue, broker, or recurring delivery.
* No notification event expansion, alert delivery retry changes, or
  delivery log schema changes.
* No host mutation, package/remediation execution, reboot, rollback,
  facts refresh, package scan, raw SSH, subprocess, or new compliance
  probe kinds.

Service shape:

* ``start_run(...)`` — persist a ``state='started'`` row and commit
  immediately so a long-running export still leaves a durable record
  if the request later hangs. Slice 2's manual export hook uses
  ``record_completed_run(...)`` instead (single-commit shape) because
  the in-memory ``collect_export_rows`` path is fast.
* ``complete_run(...)`` — transition a started row to ``succeeded``.
* ``fail_run(...)`` — transition a started row to ``failed`` with a
  bounded error message.
* ``record_completed_run(...)`` — single-shot helper used by the
  Slice 1 manual export hook: persist a ``succeeded`` row with the
  final ``row_count`` and filters.
* ``list_runs(...)`` — bounded paginated read of recent runs with
  optional kind/triggered_by/state/since filters.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import ReportRun

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabularies — mirror the DB CHECK constraints.
# ---------------------------------------------------------------------------

REPORT_KIND_PATCH_EXECUTIONS = "patch_executions"
REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS = "compliance_remediation_requests"
REPORT_KIND_COMPLIANCE_EVIDENCE = "compliance_evidence"
# PRA-178 Slice 4: broader manual exports.
REPORT_KIND_PATCH_UPDATE_PLANS = "patch_update_plans"
REPORT_KIND_PATCH_REBOOT_QUEUES = "patch_reboot_queues"
REPORT_KIND_PATCH_ROLLBACK_RUNS = "patch_rollback_runs"
REPORT_KIND_COMPLIANCE_REMEDIATION_PLANS = "compliance_remediation_plans"
REPORT_KIND_COMPLIANCE_REMEDIATION_EXECUTIONS = "compliance_remediation_executions"
# PRA-358: package posture reports promoted into the report-kind contract so
# Package Reports gets on-demand generate/export recorded as durable runs.
REPORT_KIND_PACKAGE_OUTDATED = "package_outdated"
REPORT_KIND_PACKAGE_COMPLIANCE = "package_compliance"

VALID_REPORT_KINDS: Tuple[str, ...] = (
    REPORT_KIND_PATCH_EXECUTIONS,
    REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS,
    REPORT_KIND_COMPLIANCE_EVIDENCE,
    REPORT_KIND_PATCH_UPDATE_PLANS,
    REPORT_KIND_PATCH_REBOOT_QUEUES,
    REPORT_KIND_PATCH_ROLLBACK_RUNS,
    REPORT_KIND_COMPLIANCE_REMEDIATION_PLANS,
    REPORT_KIND_COMPLIANCE_REMEDIATION_EXECUTIONS,
    REPORT_KIND_PACKAGE_OUTDATED,
    REPORT_KIND_PACKAGE_COMPLIANCE,
)


TRIGGERED_BY_USER = "user"
TRIGGERED_BY_SYSTEM_SCHEDULED = "system_scheduled"

VALID_TRIGGERED_BY: Tuple[str, ...] = (
    TRIGGERED_BY_USER,
    TRIGGERED_BY_SYSTEM_SCHEDULED,
)


STATE_STARTED = "started"
STATE_SUCCEEDED = "succeeded"
STATE_FAILED = "failed"

VALID_STATES: Tuple[str, ...] = (STATE_STARTED, STATE_SUCCEEDED, STATE_FAILED)


VALID_FORMATS: Tuple[str, ...] = ("csv", "json", "jsonl")


MAX_ERROR_MESSAGE_CHARS = 2048
MAX_FILTERS_SNAPSHOT_BYTES = 16 * 1024  # 16 KiB serialized

# Hard ceiling on a single read response so a misclicked unbounded
# query cannot dump the whole history. Operators can page via
# ``offset`` once a richer UI lands.
LIST_RUNS_MAX_LIMIT = 500
LIST_RUNS_DEFAULT_LIMIT = 100


class ReportRunError(ValueError):
    """Raised when a report-run lifecycle call is rejected for
    semantic reasons (bad vocabulary, bad bound, missing row)."""


# ---------------------------------------------------------------------------
# Internal validation helpers
# ---------------------------------------------------------------------------


def _require_kind(value: str) -> str:
    if value not in VALID_REPORT_KINDS:
        raise ReportRunError(f"report_kind must be one of: {list(VALID_REPORT_KINDS)}")
    return value


def _require_triggered_by(value: str) -> str:
    if value not in VALID_TRIGGERED_BY:
        raise ReportRunError(f"triggered_by must be one of: {list(VALID_TRIGGERED_BY)}")
    return value


def _normalize_format(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ReportRunError("format must be a string")
    lowered = value.lower()
    if lowered not in VALID_FORMATS:
        raise ReportRunError(f"format must be one of: {list(VALID_FORMATS)}")
    return lowered


def _bounded_error_message(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ReportRunError("error_message must be a string")
    if len(value) > MAX_ERROR_MESSAGE_CHARS:
        return value[:MAX_ERROR_MESSAGE_CHARS]
    return value


def _bounded_row_count(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportRunError("row_count must be a non-negative integer")
    if value < 0:
        raise ReportRunError("row_count must be a non-negative integer")
    return value


def _bounded_filters(filters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate the operator-supplied filters dict.

    The dict must be JSON-serializable and the serialized payload must
    not exceed :data:`MAX_FILTERS_SNAPSHOT_BYTES`. Callers are
    responsible for ensuring the dict carries only operator-supplied
    filter values (no request headers, tokens, cookies, or session
    blobs). The bounded JSON-serialization round-trip both validates
    the shape and strips any non-serializable values.
    """
    if filters is None:
        return {}
    if not isinstance(filters, dict):
        raise ReportRunError("filters_snapshot must be a JSON object")
    try:
        serialized = json.dumps(filters, default=str, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ReportRunError(
            f"filters_snapshot is not JSON-serializable: {exc}"
        ) from exc
    if len(serialized.encode("utf-8")) > MAX_FILTERS_SNAPSHOT_BYTES:
        raise ReportRunError(
            "filters_snapshot exceeds " f"{MAX_FILTERS_SNAPSHOT_BYTES} bytes serialized"
        )
    # Round-trip through json so the persisted dict only contains
    # JSON-compatible primitives (also strips any object identity quirks).
    return json.loads(serialized)


# ---------------------------------------------------------------------------
# Lifecycle helpers
# ---------------------------------------------------------------------------


def start_run(
    db: Session,
    *,
    report_kind: str,
    triggered_by: str = TRIGGERED_BY_USER,
    triggered_by_user_id: Optional[int] = None,
    triggered_by_username: Optional[str] = None,
    format: Optional[str] = None,
    filters_snapshot: Optional[Dict[str, Any]] = None,
    started_at: Optional[datetime] = None,
) -> ReportRun:
    """Persist a ``state='started'`` row and commit immediately.

    Reserved for long-running exports that need a durable row before
    the response body is built. The Slice 1 manual export hook uses
    :func:`record_completed_run` instead.
    """
    row = ReportRun(
        report_kind=_require_kind(report_kind),
        triggered_by=_require_triggered_by(triggered_by),
        triggered_by_user_id=triggered_by_user_id,
        triggered_by_username=triggered_by_username,
        format=_normalize_format(format),
        filters_snapshot=_bounded_filters(filters_snapshot),
        state=STATE_STARTED,
        started_at=started_at or datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def complete_run(
    db: Session,
    *,
    run_id: int,
    row_count: Optional[int],
    completed_at: Optional[datetime] = None,
) -> ReportRun:
    """Transition a started run to ``succeeded`` with the final row count."""
    row = db.query(ReportRun).filter(ReportRun.id == run_id).first()
    if row is None:
        raise ReportRunError(f"report run id={run_id} not found")
    if row.state != STATE_STARTED:
        raise ReportRunError(
            f"report run id={run_id} is not in state 'started' "
            f"(current: {row.state})"
        )
    row.state = STATE_SUCCEEDED
    row.row_count = _bounded_row_count(row_count)
    row.completed_at = completed_at or datetime.utcnow()
    db.commit()
    db.refresh(row)
    return row


def fail_run(
    db: Session,
    *,
    run_id: int,
    error_message: Optional[str],
    completed_at: Optional[datetime] = None,
) -> ReportRun:
    """Transition a started run to ``failed`` with a bounded error message."""
    row = db.query(ReportRun).filter(ReportRun.id == run_id).first()
    if row is None:
        raise ReportRunError(f"report run id={run_id} not found")
    if row.state != STATE_STARTED:
        raise ReportRunError(
            f"report run id={run_id} is not in state 'started' "
            f"(current: {row.state})"
        )
    row.state = STATE_FAILED
    row.error_message = _bounded_error_message(error_message)
    row.completed_at = completed_at or datetime.utcnow()
    db.commit()
    db.refresh(row)
    return row


def record_completed_run(
    db: Session,
    *,
    report_kind: str,
    triggered_by: str = TRIGGERED_BY_USER,
    triggered_by_user_id: Optional[int] = None,
    triggered_by_username: Optional[str] = None,
    format: Optional[str] = None,
    filters_snapshot: Optional[Dict[str, Any]] = None,
    row_count: Optional[int],
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
) -> ReportRun:
    """Single-shot helper for the Slice 1 manual export hook.

    Persists one ``state='succeeded'`` row with the final ``row_count``
    and filters, then commits. Used when the export body is built
    in-memory before the response is returned (no separate ``started``
    row is needed because the export window cannot fail between
    ``collect_export_rows`` and the response).
    """
    now = datetime.utcnow()
    row = ReportRun(
        report_kind=_require_kind(report_kind),
        triggered_by=_require_triggered_by(triggered_by),
        triggered_by_user_id=triggered_by_user_id,
        triggered_by_username=triggered_by_username,
        format=_normalize_format(format),
        filters_snapshot=_bounded_filters(filters_snapshot),
        row_count=_bounded_row_count(row_count),
        state=STATE_SUCCEEDED,
        started_at=started_at or now,
        completed_at=completed_at or now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def safe_record_completed_run(db: Optional[Session] = None, **kwargs: Any) -> None:
    """Persist a completed run without raising.

    The Slice 1 manual export routes call this AFTER the response body
    is built. A persistence failure must not break the operator's
    download — log and move on.

    When ``db`` is provided, the row is persisted through the caller's
    session and shares the request's transaction (the
    ``triggered_by_user_id`` FK target is visible inside the same
    transaction even for in-flight requests that haven't yet committed).
    When ``db`` is None — primarily for callers without a request-scoped
    session — a fresh ``SessionLocal`` is opened, used, and closed; in
    that mode the FK target must already be committed in the database
    or the insert will raise inside the swallowed ``except`` and the
    row will not be persisted.
    """
    own = db is None
    if own:
        from ..db.session import SessionLocal

        db = SessionLocal()
    try:
        record_completed_run(db, **kwargs)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("report-run persist failed: %s", exc)
        # If we opened our own session, drop any half-applied state.
        if own:
            try:
                db.rollback()
            except Exception:  # pylint: disable=broad-except
                pass
    finally:
        if own:
            db.close()


# ---------------------------------------------------------------------------
# Read API
# ---------------------------------------------------------------------------


def list_runs(
    db: Session,
    *,
    report_kind: Optional[str] = None,
    triggered_by: Optional[str] = None,
    state: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    offset: int = 0,
    limit: int = LIST_RUNS_DEFAULT_LIMIT,
) -> Tuple[List[ReportRun], int]:
    """Bounded paginated read of recent runs.

    Returns ``(rows, total)`` where ``rows`` are ordered most-recent
    first by ``started_at``. Raises :class:`ReportRunError` on bad
    filter values. ``offset`` / ``limit`` are bounded by the route
    layer; the service applies a hard ceiling of
    :data:`LIST_RUNS_MAX_LIMIT` as a defense in depth.
    """
    if report_kind is not None:
        _require_kind(report_kind)
    if triggered_by is not None:
        _require_triggered_by(triggered_by)
    if state is not None and state not in VALID_STATES:
        raise ReportRunError(f"state must be one of: {list(VALID_STATES)}")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ReportRunError("offset must be a non-negative integer")
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 1
        or limit > LIST_RUNS_MAX_LIMIT
    ):
        raise ReportRunError(f"limit must be in 1..{LIST_RUNS_MAX_LIMIT}")

    q = db.query(ReportRun)
    if report_kind is not None:
        q = q.filter(ReportRun.report_kind == report_kind)
    if triggered_by is not None:
        q = q.filter(ReportRun.triggered_by == triggered_by)
    if state is not None:
        q = q.filter(ReportRun.state == state)
    if since is not None:
        q = q.filter(ReportRun.started_at >= since)
    if until is not None:
        q = q.filter(ReportRun.started_at < until)

    total = q.count()
    rows = (
        q.order_by(ReportRun.started_at.desc(), ReportRun.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _utc_iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat() + "Z"
    return value.isoformat()


def run_read_envelope(row: ReportRun) -> Dict[str, Any]:
    """Stable wire shape used by the read endpoint."""
    return {
        "id": row.id,
        "report_kind": row.report_kind,
        "triggered_by": row.triggered_by,
        "triggered_by_user_id": row.triggered_by_user_id,
        "triggered_by_username": row.triggered_by_username,
        "format": row.format,
        "filters_snapshot": dict(row.filters_snapshot or {}),
        "row_count": row.row_count,
        "state": row.state,
        "error_message": row.error_message,
        "started_at": _utc_iso(row.started_at),
        "completed_at": _utc_iso(row.completed_at),
        "created_at": _utc_iso(row.created_at),
        "updated_at": _utc_iso(row.updated_at),
    }
