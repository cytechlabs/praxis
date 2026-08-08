"""PRA-178 Slice 5 — scheduled report runs.

Durable scheduled-report definitions plus the scheduler tick that
fires due schedules through the existing Slice 1/Slice 4 export
substrate. Each successful firing persists a :class:`ReportRun` row
with ``triggered_by='system_scheduled'`` so the same Recent Reports
panel that lists manual exports also surfaces scheduled runs.

Hard boundaries (slice locks):

* No delivery retry behavior changes — the existing
  ``alert_service`` retry shape is reused unchanged. A scheduled
  run that fails records a ``state='failed'`` ``ReportRun`` row and
  advances ``next_run_at`` so the same misconfiguration does not
  loop the scheduler.
* No new notification events beyond the Slice 3 vocabulary.
* No new export classes beyond the Slice 1/Slice 4 set.
* No host mutation, package/remediation execution, reboot,
  rollback, OpenSCAP, facts refresh, package scan, raw SSH,
  subprocess, or new compliance probe kinds.

Plain-language cadence only — ``daily`` / ``weekly`` / ``monthly``
per ``feedback_no_cron.md``. Cron expressions never reach this
module.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import ReportRun, ReportSchedule
from . import report_run_service

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabularies — mirror the DB CHECK constraints.
# ---------------------------------------------------------------------------

CADENCE_DAILY = "daily"
CADENCE_WEEKLY = "weekly"
CADENCE_MONTHLY = "monthly"

VALID_CADENCES: Tuple[str, ...] = (
    CADENCE_DAILY,
    CADENCE_WEEKLY,
    CADENCE_MONTHLY,
)


VALID_FORMATS: Tuple[str, ...] = ("csv", "json")


# Bounded read response so a misclicked unbounded GET cannot dump the
# whole history. Mirrors ``report_run_service.LIST_RUNS_MAX_LIMIT``.
LIST_SCHEDULES_MAX_LIMIT = 500
LIST_SCHEDULES_DEFAULT_LIMIT = 100


MAX_NAME_CHARS = 128
MAX_ERROR_MESSAGE_CHARS = 2048


class ReportScheduleError(ValueError):
    """Raised when a schedule lifecycle call is rejected for
    semantic reasons (bad vocabulary, bad bound, missing row).
    Route layer maps the base class to HTTP 422."""


# ---------------------------------------------------------------------------
# Internal validation helpers
# ---------------------------------------------------------------------------


def _require_kind(value: str) -> str:
    if value not in report_run_service.VALID_REPORT_KINDS:
        raise ReportScheduleError(
            f"report_kind must be one of: "
            f"{list(report_run_service.VALID_REPORT_KINDS)}"
        )
    return value


def _require_cadence(value: str) -> str:
    if value not in VALID_CADENCES:
        raise ReportScheduleError(f"cadence must be one of: {list(VALID_CADENCES)}")
    return value


def _normalize_format(value: Optional[str]) -> str:
    if value is None or value == "":
        return "csv"
    if not isinstance(value, str):
        raise ReportScheduleError("format must be a string")
    lowered = value.lower()
    if lowered not in VALID_FORMATS:
        raise ReportScheduleError(f"format must be one of: {list(VALID_FORMATS)}")
    return lowered


def _bounded_name(value: str) -> str:
    if not isinstance(value, str):
        raise ReportScheduleError("name must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ReportScheduleError("name must be a non-empty string")
    if len(cleaned) > MAX_NAME_CHARS:
        raise ReportScheduleError(f"name exceeds {MAX_NAME_CHARS} characters")
    return cleaned


# Filter keys that the underlying export resolvers parse as
# datetime windows. Slice 5a fix to the
# a typoed value here used to silently fall back to the default
# review window. Now any value present under one of these keys
# must parse cleanly via ``datetime.fromisoformat`` (with an
# optional trailing ``Z``) or schedule create/update + the
# scheduler tick refuse.
DATE_FILTER_KEYS: Tuple[str, ...] = (
    "started_after",
    "started_before",
    "created_after",
    "created_before",
    "evaluated_after",
    "evaluated_before",
)


def _validate_filter_dates(filters: Dict[str, Any]) -> None:
    """Raise :class:`ReportScheduleError` for any
    ``DATE_FILTER_KEYS`` entry that exists but is not a parseable
    ISO-8601 string / datetime.

    The dispatchers downstream pass the values through
    ``_parse_dt``, which returns ``None`` on garbage. Letting that
    happen would silently widen a scheduled export to the default
    review window. Validating up front turns
    a misconfigured schedule into an explicit failure that the
    operator sees on create/update OR in the Recent Reports panel
    as a ``state='failed'`` ``ReportRun`` row.
    """
    for key in DATE_FILTER_KEYS:
        if key not in filters:
            continue
        value = filters[key]
        if value is None:
            continue
        if isinstance(value, datetime):
            continue
        if not isinstance(value, str):
            raise ReportScheduleError(
                f"filters_snapshot.{key} must be an ISO-8601 string"
            )
        raw = value.rstrip("Z")
        try:
            datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ReportScheduleError(
                f"filters_snapshot.{key} is not a valid ISO-8601 date: {exc}"
            ) from exc


def _bounded_filters(filters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Reuses the same JSON-serializability + size cap as
    ``report_run_service._bounded_filters``, then validates the
    date-typed entries so a misconfigured schedule cannot silently
    default a scheduled export to a broad window (Slice 5a fix to
    the P2 review finding)."""
    if filters is None:
        return {}
    if not isinstance(filters, dict):
        raise ReportScheduleError("filters_snapshot must be a JSON object")
    try:
        serialized = json.dumps(filters, default=str, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ReportScheduleError(
            f"filters_snapshot is not JSON-serializable: {exc}"
        ) from exc
    if len(serialized.encode("utf-8")) > report_run_service.MAX_FILTERS_SNAPSHOT_BYTES:
        raise ReportScheduleError(
            "filters_snapshot exceeds "
            f"{report_run_service.MAX_FILTERS_SNAPSHOT_BYTES} bytes serialized"
        )
    normalized = json.loads(serialized)
    _validate_filter_dates(normalized)
    return normalized


# ---------------------------------------------------------------------------
# Cadence math
# ---------------------------------------------------------------------------


def compute_next_run_at(cadence: str, anchor: Optional[datetime] = None) -> datetime:
    """Return the next firing time for ``cadence`` after ``anchor``
    (default: now).

    ``daily`` advances by 24h; ``weekly`` by 7d; ``monthly`` by ~30d
    (calendar-month arithmetic is deferred to a later slice — the
    30-day proxy is honest about its cadence and avoids the
    DST/day-of-month edge cases that would otherwise need their
    own test surface). All cadence math is in UTC.
    """
    base = anchor or datetime.utcnow()
    if cadence == CADENCE_DAILY:
        return base + timedelta(days=1)
    if cadence == CADENCE_WEEKLY:
        return base + timedelta(days=7)
    if cadence == CADENCE_MONTHLY:
        return base + timedelta(days=30)
    raise ReportScheduleError(f"cadence must be one of: {list(VALID_CADENCES)}")


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------


def create_schedule(
    db: Session,
    *,
    name: str,
    report_kind: str,
    cadence: str,
    filters_snapshot: Optional[Dict[str, Any]] = None,
    format: Optional[str] = None,
    enabled: bool = True,
    created_by_user_id: Optional[int] = None,
    first_run_at: Optional[datetime] = None,
) -> ReportSchedule:
    """Persist a new schedule.

    ``first_run_at`` defaults to ``now() + cadence`` so a schedule
    created at noon today (cadence=daily) first fires at noon
    tomorrow rather than immediately. Operators who want an
    immediate-first-run can pass ``first_run_at=datetime.utcnow()``.
    """
    row = ReportSchedule(
        name=_bounded_name(name),
        report_kind=_require_kind(report_kind),
        cadence=_require_cadence(cadence),
        filters_snapshot=_bounded_filters(filters_snapshot),
        format=_normalize_format(format),
        enabled=bool(enabled),
        next_run_at=first_run_at or compute_next_run_at(cadence),
        created_by=created_by_user_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def update_schedule(
    db: Session,
    *,
    schedule_id: int,
    name: Optional[str] = None,
    cadence: Optional[str] = None,
    filters_snapshot: Optional[Dict[str, Any]] = None,
    format: Optional[str] = None,
    enabled: Optional[bool] = None,
    next_run_at: Optional[datetime] = None,
) -> ReportSchedule:
    """Update mutable fields. ``report_kind`` is intentionally
    immutable — a different kind needs a different schedule so the
    audit trail stays clean. Updating ``cadence`` recomputes
    ``next_run_at`` if the caller did not pass one explicitly.
    """
    row = db.query(ReportSchedule).filter(ReportSchedule.id == schedule_id).first()
    if row is None:
        raise ReportScheduleError(f"report schedule id={schedule_id} not found")
    if name is not None:
        row.name = _bounded_name(name)
    if cadence is not None:
        row.cadence = _require_cadence(cadence)
        if next_run_at is None:
            row.next_run_at = compute_next_run_at(cadence)
    if filters_snapshot is not None:
        row.filters_snapshot = _bounded_filters(filters_snapshot)
    if format is not None:
        row.format = _normalize_format(format)
    if enabled is not None:
        row.enabled = bool(enabled)
    if next_run_at is not None:
        row.next_run_at = next_run_at
    db.commit()
    db.refresh(row)
    return row


def delete_schedule(db: Session, *, schedule_id: int) -> None:
    row = db.query(ReportSchedule).filter(ReportSchedule.id == schedule_id).first()
    if row is None:
        raise ReportScheduleError(f"report schedule id={schedule_id} not found")
    db.delete(row)
    db.commit()


def get_schedule(db: Session, schedule_id: int) -> Optional[ReportSchedule]:
    return db.query(ReportSchedule).filter(ReportSchedule.id == schedule_id).first()


def list_schedules(
    db: Session,
    *,
    report_kind: Optional[str] = None,
    enabled: Optional[bool] = None,
    offset: int = 0,
    limit: int = LIST_SCHEDULES_DEFAULT_LIMIT,
) -> Tuple[List[ReportSchedule], int]:
    if report_kind is not None:
        _require_kind(report_kind)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ReportScheduleError("offset must be a non-negative integer")
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 1
        or limit > LIST_SCHEDULES_MAX_LIMIT
    ):
        raise ReportScheduleError(f"limit must be in 1..{LIST_SCHEDULES_MAX_LIMIT}")

    q = db.query(ReportSchedule)
    if report_kind is not None:
        q = q.filter(ReportSchedule.report_kind == report_kind)
    if enabled is not None:
        q = q.filter(ReportSchedule.enabled == bool(enabled))
    total = q.count()
    rows = q.order_by(ReportSchedule.id.asc()).offset(offset).limit(limit).all()
    return rows, total


# ---------------------------------------------------------------------------
# Dispatcher — report_kind → callable that materializes the export rows
# ---------------------------------------------------------------------------


def _dispatch_patch_executions(db: Session, filters: Dict[str, Any]) -> int:
    from . import patch_reports_service

    after, before = patch_reports_service.resolve_export_window(
        _parse_dt(filters.get("started_after")),
        _parse_dt(filters.get("started_before")),
    )
    rows = patch_reports_service.collect_export_rows(
        db,
        started_after=after,
        started_before=before,
        plan_id=filters.get("plan_id"),
        state=patch_reports_service.validate_state(filters.get("state")),
    )
    return len(rows)


def _dispatch_compliance_remediation_requests(
    db: Session, filters: Dict[str, Any]
) -> int:
    from . import compliance_remediation_export_service

    after, before = compliance_remediation_export_service.resolve_export_window(
        _parse_dt(filters.get("created_after")),
        _parse_dt(filters.get("created_before")),
    )
    rows = compliance_remediation_export_service.collect_export_rows(
        db,
        created_after=after,
        created_before=before,
        policy_id=filters.get("policy_id"),
        system_id=filters.get("system_id"),
        state=compliance_remediation_export_service.validate_state(
            filters.get("state")
        ),
    )
    return len(rows)


def _dispatch_patch_update_plans(db: Session, filters: Dict[str, Any]) -> int:
    from . import _export_helpers, patch_plans_export_service

    after, before = _export_helpers.resolve_export_window(
        _parse_dt(filters.get("created_after")),
        _parse_dt(filters.get("created_before")),
        after_name="created_after",
        before_name="created_before",
    )
    rows = patch_plans_export_service.collect_export_rows(
        db,
        created_after=after,
        created_before=before,
        policy_id=filters.get("policy_id"),
        state=patch_plans_export_service.validate_state(filters.get("state")),
    )
    return len(rows)


def _dispatch_compliance_remediation_plans(db: Session, filters: Dict[str, Any]) -> int:
    from . import _export_helpers, compliance_remediation_plan_export_service

    after, before = _export_helpers.resolve_export_window(
        _parse_dt(filters.get("created_after")),
        _parse_dt(filters.get("created_before")),
        after_name="created_after",
        before_name="created_before",
    )
    rows = compliance_remediation_plan_export_service.collect_export_rows(
        db,
        created_after=after,
        created_before=before,
        policy_id=filters.get("policy_id"),
        system_id=filters.get("system_id"),
        state=compliance_remediation_plan_export_service.validate_state(
            filters.get("state")
        ),
        current_only=bool(filters.get("current_only", False)),
    )
    return len(rows)


def _dispatch_compliance_remediation_executions(
    db: Session, filters: Dict[str, Any]
) -> int:
    from . import _export_helpers, compliance_remediation_execution_export_service

    after, before = _export_helpers.resolve_export_window(
        _parse_dt(filters.get("created_after")),
        _parse_dt(filters.get("created_before")),
        after_name="created_after",
        before_name="created_before",
    )
    rows = compliance_remediation_execution_export_service.collect_export_rows(
        db,
        created_after=after,
        created_before=before,
        policy_id=filters.get("policy_id"),
        system_id=filters.get("system_id"),
        state=compliance_remediation_execution_export_service.validate_state(
            filters.get("state")
        ),
    )
    return len(rows)


# report_kinds that require an execution_id parameter (per-execution
# exports). The schedule must carry the id in ``filters_snapshot``.
def _dispatch_patch_reboot_queues(db: Session, filters: Dict[str, Any]) -> int:
    from . import patch_reboots_export_service

    execution_id = filters.get("execution_id")
    if not isinstance(execution_id, int) or isinstance(execution_id, bool):
        raise ReportScheduleError(
            "patch_reboot_queues schedules require integer "
            "filters_snapshot.execution_id"
        )
    rows = patch_reboots_export_service.collect_export_rows(
        db, execution_id=execution_id
    )
    return len(rows)


def _dispatch_patch_rollback_runs(db: Session, filters: Dict[str, Any]) -> int:
    from . import patch_rollbacks_export_service

    execution_id = filters.get("execution_id")
    if not isinstance(execution_id, int) or isinstance(execution_id, bool):
        raise ReportScheduleError(
            "patch_rollback_runs schedules require integer "
            "filters_snapshot.execution_id"
        )
    rows = patch_rollbacks_export_service.collect_export_rows(
        db, execution_id=execution_id
    )
    return len(rows)


def _dispatch_compliance_evidence(db: Session, filters: Dict[str, Any]) -> int:
    # PRA-165 evidence export streams via yield_per; for scheduled
    # use we just count the rows that would be in the bounded window
    # so the report_runs row is honest about scope. Defer the actual
    # serialized blob to a later slice if operators want artifact
    # storage too.
    from . import compliance_evaluation_service

    after, before = (
        compliance_evaluation_service._resolve_export_window_or_default(  # type: ignore[attr-defined]
            _parse_dt(filters.get("evaluated_after")),
            _parse_dt(filters.get("evaluated_before")),
        )
        if hasattr(compliance_evaluation_service, "_resolve_export_window_or_default")
        else (
            _parse_dt(filters.get("evaluated_after"))
            or (datetime.utcnow() - timedelta(days=30)),
            _parse_dt(filters.get("evaluated_before")) or datetime.utcnow(),
        )
    )
    count = 0
    for _row in compliance_evaluation_service.iter_evidence_for_export(
        db,
        evaluated_after=after,
        evaluated_before=before,
        policy_id=filters.get("policy_id"),
        system_id=filters.get("system_id"),
        verdict=filters.get("verdict"),
    ):
        count += 1
    return count


def _schedule_smart_group_members(
    db: Session, smart_group_id: Any
) -> Optional[List[int]]:
    """Resolve a scheduled package report's optional ``smart_group_id`` to its
    member system ids (tenant-wide — the scheduler has no per-user fleet scope).
    ``None`` smart_group_id → None (whole fleet)."""
    if smart_group_id is None:
        return None
    from ..db.models import SmartGroupMembership

    return [
        r[0]
        for r in db.query(SmartGroupMembership.system_id)
        .filter(SmartGroupMembership.smart_group_id == smart_group_id)
        .all()
    ]


def _resolve_scheduled_outdated_system_ids(
    db: Session, filters: Dict[str, Any]
) -> Optional[List[int]]:
    """Resolve a scheduled ``package_outdated`` report's system scope from
    ``filters_snapshot``, honoring ``system_id`` + ``smart_group_id`` with the
    SAME intersection semantics as the manual export route (which the catalog
    advertises):

    * neither → ``None`` (fleet-wide);
    * ``smart_group_id`` only → its members;
    * ``system_id`` only → just that system;
    * both → the intersection (empty if the system isn't in the group).

    A present-but-non-integer ``system_id`` fails safely with
    ``ReportScheduleError`` rather than silently broadening to fleet/group scope.
    """
    members = _schedule_smart_group_members(db, filters.get("smart_group_id"))
    system_id = filters.get("system_id")
    if system_id is None:
        return members
    if isinstance(system_id, bool) or not isinstance(system_id, int):
        raise ReportScheduleError(
            "package_outdated schedules with a system_id require an integer "
            "filters_snapshot.system_id"
        )
    if members is None:
        return [system_id]
    return [system_id] if system_id in members else []


def _dispatch_package_outdated(db: Session, filters: Dict[str, Any]) -> int:
    from . import package_reports_export_service

    rows = package_reports_export_service.collect_outdated_export_rows(
        db,
        security_only=bool(filters.get("security_only", False)),
        name_filter=filters.get("name_filter"),
        system_ids=_resolve_scheduled_outdated_system_ids(db, filters),
    )
    return len(rows)


def _dispatch_package_compliance(db: Session, filters: Dict[str, Any]) -> int:
    from . import package_reports_export_service

    rows = package_reports_export_service.collect_compliance_export_rows(
        db,
        system_ids=_schedule_smart_group_members(db, filters.get("smart_group_id")),
    )
    return len(rows)


DISPATCH_MAP: Dict[str, Callable[[Session, Dict[str, Any]], int]] = {
    report_run_service.REPORT_KIND_PATCH_EXECUTIONS: _dispatch_patch_executions,
    report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS: (
        _dispatch_compliance_remediation_requests
    ),
    report_run_service.REPORT_KIND_COMPLIANCE_EVIDENCE: (_dispatch_compliance_evidence),
    report_run_service.REPORT_KIND_PATCH_UPDATE_PLANS: (_dispatch_patch_update_plans),
    report_run_service.REPORT_KIND_PATCH_REBOOT_QUEUES: (_dispatch_patch_reboot_queues),
    report_run_service.REPORT_KIND_PATCH_ROLLBACK_RUNS: (_dispatch_patch_rollback_runs),
    report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_PLANS: (
        _dispatch_compliance_remediation_plans
    ),
    report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_EXECUTIONS: (
        _dispatch_compliance_remediation_executions
    ),
    report_run_service.REPORT_KIND_PACKAGE_OUTDATED: _dispatch_package_outdated,
    report_run_service.REPORT_KIND_PACKAGE_COMPLIANCE: _dispatch_package_compliance,
}


def _parse_dt(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601-ish string back into a naive UTC datetime so
    the dispatcher can pass it to the underlying export's
    ``resolve_export_window`` helper. Returns None on missing /
    unparsable input (the helper then applies its default)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    raw = value.rstrip("Z")
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Scheduler tick
# ---------------------------------------------------------------------------


def fire_due_schedules(
    db: Session, *, now: Optional[datetime] = None
) -> Dict[str, int]:
    """Walk every enabled schedule whose ``next_run_at`` is in the
    past, dispatch its underlying export, and advance ``next_run_at``.

    Returns a small counter dict keyed on the per-schedule outcome
    (``fired_succeeded`` / ``fired_failed`` / ``skipped_not_due``).

    Idempotency / race-safety (Slice 5a fix to the P1 review
    finding): the claim is a single conditional UPDATE keyed on the
    previously-seen ``next_run_at``. Two concurrent scheduler ticks
    can both enumerate the same due row, but only one's UPDATE
    rowcount=1 — the loser's UPDATE matches zero rows and the dispatch
    is skipped. The dispatch only runs after the conditional UPDATE
    proves we won the claim.
    """
    counters = {"fired_succeeded": 0, "fired_failed": 0, "skipped_not_due": 0}
    current_now = now or datetime.utcnow()

    due = (
        db.query(ReportSchedule)
        .filter(ReportSchedule.enabled.is_(True))
        .filter(ReportSchedule.next_run_at.isnot(None))
        .filter(ReportSchedule.next_run_at <= current_now)
        .order_by(ReportSchedule.next_run_at.asc())
        .all()
    )

    for schedule in due:
        # Snapshot the claim-anchor BEFORE the SELECT-loaded row's
        # next_run_at can be mutated by another committer.
        previous_next = schedule.next_run_at
        new_next = compute_next_run_at(schedule.cadence, anchor=current_now)

        # Atomic claim via conditional UPDATE: only one concurrent
        # tick wins the row for this due window. The losing tick's
        # rowcount is 0, so we increment skipped_not_due and move on.
        claimed = (
            db.query(ReportSchedule)
            .filter(ReportSchedule.id == schedule.id)
            .filter(ReportSchedule.enabled.is_(True))
            .filter(ReportSchedule.next_run_at == previous_next)
            .update(
                {ReportSchedule.next_run_at: new_next},
                synchronize_session=False,
            )
        )
        db.commit()
        if not claimed:
            # Lost the race or the schedule was disabled / advanced
            # since our SELECT — leave the winning tick to drive the
            # firing for this window.
            counters["skipped_not_due"] += 1
            continue
        # Refresh the ORM object so subsequent reads see the
        # post-claim state and so the failed-run branch below
        # snapshots the right filters_snapshot.
        db.refresh(schedule)

        try:
            # Validate date-typed filter keys before dispatch so a
            # legacy schedule that was created with malformed dates
            # (pre Slice 5a) still fails loudly rather than silently
            # widening the scheduled export to the default window
            # (Slice 5a fix to the P2 review finding).
            _validate_filter_dates(dict(schedule.filters_snapshot or {}))
            dispatcher = DISPATCH_MAP[schedule.report_kind]
            row_count = dispatcher(db, dict(schedule.filters_snapshot or {}))
            run = report_run_service.record_completed_run(
                db,
                report_kind=schedule.report_kind,
                triggered_by=report_run_service.TRIGGERED_BY_SYSTEM_SCHEDULED,
                triggered_by_user_id=schedule.created_by,
                triggered_by_username=None,
                format=schedule.format,
                filters_snapshot=dict(schedule.filters_snapshot or {}),
                row_count=row_count,
                started_at=current_now,
            )
            schedule.last_run_at = current_now
            schedule.last_run_id = run.id
            schedule.last_run_state = report_run_service.STATE_SUCCEEDED
            db.commit()
            counters["fired_succeeded"] += 1
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(
                "report schedule %d (%s) fire failed (was due at %s): %s",
                schedule.id,
                schedule.report_kind,
                previous_next,
                exc,
            )
            # Persist a failed report_runs row so operators can see the
            # error in the Recent Reports panel.
            try:
                run = ReportRun(
                    report_kind=schedule.report_kind,
                    triggered_by=report_run_service.TRIGGERED_BY_SYSTEM_SCHEDULED,
                    triggered_by_user_id=schedule.created_by,
                    triggered_by_username=None,
                    format=schedule.format,
                    filters_snapshot=dict(schedule.filters_snapshot or {}),
                    row_count=None,
                    state=report_run_service.STATE_FAILED,
                    error_message=str(exc)[:MAX_ERROR_MESSAGE_CHARS],
                    started_at=current_now,
                    completed_at=current_now,
                )
                db.add(run)
                db.commit()
                schedule.last_run_at = current_now
                schedule.last_run_id = run.id
                schedule.last_run_state = report_run_service.STATE_FAILED
                db.commit()
            except Exception as inner:  # pylint: disable=broad-except
                logger.warning(
                    "failed to record failed report_runs row for schedule %d: %s",
                    schedule.id,
                    inner,
                )
                db.rollback()
            counters["fired_failed"] += 1

    return counters


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _utc_iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat() + "Z"
    return value.isoformat()


def schedule_read_envelope(row: ReportSchedule) -> Dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "report_kind": row.report_kind,
        "cadence": row.cadence,
        "filters_snapshot": dict(row.filters_snapshot or {}),
        "format": row.format,
        "enabled": bool(row.enabled),
        "next_run_at": _utc_iso(row.next_run_at),
        "last_run_at": _utc_iso(row.last_run_at),
        "last_run_id": row.last_run_id,
        "last_run_state": row.last_run_state,
        "created_by_user_id": row.created_by,
        "created_at": _utc_iso(row.created_at),
        "updated_at": _utc_iso(row.updated_at),
    }
