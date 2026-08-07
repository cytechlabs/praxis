"""PRA-178 Slice 2 — report-run read API.

Mounted at ``/reports``. Slice 2 exposes a single bounded read
endpoint for the durable ``report_runs`` history written by the
Slice 1 manual export hooks. No mutation routes — operators trigger
report runs via the existing Slice 1 export endpoints, and the
scheduler that would write ``triggered_by='system_scheduled'`` rows
is intentionally deferred to a later slice.

Conventions:

* ``APIRouter()`` is used; the FastAPI app already has
  ``redirect_slashes=False`` set globally, and we use empty-string
  paths for the collection root per ``feedback_trailing_slash.md``.
* Read access is admin / maintainer / auditor — the report-run row
  carries operator filters + row counts + lifecycle, no per-host
  secret, but it also is not relevant to viewer-tier roles. The
  three roles are enforced via ``require_role`` so a viewer (or
  any future read-only role) is denied at the route layer
  (Slice 2a fix to the P1 review finding).
* :class:`ReportRunError` is mapped to HTTP 422 — every failure path
  in :mod:`report_run_service` is a bad filter/vocabulary, not a
  missing row.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.entitlements import REPORTS_SCHEDULED_EXPORTS, require_entitlement
from app.db.session import get_db
from app.services import report_catalog, report_run_service, report_schedule_service
from app.services.access_authorization_service import scoped_system_ids
from app.services.report_run_service import ReportRunError
from app.services.report_schedule_service import ReportScheduleError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["reports"])


def _require_tenant_wide(db: Session, current_user) -> None:
    """PRA-281: report runs and schedules carry an arbitrary ``filters_snapshot``
    (which can encode system/group/tag ids) plus fleet-wide row counts, and are
    not attributable to a single system_id — there is no robust way to scrub a
    scoped view of them. So the whole reporting surface is tenant-wide-admin-only
    for scoped callers: reads return empty, mutations 403. Admin (scope ``None``)
    is unchanged."""
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Managing report schedules requires tenant-wide admin access",
        )


@router.get("/catalog")
def get_report_catalog(
    current_user=Depends(require_role("admin", "maintainer", "auditor")),  # noqa: F841
) -> Dict[str, Any]:
    """PRA-358: the documented report-kind contract.

    Returns one descriptor per report kind (label, description, category,
    supported formats, supported scopes, filter keys, whether it records a run
    and whether it is schedulable). The UI drives human labels + capability from
    this instead of hard-coding backend enum names. Pure metadata — no
    per-system data — so it is role-uniform (admin/maintainer/auditor) with no
    fleet-scope surface.
    """
    return {"report_kinds": report_catalog.list_catalog()}


@router.get("/runs")
def list_report_runs(
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer", "auditor")),  # noqa: F841
    report_kind: Optional[str] = Query(default=None),
    triggered_by: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(
        default=report_run_service.LIST_RUNS_DEFAULT_LIMIT,
        ge=1,
        le=report_run_service.LIST_RUNS_MAX_LIMIT,
    ),
) -> Any:
    """List recent report runs, ordered most-recent first.

    All filters are optional. ``report_kind`` / ``triggered_by`` /
    ``state`` must be drawn from the service-layer vocabularies; bad
    values raise HTTP 422.

    Returns ``{"items": [...], "total": int, "offset": int,
    "limit": int, "next_offset": int | null}``. The shape mirrors the
    existing compliance evidence / remediation list endpoints so the
    operator UI can reuse its pagination helpers.
    """
    # PRA-281: report runs are tenant-wide reporting metadata (arbitrary
    # filters_snapshot + fleet-wide counts) — a scoped caller sees none.
    if scoped_system_ids(db, current_user) is not None:
        return {
            "items": [],
            "total": 0,
            "offset": offset,
            "limit": limit,
            "next_offset": None,
        }
    try:
        rows, total = report_run_service.list_runs(
            db,
            report_kind=report_kind,
            triggered_by=triggered_by,
            state=state,
            since=since,
            until=until,
            offset=offset,
            limit=limit,
        )
    except ReportRunError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    items = [report_run_service.run_read_envelope(r) for r in rows]
    next_offset = offset + len(items) if (offset + len(items)) < total else None
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


# ---------------------------------------------------------------------------
# PRA-178 Slice 5: scheduled report runs.
# ---------------------------------------------------------------------------
#
# - GET   /reports/schedules           — admin / maintainer / auditor read
# - POST  /reports/schedules           — admin / maintainer write
# - PATCH /reports/schedules/{id}      — admin / maintainer write
# - DELETE /reports/schedules/{id}     — admin / maintainer write
#
# Schedules drive the Slice 1/4 export substrate; the scheduler tick
# (apscheduler ``report_schedules_due`` job) walks due rows every 5
# minutes and fires the underlying exports with
# ``triggered_by='system_scheduled'``. RBAC matches the Slice 2
# /reports/runs read endpoint for the GET side and the patch-policy
# writer set for the mutation side. The write surface intentionally
# does NOT expose cron expressions — cadence is plain-language only
# (``daily`` / ``weekly`` / ``monthly``) per feedback_no_cron.md.


class ScheduleCreate(BaseModel):
    name: str
    report_kind: str
    cadence: str
    filters_snapshot: Optional[Dict[str, Any]] = None
    format: Optional[str] = "csv"
    enabled: bool = True
    first_run_at: Optional[datetime] = None


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    cadence: Optional[str] = None
    filters_snapshot: Optional[Dict[str, Any]] = None
    format: Optional[str] = None
    enabled: Optional[bool] = None
    next_run_at: Optional[datetime] = None


def _schedule_error_to_http(exc: ReportScheduleError) -> HTTPException:
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


@router.get("/schedules")
def list_report_schedules(
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer", "auditor")),  # noqa: F841
    report_kind: Optional[str] = Query(default=None),
    enabled: Optional[bool] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(
        default=report_schedule_service.LIST_SCHEDULES_DEFAULT_LIMIT,
        ge=1,
        le=report_schedule_service.LIST_SCHEDULES_MAX_LIMIT,
    ),
) -> Any:
    """List scheduled-report definitions. Read access is
    admin / maintainer / auditor."""
    # PRA-281: schedules carry an arbitrary filters_snapshot — scoped callers
    # see none (tenant-wide reporting metadata).
    if scoped_system_ids(db, current_user) is not None:
        return {
            "items": [],
            "total": 0,
            "offset": offset,
            "limit": limit,
            "next_offset": None,
        }
    try:
        rows, total = report_schedule_service.list_schedules(
            db,
            report_kind=report_kind,
            enabled=enabled,
            offset=offset,
            limit=limit,
        )
    except ReportScheduleError as exc:
        raise _schedule_error_to_http(exc) from exc

    items = [report_schedule_service.schedule_read_envelope(r) for r in rows]
    next_offset = offset + len(items) if (offset + len(items)) < total else None
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


@router.post(
    "/schedules",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_entitlement(REPORTS_SCHEDULED_EXPORTS))],
)
def create_report_schedule(
    body: ScheduleCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Create a scheduled-report definition. Admin/maintainer only."""
    _require_tenant_wide(db, current_user)
    try:
        row = report_schedule_service.create_schedule(
            db,
            name=body.name,
            report_kind=body.report_kind,
            cadence=body.cadence,
            filters_snapshot=body.filters_snapshot,
            format=body.format,
            enabled=body.enabled,
            created_by_user_id=current_user.id,
            first_run_at=body.first_run_at,
        )
    except ReportScheduleError as exc:
        raise _schedule_error_to_http(exc) from exc
    return report_schedule_service.schedule_read_envelope(row)


@router.patch(
    "/schedules/{schedule_id}",
    dependencies=[Depends(require_entitlement(REPORTS_SCHEDULED_EXPORTS))],
)
def update_report_schedule(
    schedule_id: int,
    body: ScheduleUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),  # noqa: F841
) -> Any:
    """Update a scheduled-report definition. ``report_kind`` is
    intentionally immutable — create a new schedule for a different
    kind so the audit trail stays clean."""
    _require_tenant_wide(db, current_user)
    updates = body.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="no fields to update",
        )
    try:
        row = report_schedule_service.update_schedule(
            db, schedule_id=schedule_id, **updates
        )
    except ReportScheduleError as exc:
        raise _schedule_error_to_http(exc) from exc
    return report_schedule_service.schedule_read_envelope(row)


@router.delete(
    "/schedules/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_entitlement(REPORTS_SCHEDULED_EXPORTS))],
)
def delete_report_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),  # noqa: F841
) -> Response:
    _require_tenant_wide(db, current_user)
    try:
        report_schedule_service.delete_schedule(db, schedule_id=schedule_id)
    except ReportScheduleError as exc:
        raise _schedule_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
