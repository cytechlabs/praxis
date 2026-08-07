"""Patch update execution routes (PRA-171 slice 1).

Mounted at ``/patch/update-executions``. Slice 1 ships the
execution-run substrate + live-progress read model only:
``POST /start`` materializes a run from an approved/scheduled
:class:`PatchUpdatePlan`, and the metadata-only controls
(``/{execution_id}/pause`` / ``/resume`` / ``/cancel``) plus the read
endpoints (``/{execution_id}`` and ``/by-plan/{plan_id}``) round out
the surface. **No package execution.** Future PRA-171 slices wire
per-host package-manager dispatch on top of this substrate.

Conventions:

* Empty-string paths for the collection root + the global
  ``redirect_slashes=False`` setting (per ``feedback_trailing_slash.md``).
* Literal segments (``/start``, ``/by-plan/{plan_id}``,
  ``/{execution_id}/pause``, ``/{execution_id}/resume``,
  ``/{execution_id}/cancel``) are declared BEFORE ``/{execution_id}``
  so the FastAPI route-ordering rule
  (``feedback_fastapi_route_ordering.md``) is satisfied.
* :class:`PatchUpdateExecutionError` whose message contains "not found"
  maps to HTTP 404; everything else maps to HTTP 422 (the same
  PRA-161 / PRA-162 / PRA-164 service-error disambiguation contract).
* Audit emission (``patch_update_execution.started`` / ``.paused`` /
  ``.resumed`` / ``.canceled``) happens inside the service after its
  own commit via ``safe_emit`` no ``db=``.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.api.schemas.patch_executions import (
    PatchUpdateExecutionCancelRequest,
    PatchUpdateExecutionDetail,
    PatchUpdateExecutionDispatchHostOutcome,
    PatchUpdateExecutionDispatchResult,
    PatchUpdateExecutionHostPackageRead,
    PatchUpdateExecutionPauseRequest,
    PatchUpdateExecutionStart,
)
from app.api.schemas.patch_reboots import (
    PatchUpdateExecutionRebootDispatchHostOutcome,
    PatchUpdateExecutionRebootDispatchResult,
    PatchUpdateExecutionRebootQueue,
    PatchUpdateExecutionRebootReconcileResponse,
    PatchUpdateExecutionRebootRowRead,
    PatchUpdateExecutionRebootSummary,
    PatchUpdateExecutionRebootVerifyHostOutcome,
    PatchUpdateExecutionRebootVerifyResult,
)
from app.api.schemas.patch_rollbacks import (
    PatchRollbackDispatchBatchResult,
    PatchRollbackDispatchCancelRequest,
    PatchRollbackDispatchDetail,
    PatchRollbackDispatchHostOutcome,
    PatchRollbackDispatchHostPackageRead,
    PatchRollbackDispatchHostRead,
    PatchRollbackDispatchRunRead,
    PatchRollbackDispatchStartRequest,
    PatchRollbackVerifyHostOutcome,
    PatchRollbackVerifyResult,
    PatchUpdateExecutionRollbackApprovalSummary,
    PatchUpdateExecutionRollbackDetail,
    PatchUpdateExecutionRollbackEvaluateResponse,
    PatchUpdateExecutionRollbackHostRead,
    PatchUpdateExecutionRollbackPackageRead,
    PatchUpdateExecutionRollbackRead,
    PatchUpdateExecutionRollbackRequestApproval,
    PatchUpdateExecutionRollbackRequestApprovalResponse,
    PatchUpdateExecutionRollbackSummary,
    PatchUpdateExecutionRollbackVote,
    PatchUpdateExecutionRollbackVoteResponse,
)
from app.core.auth import get_current_user, get_user_roles, require_role
from app.db.models import (
    PatchRollbackDispatchHost,
    PatchRollbackDispatchHostPackage,
    PatchRollbackDispatchRun,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdateExecutionReboot,
    PatchUpdateExecutionRollback,
    PatchUpdateExecutionRollbackHost,
    PatchUpdateExecutionRollbackPackage,
)
from app.db.session import get_db
from app.services import (
    _export_helpers,
    patch_execution_dispatch_service,
    patch_execution_service,
    patch_reboot_dispatch_service,
    patch_reboot_service,
    patch_reboot_verify_service,
    patch_reboots_export_service,
    patch_reports_service,
    patch_rollback_dispatch_service,
    patch_rollback_service,
    patch_rollback_verify_service,
    patch_rollbacks_export_service,
    patch_scope,
    report_run_service,
)
from app.services.access_authorization_service import scoped_system_ids
from app.services.patch_execution_service import PatchUpdateExecutionError
from app.services.patch_reboot_service import PatchUpdateRebootError, utc_iso
from app.services.patch_rollback_service import PatchUpdateRollbackError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["patch-update-executions"])


def require_execution_scope(*allowed_roles: str):
    """PRA-281 Slice 6 shared gate for ``/{execution_id}/...`` routes.

    Runs BEFORE the route body (and thus before any DB state change or SSH/agent
    work): an optional global-role gate (403) then the fleet-scope gate. A scoped
    caller may only see/operate on an execution whose materialized target hosts are
    ENTIRELY within their scope — out-of-scope-only and mixed-scope executions (and
    nonexistent ids) return the same non-disclosing 404, so hidden execution
    existence, host ids/hostnames, package names, snapshots, progress, rollback
    candidates, approval state, and export rows never leak. Admins (tenant-wide
    scope) pass and existence is enforced downstream as before.
    """

    def checker(
        execution_id: int = Path(...),
        current_user=Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        if allowed_roles and not any(
            role in allowed_roles for role in get_user_roles(current_user)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(allowed_roles)}",
            )
        if not patch_scope.execution_visible_to_scope(
            db, execution_id, scoped_system_ids(db, current_user)
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"patch update execution {execution_id} not found",
            )
        return current_user

    return checker


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _package_to_read(row: PatchUpdateExecutionHostPackage) -> dict:
    return {
        "id": row.id,
        "execution_host_id": row.execution_host_id,
        "package_name": row.package_name,
        "requested_version_snapshot": row.requested_version_snapshot,
        "installed_version_before": row.installed_version_before,
        "installed_version_after": row.installed_version_after,
        "package_manager_family_snapshot": row.package_manager_family_snapshot,
        "outcome": row.outcome,
        "error_code": row.error_code,
        "details": dict(row.details or {}),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _host_to_read(host: PatchUpdateExecutionHost) -> dict:
    return {
        "id": host.id,
        "execution_id": host.execution_id,
        "plan_host_id": host.plan_host_id,
        "system_id_snapshot": host.system_id_snapshot,
        "system_hostname_snapshot": host.system_hostname_snapshot,
        "wave_index": host.wave_index,
        "state": host.state,
        "selected_package_count": int(host.selected_package_count or 0),
        "skip_reasons": list(host.skip_reasons or []),
        "error_details": dict(host.error_details or {}),
        "started_at": host.started_at,
        "completed_at": host.completed_at,
        "created_at": host.created_at,
        "updated_at": host.updated_at,
    }


def _execution_to_read(execution: PatchUpdateExecution) -> dict:
    return {
        "id": execution.id,
        "plan_id": execution.plan_id,
        "state": execution.state,
        "started_by": execution.started_by,
        "started_at": execution.started_at,
        "completed_at": execution.completed_at,
        "paused_at": execution.paused_at,
        "canceled_at": execution.canceled_at,
        "max_parallel_per_wave": execution.max_parallel_per_wave,
        "failure_threshold_percent": execution.failure_threshold_percent,
        "pause_reason": execution.pause_reason,
        "cancel_reason": execution.cancel_reason,
        "plan_state_snapshot": execution.plan_state_snapshot,
        "policy_snapshot": dict(execution.policy_snapshot or {}),
        "execution_config_snapshot": dict(execution.execution_config_snapshot or {}),
        "progress_summary": dict(execution.progress_summary or {}),
        "created_at": execution.created_at,
        "updated_at": execution.updated_at,
    }


def _execution_to_detail(db: Session, execution: PatchUpdateExecution) -> dict:
    base = _execution_to_read(execution)
    progress, hosts = patch_execution_service.execution_with_progress(db, execution)[1:]
    base["progress"] = progress
    base["hosts"] = [_host_to_read(h) for h in hosts]
    return base


def _error_to_http(exc: PatchUpdateExecutionError) -> HTTPException:
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


def _reboot_error_to_http(exc: PatchUpdateRebootError) -> HTTPException:
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


def _reboot_row_to_read(row: PatchUpdateExecutionReboot) -> dict:
    # PRA-172 review lock #2: timestamp payloads are absolute UTC.
    # Naive datetimes from the DB are normalized to ``...Z`` so API
    # consumers cannot mistake them for local time.
    return {
        "id": row.id,
        "execution_id": row.execution_id,
        "execution_host_id": row.execution_host_id,
        "plan_id_snapshot": row.plan_id_snapshot,
        "system_id_snapshot": row.system_id_snapshot,
        "system_hostname_snapshot": row.system_hostname_snapshot,
        "wave_index": row.wave_index,
        "state": row.state,
        "reboot_policy_snapshot": row.reboot_policy_snapshot,
        "reboot_window_id_snapshot": row.reboot_window_id_snapshot,
        "reboot_required_fact": row.reboot_required_fact,
        "decision_code": row.decision_code,
        "decision_details": dict(row.decision_details or {}),
        "scheduled_for_at": utc_iso(row.scheduled_for_at),
        "started_at": utc_iso(row.started_at),
        "completed_at": utc_iso(row.completed_at),
        "transport_kind": row.transport_kind,
        "command_snapshot": row.command_snapshot,
        "exit_signal_kind": row.exit_signal_kind,
        "dispatch_details": dict(row.dispatch_details or {}),
        "verified_at": utc_iso(row.verified_at),
        "verification_details": dict(row.verification_details or {}),
        "created_at": utc_iso(row.created_at),
        "updated_at": utc_iso(row.updated_at),
    }


def _rollback_error_to_http(exc: PatchUpdateRollbackError) -> HTTPException:
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


def _rollback_row_to_read(row: PatchUpdateExecutionRollback) -> dict:
    # PRA-173 review lock #2 (carry-forward from PRA-172): persisted
    # / detail / read payload timestamps are absolute UTC.
    return {
        "id": row.id,
        "execution_id": row.execution_id,
        "plan_id_snapshot": row.plan_id_snapshot,
        "execution_state_snapshot": row.execution_state_snapshot,
        "state": row.state,
        "refusal_reason": row.refusal_reason,
        "refusal_details": dict(row.refusal_details or {}),
        "feasibility_summary": PatchUpdateExecutionRollbackSummary(
            **(row.feasibility_summary or {})
        ),
        "evaluated_at": utc_iso(row.evaluated_at),
        "created_at": utc_iso(row.created_at),
        "updated_at": utc_iso(row.updated_at),
    }


def _rollback_host_to_read(row: PatchUpdateExecutionRollbackHost) -> dict:
    return {
        "id": row.id,
        "rollback_id": row.rollback_id,
        "execution_host_id": row.execution_host_id,
        "plan_host_id_snapshot": row.plan_host_id_snapshot,
        "system_id_snapshot": row.system_id_snapshot,
        "system_hostname_snapshot": row.system_hostname_snapshot,
        "wave_index": row.wave_index,
        "execution_host_state_snapshot": row.execution_host_state_snapshot,
        "state": row.state,
        "refusal_reason": row.refusal_reason,
        "refusal_details": dict(row.refusal_details or {}),
        "content_profile_snapshot": dict(row.content_profile_snapshot or {}),
        "package_summary": dict(row.package_summary or {}),
        "evaluated_at": utc_iso(row.evaluated_at),
        "created_at": utc_iso(row.created_at),
        "updated_at": utc_iso(row.updated_at),
    }


def _rollback_package_to_read(row: PatchUpdateExecutionRollbackPackage) -> dict:
    return {
        "id": row.id,
        "rollback_host_id": row.rollback_host_id,
        "execution_host_package_id": row.execution_host_package_id,
        "package_name": row.package_name,
        "package_manager_family_snapshot": row.package_manager_family_snapshot,
        "installed_version_before_snapshot": row.installed_version_before_snapshot,
        "installed_version_after_snapshot": row.installed_version_after_snapshot,
        "requested_version_snapshot": row.requested_version_snapshot,
        "target_rollback_version": row.target_rollback_version,
        "package_outcome_snapshot": row.package_outcome_snapshot,
        "state": row.state,
        "refusal_reason": row.refusal_reason,
        "refusal_details": dict(row.refusal_details or {}),
        "content_evidence": dict(row.content_evidence or {}),
        "command_plan": (dict(row.command_plan) if row.command_plan else None),
        "evaluated_at": utc_iso(row.evaluated_at),
        "created_at": utc_iso(row.created_at),
        "updated_at": utc_iso(row.updated_at),
    }


def _rollback_approval_summary(summary: Optional[dict]) -> Optional[dict]:
    """Serialize the rollback approval summary into the wire shape
    expected by :class:`PatchUpdateExecutionRollbackApprovalSummary`.

    Returns ``None`` when no approval has been requested. Converts
    naive-UTC datetime columns through ``utc_iso`` per the
    PRA-172 / PRA-173 review-lock #2 carry-forward.
    """
    if summary is None:
        return None
    return {
        "rollback_approval_link_id": summary["rollback_approval_link_id"],
        "approval_id": summary["approval_id"],
        "status": summary.get("status"),
        "required_approvals": summary.get("required_approvals"),
        "expires_at": utc_iso(summary.get("expires_at")),
        "decided_by": summary.get("decided_by"),
        "decided_at": utc_iso(summary.get("decided_at")),
        "requested_by": summary["requested_by"],
        "requested_at": utc_iso(summary["requested_at"]),
        "frozen_plan_snapshot": dict(summary.get("frozen_plan_snapshot") or {}),
    }


def _actor_ip(request) -> Optional[str]:
    if request is None or request.client is None:
        return None
    return request.client.host


# ---------------------------------------------------------------------------
# PRA-178 Slice 1: review-period export.
#
# Literal-segment ``/export`` declared BEFORE ``/{execution_id}`` per
# ``feedback_fastapi_route_ordering.md``. Admin/maintainer-only because
# the export bundles every execution row in the review window — auditor
# read is intentionally NOT extended here; auditors can use the per-
# execution detail routes for spot reads.
#
# Review-period bounds, format vocabulary, row cap, and audit emission
# all live in :mod:`patch_reports_service` so later PRA-178 slices that
# schedule the same report can reuse them without re-deriving the row
# shape.
# ---------------------------------------------------------------------------


@router.get(
    "/export",
    response_class=StreamingResponse,
)
def export_patch_update_executions(
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    format: str = Query(default="csv"),
    started_after: Optional[datetime] = Query(default=None),
    started_before: Optional[datetime] = Query(default=None),
    plan_id: Optional[int] = Query(default=None, ge=1),
    state: Optional[str] = Query(default=None),
) -> Any:
    """Bounded review-period export of patch update executions.

    Defaults to the last ``EXPORT_DEFAULT_WINDOW_DAYS`` days when both
    bounds are omitted; refuses inverted windows, windows longer than
    ``EXPORT_WINDOW_MAX_DAYS``, or filter sets that would produce more
    than ``EXPORT_MAX_ROWS`` rows. Stable CSV column order is pinned at
    ``patch_reports_service.EXPORT_CSV_COLUMNS``; JSON returns a JSON
    array of the same wire shape. Audit event
    ``patch_execution_export.requested`` emits AFTER the response body
    is built so the recorded row count is accurate.
    """
    try:
        fmt = patch_reports_service.validate_format(format)
        validated_state = patch_reports_service.validate_state(state)
        after, before = patch_reports_service.resolve_export_window(
            started_after, started_before
        )
        rows = patch_reports_service.collect_export_rows(
            db,
            started_after=after,
            started_before=before,
            plan_id=plan_id,
            state=validated_state,
            # PRA-281: only executions fully in the caller's fleet scope are
            # exported (admin scope=None → all; empty scope → empty export).
            scope_system_ids=scoped_system_ids(db, current_user),
        )
    except patch_reports_service.PatchReportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    filters = patch_reports_service.filters_for_audit(
        started_after=after,
        started_before=before,
        plan_id=plan_id,
        state=validated_state,
    )
    patch_reports_service.emit_export_requested_audit(
        actor_user_id=current_user.id,
        actor_username=getattr(current_user, "username", None),
        actor_ip=_actor_ip(request),
        export_format=fmt,
        filters=filters,
        row_count=len(rows),
    )
    # PRA-178 Slice 2: persist a durable report-run record alongside the
    # audit event. Shares the request session so the row participates in
    # the request transaction and the ``triggered_by_user_id`` FK can
    # see in-flight user rows (matters for tests that seed the user in
    # a savepoint; in production the user is always committed). Wrapped
    # in safe_record_completed_run so a persist failure cannot break
    # the operator's download.
    report_run_service.safe_record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_EXECUTIONS,
        triggered_by=report_run_service.TRIGGERED_BY_USER,
        triggered_by_user_id=current_user.id,
        triggered_by_username=getattr(current_user, "username", None),
        format=fmt,
        filters_snapshot=filters,
        row_count=len(rows),
    )

    if fmt == "json":
        return JSONResponse(
            content=rows,
            headers={
                "Content-Disposition": (
                    "attachment; filename=patch-executions-export.json"
                )
            },
        )

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(patch_reports_service.EXPORT_CSV_COLUMNS),
        extrasaction="ignore",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": ("attachment; filename=patch-executions-export.csv")
        },
    )


# ---------------------------------------------------------------------------
# Start — explicit ``/start`` URL so the surface is honest about the
# transition the endpoint performs (a substrate materialization, not a
# package-manager invocation).
# ---------------------------------------------------------------------------


@router.post(
    "/start",
    response_model=PatchUpdateExecutionDetail,
    status_code=status.HTTP_201_CREATED,
)
def start_patch_update_execution(
    body: PatchUpdateExecutionStart,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    # PRA-281: a scoped caller may only start a plan whose target systems are
    # non-empty and entirely in scope — reject before any materialization or side
    # effect, with a non-disclosing 404 (out-of-scope == mixed == nonexistent).
    scope = scoped_system_ids(db, current_user)
    if scope is not None and not patch_scope.plan_visible_to_scope(
        db, body.plan_id, scope
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch update plan {body.plan_id} not found",
        )
    try:
        execution = patch_execution_service.start_execution(
            db,
            plan_id=body.plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            max_parallel_per_wave=body.max_parallel_per_wave,
            failure_threshold_percent=body.failure_threshold_percent,
        )
    except PatchUpdateExecutionError as exc:
        raise _error_to_http(exc) from exc
    logger.info(
        "started patch update execution id=%d plan=%d state=%s",
        execution.id,
        execution.plan_id,
        execution.state,
    )
    return _execution_to_detail(db, execution)


# ---------------------------------------------------------------------------
# By-plan lookup — literal segment declared BEFORE /{execution_id}.
# Returns 404 when the plan exists but no execution has ever been started
# for it; the operator UI uses this to decide whether to render the
# "Start execution" affordance.
# ---------------------------------------------------------------------------


@router.get(
    "/by-plan/{plan_id}",
    response_model=PatchUpdateExecutionDetail,
)
def get_latest_execution_for_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    # PRA-281: a single uniform 404 for scoped callers whether the plan is out of
    # scope, has no execution, or the execution is out-of-scope/mixed — so a
    # scoped caller cannot probe hidden plan/execution existence.
    scope = scoped_system_ids(db, current_user)
    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=(f"no patch update execution has ever been started for plan {plan_id}"),
    )
    if scope is not None and not patch_scope.plan_visible_to_scope(db, plan_id, scope):
        raise not_found
    try:
        execution = patch_execution_service.latest_execution_for_plan(db, plan_id)
    except PatchUpdateExecutionError as exc:
        raise _error_to_http(exc) from exc
    if execution is None:
        raise not_found
    if scope is not None and not patch_scope.execution_visible_to_scope(
        db, execution.id, scope
    ):
        raise not_found
    return _execution_to_detail(db, execution)


# ---------------------------------------------------------------------------
# Pause / resume / cancel — literal segments declared BEFORE /{execution_id}.
# All three are metadata-only in Slice 1 (no in-flight work to interrupt).
# ---------------------------------------------------------------------------


@router.post(
    "/{execution_id}/pause",
    response_model=PatchUpdateExecutionDetail,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def pause_patch_update_execution(
    execution_id: int,
    body: PatchUpdateExecutionPauseRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        execution = patch_execution_service.pause_execution(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            pause_reason=body.pause_reason,
        )
    except PatchUpdateExecutionError as exc:
        raise _error_to_http(exc) from exc
    return _execution_to_detail(db, execution)


@router.post(
    "/{execution_id}/resume",
    response_model=PatchUpdateExecutionDetail,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def resume_patch_update_execution(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        execution = patch_execution_service.resume_execution(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchUpdateExecutionError as exc:
        raise _error_to_http(exc) from exc
    return _execution_to_detail(db, execution)


@router.post(
    "/{execution_id}/cancel",
    response_model=PatchUpdateExecutionDetail,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def cancel_patch_update_execution(
    execution_id: int,
    body: PatchUpdateExecutionCancelRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        execution = patch_execution_service.cancel_execution(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            cancel_reason=body.cancel_reason,
        )
    except PatchUpdateExecutionError as exc:
        raise _error_to_http(exc) from exc
    return _execution_to_detail(db, execution)


# ---------------------------------------------------------------------------
# Slice 2: dispatch-next + per-host package drill-down
#
# Both literal-segment routes are declared BEFORE /{execution_id} so the
# detail handler does not swallow their paths.
# ---------------------------------------------------------------------------


@router.post(
    "/{execution_id}/dispatch-next",
    response_model=PatchUpdateExecutionDispatchResult,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def dispatch_next_patch_update_execution(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Dispatch the next bounded batch of pending hosts for an
    execution. Slice 2: trigger-based, one batch per call. The
    response includes the refreshed execution detail so the
    operator UI can render the new state without a follow-up
    round-trip."""
    try:
        summary = patch_execution_dispatch_service.dispatch_next_batch(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchUpdateExecutionError as exc:
        raise _error_to_http(exc) from exc

    execution = patch_execution_service.get_execution(db, execution_id)
    return {
        "execution_id": summary.execution_id,
        "wave_index": summary.wave_index,
        "dispatched_count": summary.dispatched_count,
        "succeeded_count": summary.succeeded_count,
        "failed_count": summary.failed_count,
        "no_pending": summary.no_pending,
        "pause_reason": summary.pause_reason,
        "host_outcomes": [
            PatchUpdateExecutionDispatchHostOutcome(**h) for h in summary.host_outcomes
        ],
        "completed_wave_indexes": summary.completed_wave_indexes,
        "threshold_pause": summary.threshold_pause,
        "finalized_state": summary.finalized_state,
        "execution": _execution_to_detail(db, execution),
    }


@router.get(
    "/{execution_id}/hosts/{execution_host_id}/packages",
    response_model=List[PatchUpdateExecutionHostPackageRead],
    dependencies=[Depends(require_execution_scope())],
)
def list_patch_update_execution_host_packages(
    execution_id: int,
    execution_host_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Per-package execution result rows for one execution host.
    Slice 2 read endpoint backing the operator UI's per-host
    package drill-down. Returns 404 when the execution host is not
    part of the named execution."""
    host = (
        db.query(PatchUpdateExecutionHost)
        .filter(
            PatchUpdateExecutionHost.id == execution_host_id,
            PatchUpdateExecutionHost.execution_id == execution_id,
        )
        .first()
    )
    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"execution host id={execution_host_id} not found on "
                f"execution {execution_id}"
            ),
        )
    try:
        rows = patch_execution_dispatch_service.list_host_packages(
            db, execution_host_id
        )
    except PatchUpdateExecutionError as exc:
        raise _error_to_http(exc) from exc
    return [_package_to_read(r) for r in rows]


# ---------------------------------------------------------------------------
# PRA-172 slice 1: reboot queue read + reconcile.
#
# Both literal-segment routes are declared BEFORE /{execution_id} so the
# detail handler does not swallow their paths
# (``feedback_fastapi_route_ordering.md``).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# PRA-178 Slice 4: per-execution reboot queue + rollback runs exports.
# Literal segments declared BEFORE the rest of the
# ``/{execution_id}/reboots/*`` and ``/{execution_id}/rollback/*``
# routes for predictable matching. Admin/maintainer-only — bulk
# evidence dump matches the Slice 1 RBAC.
# ---------------------------------------------------------------------------


@router.get(
    "/{execution_id}/reboots/export",
    response_class=StreamingResponse,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def export_patch_update_execution_reboots(
    execution_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    format: str = Query(default="csv"),
) -> Any:
    """Bounded per-execution export of the reboot queue rows.

    Capped at ``EXPORT_MAX_ROWS = 50_000`` rows; refuses oversized
    requests with HTTP 422. Returns 404 when ``execution_id`` does
    not reference a known patch update execution so the route does
    not silently emit an audit event or persist a report_runs row
    for a typoed id (PRA-178 Slice 4a fix to the P2 review finding). Emits ``patch_reboot_export.requested`` AFTER
    materialization and persists a ``report_runs`` row through the
    Slice 2 hook on success.
    """
    if patch_execution_service.get_execution(db, execution_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch update execution {execution_id} not found",
        )
    try:
        fmt = _export_helpers.validate_format(format)
        rows = patch_reboots_export_service.collect_export_rows(
            db, execution_id=execution_id
        )
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    filters = patch_reboots_export_service.filters_for_audit(execution_id=execution_id)
    _export_helpers.emit_export_requested(
        action=patch_reboots_export_service.AUDIT_PATCH_REBOOT_EXPORT_REQUESTED,
        target_kind="patch_reboot_queue_export",
        actor_user_id=current_user.id,
        actor_username=getattr(current_user, "username", None),
        actor_ip=_actor_ip(request),
        export_format=fmt,
        filters=filters,
        row_count=len(rows),
    )
    report_run_service.safe_record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_REBOOT_QUEUES,
        triggered_by=report_run_service.TRIGGERED_BY_USER,
        triggered_by_user_id=current_user.id,
        triggered_by_username=getattr(current_user, "username", None),
        format=fmt,
        filters_snapshot=filters,
        row_count=len(rows),
    )
    if fmt == "json":
        return JSONResponse(
            content=rows,
            headers={
                "Content-Disposition": (
                    f"attachment; filename=patch-reboots-execution-{execution_id}.json"
                )
            },
        )
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(patch_reboots_export_service.EXPORT_CSV_COLUMNS),
        extrasaction="ignore",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename=patch-reboots-execution-{execution_id}.csv"
            )
        },
    )


@router.get(
    "/{execution_id}/rollback/export",
    response_class=StreamingResponse,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def export_patch_update_execution_rollback(
    execution_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    format: str = Query(default="csv"),
) -> Any:
    """Bounded per-execution export of the rollback dispatch runs +
    per-host rows (mixed ``row_kind`` shape mirroring the live
    detail payload).

    Returns 404 when ``execution_id`` does not reference a known
    patch update execution so the route does not silently emit an
    audit event or persist a report_runs row for a typoed id
    (PRA-178 Slice 4a fix to the P2 review finding).
    """
    if patch_execution_service.get_execution(db, execution_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch update execution {execution_id} not found",
        )
    try:
        fmt = _export_helpers.validate_format(format)
        rows = patch_rollbacks_export_service.collect_export_rows(
            db, execution_id=execution_id
        )
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    filters = patch_rollbacks_export_service.filters_for_audit(
        execution_id=execution_id
    )
    _export_helpers.emit_export_requested(
        action=patch_rollbacks_export_service.AUDIT_PATCH_ROLLBACK_EXPORT_REQUESTED,
        target_kind="patch_rollback_run_export",
        actor_user_id=current_user.id,
        actor_username=getattr(current_user, "username", None),
        actor_ip=_actor_ip(request),
        export_format=fmt,
        filters=filters,
        row_count=len(rows),
    )
    report_run_service.safe_record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_ROLLBACK_RUNS,
        triggered_by=report_run_service.TRIGGERED_BY_USER,
        triggered_by_user_id=current_user.id,
        triggered_by_username=getattr(current_user, "username", None),
        format=fmt,
        filters_snapshot=filters,
        row_count=len(rows),
    )
    if fmt == "json":
        return JSONResponse(
            content=rows,
            headers={
                "Content-Disposition": (
                    f"attachment; filename=patch-rollback-execution-{execution_id}.json"
                )
            },
        )
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(patch_rollbacks_export_service.EXPORT_CSV_COLUMNS),
        extrasaction="ignore",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename=patch-rollback-execution-{execution_id}.csv"
            )
        },
    )


@router.get(
    "/{execution_id}/reboots",
    response_model=PatchUpdateExecutionRebootQueue,
    dependencies=[Depends(require_execution_scope())],
)
def list_patch_update_execution_reboots(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Return the reboot queue for an execution.

    Slice 1 read surface: per-execution rollup + the per-host rows.
    Empty rows + zero-count summary when ``reconcile`` has not run
    yet; the operator UI uses this to decide whether to surface the
    "Initialize reboot queue" affordance."""
    try:
        execution, rows, summary = patch_reboot_service.get_reboot_queue(
            db, execution_id
        )
    except PatchUpdateRebootError as exc:
        raise _reboot_error_to_http(exc) from exc
    return {
        "execution_id": execution.id,
        "execution_state": execution.state,
        "plan_id": execution.plan_id,
        "summary": PatchUpdateExecutionRebootSummary(**summary),
        "rows": [
            PatchUpdateExecutionRebootRowRead(**_reboot_row_to_read(r)) for r in rows
        ],
    }


@router.post(
    "/{execution_id}/reboots/reconcile",
    response_model=PatchUpdateExecutionRebootReconcileResponse,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def reconcile_patch_update_execution_reboots(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),  # noqa: F841
) -> Any:
    """Initialize or refresh the reboot queue for a terminal execution.

    Slice 1: explicit, idempotent reconcile (no background daemon).
    Refuses with 422 when the execution is non-terminal; later
    slices will revisit the gate when reboot scheduling/dispatch
    lands."""
    try:
        patch_reboot_service.reconcile_reboot_queue(db, execution_id)
        execution, rows, summary = patch_reboot_service.get_reboot_queue(
            db, execution_id
        )
    except PatchUpdateRebootError as exc:
        raise _reboot_error_to_http(exc) from exc
    return {
        "execution_id": execution.id,
        "execution_state": execution.state,
        "plan_id": execution.plan_id,
        "summary": PatchUpdateExecutionRebootSummary(**summary),
        "rows": [
            PatchUpdateExecutionRebootRowRead(**_reboot_row_to_read(r)) for r in rows
        ],
    }


@router.post(
    "/{execution_id}/reboots/dispatch-due",
    response_model=PatchUpdateExecutionRebootDispatchResult,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def dispatch_due_patch_update_execution_reboots(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Dispatch one bounded batch of due ``scheduled`` reboot rows.

    Slice 3: trigger-based, one batch per call. Walks rows whose
    ``scheduled_for_at <= now`` and dispatches the reboot command
    over SSH. Successful rows transition to ``rebooting`` and wait
    for a future verification slice; failed rows transition to
    ``failed`` directly with structured ``dispatch_details``. The
    response carries the per-row outcomes plus the refreshed queue
    so the operator UI can render the new state without a follow-up
    round-trip.

    Refuses with 422 when the execution is non-terminal (Slice 3
    only dispatches reboots for executions that have already
    reached their final state — the reboot queue is only populated
    by Slice 2's auto-reconcile hook after finalize)."""
    try:
        summary = patch_reboot_dispatch_service.dispatch_due_reboots(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
        execution, rows, queue_summary = patch_reboot_service.get_reboot_queue(
            db, execution_id
        )
    except PatchUpdateRebootError as exc:
        raise _reboot_error_to_http(exc) from exc

    queue_payload = PatchUpdateExecutionRebootQueue(
        execution_id=execution.id,
        execution_state=execution.state,
        plan_id=execution.plan_id,
        summary=PatchUpdateExecutionRebootSummary(**queue_summary),
        rows=[
            PatchUpdateExecutionRebootRowRead(**_reboot_row_to_read(r)) for r in rows
        ],
    )

    return {
        "execution_id": summary.execution_id,
        "dispatched_count": summary.dispatched_count,
        "succeeded_count": summary.succeeded_count,
        "failed_count": summary.failed_count,
        "not_due_count": summary.not_due_count,
        "no_due": summary.no_due,
        "pause_reason": summary.pause_reason,
        "threshold_pause": summary.threshold_pause,
        "host_outcomes": [
            PatchUpdateExecutionRebootDispatchHostOutcome(
                execution_reboot_id=o.execution_reboot_id,
                execution_host_id=o.execution_host_id,
                system_id=o.system_id,
                state=o.state,
                exit_signal_kind=o.exit_signal_kind,
                transport_kind=o.transport_kind,
                exit_code=o.exit_code,
                error_code=o.error_code,
            )
            for o in summary.host_outcomes
        ],
        "queue": queue_payload,
    }


@router.post(
    "/{execution_id}/reboots/verify-due",
    response_model=PatchUpdateExecutionRebootVerifyResult,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def verify_due_patch_update_execution_reboots(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Verify one bounded batch of due ``rebooting`` reboot rows.

    Slice 4: trigger-based, one batch per call. Walks rows whose
    dispatch ``started_at`` is at least the configured grace
    period in the past, atomically claims each
    ``rebooting`` → ``verifying``, runs the SSH health probe, and
    transitions to ``healthy`` (success) or ``failed`` (terminal
    verification failure). Failures count against the reboot-wave
    failure threshold; on breach the batch stops mid-verify with
    structured pause context.

    Refuses with 422 when the execution is non-terminal."""
    try:
        summary = patch_reboot_verify_service.verify_due_reboots(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
        execution, rows, queue_summary = patch_reboot_service.get_reboot_queue(
            db, execution_id
        )
    except PatchUpdateRebootError as exc:
        raise _reboot_error_to_http(exc) from exc

    queue_payload = PatchUpdateExecutionRebootQueue(
        execution_id=execution.id,
        execution_state=execution.state,
        plan_id=execution.plan_id,
        summary=PatchUpdateExecutionRebootSummary(**queue_summary),
        rows=[
            PatchUpdateExecutionRebootRowRead(**_reboot_row_to_read(r)) for r in rows
        ],
    )

    return {
        "execution_id": summary.execution_id,
        "verified_count": summary.verified_count,
        "succeeded_count": summary.succeeded_count,
        "failed_count": summary.failed_count,
        "not_due_count": summary.not_due_count,
        "no_due": summary.no_due,
        "pause_reason": summary.pause_reason,
        "threshold_pause": summary.threshold_pause,
        "host_outcomes": [
            PatchUpdateExecutionRebootVerifyHostOutcome(
                execution_reboot_id=o.execution_reboot_id,
                execution_host_id=o.execution_host_id,
                system_id=o.system_id,
                state=o.state,
                reason=o.reason,
            )
            for o in summary.host_outcomes
        ],
        "queue": queue_payload,
    }


# ---------------------------------------------------------------------------
# PRA-173 slice 1: rollback feasibility read + evaluate.
#
# Both literal-segment routes are declared BEFORE /{execution_id} so the
# detail handler does not swallow their paths
# (``feedback_fastapi_route_ordering.md``).
# ---------------------------------------------------------------------------


def _rollback_detail_payload(db: Session, execution_id: int) -> dict:
    """Shared response builder for the rollback feasibility detail
    + evaluate endpoints."""
    try:
        (
            execution,
            rollback_row,
            host_rows,
            packages_by_host,
        ) = patch_rollback_service.get_rollback_for_execution(db, execution_id)
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    hosts_payload = [
        PatchUpdateExecutionRollbackHostRead(**_rollback_host_to_read(h))
        for h in host_rows
    ]
    packages_payload: List[PatchUpdateExecutionRollbackPackageRead] = []
    for host_row in host_rows:
        for pkg in packages_by_host.get(host_row.id, []):
            packages_payload.append(
                PatchUpdateExecutionRollbackPackageRead(
                    **_rollback_package_to_read(pkg)
                )
            )

    approval_payload: Optional[PatchUpdateExecutionRollbackApprovalSummary] = None
    if rollback_row is not None:
        raw = patch_rollback_service.get_rollback_approval_summary(db, rollback_row.id)
        approval_dict = _rollback_approval_summary(raw)
        if approval_dict is not None:
            approval_payload = PatchUpdateExecutionRollbackApprovalSummary(
                **approval_dict
            )

    return {
        "execution_id": execution.id,
        "execution_state": execution.state,
        "plan_id": execution.plan_id,
        "rollback": (
            PatchUpdateExecutionRollbackRead(**_rollback_row_to_read(rollback_row))
            if rollback_row is not None
            else None
        ),
        "hosts": hosts_payload,
        "packages": packages_payload,
        "approval": approval_payload,
    }


@router.get(
    "/{execution_id}/rollback",
    response_model=PatchUpdateExecutionRollbackDetail,
    dependencies=[Depends(require_execution_scope())],
)
def get_patch_update_execution_rollback(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Return the rollback feasibility artifact for an execution.

    Slice 1 read surface: per-execution header + per-host + per-
    package rows. ``rollback`` is ``None`` when no evaluation has
    been run yet; the operator UI uses that to decide whether to
    surface the "Evaluate rollback feasibility" affordance."""
    return _rollback_detail_payload(db, execution_id)


@router.post(
    "/{execution_id}/rollback/evaluate",
    response_model=PatchUpdateExecutionRollbackEvaluateResponse,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def evaluate_patch_update_execution_rollback(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Initialize or refresh the rollback feasibility artifact for an
    execution.

    Slice 1: explicit, idempotent evaluation (no background daemon
    and no command planning, approval, or execution). Non-terminal
    executions produce a ``refused`` header row with
    ``execution_not_terminal`` rather than 422-ing — the read API
    must always have an artifact to render."""
    try:
        patch_rollback_service.evaluate_rollback_feasibility(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    return _rollback_detail_payload(db, execution_id)


@router.post(
    "/{execution_id}/rollback/request-approval",
    response_model=PatchUpdateExecutionRollbackRequestApprovalResponse,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def request_patch_update_execution_rollback_approval(
    execution_id: int,
    body: PatchUpdateExecutionRollbackRequestApproval,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Create (or reuse) a rollback-scoped approval request.

    PRA-173 Slice 2: wires the existing PRA-161
    ``patch_approval_service`` primitive
    (``subject_kind='rollback'``) to the rollback feasibility
    artifact and freezes the current per-package command plans
    into the approval link so the dispatch slice (future) reads
    the exact bytes operators voted on. Idempotent: if a still-
    pending approval link already exists, the same row is
    returned without creating a duplicate. **No dispatch / no
    execution / no auto-approval** — the PRA-161 lock holds."""
    expires_at_dt: Optional[Any] = None
    if body.expires_at is not None:
        try:
            from datetime import datetime as _dt

            iso = body.expires_at.rstrip("Z")
            expires_at_dt = _dt.fromisoformat(iso)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"expires_at must be ISO 8601: {exc}",
            ) from exc
    try:
        patch_rollback_service.request_rollback_approval(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            required_approvals=body.required_approvals,
            expires_at=expires_at_dt,
            comment=body.comment,
        )
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    return _rollback_detail_payload(db, execution_id)


@router.post(
    "/{execution_id}/rollback/vote",
    response_model=PatchUpdateExecutionRollbackVoteResponse,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def vote_patch_update_execution_rollback(
    execution_id: int,
    body: PatchUpdateExecutionRollbackVote,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Record one approve/reject vote against the rollback's most
    recent pending approval row.

    Wraps :func:`patch_approval_service.record_vote` so the
    PRA-161 voting semantics (multi-distinct-vote spine,
    reject-shorts, expired-on-access) apply unchanged. Emits
    ``patch_rollback.approved`` / ``patch_rollback.rejected`` on
    the terminal transition. **No dispatch** — Slice 3 owns the
    "approval is approved, now run" boundary."""
    try:
        result = patch_rollback_service.record_rollback_approval_vote(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            decision=body.decision,
            comment=body.comment,
        )
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    return result


# ---------------------------------------------------------------------------
# PRA-173 slice 3: rollback dispatch (start / dispatch-next / cancel / read).
#
# Literal-segment-before-`/{execution_id}` so the detail handler does
# not swallow these paths
# (``feedback_fastapi_route_ordering.md``).
# ---------------------------------------------------------------------------


def _dispatch_run_to_read(run: PatchRollbackDispatchRun) -> dict:
    return {
        "id": run.id,
        "rollback_id": run.rollback_id,
        "rollback_approval_link_id": run.rollback_approval_link_id,
        "state": run.state,
        "started_by": run.started_by,
        "started_at": utc_iso(run.started_at),
        "completed_at": utc_iso(run.completed_at),
        "paused_at": utc_iso(run.paused_at),
        "canceled_at": utc_iso(run.canceled_at),
        "max_parallel": run.max_parallel,
        "pause_reason": run.pause_reason,
        "cancel_reason": run.cancel_reason,
        "progress_summary": dict(run.progress_summary or {}),
        "created_at": utc_iso(run.created_at),
        "updated_at": utc_iso(run.updated_at),
    }


def _dispatch_host_to_read(host: PatchRollbackDispatchHost) -> dict:
    return {
        "id": host.id,
        "rollback_dispatch_run_id": host.rollback_dispatch_run_id,
        "rollback_host_id": host.rollback_host_id,
        "system_id_snapshot": host.system_id_snapshot,
        "system_hostname_snapshot": host.system_hostname_snapshot,
        "state": host.state,
        "error_details": dict(host.error_details or {}),
        "started_at": utc_iso(host.started_at),
        "completed_at": utc_iso(host.completed_at),
        "created_at": utc_iso(host.created_at),
        "updated_at": utc_iso(host.updated_at),
    }


def _dispatch_package_to_read(pkg: PatchRollbackDispatchHostPackage) -> dict:
    return {
        "id": pkg.id,
        "rollback_dispatch_host_id": pkg.rollback_dispatch_host_id,
        "rollback_package_id": pkg.rollback_package_id,
        "package_name": pkg.package_name,
        "package_manager_family_snapshot": pkg.package_manager_family_snapshot,
        "target_rollback_version_snapshot": pkg.target_rollback_version_snapshot,
        "installed_version_before": pkg.installed_version_before,
        "installed_version_after": pkg.installed_version_after,
        "outcome": pkg.outcome,
        "error_code": pkg.error_code,
        "details": dict(pkg.details or {}),
        "created_at": utc_iso(pkg.created_at),
        "updated_at": utc_iso(pkg.updated_at),
    }


def _rollback_dispatch_detail_payload(db: Session, execution_id: int) -> dict:
    """Shared response builder for the rollback dispatch detail +
    start + cancel endpoints."""
    try:
        (
            execution,
            run,
            host_rows,
            packages_by_host,
        ) = patch_rollback_dispatch_service.get_latest_dispatch_for_execution(
            db, execution_id
        )
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    hosts_payload = [
        PatchRollbackDispatchHostRead(**_dispatch_host_to_read(h)) for h in host_rows
    ]
    packages_payload: List[PatchRollbackDispatchHostPackageRead] = []
    for host_row in host_rows:
        for pkg in packages_by_host.get(host_row.id, []):
            packages_payload.append(
                PatchRollbackDispatchHostPackageRead(**_dispatch_package_to_read(pkg))
            )

    return {
        "execution_id": execution.id,
        "execution_state": execution.state,
        "plan_id": execution.plan_id,
        "run": (
            PatchRollbackDispatchRunRead(**_dispatch_run_to_read(run))
            if run is not None
            else None
        ),
        "hosts": hosts_payload,
        "packages": packages_payload,
    }


@router.get(
    "/{execution_id}/rollback/dispatch",
    response_model=PatchRollbackDispatchDetail,
    dependencies=[Depends(require_execution_scope())],
)
def get_patch_update_execution_rollback_dispatch(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Return the latest rollback dispatch artifact for an execution.

    ``run`` is ``None`` when no dispatch has been started; the
    operator UI uses that to decide whether to render the "Start
    rollback dispatch" affordance."""
    return _rollback_dispatch_detail_payload(db, execution_id)


@router.post(
    "/{execution_id}/rollback/start",
    response_model=PatchRollbackDispatchDetail,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def start_patch_update_execution_rollback(
    execution_id: int,
    body: PatchRollbackDispatchStartRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Start a new rollback dispatch run for this execution.

    PRA-173 Slice 3: refuses 422 unless the rollback approval is
    ``approved`` and a frozen plan snapshot exists; refuses 422 if
    a non-terminal dispatch run already exists for this rollback.
    Emits ``patch_rollback.started`` via ``safe_emit`` no ``db=``.
    Does NOT dispatch any package work itself — call
    ``/dispatch-next`` to process bounded batches."""
    try:
        patch_rollback_dispatch_service.start_rollback_execution(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            max_parallel=body.max_parallel,
        )
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    return _rollback_dispatch_detail_payload(db, execution_id)


@router.post(
    "/{execution_id}/rollback/dispatch-next",
    response_model=PatchRollbackDispatchBatchResult,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def dispatch_next_patch_update_execution_rollback(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Dispatch the next bounded batch of pending hosts for the
    latest rollback dispatch run on this execution.

    PRA-173 Slice 3: trigger-based, one batch per call. Consumes
    the frozen plan snapshot only — does NOT re-derive commands
    from the live ``command_plan`` columns. Emits per-host
    ``patch_rollback.host_succeeded`` / ``host_failed`` and a
    final ``patch_rollback.completed`` when every host has a
    terminal state."""
    try:
        # Find the latest run id for this execution and route
        # dispatch-next to it.
        (
            _execution,
            run,
            _hosts,
            _packages_by_host,
        ) = patch_rollback_dispatch_service.get_latest_dispatch_for_execution(
            db, execution_id
        )
        if run is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"execution {execution_id} has no rollback dispatch run; "
                    "call /rollback/start first"
                ),
            )
        summary = patch_rollback_dispatch_service.dispatch_next_batch(
            db,
            run.id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    dispatch_payload = _rollback_dispatch_detail_payload(db, execution_id)

    return {
        "rollback_dispatch_run_id": summary.rollback_dispatch_run_id,
        "dispatched_count": summary.dispatched_count,
        "succeeded_count": summary.succeeded_count,
        "failed_count": summary.failed_count,
        "no_pending": summary.no_pending,
        "finalized_state": summary.finalized_state,
        "host_outcomes": [
            PatchRollbackDispatchHostOutcome(**outcome)
            for outcome in summary.host_outcomes
        ],
        "dispatch": PatchRollbackDispatchDetail(**dispatch_payload),
    }


@router.post(
    "/{execution_id}/rollback/cancel",
    response_model=PatchRollbackDispatchDetail,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def cancel_patch_update_execution_rollback(
    execution_id: int,
    body: PatchRollbackDispatchCancelRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Cancel the latest rollback dispatch run for this execution.

    Metadata-only: pending hosts flip to ``canceled``; succeeded /
    failed rows are preserved. Refuses 422 when the run is already
    terminal."""
    try:
        (
            _execution,
            run,
            _hosts,
            _packages_by_host,
        ) = patch_rollback_dispatch_service.get_latest_dispatch_for_execution(
            db, execution_id
        )
        if run is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"execution {execution_id} has no rollback dispatch run to cancel"
                ),
            )
        patch_rollback_dispatch_service.cancel_rollback_execution(
            db,
            run.id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            cancel_reason=body.cancel_reason,
        )
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    return _rollback_dispatch_detail_payload(db, execution_id)


@router.post(
    "/{execution_id}/rollback/verify-due",
    response_model=PatchRollbackVerifyResult,
    dependencies=[Depends(require_execution_scope("admin", "maintainer"))],
)
def verify_due_patch_update_execution_rollback(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Run one bounded verify-due batch for the latest rollback
    dispatch run on this execution.

    PRA-173 Slice 4: walks dispatch hosts in ``succeeded`` /
    ``failed`` whose package rows still lack
    ``installed_version_after``, probes each host's current
    package versions, writes the observation back to the package
    row, and emits ``PackageHistory`` rows (one per package with a
    resolvable ``Package`` row). Emits
    ``patch_rollback.host_verified`` per host and
    ``patch_rollback.verification_complete`` once when every
    dispatched host is verified or has a recorded refusal."""
    try:
        (
            _execution,
            run,
            _hosts,
            _packages_by_host,
        ) = patch_rollback_dispatch_service.get_latest_dispatch_for_execution(
            db, execution_id
        )
        if run is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"execution {execution_id} has no rollback dispatch run to "
                    "verify; call /rollback/start first"
                ),
            )
        summary = patch_rollback_verify_service.verify_due_rollbacks(
            db,
            run.id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchUpdateRollbackError as exc:
        raise _rollback_error_to_http(exc) from exc

    dispatch_payload = _rollback_dispatch_detail_payload(db, execution_id)

    return {
        "rollback_dispatch_run_id": summary.rollback_dispatch_run_id,
        "attempted_host_count": summary.attempted_host_count,
        "reachable_host_count": summary.reachable_host_count,
        "unreachable_host_count": summary.unreachable_host_count,
        "no_due": summary.no_due,
        "verification_complete": summary.verification_complete,
        "host_outcomes": [
            PatchRollbackVerifyHostOutcome(**outcome)
            for outcome in summary.host_outcomes
        ],
        "dispatch": PatchRollbackDispatchDetail(**dispatch_payload),
    }


# ---------------------------------------------------------------------------
# Detail
# ---------------------------------------------------------------------------


@router.get(
    "/{execution_id}",
    response_model=PatchUpdateExecutionDetail,
    dependencies=[Depends(require_execution_scope())],
)
def get_patch_update_execution(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    execution = patch_execution_service.get_execution(db, execution_id)
    if execution is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch update execution {execution_id} not found",
        )
    return _execution_to_detail(db, execution)
