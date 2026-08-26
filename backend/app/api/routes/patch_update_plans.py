"""Patch update plan routes (PRA-164 slices 1 + 2 + 3).

Mounted at ``/patch/update-plans``. Slice 1 shipped dry-run plan
creation, list, get, refresh, and cancel; Slice 2 added per-host
selection-preview readback and a plan-wide selection lookup; Slice
3 adds per-host preflight snapshot readback (strict version-level
content-availability state). No execution path, approval creation,
probes, reboot, rollback, mirror rebuild/re-sign, or airgap changes
land here.

Conventions:

* Empty-string paths for the collection root + the global
  ``redirect_slashes=False`` setting (per
  ``feedback_trailing_slash.md``).
* Literal segments (``/dry-run``, ``/{plan_id}/refresh``,
  ``/{plan_id}/cancel``, ``/{plan_id}/hosts``,
  ``/{plan_id}/selected-packages``) are declared BEFORE
  ``/{plan_id}`` so the FastAPI route-ordering rule
  (``feedback_fastapi_route_ordering.md``) is satisfied.
* :class:`PatchUpdatePlanError` whose message contains "not found"
  maps to HTTP 404; everything else maps to HTTP 422 (the same
  PRA-161 / PRA-162 service-error disambiguation contract).
* Audit emission for ``patch_update_plan.created`` / ``.refreshed`` /
  ``.canceled`` / ``.selection_recomputed`` happens inside the
  service after its own commit.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.responses import Response as FastAPIResponse
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.schemas.patch_reboots import (
    PatchUpdateExecutionRebootRowRead,
    PatchUpdateExecutionRebootSummary,
    PatchUpdatePlanRebootExecutionRef,
    PatchUpdatePlanRebootQueue,
)
from app.api.schemas.patch_rollbacks import (
    PatchUpdateExecutionRollbackRead,
    PatchUpdateExecutionRollbackSummary,
    PatchUpdatePlanRollbackExecutionRef,
    PatchUpdatePlanRollbackRead,
    PatchUpdatePlanRollbackSummary,
)
from app.api.schemas.patch_update_plans import (
    PatchUpdatePlanApprovalDecision,
    PatchUpdatePlanApprovalRequest,
    PatchUpdatePlanArchiveRequest,
    PatchUpdatePlanCreate,
    PatchUpdatePlanDetail,
    PatchUpdatePlanHostRead,
    PatchUpdatePlanPreflightSnapshotRead,
    PatchUpdatePlanRead,
    PatchUpdatePlanScheduleRequest,
    PatchUpdatePlanSelectedPackageRead,
    PatchUpdatePlanSupersedeRequest,
)
from app.core.auth import get_current_user, require_role
from app.db.models import (
    PatchUpdateExecutionReboot,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    PatchUpdatePlanPreflightSnapshot,
    PatchUpdatePlanSelectedPackage,
)
from app.db.session import get_db
from app.services import (
    _export_helpers,
    patch_plans_export_service,
    patch_reboot_service,
    patch_rollback_service,
    patch_update_plan_service,
    report_run_service,
)
from app.services.access_authorization_service import scoped_system_ids
from app.services.patch_reboot_service import PatchUpdateRebootError, utc_iso
from app.services.patch_rollback_service import PatchUpdateRollbackError
from app.services.patch_update_plan_service import (
    VALID_CONTENT_AVAILABILITY_STATES,
    VALID_PLAN_STATES,
    VALID_SELECTION_STATES,
    PatchUpdatePlanError,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["patch-update-plans"])


# ---------------------------------------------------------------------------
# PRA-281: fleet-scope plan visibility
#
# A patch update plan's authoritative target host set is its non-null
# ``PatchUpdatePlanHost.system_id`` rows. ``system_id`` is nullable only as a
# deleted-system tombstone (``ON DELETE SET NULL``) — never a live/auto-discovery
# placeholder — so tombstone rows are excluded from the scope decision.
#
# Visibility rule (conservative default): a plan is visible/operable to a scoped
# caller ONLY when its non-null target host set is non-empty AND fully within the
# caller's fleet scope. Mixed, hidden-only, empty-target, and tenant-wide/
# auto-discovered plans are a non-disclosing 404 for direct ``plan_id`` reads and
# actions, and are excluded from lists/exports. Tenant-wide admins are unchanged.
# ---------------------------------------------------------------------------


def _plan_target_system_ids(db: Session, plan_id: int) -> set:
    """Non-null target system-id set for a single plan."""
    return {
        r[0]
        for r in db.query(PatchUpdatePlanHost.system_id)
        .filter(
            PatchUpdatePlanHost.plan_id == plan_id,
            PatchUpdatePlanHost.system_id.isnot(None),
        )
        .all()
    }


def _bulk_plan_members(db: Session, plan_ids: List[int]) -> dict:
    """Map every ``plan_id`` to its non-null target system-id set in one query."""
    members: dict = {pid: set() for pid in plan_ids}
    if not plan_ids:
        return members
    for pid, sid in (
        db.query(PatchUpdatePlanHost.plan_id, PatchUpdatePlanHost.system_id)
        .filter(
            PatchUpdatePlanHost.plan_id.in_(plan_ids),
            PatchUpdatePlanHost.system_id.isnot(None),
        )
        .all()
    ):
        members[pid].add(sid)
    return members


def _plan_visible_to_scope(members: set, scope) -> bool:
    """``scope is None`` = tenant-wide admin (always visible). Otherwise the plan
    is visible only when its non-null target set is non-empty and fully in scope."""
    if scope is None:
        return True
    return bool(members) and members.issubset(scope)


def _scoped_plan_or_404(db: Session, current_user, plan_id: int) -> None:
    """Non-disclosing 404 for a scoped caller when the plan is missing, hidden,
    mixed, empty-target, or auto-discovered — BEFORE any host snapshot, package
    row, preflight, reboot/rollback summary, export bundle, or mutation side
    effect. Admins pass through untouched (route does its own existence check)."""
    scope = scoped_system_ids(db, current_user)
    if scope is None:
        return
    if patch_update_plan_service.get_plan(
        db, plan_id
    ) is None or not _plan_visible_to_scope(
        _plan_target_system_ids(db, plan_id), scope
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch update plan {plan_id} not found",
        )


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _host_to_read(host: PatchUpdatePlanHost) -> dict:
    return {
        "id": host.id,
        "plan_id": host.plan_id,
        "system_id": host.system_id,
        "system_hostname_snapshot": host.system_hostname_snapshot,
        "policy_id_snapshot": host.policy_id_snapshot,
        "policy_slug_snapshot": host.policy_slug_snapshot,
        "policy_resolution_kind": host.policy_resolution_kind,
        "ring_id_snapshot": host.ring_id_snapshot,
        "ring_slug_snapshot": host.ring_slug_snapshot,
        "ring_name_snapshot": host.ring_name_snapshot,
        "ring_sort_order_snapshot": host.ring_sort_order_snapshot,
        "ring_source_tier": host.ring_source_tier,
        "ring_resolution_status": host.ring_resolution_status,
        "wave_index": host.wave_index,
        "content_profile_state": host.content_profile_state,
        "content_profile_id_snapshot": host.content_profile_id_snapshot,
        "content_profile_slug_snapshot": host.content_profile_slug_snapshot,
        "content_profile_display_name_snapshot": (
            host.content_profile_display_name_snapshot
        ),
        "content_profile_package_family_snapshot": (
            host.content_profile_package_family_snapshot
        ),
        "content_profile_conflict_snapshot": list(
            host.content_profile_conflict_snapshot or []
        ),
        "state": host.state,
        "block_reasons": list(host.block_reasons or []),
        # Slice 2: per-host selection-preview rollup; null for blocked
        # hosts and any host whose system was deleted before selection.
        "selection_summary": (
            dict(host.selection_summary) if host.selection_summary else None
        ),
        # Slice 3: per-host preflight rollup; null for blocked hosts,
        # hosts whose system was deleted before preflight, and hosts
        # whose Slice 2 selection produced zero rows.
        "preflight_summary": (
            dict(host.preflight_summary) if host.preflight_summary else None
        ),
        "created_at": host.created_at,
        "updated_at": host.updated_at,
    }


def _preflight_to_read(row: PatchUpdatePlanPreflightSnapshot) -> dict:
    return {
        "id": row.id,
        "plan_host_id": row.plan_host_id,
        "package_name": row.package_name,
        "installed_version_at_preflight": row.installed_version_at_preflight,
        "package_manager_family_snapshot": row.package_manager_family_snapshot,
        "content_availability_state": row.content_availability_state,
        "availability_details": dict(row.availability_details or {}),
        "evaluated_at": row.evaluated_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _selected_to_read(row: PatchUpdatePlanSelectedPackage) -> dict:
    return {
        "id": row.id,
        "plan_host_id": row.plan_host_id,
        "package_name": row.package_name,
        "installed_version_snapshot": row.installed_version_snapshot,
        "available_version_snapshot": row.available_version_snapshot,
        "advisory_id_snapshot": row.advisory_id_snapshot,
        "advisory_source_kind_snapshot": row.advisory_source_kind_snapshot,
        "advisory_class_snapshot": row.advisory_class_snapshot,
        "advisory_severity_snapshot": row.advisory_severity_snapshot,
        "selection_reason": row.selection_reason,
        "state": row.state,
        "details": dict(row.details or {}),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _plan_to_read(plan: PatchUpdatePlan, flags: Optional[dict] = None) -> dict:
    base = {
        "id": plan.id,
        "policy_id": plan.policy_id,
        "name": plan.name,
        "description": plan.description,
        "state": plan.state,
        "scheduled_start_at": plan.scheduled_start_at,
        "maintenance_window_id": plan.maintenance_window_id,
        "reboot_window_id": plan.reboot_window_id,
        "policy_snapshot": dict(plan.policy_snapshot or {}),
        "ring_sequence_snapshot": list(plan.ring_sequence_snapshot or []),
        "request_snapshot": dict(plan.request_snapshot or {}),
        "block_reasons": list(plan.block_reasons or []),
        "created_by": plan.created_by,
        "archived_at": plan.archived_at,
        "archived_by": plan.archived_by,
        "archive_reason": plan.archive_reason,
        "created_at": plan.created_at,
        "updated_at": plan.updated_at,
    }
    if flags is not None:
        base.update(flags)
    return base


def _plan_flags(db: Session, plan: PatchUpdatePlan) -> dict:
    """Per-plan cleanup affordances (single-plan endpoints). The list route
    batches this to avoid N+1 — see _rows_with_flags."""
    return patch_update_plan_service.plan_action_flags(
        plan,
        has_lifecycle_history=patch_update_plan_service.plan_has_lifecycle_history(
            db, plan
        ),
    )


def _rows_with_flags(db: Session, plans: List[PatchUpdatePlan]) -> List[dict]:
    """Serialize a page of plans with batch-computed cleanup affordances."""
    history = patch_update_plan_service.lifecycle_history_by_plan(db, plans)
    return [
        _plan_to_read(
            p,
            patch_update_plan_service.plan_action_flags(
                p, has_lifecycle_history=history.get(p.id, False)
            ),
        )
        for p in plans
    ]


def _plan_to_detail(db: Session, plan: PatchUpdatePlan) -> dict:
    base = _plan_to_read(plan, _plan_flags(db, plan))
    hosts = patch_update_plan_service.list_plan_hosts(db, plan.id)
    base["hosts"] = [_host_to_read(h) for h in hosts]
    # Slice 4: include the most recent approval status so the operator
    # UI can render approve/reject controls without a follow-up call.
    base["approval"] = patch_update_plan_service.get_plan_approval(db, plan)
    return base


def _error_to_http(exc: PatchUpdatePlanError) -> HTTPException:
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


def _actor_ip(request) -> Optional[str]:
    if request is None or request.client is None:
        return None
    return request.client.host


# ---------------------------------------------------------------------------
# Dry-run create — explicit ``/dry-run`` URL so the surface is honest
# about what the endpoint produces (a plan, not permission to execute).
# ---------------------------------------------------------------------------


@router.post(
    "/dry-run",
    response_model=PatchUpdatePlanDetail,
    status_code=status.HTTP_201_CREATED,
)
def create_patch_update_plan_dry_run(
    body: PatchUpdatePlanCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    # PRA-281: gate the target set BEFORE the service creates a plan, snapshots
    # hosts, resolves policy, runs selection, or emits audit.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        if body.target_system_ids is None:
            # Auto-discovery materializes EVERY system bound to the policy — a
            # fleet-wide plan a scoped caller must not create. Require an explicit
            # in-scope target list; auto-discovery is tenant-wide-admin-only.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "auto-discovery (omitted target_system_ids) requires a "
                    "tenant-wide administrator; specify target_system_ids"
                ),
            )
        # NOTE: an explicit EMPTY list never reaches here — the
        # ``PatchUpdatePlanCreate._target_system_ids`` schema validator rejects
        # ``[]`` with a 422 before the route body, so no zero-host blocked plan can
        # be persisted (verified by test_patch_plan_dry_run_rejects_empty_...).
        # Explicit targets: reject the whole request with a non-disclosing 404 if
        # any id is out of scope, before any service side effect.
        for sid in body.target_system_ids:
            if sid not in scope:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="System not found",
                )
    try:
        plan = patch_update_plan_service.create_plan(
            db,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            policy_id=body.policy_id,
            name=body.name,
            description=body.description,
            target_system_ids=body.target_system_ids,
            scheduled_start_at=body.scheduled_start_at,
            maintenance_window_id=body.maintenance_window_id,
            reboot_window_id=body.reboot_window_id,
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc

    logger.info(
        "created patch update plan id=%d policy=%d state=%s",
        plan.id,
        plan.policy_id,
        plan.state,
    )
    return _plan_to_detail(db, plan)


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


@router.get("", response_model=List[PatchUpdatePlanRead])
def list_patch_update_plans(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    policy_id: Optional[int] = Query(None, ge=1),
    state: Optional[str] = Query(None),
    include_archived: bool = Query(False),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> Any:
    if state is not None and state not in VALID_PLAN_STATES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"state must be one of {sorted(VALID_PLAN_STATES)}",
        )
    scope = scoped_system_ids(db, current_user)
    try:
        if scope is None:
            rows, _total = patch_update_plan_service.list_plans(
                db,
                policy_id=policy_id,
                state=state,
                include_archived=include_archived,
                offset=offset,
                limit=limit,
            )
            return _rows_with_flags(db, rows)
        # PRA-281: a scoped caller sees only fully-in-scope plans. Fetch the
        # matching set, filter by visibility, then apply offset/limit against the
        # VISIBLE set so hidden plans never occupy a page slot.
        candidate, _total = patch_update_plan_service.list_plans(
            db,
            policy_id=policy_id,
            state=state,
            include_archived=include_archived,
            offset=0,
            limit=100_000,
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    members = _bulk_plan_members(db, [p.id for p in candidate])
    visible = [
        p for p in candidate if _plan_visible_to_scope(members.get(p.id, set()), scope)
    ]
    return _rows_with_flags(db, visible[offset : offset + limit])


# ---------------------------------------------------------------------------
# PRA-178 Slice 4: bounded review-period export of patch update plans.
# Literal-segment ``/export`` declared BEFORE ``/{plan_id}`` per the
# FastAPI route-ordering rule. Admin/maintainer-only (matches the
# Slice 1 patch executions export).
# ---------------------------------------------------------------------------


@router.get("/export", response_class=StreamingResponse)
def export_patch_update_plans(
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    format: str = Query(default="csv"),
    created_after: Optional[datetime] = Query(default=None),
    created_before: Optional[datetime] = Query(default=None),
    policy_id: Optional[int] = Query(default=None, ge=1),
    state: Optional[str] = Query(default=None),
) -> Any:
    """Bounded review-period export of patch update plans.

    Defaults to the last 30 days when both bounds are omitted; refuses
    inverted windows, windows longer than 366 days, or filter sets that
    would produce more than 50,000 rows with HTTP 422. Emits
    ``patch_plan_export.requested`` AFTER materialization and persists a
    ``report_runs`` row through the Slice 2 hook so the export shows up
    in the Recent Reports panel.
    """
    try:
        fmt = _export_helpers.validate_format(format)
        validated_state = patch_plans_export_service.validate_state(state)
        after, before = _export_helpers.resolve_export_window(
            created_after,
            created_before,
            after_name="created_after",
            before_name="created_before",
        )
        rows = patch_plans_export_service.collect_export_rows(
            db,
            created_after=after,
            created_before=before,
            policy_id=policy_id,
            state=validated_state,
        )
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    # PRA-281: a scoped caller's export includes only fully-in-scope plans. Each
    # export row is keyed by ``id`` = plan.id; drop rows for non-visible plans
    # before serialization, audit, and the report-run record.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        row_plan_ids = [r["id"] for r in rows]
        members = _bulk_plan_members(db, row_plan_ids)
        rows = [
            r
            for r in rows
            if _plan_visible_to_scope(members.get(r["id"], set()), scope)
        ]

    filters = patch_plans_export_service.filters_for_audit(
        created_after=after,
        created_before=before,
        policy_id=policy_id,
        state=validated_state,
    )
    _export_helpers.emit_export_requested(
        action=patch_plans_export_service.AUDIT_PATCH_PLAN_EXPORT_REQUESTED,
        target_kind="patch_update_plan_export",
        actor_user_id=current_user.id,
        actor_username=getattr(current_user, "username", None),
        actor_ip=_actor_ip(request),
        export_format=fmt,
        filters=filters,
        row_count=len(rows),
    )
    report_run_service.safe_record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_PATCH_UPDATE_PLANS,
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
                    "attachment; filename=patch-update-plans-export.json"
                )
            },
        )
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(patch_plans_export_service.EXPORT_CSV_COLUMNS),
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
                "attachment; filename=patch-update-plans-export.csv"
            )
        },
    )


# ---------------------------------------------------------------------------
# Refresh / cancel — literal segments declared BEFORE /{plan_id}
# ---------------------------------------------------------------------------


@router.post(
    "/{plan_id}/refresh",
    response_model=PatchUpdatePlanDetail,
)
def refresh_patch_update_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan = patch_update_plan_service.refresh_plan(
            db,
            plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return _plan_to_detail(db, plan)


@router.post(
    "/{plan_id}/cancel",
    response_model=PatchUpdatePlanRead,
)
def cancel_patch_update_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan = patch_update_plan_service.cancel_plan(
            db,
            plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return _plan_to_read(plan, _plan_flags(db, plan))


@router.delete("/{plan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_patch_update_plan(
    plan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Response:
    """PRA-355: delete a pre-execution (test/draft) plan for cleanup.

    Executed plans are refused with a bounded 422 — their execution/reboot/
    rollback/evidence history is immutable audit data.
    """
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        patch_update_plan_service.delete_plan(
            db,
            plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{plan_id}/hosts",
    response_model=List[PatchUpdatePlanHostRead],
)
def list_patch_update_plan_hosts(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        hosts = patch_update_plan_service.list_plan_hosts(db, plan_id)
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return [_host_to_read(h) for h in hosts]


# ---------------------------------------------------------------------------
# Slice 2: selection-preview readers
#
# Both literal-segment routes are declared before /{plan_id} so the
# detail handler does not swallow their paths.
# ---------------------------------------------------------------------------


@router.get(
    "/{plan_id}/hosts/{plan_host_id}/selected-packages",
    response_model=List[PatchUpdatePlanSelectedPackageRead],
)
def list_patch_update_plan_host_selected_packages(
    plan_id: int,
    plan_host_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    # PRA-281: gate the plan first so a hidden plan_host_id under a hidden plan is
    # not probeable; the service filters selected packages by ``plan_id`` so a
    # plan_host_id from another plan yields no rows.
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        rows = patch_update_plan_service.list_host_selected_packages(
            db, plan_id=plan_id, plan_host_id=plan_host_id
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return [_selected_to_read(r) for r in rows]


@router.get(
    "/{plan_id}/selected-packages",
    response_model=List[PatchUpdatePlanSelectedPackageRead],
)
def list_patch_update_plan_selected_packages(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    state: Optional[str] = Query(None),
) -> Any:
    if state is not None and state not in VALID_SELECTION_STATES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"state must be one of {sorted(VALID_SELECTION_STATES)}",
        )
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        rows = patch_update_plan_service.list_plan_selected_packages(
            db, plan_id=plan_id, state=state
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return [_selected_to_read(r) for r in rows]


# ---------------------------------------------------------------------------
# Slice 3: preflight readers
#
# Both literal-segment routes are declared before /{plan_id} so the
# detail handler does not swallow their paths.
# ---------------------------------------------------------------------------


@router.get(
    "/{plan_id}/hosts/{plan_host_id}/preflight",
    response_model=List[PatchUpdatePlanPreflightSnapshotRead],
)
def list_patch_update_plan_host_preflight(
    plan_id: int,
    plan_host_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    # PRA-281: gate the plan first (see selected-packages) — the service filters
    # preflight rows by ``plan_id`` so a foreign plan_host_id yields no rows.
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        rows = patch_update_plan_service.list_host_preflight(
            db, plan_id=plan_id, plan_host_id=plan_host_id
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return [_preflight_to_read(r) for r in rows]


@router.get(
    "/{plan_id}/preflight",
    response_model=List[PatchUpdatePlanPreflightSnapshotRead],
)
def list_patch_update_plan_preflight(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    content_availability_state: Optional[str] = Query(None),
) -> Any:
    if (
        content_availability_state is not None
        and content_availability_state not in VALID_CONTENT_AVAILABILITY_STATES
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "content_availability_state must be one of "
                f"{sorted(VALID_CONTENT_AVAILABILITY_STATES)}"
            ),
        )
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        rows = patch_update_plan_service.list_plan_preflight(
            db,
            plan_id=plan_id,
            content_availability_state=content_availability_state,
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return [_preflight_to_read(r) for r in rows]


# ---------------------------------------------------------------------------
# Slice 4: approval / schedule / supersede / export
#
# All literal-segment routes are declared before /{plan_id} so the
# detail handler does not swallow their paths.
# ---------------------------------------------------------------------------


@router.post(
    "/{plan_id}/approval/request",
    response_model=PatchUpdatePlanDetail,
)
def request_patch_update_plan_approval(
    plan_id: int,
    body: PatchUpdatePlanApprovalRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan = patch_update_plan_service.request_approval(
            db,
            plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            expires_at=body.expires_at,
            comment=body.comment,
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return _plan_to_detail(db, plan)


@router.post(
    "/{plan_id}/approval/approve",
    response_model=PatchUpdatePlanDetail,
)
def approve_patch_update_plan(
    plan_id: int,
    body: PatchUpdatePlanApprovalDecision,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Decisive approve.

    Disambiguates by plan state: ``draft`` plans whose policy does
    not require approval take the direct-approve path; plans in
    ``awaiting_approval`` take the vote path. Anything else returns
    422 with the structured plan-state error from the service.
    """
    _scoped_plan_or_404(db, current_user, plan_id)
    plan_lookup = patch_update_plan_service.get_plan(db, plan_id)
    if plan_lookup is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch update plan {plan_id} not found",
        )
    try:
        if plan_lookup.state == patch_update_plan_service.PLAN_STATE_DRAFT:
            plan = patch_update_plan_service.approve_directly(
                db,
                plan_id,
                actor_user_id=current_user.id,
                actor_username=getattr(current_user, "username", None),
                comment=body.comment,
            )
        else:
            plan = patch_update_plan_service.record_approval_vote(
                db,
                plan_id,
                actor_user_id=current_user.id,
                decision="approve",
                actor_username=getattr(current_user, "username", None),
                comment=body.comment,
            )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return _plan_to_detail(db, plan)


@router.post(
    "/{plan_id}/approval/reject",
    response_model=PatchUpdatePlanDetail,
)
def reject_patch_update_plan(
    plan_id: int,
    body: PatchUpdatePlanApprovalDecision,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Record a rejection vote against the plan's pending approval.
    Only valid for plans in ``awaiting_approval`` (use cancel for
    drafts that should never be approved)."""
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan = patch_update_plan_service.record_approval_vote(
            db,
            plan_id,
            actor_user_id=current_user.id,
            decision="reject",
            actor_username=getattr(current_user, "username", None),
            comment=body.comment,
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return _plan_to_detail(db, plan)


@router.post(
    "/{plan_id}/schedule",
    response_model=PatchUpdatePlanDetail,
)
def schedule_patch_update_plan(
    plan_id: int,
    body: PatchUpdatePlanScheduleRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan = patch_update_plan_service.schedule_plan(
            db,
            plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            scheduled_start_at=body.scheduled_start_at,
            maintenance_window_id=body.maintenance_window_id,
            reboot_window_id=body.reboot_window_id,
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return _plan_to_detail(db, plan)


@router.post(
    "/{plan_id}/supersede",
    response_model=PatchUpdatePlanDetail,
)
def supersede_patch_update_plan(
    plan_id: int,
    body: PatchUpdatePlanSupersedeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan = patch_update_plan_service.supersede_plan(
            db,
            plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            comment=body.comment,
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return _plan_to_detail(db, plan)


@router.post(
    "/{plan_id}/archive",
    response_model=PatchUpdatePlanDetail,
)
def archive_patch_update_plan(
    plan_id: int,
    request: Request,
    body: Optional[PatchUpdatePlanArchiveRequest] = None,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    """PRA-355: admin archive/retire of a plan WITH patch-lifecycle history.

    Non-destructive — hides the plan from normal operator lists/selectors while
    preserving every evidence row (approvals, executions, reboot, rollback,
    selected-package) as an immutable tombstone. Admin-only; hard delete stays
    available (admin/maintainer) for true pre-history drafts only.
    """
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan = patch_update_plan_service.archive_plan(
            db,
            plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
            reason=body.reason if body is not None else None,
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    return _plan_to_detail(db, plan)


@router.get("/{plan_id}/export")
def export_patch_update_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> FastAPIResponse:
    """JSON audit-export bundle. Returns a download with
    Content-Disposition `attachment` so operator browsers save the
    file directly. Reads existing storage only — no execution; emits
    `patch_update_plan.exported`."""
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        bundle = patch_update_plan_service.build_export_bundle(
            db,
            plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except PatchUpdatePlanError as exc:
        raise _error_to_http(exc) from exc
    payload = json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")
    return FastAPIResponse(
        content=payload,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f"attachment; filename=patch-update-plan-{plan_id}.json"
            )
        },
    )


# ---------------------------------------------------------------------------
# PRA-172 slice 1: plan-scoped reboot queue read.
#
# Literal ``/reboots`` segment declared BEFORE ``/{plan_id}`` so the
# detail handler does not swallow the path
# (``feedback_fastapi_route_ordering.md``).
# ---------------------------------------------------------------------------


def _reboot_row_to_read(row: PatchUpdateExecutionReboot) -> dict:
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


@router.get(
    "/{plan_id}/reboots",
    response_model=PatchUpdatePlanRebootQueue,
)
def get_patch_update_plan_reboot_queue(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    """Plan-scoped reboot queue read.

    Walks every execution started for the plan and returns the union
    of reboot-queue rows + an aggregate summary. Empty plans (no
    executions yet, or no reconciled queue rows) return zero-count
    summaries rather than refusing — the plan surface is read-only
    and must not require a prior reconcile to render.

    Returns 404 only when the plan id does not exist; 422 on any
    other semantic error (none currently raised in Slice 1)."""
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan, executions, rows, summary = patch_reboot_service.get_plan_reboot_queue(
            db, plan_id
        )
    except PatchUpdateRebootError as exc:
        msg = str(exc)
        if "not found" in msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=msg
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg
        ) from exc

    # Build per-execution refs with the same UTC convention.
    execution_summaries: dict = {e.id: [] for e in executions}
    for row in rows:
        execution_summaries.setdefault(row.execution_id, []).append(row)

    execution_refs = [
        PatchUpdatePlanRebootExecutionRef(
            execution_id=e.id,
            execution_state=e.state,
            started_at=utc_iso(e.started_at),
            completed_at=utc_iso(e.completed_at),
            summary=PatchUpdateExecutionRebootSummary(
                **patch_reboot_service.build_reboot_summary(
                    execution_summaries.get(e.id, []),
                    reconciliation=patch_reboot_service.evaluate_reconciliation(
                        db, e.id
                    ),
                )
            ),
        )
        for e in executions
    ]

    return {
        "plan_id": plan.id,
        "plan_state": plan.state,
        "summary": PatchUpdateExecutionRebootSummary(**summary),
        "executions": execution_refs,
        "rows": [
            PatchUpdateExecutionRebootRowRead(**_reboot_row_to_read(r)) for r in rows
        ],
    }


# ---------------------------------------------------------------------------
# PRA-173 slice 1: plan-scoped rollback feasibility read.
#
# Literal ``/rollback`` segment declared BEFORE ``/{plan_id}`` so the
# detail handler does not swallow the path
# (``feedback_fastapi_route_ordering.md``).
# ---------------------------------------------------------------------------


def _plan_rollback_row_to_read(row) -> dict:
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


@router.get(
    "/{plan_id}/rollback",
    response_model=PatchUpdatePlanRollbackRead,
)
def get_patch_update_plan_rollback(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    """Plan-scoped rollback feasibility read.

    Walks every execution started for the plan and returns the
    per-execution rollback header (or ``None`` when no evaluation
    has been run) plus an aggregate summary across every
    ``evaluated`` row. Empty plans (no executions yet, or executions
    with no evaluated rollback rows) return zero-count summaries
    rather than refusing — the plan surface is read-only and must
    not require a prior evaluate to render.

    Returns 404 only when the plan id does not exist; 422 on any
    other semantic error (none currently raised in Slice 1).
    """
    _scoped_plan_or_404(db, current_user, plan_id)
    try:
        plan, pairs, aggregate = patch_rollback_service.get_plan_rollback_summary(
            db, plan_id
        )
    except PatchUpdateRollbackError as exc:
        msg = str(exc)
        if "not found" in msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=msg
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg
        ) from exc

    execution_refs = [
        PatchUpdatePlanRollbackExecutionRef(
            execution_id=execution.id,
            execution_state=execution.state,
            started_at=utc_iso(execution.started_at),
            completed_at=utc_iso(execution.completed_at),
            rollback=(
                PatchUpdateExecutionRollbackRead(
                    **_plan_rollback_row_to_read(rollback_row)
                )
                if rollback_row is not None
                else None
            ),
        )
        for execution, rollback_row in pairs
    ]

    return {
        "plan_id": plan.id,
        "plan_state": plan.state,
        "summary": PatchUpdatePlanRollbackSummary(**aggregate),
        "executions": execution_refs,
    }


# ---------------------------------------------------------------------------
# Detail
# ---------------------------------------------------------------------------


@router.get(
    "/{plan_id}",
    response_model=PatchUpdatePlanDetail,
)
def get_patch_update_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    _scoped_plan_or_404(db, current_user, plan_id)
    plan = patch_update_plan_service.get_plan(db, plan_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch update plan {plan_id} not found",
        )
    return _plan_to_detail(db, plan)
