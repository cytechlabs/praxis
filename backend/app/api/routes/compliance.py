"""Compliance policy routes (PRA-165 slice 1).

Mounted at ``/compliance``. Slice 1 exposes only CRUD + starter-pack
seed. No probe execution, no per-host evidence, no dashboard, no
export — those live in later slices.

Conventions:

* ``APIRouter()`` is used; the FastAPI app already has
  ``redirect_slashes=False`` set globally, and we use empty-string
  paths for the collection root per ``feedback_trailing_slash.md``.
* Service-level :class:`ComplianceError` is mapped to HTTP 422
  (validation), or 404 when the message contains ``"not found"``.
* Audit emission happens inside the service after its own commit
  (see service docstring).
* Slugged lookups are declared BEFORE ``/{policy_id}`` per
  ``feedback_fastapi_route_ordering.md``.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.api.schemas.compliance import (
    ComplianceCheckCreate,
    ComplianceCheckRead,
    ComplianceCheckUpdate,
    ComplianceEvidencePage,
    ComplianceFleetSummary,
    CompliancePolicyCreate,
    CompliancePolicyDetail,
    CompliancePolicyEnabledUpdate,
    CompliancePolicyRead,
    CompliancePolicyRunResult,
    CompliancePolicySummary,
    CompliancePolicyUpdate,
    ComplianceRemediationDecisionBody,
    ComplianceRemediationExecutionAttemptCreate,
    ComplianceRemediationExecutionAttemptPage,
    ComplianceRemediationExecutionAttemptRead,
    ComplianceRemediationExecutionBatchResult,
    ComplianceRemediationExecutionRequestRollup,
    ComplianceRemediationFleetSummary,
    ComplianceRemediationHostInventory,
    ComplianceRemediationPlanPage,
    ComplianceRemediationPlanRead,
    ComplianceRemediationRequestCreate,
    ComplianceRemediationRequestPage,
    ComplianceRemediationRequestRead,
    StarterPackEntryRead,
    StarterPackSeedResult,
)
from app.core.auth import get_current_user, require_role
from app.db.session import get_db
from app.services import (
    _export_helpers,
    access_authorization_service,
    compliance_evaluation_service,
    compliance_remediation_execution_export_service,
    compliance_remediation_execution_service,
    compliance_remediation_export_service,
    compliance_remediation_plan_export_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
    report_run_service,
)
from app.services.compliance_evaluation_service import (
    EVIDENCE_PAGE_DEFAULT,
    EVIDENCE_PAGE_MAX,
    EXPORT_CSV_COLUMNS,
    EXPORT_WINDOW_MAX_DAYS,
    VALID_VERDICTS,
)
from app.services.compliance_service import ComplianceError, utc_iso

logger = logging.getLogger(__name__)


def _actor_ip(request) -> Optional[str]:
    if request is None or request.client is None:
        return None
    return request.client.host


def _compliance_error_to_http(exc: ComplianceError) -> HTTPException:
    msg = str(exc)
    if "not found" in msg:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


# ---------------------------------------------------------------------------
# PRA-281 fleet-scope helpers.
#
# Every host-derived compliance row (evidence / remediation request / plan /
# execution attempt) carries a direct ``system_id`` column, so scoping is a
# plain set membership check. ``scoped_system_ids`` returns ``None`` for a
# tenant-wide admin (no restriction) or the caller's grant set otherwise (an
# empty set = access to nothing).
# ---------------------------------------------------------------------------


def _fleet_scope(db: Session, current_user):
    """The caller's fleet scope: ``None`` (tenant-wide admin) or a set of ids."""
    return access_authorization_service.scoped_system_ids(db, current_user)


def _out_of_scope(scope, system_id) -> bool:
    """True when a scoped caller (``scope`` is a set) may not see ``system_id``.

    Admins (``scope`` is ``None``) always return False. Used to turn an
    out-of-scope direct id or explicit filter into a non-disclosing 404,
    identical to the response for a nonexistent row.
    """
    return scope is not None and system_id is not None and system_id not in scope


def _scoped_request_or_404(db: Session, current_user, request_id: int):
    """Fetch a remediation request, returning a non-disclosing 404 when it is
    missing OR out of the caller's fleet scope (identical response either way).
    Used by every request-keyed read/mutation before any side effect.
    """
    row = compliance_remediation_service.get_request(db, request_id)
    if row is None or _out_of_scope(_fleet_scope(db, current_user), row.system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"compliance remediation request {request_id} not found",
        )
    return row


# ---------------------------------------------------------------------------
# Policy router — mounted at /compliance/policies
# ---------------------------------------------------------------------------


policies_router = APIRouter(tags=["compliance-policies"])


@policies_router.post(
    "",
    response_model=CompliancePolicyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_compliance_policy(
    body: CompliancePolicyCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        policy = compliance_service.create_policy(
            db,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            slug=body.slug,
            name=body.name,
            description=body.description,
            severity=body.severity,
            category=body.category,
            schedule_interval_hours=body.schedule_interval_hours,
            evidence_retention_days=body.evidence_retention_days,
            remediation_guidance=body.remediation_guidance,
            enabled=body.enabled,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return compliance_service.policy_read_envelope(policy)


@policies_router.get("", response_model=List[CompliancePolicyRead])
def list_compliance_policies(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    enabled_only: bool = False,
    built_in_only: bool = False,
    offset: int = 0,
    limit: int = 100,
) -> Any:
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="offset must be >= 0",
        )
    if not (1 <= limit <= 500):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be 1..500",
        )
    rows, _total = compliance_service.list_policies(
        db,
        enabled_only=enabled_only,
        built_in_only=built_in_only,
        offset=offset,
        limit=limit,
    )
    return [compliance_service.policy_read_envelope(p) for p in rows]


# Slugged lookup BEFORE /{policy_id} per
# feedback_fastapi_route_ordering.md.
@policies_router.get(
    "/by-slug/{slug}",
    response_model=CompliancePolicyDetail,
)
def get_compliance_policy_by_slug(
    slug: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    policy = compliance_service.get_policy_by_slug(db, slug)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"compliance policy slug={slug!r} not found",
        )
    return compliance_service.policy_read_envelope(policy, db=db, include_checks=True)


@policies_router.get(
    "/{policy_id}",
    response_model=CompliancePolicyDetail,
)
def get_compliance_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    policy = compliance_service.get_policy(db, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"compliance policy {policy_id} not found",
        )
    return compliance_service.policy_read_envelope(policy, db=db, include_checks=True)


@policies_router.patch(
    "/{policy_id}",
    response_model=CompliancePolicyRead,
)
def update_compliance_policy(
    policy_id: int,
    body: CompliancePolicyUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    updates = body.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="no fields to update",
        )
    try:
        policy = compliance_service.update_policy(
            db,
            policy_id,
            updates,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return compliance_service.policy_read_envelope(policy)


@policies_router.post(
    "/{policy_id}/enabled",
    response_model=CompliancePolicyRead,
)
def set_compliance_policy_enabled(
    policy_id: int,
    body: CompliancePolicyEnabledUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        policy = compliance_service.set_policy_enabled(
            db,
            policy_id,
            body.enabled,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return compliance_service.policy_read_envelope(policy)


@policies_router.post(
    "/{policy_id}/run",
    response_model=CompliancePolicyRunResult,
)
def run_compliance_policy_now(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """PRA-312: evaluate a policy across the fleet right now.

    Operator control so a newly enabled policy does not have to wait for the next
    15-minute scheduler sweep. Same evaluation path (existing facts + inventory);
    evidence + retention behavior is unchanged.
    """
    try:
        summary = compliance_evaluation_service.run_policy_now(
            db,
            policy_id=policy_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    policy = compliance_service.get_policy(db, policy_id)
    return {
        "policy_id": summary.policy_id,
        "policy_slug": summary.policy_slug,
        "run_id": summary.run_id,
        "evaluated_at": utc_iso(summary.evaluated_at),
        "counts": summary.counts,
        "evidence_count": summary.evidence_count,
        "last_run_status": policy.last_run_status if policy else "success",
    }


@policies_router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_compliance_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    try:
        compliance_service.delete_policy(
            db,
            policy_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Check sub-resource — /compliance/policies/{policy_id}/checks
# ---------------------------------------------------------------------------


@policies_router.get(
    "/{policy_id}/checks",
    response_model=List[ComplianceCheckRead],
)
def list_compliance_policy_checks(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        rows = compliance_service.list_checks(db, policy_id)
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return [compliance_service.check_read_envelope(c) for c in rows]


@policies_router.post(
    "/{policy_id}/checks",
    response_model=ComplianceCheckRead,
    status_code=status.HTTP_201_CREATED,
)
def add_compliance_policy_check(
    policy_id: int,
    body: ComplianceCheckCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    try:
        check = compliance_service.add_check(
            db,
            policy_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            slug=body.slug,
            title=body.title,
            kind=body.kind,
            definition=body.definition,
            description=body.description,
            severity_override=body.severity_override,
            remediation_guidance=body.remediation_guidance,
            enabled=body.enabled,
            display_order=body.display_order,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return compliance_service.check_read_envelope(check)


# ---------------------------------------------------------------------------
# Evidence + summary sub-resources on the policies router — Slice 3
#
# Evidence is read-only; admin/maintainer is NOT required because the
# Slice 1 RBAC locks say auditors can read. The list/summary endpoints
# therefore accept any authenticated user (auditor role inclusive).
# Export endpoints below DO require admin/maintainer because they
# return bulk evidence and would otherwise risk auditor exfil with no
# operator approval.
# ---------------------------------------------------------------------------


def _evidence_envelope(row) -> dict:
    return compliance_evaluation_service.evidence_export_row(row)


@policies_router.get(
    "/{policy_id}/evidence",
    response_model=ComplianceEvidencePage,
)
def list_compliance_policy_evidence(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    system_id: Optional[int] = Query(default=None, ge=1),
    verdict: Optional[str] = Query(default=None),
    evaluated_after: Optional[datetime] = Query(default=None),
    evaluated_before: Optional[datetime] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=EVIDENCE_PAGE_DEFAULT, ge=1, le=EVIDENCE_PAGE_MAX),
) -> Any:
    # 404 if the policy doesn't exist, otherwise empty page is a
    # legitimate answer (never-evaluated policy).
    if compliance_service.get_policy(db, policy_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"compliance policy {policy_id} not found",
        )
    # PRA-281: an explicit out-of-scope system_id filter is a non-disclosing 404
    # before the query; rows AND total are additionally scoped to the caller.
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        rows, total = compliance_evaluation_service.list_evidence_paginated(
            db,
            policy_id=policy_id,
            system_id=system_id,
            verdict=verdict,
            evaluated_after=evaluated_after,
            evaluated_before=evaluated_before,
            offset=offset,
            limit=limit,
            allowed_system_ids=scope,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    items = [_evidence_envelope(r) for r in rows]
    next_offset = offset + len(items) if (offset + len(items)) < total else None
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


@policies_router.get(
    "/{policy_id}/summary",
    response_model=CompliancePolicySummary,
)
def get_compliance_policy_summary(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    try:
        # PRA-281: per-host + total rollups are scoped to the caller's fleet.
        return compliance_evaluation_service.policy_summary(
            db,
            policy_id=policy_id,
            allowed_system_ids=_fleet_scope(db, current_user),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc


# ---------------------------------------------------------------------------
# Direct-check sub-resource — /compliance/checks/{check_id}
#
# Lives on a separate router so the URL is short and PATCH/DELETE
# don't need a redundant policy_id segment.
# ---------------------------------------------------------------------------


checks_router = APIRouter(tags=["compliance-checks"])


@checks_router.patch(
    "/{check_id}",
    response_model=ComplianceCheckRead,
)
def update_compliance_check(
    check_id: int,
    body: ComplianceCheckUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    updates = body.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="no fields to update",
        )
    try:
        check = compliance_service.update_check(
            db,
            check_id,
            updates,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return compliance_service.check_read_envelope(check)


@checks_router.delete(
    "/{check_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_compliance_check(
    check_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
):
    try:
        compliance_service.delete_check(
            db,
            check_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Starter-pack sub-resource — /compliance/starter-pack
# ---------------------------------------------------------------------------


starter_pack_router = APIRouter(tags=["compliance-starter-pack"])


@starter_pack_router.get(
    "",
    response_model=List[StarterPackEntryRead],
)
def list_compliance_starter_pack(
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Return a preview of the built-in starter pack. Read-only —
    seeding requires POST and the admin role.
    """
    return compliance_service.starter_pack_preview()


@starter_pack_router.post(
    "/seed",
    response_model=StarterPackSeedResult,
)
def seed_compliance_starter_pack(
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    try:
        return compliance_service.seed_starter_pack(
            db,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc


# ---------------------------------------------------------------------------
# Per-host evidence sub-resource — /compliance/systems/{system_id}/evidence
# ---------------------------------------------------------------------------


systems_router = APIRouter(tags=["compliance-systems"])


@systems_router.get(
    "/{system_id}/evidence",
    response_model=ComplianceEvidencePage,
)
def list_compliance_system_evidence(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    policy_id: Optional[int] = Query(default=None, ge=1),
    verdict: Optional[str] = Query(default=None),
    evaluated_after: Optional[datetime] = Query(default=None),
    evaluated_before: Optional[datetime] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=EVIDENCE_PAGE_DEFAULT, ge=1, le=EVIDENCE_PAGE_MAX),
) -> Any:
    # PRA-281: a direct out-of-scope (or empty-scope) system id is a
    # non-disclosing 404 before any evidence row is returned.
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        rows, total = compliance_evaluation_service.list_evidence_paginated(
            db,
            system_id=system_id,
            policy_id=policy_id,
            verdict=verdict,
            evaluated_after=evaluated_after,
            evaluated_before=evaluated_before,
            offset=offset,
            limit=limit,
            allowed_system_ids=scope,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    items = [_evidence_envelope(r) for r in rows]
    next_offset = offset + len(items) if (offset + len(items)) < total else None
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


# ---------------------------------------------------------------------------
# Fleet summary — /compliance/fleet/summary
#
# Stale-policy definition: ``last_run_at`` is null OR older than
# ``2 * schedule_interval_hours``. Documented inline so operators
# don't have to grok the service module.
# ---------------------------------------------------------------------------


fleet_router = APIRouter(tags=["compliance-fleet"])


@fleet_router.get(
    "/summary",
    response_model=ComplianceFleetSummary,
)
def get_compliance_fleet_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    # PRA-281: every per-policy / per-severity / per-host / total count is
    # scoped to the caller's fleet (admin tenant-wide; empty scope → zeros).
    return compliance_evaluation_service.fleet_summary(
        db, allowed_system_ids=_fleet_scope(db, current_user)
    )


# ---------------------------------------------------------------------------
# Exports — /compliance/exports/evidence.jsonl + /evidence.csv
#
# Both endpoints stream via ``yield_per`` so a multi-million-row
# fleet export does not materialize in backend memory. The audit
# event ``compliance_export.requested`` emits AFTER the last byte
# is generated so the row count + filters are accurate.
# ---------------------------------------------------------------------------


exports_router = APIRouter(tags=["compliance-exports"])


def _export_filters_for_audit(
    *,
    evaluated_after: datetime,
    evaluated_before: datetime,
    policy_id: Optional[int],
    system_id: Optional[int],
    verdict: Optional[str],
) -> dict:
    return {
        "evaluated_after": utc_iso(evaluated_after),
        "evaluated_before": utc_iso(evaluated_before),
        "policy_id": policy_id,
        "system_id": system_id,
        "verdict": verdict,
    }


def _resolve_export_window(
    evaluated_after: Optional[datetime],
    evaluated_before: Optional[datetime],
) -> tuple:
    """Validate + apply defaults for the export time window.

    The window MUST be bounded — see ``EXPORT_WINDOW_MAX_DAYS``. We
    default to the last 7 days when the caller omits both bounds so
    a casual ``GET .../evidence.jsonl`` doesn't accidentally dump
    every evidence row in the database.
    """
    now = datetime.utcnow()
    if evaluated_before is None:
        evaluated_before = now
    if evaluated_after is None:
        evaluated_after = evaluated_before - timedelta(days=7)
    if evaluated_before <= evaluated_after:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="evaluated_before must be strictly greater than evaluated_after",
        )
    if (evaluated_before - evaluated_after) > timedelta(days=EXPORT_WINDOW_MAX_DAYS):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"export window must be <= {EXPORT_WINDOW_MAX_DAYS} days",
        )
    return evaluated_after, evaluated_before


def _validate_export_verdict(verdict: Optional[str]) -> None:
    """Validate ``verdict`` before any ``StreamingResponse`` is
    constructed. The service layer would otherwise raise inside the
    generator and produce a partial / header-only stream — this synchronous check turns a bad filter
    into a normal 422 with no partial bytes on the wire.
    """
    if verdict is None:
        return
    if verdict not in VALID_VERDICTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"verdict must be one of: {list(VALID_VERDICTS)}",
        )


@exports_router.get(
    "/evidence.jsonl",
    response_class=StreamingResponse,
)
def export_evidence_jsonl(
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    evaluated_after: Optional[datetime] = Query(default=None),
    evaluated_before: Optional[datetime] = Query(default=None),
    policy_id: Optional[int] = Query(default=None, ge=1),
    system_id: Optional[int] = Query(default=None, ge=1),
    verdict: Optional[str] = Query(default=None),
):
    _validate_export_verdict(verdict)
    after, before = _resolve_export_window(evaluated_after, evaluated_before)
    # PRA-281: resolve scope and reject an explicit out-of-scope system_id
    # BEFORE any StreamingResponse is constructed (no partial bytes on the wire).
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    actor_id = current_user.id
    actor_username = getattr(current_user, "username", None)
    actor_ip = _actor_ip(request)
    filters = _export_filters_for_audit(
        evaluated_after=after,
        evaluated_before=before,
        policy_id=policy_id,
        system_id=system_id,
        verdict=verdict,
    )
    # PRA-281: record the scoped filter set so the audit never claims a
    # tenant-wide export for a scoped caller.
    if scope is not None:
        filters["scope_system_ids"] = sorted(scope)

    def _stream():
        row_count = 0
        try:
            for row in compliance_evaluation_service.iter_evidence_for_export(
                db,
                evaluated_after=after,
                evaluated_before=before,
                policy_id=policy_id,
                system_id=system_id,
                verdict=verdict,
                allowed_system_ids=scope,
            ):
                payload = compliance_evaluation_service.evidence_export_row(row)
                yield (
                    json.dumps(payload, separators=(",", ":"), default=str) + "\n"
                ).encode("utf-8")
                row_count += 1
        finally:
            # Audit emit AFTER the last row regardless of generator
            # closure — safe_emit opens its own SessionLocal so the
            # request's ``db`` lifetime doesn't matter here.
            compliance_evaluation_service.emit_export_requested_audit(
                actor_user_id=actor_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                export_format="jsonl",
                filters=filters,
                row_count=row_count,
            )
            # PRA-358: record the durable report_run so the evidence export
            # shows up in Recent Reports like every other report kind. db=None
            # opens its own SessionLocal (the request session is unreliable
            # inside the generator's finally).
            report_run_service.safe_record_completed_run(
                report_kind=report_run_service.REPORT_KIND_COMPLIANCE_EVIDENCE,
                triggered_by=report_run_service.TRIGGERED_BY_USER,
                triggered_by_user_id=actor_id,
                triggered_by_username=actor_username,
                format="jsonl",
                filters_snapshot=filters,
                row_count=row_count,
            )

    return StreamingResponse(
        _stream(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=evidence.jsonl"},
    )


@exports_router.get(
    "/evidence.csv",
    response_class=StreamingResponse,
)
def export_evidence_csv(
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    evaluated_after: Optional[datetime] = Query(default=None),
    evaluated_before: Optional[datetime] = Query(default=None),
    policy_id: Optional[int] = Query(default=None, ge=1),
    system_id: Optional[int] = Query(default=None, ge=1),
    verdict: Optional[str] = Query(default=None),
):
    _validate_export_verdict(verdict)
    after, before = _resolve_export_window(evaluated_after, evaluated_before)
    # PRA-281: resolve scope + reject an explicit out-of-scope system_id before
    # any bytes (not even the CSV header) are yielded.
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    actor_id = current_user.id
    actor_username = getattr(current_user, "username", None)
    actor_ip = _actor_ip(request)
    filters = _export_filters_for_audit(
        evaluated_after=after,
        evaluated_before=before,
        policy_id=policy_id,
        system_id=system_id,
        verdict=verdict,
    )
    if scope is not None:
        filters["scope_system_ids"] = sorted(scope)

    def _stream():
        row_count = 0
        # Single reusable in-memory buffer; csv.writer flushes per row
        # via getvalue()/truncate so we don't hold > 1 row in RAM.
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=list(EXPORT_CSV_COLUMNS), extrasaction="ignore"
        )
        writer.writeheader()
        header_bytes = buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate(0)
        yield header_bytes
        try:
            for row in compliance_evaluation_service.iter_evidence_for_export(
                db,
                evaluated_after=after,
                evaluated_before=before,
                policy_id=policy_id,
                system_id=system_id,
                verdict=verdict,
                allowed_system_ids=scope,
            ):
                payload = compliance_evaluation_service.evidence_export_row(row)
                writer.writerow(payload)
                chunk = buf.getvalue().encode("utf-8")
                buf.seek(0)
                buf.truncate(0)
                yield chunk
                row_count += 1
        finally:
            compliance_evaluation_service.emit_export_requested_audit(
                actor_user_id=actor_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                export_format="csv",
                filters=filters,
                row_count=row_count,
            )
            # PRA-358: record the durable report_run (see the jsonl route).
            report_run_service.safe_record_completed_run(
                report_kind=report_run_service.REPORT_KIND_COMPLIANCE_EVIDENCE,
                triggered_by=report_run_service.TRIGGERED_BY_USER,
                triggered_by_user_id=actor_id,
                triggered_by_username=actor_username,
                format="csv",
                filters_snapshot=filters,
                row_count=row_count,
            )

    return StreamingResponse(
        _stream(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=evidence.csv"},
    )


# ---------------------------------------------------------------------------
# PRA-178 Slice 1: bounded review-period export of compliance remediation
# requests. Admin/maintainer-only to mirror the evidence export RBAC.
# Lives on the same ``exports_router`` so the URL family
# (``/compliance/exports/...``) stays consistent. Uses
# ``?format=csv|json`` rather than the ``.jsonl`` / ``.csv`` suffix
# pattern that the streaming evidence export uses — the wire shape here
# is a bounded JSON array / standard CSV (capped at
# ``EXPORT_MAX_ROWS``), not an unbounded NDJSON stream, so a single
# format-flag endpoint is the honest surface.
# ---------------------------------------------------------------------------


@exports_router.get(
    "/remediation-requests",
    response_class=StreamingResponse,
)
def export_compliance_remediation_requests(
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    format: str = Query(default="csv"),
    created_after: Optional[datetime] = Query(default=None),
    created_before: Optional[datetime] = Query(default=None),
    policy_id: Optional[int] = Query(default=None, ge=1),
    system_id: Optional[int] = Query(default=None, ge=1),
    state: Optional[str] = Query(default=None),
) -> Any:
    """Bounded review-period export of compliance remediation requests.

    Defaults to the last
    ``compliance_remediation_export_service.EXPORT_DEFAULT_WINDOW_DAYS``
    days when both bounds are omitted; refuses inverted, oversized, or
    row-cap-exceeding windows with HTTP 422. Stable CSV column order is
    pinned at ``compliance_remediation_export_service.EXPORT_CSV_COLUMNS``;
    JSON returns a JSON array of the same wire shape. Audit event
    ``compliance_remediation_export.requested`` emits AFTER the
    response body is built so the recorded row count is accurate.
    """
    # PRA-281: reject an explicit out-of-scope system_id before any rows are
    # collected; scope the collected set to the caller's fleet.
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        fmt = compliance_remediation_export_service.validate_format(format)
        validated_state = compliance_remediation_export_service.validate_state(state)
        after, before = compliance_remediation_export_service.resolve_export_window(
            created_after, created_before
        )
        rows = compliance_remediation_export_service.collect_export_rows(
            db,
            created_after=after,
            created_before=before,
            policy_id=policy_id,
            system_id=system_id,
            state=validated_state,
            allowed_system_ids=scope,
        )
    except (
        compliance_remediation_export_service.ComplianceRemediationReportError
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    filters = compliance_remediation_export_service.filters_for_audit(
        created_after=after,
        created_before=before,
        policy_id=policy_id,
        system_id=system_id,
        state=validated_state,
    )
    if scope is not None:
        filters["scope_system_ids"] = sorted(scope)
    compliance_remediation_export_service.emit_export_requested_audit(
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
    # a savepoint). Wrapped in safe_record_completed_run so a persist
    # failure cannot break the operator's download.
    report_run_service.safe_record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS,
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
                    "attachment; filename=remediation-requests-export.json"
                )
            },
        )

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(compliance_remediation_export_service.EXPORT_CSV_COLUMNS),
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
                "attachment; filename=remediation-requests-export.csv"
            )
        },
    )


# ---------------------------------------------------------------------------
# PRA-178 Slice 4: bounded review-period exports for remediation
# plans and remediation execution attempts. Admin/maintainer-only —
# mirrors the Slice 1 evidence + remediation-requests RBAC.
# ---------------------------------------------------------------------------


@exports_router.get(
    "/remediation-plans",
    response_class=StreamingResponse,
)
def export_compliance_remediation_plans(
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    format: str = Query(default="csv"),
    created_after: Optional[datetime] = Query(default=None),
    created_before: Optional[datetime] = Query(default=None),
    policy_id: Optional[int] = Query(default=None, ge=1),
    system_id: Optional[int] = Query(default=None, ge=1),
    state: Optional[str] = Query(default=None),
    current_only: bool = Query(default=False),
) -> Any:
    """Bounded review-period export of compliance remediation plans.

    Includes both current and superseded plans by default; pass
    ``current_only=true`` to limit to the active plan per request.
    """
    # PRA-281: reject an explicit out-of-scope system_id before collecting rows.
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        fmt = _export_helpers.validate_format(format)
        validated_state = compliance_remediation_plan_export_service.validate_state(
            state
        )
        after, before = _export_helpers.resolve_export_window(
            created_after,
            created_before,
            after_name="created_after",
            before_name="created_before",
        )
        rows = compliance_remediation_plan_export_service.collect_export_rows(
            db,
            created_after=after,
            created_before=before,
            policy_id=policy_id,
            system_id=system_id,
            state=validated_state,
            current_only=current_only,
            allowed_system_ids=scope,
        )
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    filters = compliance_remediation_plan_export_service.filters_for_audit(
        created_after=after,
        created_before=before,
        policy_id=policy_id,
        system_id=system_id,
        state=validated_state,
        current_only=current_only,
    )
    if scope is not None:
        filters["scope_system_ids"] = sorted(scope)
    _export_helpers.emit_export_requested(
        action=(
            compliance_remediation_plan_export_service.AUDIT_REMEDIATION_PLAN_EXPORT_REQUESTED
        ),
        target_kind="compliance_remediation_plan_export",
        actor_user_id=current_user.id,
        actor_username=getattr(current_user, "username", None),
        actor_ip=_actor_ip(request),
        export_format=fmt,
        filters=filters,
        row_count=len(rows),
    )
    report_run_service.safe_record_completed_run(
        db,
        report_kind=report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_PLANS,
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
                    "attachment; filename=remediation-plans-export.json"
                )
            },
        )
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(compliance_remediation_plan_export_service.EXPORT_CSV_COLUMNS),
        extrasaction="ignore",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": ("attachment; filename=remediation-plans-export.csv")
        },
    )


@exports_router.get(
    "/remediation-executions",
    response_class=StreamingResponse,
)
def export_compliance_remediation_executions(
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
    format: str = Query(default="csv"),
    created_after: Optional[datetime] = Query(default=None),
    created_before: Optional[datetime] = Query(default=None),
    policy_id: Optional[int] = Query(default=None, ge=1),
    system_id: Optional[int] = Query(default=None, ge=1),
    state: Optional[str] = Query(default=None),
) -> Any:
    """Bounded review-period export of compliance remediation
    execution attempts."""
    # PRA-281: reject an explicit out-of-scope system_id before collecting rows.
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        fmt = _export_helpers.validate_format(format)
        validated_state = (
            compliance_remediation_execution_export_service.validate_state(state)
        )
        after, before = _export_helpers.resolve_export_window(
            created_after,
            created_before,
            after_name="created_after",
            before_name="created_before",
        )
        rows = compliance_remediation_execution_export_service.collect_export_rows(
            db,
            created_after=after,
            created_before=before,
            policy_id=policy_id,
            system_id=system_id,
            state=validated_state,
            allowed_system_ids=scope,
        )
    except _export_helpers.ExportError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    filters = compliance_remediation_execution_export_service.filters_for_audit(
        created_after=after,
        created_before=before,
        policy_id=policy_id,
        system_id=system_id,
        state=validated_state,
    )
    if scope is not None:
        filters["scope_system_ids"] = sorted(scope)
    _export_helpers.emit_export_requested(
        action=(
            compliance_remediation_execution_export_service.AUDIT_REMEDIATION_EXECUTION_EXPORT_REQUESTED
        ),
        target_kind="compliance_remediation_execution_export",
        actor_user_id=current_user.id,
        actor_username=getattr(current_user, "username", None),
        actor_ip=_actor_ip(request),
        export_format=fmt,
        filters=filters,
        row_count=len(rows),
    )
    report_run_service.safe_record_completed_run(
        db,
        report_kind=(report_run_service.REPORT_KIND_COMPLIANCE_REMEDIATION_EXECUTIONS),
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
                    "attachment; filename=remediation-executions-export.json"
                )
            },
        )
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(
            compliance_remediation_execution_export_service.EXPORT_CSV_COLUMNS
        ),
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
                "attachment; filename=remediation-executions-export.csv"
            )
        },
    )


# ---------------------------------------------------------------------------
# PRA-167 Slice 1 — non-executing remediation request substrate.
#
# Mounted at /compliance/remediation-requests. Slice 1 exposes
# create / list / get / approve / reject / cancel. Approval flips
# state only — it never runs commands, dispatches jobs, or mutates
# hosts. Later slices will read the approved state and decide whether
# to execute.
#
# RBAC:
#   * POST /            — admin or maintainer (open a request)
#   * GET  /, GET /{id} — any authenticated user (auditor inclusive)
#   * POST /{id}/approve and /reject — admin
#   * POST /{id}/cancel — admin OR the requester (self-withdraw)
# ---------------------------------------------------------------------------


remediation_router = APIRouter(tags=["compliance-remediation"])


def _remediation_envelope(row) -> dict:
    return compliance_remediation_service.remediation_request_read_envelope(row)


@remediation_router.post(
    "",
    response_model=ComplianceRemediationRequestRead,
    status_code=status.HTTP_201_CREATED,
)
def create_compliance_remediation_request(
    body: ComplianceRemediationRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    # PRA-281: a request is host-derived from its evidence row. A scoped caller
    # may not open a request against out-of-scope (or nonexistent) evidence —
    # both yield the same non-disclosing "evidence not found" 404 BEFORE any
    # request row is written or audit emitted.
    scope = _fleet_scope(db, current_user)
    if scope is not None:
        from app.db.compliance_models import CompliancePolicyEvidence

        ev_system_id = (
            db.query(CompliancePolicyEvidence.system_id)
            .filter(CompliancePolicyEvidence.id == body.evidence_id)
            .scalar()
        )
        if ev_system_id is None or ev_system_id not in scope:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"compliance evidence id={body.evidence_id} not found",
            )
    try:
        row = compliance_remediation_service.create_request(
            db,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
            evidence_id=body.evidence_id,
            justification=body.justification,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return _remediation_envelope(row)


@remediation_router.get(
    "",
    response_model=ComplianceRemediationRequestPage,
)
def list_compliance_remediation_requests(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    policy_id: Optional[int] = Query(default=None, ge=1),
    system_id: Optional[int] = Query(default=None, ge=1),
    state: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> Any:
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        rows, total = compliance_remediation_service.list_requests(
            db,
            policy_id=policy_id,
            system_id=system_id,
            state=state,
            offset=offset,
            limit=limit,
            allowed_system_ids=scope,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    items = [_remediation_envelope(r) for r in rows]
    next_offset = offset + len(items) if (offset + len(items)) < total else None
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


@remediation_router.get(
    "/{request_id}",
    response_model=ComplianceRemediationRequestRead,
)
def get_compliance_remediation_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    row = _scoped_request_or_404(db, current_user, request_id)
    return _remediation_envelope(row)


@remediation_router.post(
    "/{request_id}/approve",
    response_model=ComplianceRemediationRequestRead,
)
def approve_compliance_remediation_request(
    request_id: int,
    body: ComplianceRemediationDecisionBody,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    # PRA-281: scope-gate before the state transition / audit.
    _scoped_request_or_404(db, current_user, request_id)
    try:
        row = compliance_remediation_service.approve_request(
            db,
            request_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
            decided_reason=body.decided_reason,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return _remediation_envelope(row)


@remediation_router.post(
    "/{request_id}/reject",
    response_model=ComplianceRemediationRequestRead,
)
def reject_compliance_remediation_request(
    request_id: int,
    body: ComplianceRemediationDecisionBody,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    # PRA-281: scope-gate before the state transition / audit.
    _scoped_request_or_404(db, current_user, request_id)
    try:
        row = compliance_remediation_service.reject_request(
            db,
            request_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
            decided_reason=body.decided_reason,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return _remediation_envelope(row)


@remediation_router.post(
    "/{request_id}/cancel",
    response_model=ComplianceRemediationRequestRead,
)
def cancel_compliance_remediation_request(
    request_id: int,
    body: ComplianceRemediationDecisionBody,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Cancel a remediation request.

    Allowed for: an admin (any pending request) or the original
    requester (self-withdraw — a maintainer who opened a request can
    still close it themselves). The service layer records which case
    applied via the ``self_cancel`` audit flag.
    """
    # PRA-281: non-disclosing 404 for a missing OR out-of-scope request, before
    # the ownership check or any cancel side effect.
    row = _scoped_request_or_404(db, current_user, request_id)
    is_admin = any(r.name == "admin" for r in getattr(current_user, "roles", []) or [])
    if not is_admin and row.requested_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "only an admin or the original requester may cancel this "
                "remediation request"
            ),
        )
    try:
        row = compliance_remediation_service.cancel_request(
            db,
            request_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
            decided_reason=body.decided_reason,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return _remediation_envelope(row)


# ---------------------------------------------------------------------------
# PRA-167 Slice 2 — non-executing remediation execution-plan preview.
#
# Plans are produced from approved Slice 1 remediation requests.
# Building a plan does NOT execute anything, mutate hosts, dispatch
# jobs, refresh facts, scan packages, or change the source request's
# state. The route layer reuses the existing remediation_router so
# the wire shape is intuitive: a plan is a sub-resource of the
# request that owns it. A separate plans_router exposes flat
# list/get-by-id for the dashboard reads.
# ---------------------------------------------------------------------------


def _plan_envelope(plan, db: Optional[Session] = None) -> dict:
    return compliance_remediation_plan_service.remediation_plan_read_envelope(
        plan, db=db
    )


@remediation_router.post(
    "/{request_id}/plan",
    response_model=ComplianceRemediationPlanRead,
)
def build_compliance_remediation_plan(
    request_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Build or refresh the remediation execution-plan preview for an
    approved request. Idempotent: re-posting overwrites the existing
    plan row in place. Never executes anything on the host.
    """
    # PRA-281: scope-gate on the parent request before building the plan.
    _scoped_request_or_404(db, current_user, request_id)
    try:
        plan = compliance_remediation_plan_service.build_or_refresh_plan(
            db,
            request_id=request_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return _plan_envelope(plan, db=db)


@remediation_router.post(
    "/{request_id}/plan/acknowledge",
    response_model=ComplianceRemediationPlanRead,
)
def acknowledge_compliance_remediation_plan(
    request_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    """Acknowledge the current plan preview for a remediation request.

    Operator says "this is the plan I intend to run" — flips the
    metadata only. Does NOT execute, dispatch, refresh, scan,
    install, remove, reboot, or roll back anything.

    Fails closed if the request has no current plan, the plan is
    superseded / already-acknowledged / non-``planned`` /
    stale, or the source request is no longer approved.
    """
    # PRA-281: non-disclosing 404 for a missing OR out-of-scope request.
    _scoped_request_or_404(db, current_user, request_id)
    plan = compliance_remediation_plan_service.get_plan_for_request(db, request_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"compliance remediation request {request_id} has no plan "
                "preview yet"
            ),
        )
    try:
        plan = compliance_remediation_plan_service.acknowledge_plan(
            db,
            plan_id=plan.id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return _plan_envelope(plan, db=db)


@remediation_router.get(
    "/{request_id}/plan",
    response_model=ComplianceRemediationPlanRead,
)
def get_compliance_remediation_plan(
    request_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Any:
    # PRA-281: non-disclosing 404 if the request is missing OR out of scope.
    _scoped_request_or_404(db, current_user, request_id)
    plan = compliance_remediation_plan_service.get_plan_for_request(db, request_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"compliance remediation request {request_id} has no plan "
                "preview yet"
            ),
        )
    return _plan_envelope(plan, db=db)


# Flat plan resource — admin/auditor dashboard read path. Plans
# carry no per-host secret; auditor read access is intentional.
plans_router = APIRouter(tags=["compliance-remediation-plans"])


@plans_router.get(
    "",
    response_model=ComplianceRemediationPlanPage,
)
def list_compliance_remediation_plans(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    state: Optional[str] = Query(default=None),
    plan_kind: Optional[str] = Query(default=None),
    system_id: Optional[int] = Query(default=None, ge=1),
    is_current: Optional[bool] = Query(default=None),
    acknowledged: Optional[bool] = Query(default=None),
    ready_for_execution: Optional[bool] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> Any:
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        rows, total = compliance_remediation_plan_service.list_plans(
            db,
            state=state,
            plan_kind=plan_kind,
            system_id=system_id,
            is_current=is_current,
            acknowledged=acknowledged,
            ready_for_execution=ready_for_execution,
            offset=offset,
            limit=limit,
            allowed_system_ids=scope,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    items = [_plan_envelope(p, db=db) for p in rows]
    next_offset = offset + len(items) if (offset + len(items)) < total else None
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


@plans_router.get(
    "/{plan_id}",
    response_model=ComplianceRemediationPlanRead,
)
def get_compliance_remediation_plan_by_id(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    plan = compliance_remediation_plan_service.get_plan(db, plan_id)
    # PRA-281: an out-of-scope plan is a non-disclosing 404, same as nonexistent.
    if plan is None or _out_of_scope(_fleet_scope(db, current_user), plan.system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"compliance remediation plan {plan_id} not found",
        )
    return _plan_envelope(plan, db=db)


# ---------------------------------------------------------------------------
# PRA-167 Slice 4 — read-only fleet remediation summary + per-host inventory.
#
# Both endpoints are metadata-only: no probes, no facts refresh, no
# package scan, no SSH, no dispatch, no host mutation, no execution.
# Auditor read access is intentional — counts and inventory carry no
# per-host secret.
# ---------------------------------------------------------------------------


remediation_fleet_router = APIRouter(tags=["compliance-remediation-fleet"])


@remediation_fleet_router.get(
    "/fleet-summary",
    response_model=ComplianceRemediationFleetSummary,
)
def get_compliance_remediation_fleet_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Fleet-wide remediation rollup.

    Read-only. Counts come from bounded ``GROUP BY`` queries for the
    request states / current-plan states / per-severity rollup;
    ``acknowledged`` / ``ready_for_execution`` / ``is_stale`` are
    computed in Python over the current-plan slice because they
    consult the live check definition. The current-plan slice has
    one row per request, so the Python pass is linear in
    current-plan count, not in plan history.
    """
    # PRA-281: every request/plan count is scoped to the caller's fleet.
    return compliance_remediation_plan_service.fleet_remediation_summary(
        db, allowed_system_ids=_fleet_scope(db, current_user)
    )


@systems_router.get(
    "/{system_id}/remediation",
    response_model=ComplianceRemediationHostInventory,
)
def get_compliance_system_remediation_inventory(
    system_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    limit: int = Query(default=50, ge=1, le=500),
    open_offset: int = Query(default=0, ge=0),
    approved_offset: int = Query(default=0, ge=0),
    current_plans_offset: int = Query(default=0, ge=0),
    ready_plans_offset: int = Query(default=0, ge=0),
    superseded_offset: int = Query(default=0, ge=0),
) -> Any:
    """Per-host remediation inventory.

    Returns 404 when the host does not exist. All five sections —
    ``open_requests`` / ``approved_requests`` / ``current_plans`` /
    ``ready_plans`` / ``superseded_history`` — are bounded paged
    envelopes (``items`` / ``total`` / ``offset`` / ``limit`` /
    ``next_offset``). The shared ``limit`` applies to every section;
    per-section ``*_offset`` params let operators page through one
    section without disturbing the others. Read-only and
    metadata-only.
    """
    from app.db.models import System

    # PRA-281: a direct out-of-scope (or empty-scope) system id is a
    # non-disclosing 404, identical to a nonexistent host, before any
    # request/plan inventory is resolved.
    if _out_of_scope(_fleet_scope(db, current_user), system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    if db.query(System.id).filter(System.id == system_id).first() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        return compliance_remediation_plan_service.host_remediation_inventory(
            db,
            system_id=system_id,
            limit=limit,
            open_offset=open_offset,
            approved_offset=approved_offset,
            current_plans_offset=current_plans_offset,
            ready_plans_offset=ready_plans_offset,
            superseded_offset=superseded_offset,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc


# ---------------------------------------------------------------------------
# PRA-176 Slice 1 — non-executing compliance remediation execution-attempt
# substrate.
#
# Mounted at /compliance/remediation-executions. Slice 1 exposes
# create / list / get. Creating an attempt persists a durable
# audit-row for an operator's intent to dispatch a current
# acknowledged ready package plan; it does NOT run commands,
# dispatch jobs, queue work, mutate hosts, refresh facts, or scan
# packages. The readiness gate is re-checked at write time so a
# stale UI cannot bypass it by replaying a previously-true
# ``ready_for_execution`` flag.
#
# RBAC:
#   * POST /             — admin (matches PRA-167 plan acknowledge
#                          RBAC; intentionally stricter than the
#                          create-remediation-request RBAC because
#                          this is the "execute decision" surface)
#   * GET  /, GET /{id}  — any authenticated user (auditor inclusive)
# ---------------------------------------------------------------------------


executions_router = APIRouter(tags=["compliance-remediation-executions"])


def _execution_envelope(row) -> dict:
    return compliance_remediation_execution_service.attempt_read_envelope(row)


@executions_router.post(
    "",
    response_model=ComplianceRemediationExecutionAttemptRead,
    status_code=status.HTTP_201_CREATED,
)
def create_compliance_remediation_execution_attempt(
    body: ComplianceRemediationExecutionAttemptCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    """Create a durable remediation execution-attempt record.

    Slice 1 is pre-dispatch: this endpoint persists one row and
    emits one ``compliance_remediation_execution.created`` audit
    event. It does NOT execute, dispatch, queue, run SSH, talk to
    an agent, mutate a host, refresh facts, or scan packages.

    Fails closed (HTTP 422) when the referenced plan is superseded,
    not in state ``planned``, not acknowledged, of a non-package
    plan_kind, stale, or whose source request is no longer
    approved. Returns HTTP 404 when the plan does not exist.
    """
    # PRA-281: an attempt is host-derived from its plan. A scoped caller may not
    # create one against an out-of-scope (or nonexistent) plan — both yield the
    # same non-disclosing 404 BEFORE any attempt row is written or audit emitted.
    scope = _fleet_scope(db, current_user)
    if scope is not None:
        plan = compliance_remediation_plan_service.get_plan(db, body.plan_id)
        if plan is None or plan.system_id not in scope:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"compliance remediation plan {body.plan_id} not found",
            )
    try:
        row = compliance_remediation_execution_service.create_attempt(
            db,
            plan_id=body.plan_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return _execution_envelope(row)


@executions_router.get(
    "",
    response_model=ComplianceRemediationExecutionAttemptPage,
)
def list_compliance_remediation_execution_attempts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    request_id: Optional[int] = Query(default=None, ge=1),
    plan_id: Optional[int] = Query(default=None, ge=1),
    system_id: Optional[int] = Query(default=None, ge=1),
    state: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> Any:
    scope = _fleet_scope(db, current_user)
    if _out_of_scope(scope, system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"system {system_id} not found",
        )
    try:
        rows, total = compliance_remediation_execution_service.list_attempts(
            db,
            request_id=request_id,
            plan_id=plan_id,
            system_id=system_id,
            state=state,
            offset=offset,
            limit=limit,
            allowed_system_ids=scope,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    items = [_execution_envelope(r) for r in rows]
    next_offset = offset + len(items) if (offset + len(items)) < total else None
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


@executions_router.get(
    "/{attempt_id}",
    response_model=ComplianceRemediationExecutionAttemptRead,
)
def get_compliance_remediation_execution_attempt(
    attempt_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    row = compliance_remediation_execution_service.get_attempt(db, attempt_id)
    # PRA-281: an out-of-scope attempt is a non-disclosing 404, same as missing.
    if row is None or _out_of_scope(_fleet_scope(db, current_user), row.system_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"compliance remediation execution attempt {attempt_id} " "not found"
            ),
        )
    return _execution_envelope(row)


# ---------------------------------------------------------------------------
# PRA-176 Slice 2 — single-attempt dispatch through the governed PRA-171
# patch transport.
#
# Admin-only POST that consumes a Slice 1 ``pending`` attempt, re-checks
# the full readiness gate at execution time, builds the package
# install/remove/upgrade argv from the attempt's snapshot fields, and
# delegates to ``patch_execution_dispatch_service.default_dispatch``
# (the same governed transport seam PRA-171 uses). No raw SSH,
# subprocess, package-manager, or local-fallback path is introduced
# here. Fails closed (422) on any readiness-gate, lineage, or
# package-identifier refusal; the service raises before the transport
# is invoked.
# ---------------------------------------------------------------------------


@executions_router.post(
    "/{attempt_id}/dispatch",
    response_model=ComplianceRemediationExecutionAttemptRead,
)
def dispatch_compliance_remediation_execution_attempt(
    attempt_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    """Dispatch one ``pending`` execution attempt.

    Re-runs the Slice 1 readiness gate at execution time (current,
    acknowledged, ``planned``, non-stale, executable package plan
    kind, source request still ``approved``) and refuses with HTTP
    422 on any branch. Returns HTTP 404 when the attempt does not
    exist.

    The attempt transitions through ``pending → dispatched →
    succeeded | failed`` on the same row. ``dispatched`` commits
    before the transport call so a transport hang still leaves a
    durable record; the terminal state and outcome columns commit
    after the transport returns.
    """
    # PRA-281: scope-gate on the attempt's system BEFORE the readiness gate,
    # transport call, or any state transition. Out-of-scope == non-disclosing 404.
    scope = _fleet_scope(db, current_user)
    if scope is not None:
        existing = compliance_remediation_execution_service.get_attempt(db, attempt_id)
        if existing is None or existing.system_id not in scope:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"compliance remediation execution attempt {attempt_id} not found"
                ),
            )
    try:
        row = compliance_remediation_execution_service.dispatch_attempt(
            db,
            attempt_id=attempt_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
    return _execution_envelope(row)


# ---------------------------------------------------------------------------
# PRA-176 Slice 3 — bounded multi-attempt batch dispatch + per-request
# rollup, mounted under the existing remediation-requests sub-resource
# so the operator story stays "I work on one request at a time."
#
# Batch dispatch is admin-only (same RBAC as the single-attempt
# dispatch). Rollup is read-only and accepts any authenticated user
# (auditor inclusive) to match the existing per-request read surfaces.
# Neither endpoint introduces a new transport path; the batch route
# delegates to ``dispatch_attempts_for_request`` which loops the
# governed Slice 2 ``dispatch_attempt`` for each pending row.
# ---------------------------------------------------------------------------


@remediation_router.post(
    "/{request_id}/dispatch-executions",
    response_model=ComplianceRemediationExecutionBatchResult,
)
def dispatch_compliance_remediation_request_batch(
    request_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
    limit: int = Query(
        default=compliance_remediation_execution_service.MAX_BATCH_SIZE,
        ge=1,
        le=compliance_remediation_execution_service.MAX_BATCH_SIZE,
    ),
) -> Any:
    """Dispatch every ``pending`` execution attempt for one
    remediation request, bounded by ``limit``.

    Continue-on-error: failed and refused attempts are recorded in
    the returned batch envelope without stopping the loop. Per-attempt
    audit events still fire from the underlying Slice 2 dispatch path;
    a single ``compliance_remediation_execution.batch_dispatched``
    event emits with the aggregate counts after the loop returns.

    Returns HTTP 404 when the remediation request does not exist.
    Returns HTTP 422 when the ``limit`` query parameter is outside the
    1..MAX_BATCH_SIZE range.
    """
    # PRA-281: fail closed (non-disclosing 404) when the request is hidden,
    # before any attempt is dispatched.
    _scoped_request_or_404(db, current_user, request_id)
    try:
        return compliance_remediation_execution_service.dispatch_attempts_for_request(
            db,
            request_id=request_id,
            actor_user_id=current_user.id,
            actor_username=getattr(current_user, "username", None),
            actor_ip=_actor_ip(request),
            limit=limit,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc


@remediation_router.get(
    "/{request_id}/executions",
    response_model=ComplianceRemediationExecutionRequestRollup,
)
def get_compliance_remediation_request_executions(
    request_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
    offset: int = Query(default=0, ge=0),
    limit: int = Query(
        default=compliance_remediation_execution_service.MAX_BATCH_SIZE,
        ge=1,
        le=compliance_remediation_execution_service.MAX_BATCH_SIZE,
    ),
) -> Any:
    """Read-only paginated aggregate of every execution attempt tied
    to one remediation request.

    Whole-request totals (``total_attempts``, ``counts_by_state``,
    ``counts_by_failure_reason``) reflect the entire request history
    regardless of the returned page. Page-local aggregates
    (``page_counts_by_state``, ``page_counts_by_failure_reason``)
    reflect the returned ``offset..offset+limit`` slice only.
    ``has_more`` / ``next_offset`` make end-of-stream explicit.

    Returns HTTP 404 when the remediation request does not exist.
    Returns HTTP 422 for negative ``offset`` or out-of-range
    ``limit`` via the existing FastAPI Query constraints. Auditor
    read access is intentional — attempt rows carry no per-host
    secret beyond what the per-attempt list/read already exposes.
    """
    # PRA-281: non-disclosing 404 for a hidden request before its execution
    # rollup (which echoes the request's system_id + attempt rows) is built.
    _scoped_request_or_404(db, current_user, request_id)
    try:
        return compliance_remediation_execution_service.attempt_rollup_for_request(
            db,
            request_id=request_id,
            offset=offset,
            limit=limit,
        )
    except ComplianceError as exc:
        raise _compliance_error_to_http(exc) from exc
