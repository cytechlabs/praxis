"""PRA-178 Slice 1 — compliance remediation request review-period export.

Read-only service surface for the manual reporting/export foundation.
Slice 1 ships:

* a bounded review-period iterator over
  ``compliance_remediation_requests``
* a stable export wire shape consumed by both CSV and JSON output
* a post-stream audit emission helper

This sits next to :mod:`compliance_evaluation_service`'s
``compliance_export.requested`` evidence export. The two are
intentionally separate because the wire shapes and the operator's
review intent differ — evidence is per-check / per-host verdict
history, while remediation requests are per-decision lineage.

Hard boundaries (slice locks):

* No scheduler, worker, queue, broker, or recurring delivery.
* No host mutation, command execution, dispatch, runner, rollback,
  facts/package refresh, or new probe kinds.
* No notification event expansion or alert delivery retry changes.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from app.services.access_authorization_service import scope_in_clause

from ..db.models import ComplianceRemediationRequest, System, User
from .audit_event_service import safe_emit
from .compliance_remediation_service import VALID_STATES
from .compliance_service import utc_iso

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local error class
# ---------------------------------------------------------------------------


class ComplianceRemediationReportError(ValueError):
    """Raised when a remediation request export is rejected for
    semantic reasons (bad window, bad filter, row cap exceeded)."""


# ---------------------------------------------------------------------------
# Window + size guards — mirror ``patch_reports_service``.
# ---------------------------------------------------------------------------

EXPORT_WINDOW_MAX_DAYS = 366
EXPORT_DEFAULT_WINDOW_DAYS = 30
EXPORT_MAX_ROWS = 50_000
EXPORT_STREAM_CHUNK = 500


AUDIT_COMPLIANCE_REMEDIATION_EXPORT_REQUESTED = (
    "compliance_remediation_export.requested"
)


VALID_EXPORT_FORMATS: Tuple[str, ...] = ("csv", "json")


EXPORT_CSV_COLUMNS: Tuple[str, ...] = (
    "id",
    "state",
    "policy_id",
    "policy_slug",
    "policy_version",
    "check_id",
    "check_slug",
    "check_kind",
    "severity",
    "verdict_snapshot",
    "verdict_reason_snapshot",
    "system_id",
    "system_hostname",
    "evidence_id",
    "evaluation_run_id",
    "requested_by_user_id",
    "requested_by_username",
    "decided_by_user_id",
    "decided_by_username",
    "decided_at",
    "decided_reason",
    "justification",
    "created_at",
    "updated_at",
)


# ---------------------------------------------------------------------------
# Window resolution + validation
# ---------------------------------------------------------------------------


def resolve_export_window(
    created_after: Optional[datetime],
    created_before: Optional[datetime],
) -> Tuple[datetime, datetime]:
    """Default + validate the export window. Defaults to the last
    :data:`EXPORT_DEFAULT_WINDOW_DAYS` days when both bounds are
    omitted; raises :class:`ComplianceRemediationReportError` on
    inverted or oversized windows.
    """
    now = datetime.utcnow()
    if created_before is None:
        created_before = now
    if created_after is None:
        created_after = created_before - timedelta(days=EXPORT_DEFAULT_WINDOW_DAYS)
    if created_before <= created_after:
        raise ComplianceRemediationReportError(
            "created_before must be strictly greater than created_after"
        )
    if (created_before - created_after) > timedelta(days=EXPORT_WINDOW_MAX_DAYS):
        raise ComplianceRemediationReportError(
            f"export window must be <= {EXPORT_WINDOW_MAX_DAYS} days"
        )
    return created_after, created_before


def validate_format(fmt: Optional[str]) -> str:
    if fmt is None or fmt == "":
        return "csv"
    if not isinstance(fmt, str):
        raise ComplianceRemediationReportError("format must be a string")
    lowered = fmt.lower()
    if lowered not in VALID_EXPORT_FORMATS:
        raise ComplianceRemediationReportError(
            f"format must be one of: {list(VALID_EXPORT_FORMATS)}"
        )
    return lowered


def validate_state(state: Optional[str]) -> Optional[str]:
    if state is None:
        return None
    if not isinstance(state, str):
        raise ComplianceRemediationReportError("state must be a string")
    if state not in VALID_STATES:
        raise ComplianceRemediationReportError(
            f"state must be one of: {list(VALID_STATES)}"
        )
    return state


# ---------------------------------------------------------------------------
# Row materialization
# ---------------------------------------------------------------------------


def request_export_row(
    row: ComplianceRemediationRequest,
    *,
    system_hostname: Optional[str],
    requested_by_username: Optional[str],
    decided_by_username: Optional[str],
) -> Dict[str, Any]:
    """Stable wire shape used by both CSV and JSON exports.

    All identity columns are snapshot fields from the request itself
    (frozen at request creation per the PRA-167 design); the only
    looked-up fields are the joined ``system_hostname`` and the actor
    usernames, which we resolve through a single batched query per
    chunk rather than per row.
    """
    return {
        "id": row.id,
        "state": row.state,
        "policy_id": row.policy_id,
        "policy_slug": row.policy_slug,
        "policy_version": row.policy_version,
        "check_id": row.check_id,
        "check_slug": row.check_slug,
        "check_kind": row.check_kind,
        "severity": row.severity_snapshot,
        "verdict_snapshot": row.verdict_snapshot,
        "verdict_reason_snapshot": row.verdict_reason_snapshot,
        "system_id": row.system_id,
        "system_hostname": system_hostname,
        "evidence_id": row.evidence_id,
        "evaluation_run_id": row.evaluation_run_id,
        "requested_by_user_id": row.requested_by,
        "requested_by_username": requested_by_username,
        "decided_by_user_id": row.decided_by,
        "decided_by_username": decided_by_username,
        "decided_at": utc_iso(row.decided_at) if row.decided_at else None,
        "decided_reason": row.decided_reason,
        "justification": row.justification,
        "created_at": utc_iso(row.created_at) if row.created_at else None,
        "updated_at": utc_iso(row.updated_at) if row.updated_at else None,
    }


def iter_requests_for_export(
    db: Session,
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    state: Optional[str] = None,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Iterable[
    Tuple[ComplianceRemediationRequest, Optional[str], Optional[str], Optional[str]]
]:
    """Yield ``(request, system_hostname, requested_by_username,
    decided_by_username)`` tuples in ascending ``created_at`` order
    over the review window.

    ``allowed_system_ids`` (PRA-281) is the caller's fleet scope, applied at
    the SQL level BEFORE the first row is yielded (``None`` = admin; empty =
    nothing).
    """
    q = db.query(ComplianceRemediationRequest).filter(
        ComplianceRemediationRequest.created_at >= created_after,
        ComplianceRemediationRequest.created_at < created_before,
    )
    if policy_id is not None:
        q = q.filter(ComplianceRemediationRequest.policy_id == policy_id)
    if system_id is not None:
        q = q.filter(ComplianceRemediationRequest.system_id == system_id)
    if state is not None:
        q = q.filter(ComplianceRemediationRequest.state == state)
    scope_clause = scope_in_clause(
        ComplianceRemediationRequest.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)
    q = q.order_by(
        ComplianceRemediationRequest.created_at.asc(),
        ComplianceRemediationRequest.id.asc(),
    )

    chunk: List[ComplianceRemediationRequest] = []
    for row in q.yield_per(EXPORT_STREAM_CHUNK):
        chunk.append(row)
        if len(chunk) >= EXPORT_STREAM_CHUNK:
            yield from _materialize_chunk(db, chunk)
            chunk = []
    if chunk:
        yield from _materialize_chunk(db, chunk)


def _materialize_chunk(
    db: Session, chunk: List[ComplianceRemediationRequest]
) -> Iterable[
    Tuple[ComplianceRemediationRequest, Optional[str], Optional[str], Optional[str]]
]:
    system_ids = {r.system_id for r in chunk if r.system_id is not None}
    user_ids = set()
    for r in chunk:
        if r.requested_by is not None:
            user_ids.add(r.requested_by)
        if r.decided_by is not None:
            user_ids.add(r.decided_by)

    sys_map: Dict[int, Optional[str]] = {}
    if system_ids:
        srows = db.query(System).filter(System.id.in_(system_ids)).all()
        sys_map = {s.id: getattr(s, "hostname", None) for s in srows}

    user_map: Dict[int, Optional[str]] = {}
    if user_ids:
        urows = db.query(User).filter(User.id.in_(user_ids)).all()
        user_map = {u.id: getattr(u, "username", None) for u in urows}

    for row in chunk:
        yield (
            row,
            sys_map.get(row.system_id) if row.system_id else None,
            user_map.get(row.requested_by) if row.requested_by else None,
            user_map.get(row.decided_by) if row.decided_by else None,
        )


def collect_export_rows(
    db: Session,
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    state: Optional[str] = None,
    allowed_system_ids: Optional[Set[int]] = None,
) -> List[Dict[str, Any]]:
    """Materialize the export window into a bounded list of stable
    wire-shape dicts. Raises :class:`ComplianceRemediationReportError`
    when the filter would produce more than :data:`EXPORT_MAX_ROWS`
    rows. ``allowed_system_ids`` (PRA-281) applies the caller's fleet scope.
    """
    out: List[Dict[str, Any]] = []
    for row, hostname, requested_username, decided_username in iter_requests_for_export(
        db,
        created_after=created_after,
        created_before=created_before,
        policy_id=policy_id,
        system_id=system_id,
        state=state,
        allowed_system_ids=allowed_system_ids,
    ):
        out.append(
            request_export_row(
                row,
                system_hostname=hostname,
                requested_by_username=requested_username,
                decided_by_username=decided_username,
            )
        )
        if len(out) > EXPORT_MAX_ROWS:
            raise ComplianceRemediationReportError(
                "compliance remediation export would exceed "
                f"{EXPORT_MAX_ROWS} rows; narrow the review window or "
                "filter by policy_id / system_id / state"
            )
    return out


# ---------------------------------------------------------------------------
# Audit emission
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
    """Emit ``compliance_remediation_export.requested`` AFTER the
    export response is built. Goes through :func:`safe_emit` with no
    ``db=`` so the request-scoped session lifetime does not matter.
    """
    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_EXPORT_REQUESTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_request_export",
        target_id=None,
        context={
            "format": export_format,
            "filters": filters,
            "row_count": row_count,
        },
    )


def filters_for_audit(
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int],
    system_id: Optional[int],
    state: Optional[str],
) -> Dict[str, Any]:
    return {
        "created_after": utc_iso(created_after),
        "created_before": utc_iso(created_before),
        "policy_id": policy_id,
        "system_id": system_id,
        "state": state,
    }
