"""PRA-178 Slice 4 — compliance remediation execution attempts export.

Bounded CSV/JSON export over
``compliance_remediation_execution_attempts``. Mirrors the Slice 1
export pattern; one row per attempt with its terminal state,
failure reason, and bounded outcome summaries already persisted by
PRA-176.

Hard boundaries (slice locks): no scheduler, worker, queue, broker,
recurring delivery, delivery retry, host mutation, package execution,
remediation execution, reboot, rollback, OpenSCAP, facts refresh,
package scan, raw SSH, subprocess, or new compliance probe kinds.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from app.services.access_authorization_service import scope_in_clause

from ..db.models import ComplianceRemediationExecutionAttempt, System, User
from . import _export_helpers as eh

logger = logging.getLogger(__name__)


AUDIT_REMEDIATION_EXECUTION_EXPORT_REQUESTED = (
    "compliance_remediation_execution_export.requested"
)


EXPORT_CSV_COLUMNS: Tuple[str, ...] = (
    "id",
    "request_id",
    "plan_id",
    "state",
    "policy_id",
    "policy_slug",
    "policy_version",
    "check_id",
    "check_slug",
    "check_kind",
    "severity",
    "plan_kind_snapshot",
    "package_name",
    "package_version_target",
    "system_id",
    "system_hostname",
    "transport",
    "exit_code",
    "duration_ms",
    "failure_reason",
    "approval_decided_by_user_id",
    "approval_decided_at",
    "dispatched_at",
    "completed_at",
    "created_by_user_id",
    "created_by_username",
    "created_at",
    "updated_at",
)


VALID_ATTEMPT_STATES: Tuple[str, ...] = (
    "pending",
    "dispatched",
    "succeeded",
    "failed",
    "cancelled",
)


def validate_state(state: Optional[str]) -> Optional[str]:
    return eh.validate_choice(state, field="state", allowed=VALID_ATTEMPT_STATES)


def _attempt_row(
    row: ComplianceRemediationExecutionAttempt,
    *,
    system_hostname: Optional[str],
    created_username: Optional[str],
) -> Dict[str, Any]:
    return {
        "id": row.id,
        "request_id": row.request_id,
        "plan_id": row.plan_id,
        "state": row.state,
        "policy_id": row.policy_id,
        "policy_slug": row.policy_slug,
        "policy_version": row.policy_version,
        "check_id": row.check_id,
        "check_slug": row.check_slug,
        "check_kind": row.check_kind,
        "severity": row.severity_snapshot,
        "plan_kind_snapshot": row.plan_kind_snapshot,
        "package_name": row.package_name,
        "package_version_target": row.package_version_target,
        "system_id": row.system_id,
        "system_hostname": system_hostname,
        "transport": row.transport,
        "exit_code": row.exit_code,
        "duration_ms": row.duration_ms,
        "failure_reason": row.failure_reason,
        "approval_decided_by_user_id": row.approval_decided_by,
        "approval_decided_at": eh.utc_iso(row.approval_decided_at),
        "dispatched_at": eh.utc_iso(row.dispatched_at),
        "completed_at": eh.utc_iso(row.completed_at),
        "created_by_user_id": row.created_by,
        "created_by_username": created_username,
        "created_at": eh.utc_iso(row.created_at),
        "updated_at": eh.utc_iso(row.updated_at),
    }


def iter_attempts_for_export(
    db: Session,
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    state: Optional[str] = None,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Iterable[
    Tuple[ComplianceRemediationExecutionAttempt, Optional[str], Optional[str]]
]:
    q = db.query(ComplianceRemediationExecutionAttempt).filter(
        ComplianceRemediationExecutionAttempt.created_at >= created_after,
        ComplianceRemediationExecutionAttempt.created_at < created_before,
    )
    if policy_id is not None:
        q = q.filter(ComplianceRemediationExecutionAttempt.policy_id == policy_id)
    if system_id is not None:
        q = q.filter(ComplianceRemediationExecutionAttempt.system_id == system_id)
    if state is not None:
        q = q.filter(ComplianceRemediationExecutionAttempt.state == state)
    scope_clause = scope_in_clause(
        ComplianceRemediationExecutionAttempt.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)
    q = q.order_by(
        ComplianceRemediationExecutionAttempt.created_at.asc(),
        ComplianceRemediationExecutionAttempt.id.asc(),
    )

    chunk: List[ComplianceRemediationExecutionAttempt] = []
    for row in q.yield_per(eh.EXPORT_STREAM_CHUNK):
        chunk.append(row)
        if len(chunk) >= eh.EXPORT_STREAM_CHUNK:
            yield from _materialize_chunk(db, chunk)
            chunk = []
    if chunk:
        yield from _materialize_chunk(db, chunk)


def _materialize_chunk(
    db: Session, chunk: List[ComplianceRemediationExecutionAttempt]
) -> Iterable[
    Tuple[ComplianceRemediationExecutionAttempt, Optional[str], Optional[str]]
]:
    system_ids = {r.system_id for r in chunk if r.system_id is not None}
    user_ids = {r.created_by for r in chunk if r.created_by is not None}

    sys_map: Dict[int, Optional[str]] = {}
    if system_ids:
        for s in db.query(System).filter(System.id.in_(system_ids)).all():
            sys_map[s.id] = getattr(s, "hostname", None)

    user_map: Dict[int, Optional[str]] = {}
    if user_ids:
        for u in db.query(User).filter(User.id.in_(user_ids)).all():
            user_map[u.id] = getattr(u, "username", None)

    for row in chunk:
        yield (
            row,
            sys_map.get(row.system_id) if row.system_id else None,
            user_map.get(row.created_by) if row.created_by else None,
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
    out: List[Dict[str, Any]] = []
    for row, hostname, created_un in iter_attempts_for_export(
        db,
        created_after=created_after,
        created_before=created_before,
        policy_id=policy_id,
        system_id=system_id,
        state=state,
        allowed_system_ids=allowed_system_ids,
    ):
        out.append(
            _attempt_row(
                row,
                system_hostname=hostname,
                created_username=created_un,
            )
        )
        eh.assert_row_cap(len(out), label="compliance remediation execution attempts")
    return out


def filters_for_audit(
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int],
    system_id: Optional[int],
    state: Optional[str],
) -> Dict[str, Any]:
    return eh.filters_snapshot(
        created_after=created_after,
        created_before=created_before,
        policy_id=policy_id,
        system_id=system_id,
        state=state,
    )
