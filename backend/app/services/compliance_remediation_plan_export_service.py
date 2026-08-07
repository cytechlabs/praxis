"""PRA-178 Slice 4 — compliance remediation plans review-period export.

Bounded CSV/JSON export over ``compliance_remediation_plans``,
including current and superseded plans by ``created_at``. Mirrors the
Slice 1 export pattern.

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

from ..db.models import ComplianceRemediationPlan, System, User
from . import _export_helpers as eh

logger = logging.getLogger(__name__)


AUDIT_REMEDIATION_PLAN_EXPORT_REQUESTED = "compliance_remediation_plan_export.requested"


EXPORT_CSV_COLUMNS: Tuple[str, ...] = (
    "id",
    "request_id",
    "state",
    "plan_kind",
    "policy_id",
    "policy_slug",
    "policy_version",
    "check_id",
    "check_slug",
    "check_kind",
    "severity",
    "system_id",
    "system_hostname",
    "is_current",
    "acknowledged_at",
    "acknowledged_by_user_id",
    "acknowledged_by_username",
    "superseded_by_plan_id",
    "unsupported_reason",
    "error_message",
    "step_count",
    "created_by_user_id",
    "created_by_username",
    "created_at",
    "updated_at",
)


VALID_PLAN_STATES: Tuple[str, ...] = ("planned", "unsupported", "failed")


def validate_state(state: Optional[str]) -> Optional[str]:
    return eh.validate_choice(state, field="state", allowed=VALID_PLAN_STATES)


def _plan_row(
    plan: ComplianceRemediationPlan,
    *,
    system_hostname: Optional[str],
    created_username: Optional[str],
    ack_username: Optional[str],
) -> Dict[str, Any]:
    steps = plan.plan_steps or []
    step_count = len(steps) if isinstance(steps, list) else 0
    return {
        "id": plan.id,
        "request_id": plan.request_id,
        "state": plan.state,
        "plan_kind": plan.plan_kind,
        "policy_id": plan.policy_id,
        "policy_slug": plan.policy_slug,
        "policy_version": plan.policy_version,
        "check_id": plan.check_id,
        "check_slug": plan.check_slug,
        "check_kind": plan.check_kind,
        "severity": plan.severity_snapshot,
        "system_id": plan.system_id,
        "system_hostname": system_hostname,
        "is_current": plan.superseded_by_plan_id is None,
        "acknowledged_at": eh.utc_iso(plan.acknowledged_at),
        "acknowledged_by_user_id": plan.acknowledged_by,
        "acknowledged_by_username": ack_username,
        "superseded_by_plan_id": plan.superseded_by_plan_id,
        "unsupported_reason": plan.unsupported_reason,
        "error_message": plan.error_message,
        "step_count": step_count,
        "created_by_user_id": plan.created_by,
        "created_by_username": created_username,
        "created_at": eh.utc_iso(plan.created_at),
        "updated_at": eh.utc_iso(plan.updated_at),
    }


def iter_plans_for_export(
    db: Session,
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    state: Optional[str] = None,
    current_only: bool = False,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Iterable[
    Tuple[ComplianceRemediationPlan, Optional[str], Optional[str], Optional[str]]
]:
    q = db.query(ComplianceRemediationPlan).filter(
        ComplianceRemediationPlan.created_at >= created_after,
        ComplianceRemediationPlan.created_at < created_before,
    )
    if policy_id is not None:
        q = q.filter(ComplianceRemediationPlan.policy_id == policy_id)
    if system_id is not None:
        q = q.filter(ComplianceRemediationPlan.system_id == system_id)
    if state is not None:
        q = q.filter(ComplianceRemediationPlan.state == state)
    if current_only:
        q = q.filter(ComplianceRemediationPlan.superseded_by_plan_id.is_(None))
    scope_clause = scope_in_clause(
        ComplianceRemediationPlan.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)
    q = q.order_by(
        ComplianceRemediationPlan.created_at.asc(),
        ComplianceRemediationPlan.id.asc(),
    )

    chunk: List[ComplianceRemediationPlan] = []
    for plan in q.yield_per(eh.EXPORT_STREAM_CHUNK):
        chunk.append(plan)
        if len(chunk) >= eh.EXPORT_STREAM_CHUNK:
            yield from _materialize_chunk(db, chunk)
            chunk = []
    if chunk:
        yield from _materialize_chunk(db, chunk)


def _materialize_chunk(
    db: Session, chunk: List[ComplianceRemediationPlan]
) -> Iterable[
    Tuple[ComplianceRemediationPlan, Optional[str], Optional[str], Optional[str]]
]:
    system_ids = {p.system_id for p in chunk if p.system_id is not None}
    user_ids = set()
    for p in chunk:
        if p.created_by is not None:
            user_ids.add(p.created_by)
        if p.acknowledged_by is not None:
            user_ids.add(p.acknowledged_by)

    sys_map: Dict[int, Optional[str]] = {}
    if system_ids:
        for s in db.query(System).filter(System.id.in_(system_ids)).all():
            sys_map[s.id] = getattr(s, "hostname", None)

    user_map: Dict[int, Optional[str]] = {}
    if user_ids:
        for u in db.query(User).filter(User.id.in_(user_ids)).all():
            user_map[u.id] = getattr(u, "username", None)

    for plan in chunk:
        yield (
            plan,
            sys_map.get(plan.system_id) if plan.system_id else None,
            user_map.get(plan.created_by) if plan.created_by else None,
            user_map.get(plan.acknowledged_by) if plan.acknowledged_by else None,
        )


def collect_export_rows(
    db: Session,
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    state: Optional[str] = None,
    current_only: bool = False,
    allowed_system_ids: Optional[Set[int]] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for plan, hostname, created_un, ack_un in iter_plans_for_export(
        db,
        created_after=created_after,
        created_before=created_before,
        policy_id=policy_id,
        system_id=system_id,
        state=state,
        current_only=current_only,
        allowed_system_ids=allowed_system_ids,
    ):
        out.append(
            _plan_row(
                plan,
                system_hostname=hostname,
                created_username=created_un,
                ack_username=ack_un,
            )
        )
        eh.assert_row_cap(len(out), label="compliance remediation plans")
    return out


def filters_for_audit(
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int],
    system_id: Optional[int],
    state: Optional[str],
    current_only: bool,
) -> Dict[str, Any]:
    return eh.filters_snapshot(
        created_after=created_after,
        created_before=created_before,
        policy_id=policy_id,
        system_id=system_id,
        state=state,
        current_only=current_only,
    )
