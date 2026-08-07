"""PRA-178 Slice 4 — patch update plans review-period export.

Read-only service surface for the manual CSV/JSON export over
``patch_update_plans``. Mirrors the Slice 1 export pattern: bounded
review window, JSON wire shape + pinned CSV columns, audit emission,
and Slice 2 ``report_runs`` recording at the route layer.

Hard boundaries (slice locks):

* No scheduler, worker, queue, broker, or recurring delivery.
* No host mutation, package/remediation execution, reboot, rollback,
  facts refresh, package scan, raw SSH, subprocess, or new compliance
  probe kinds.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import PatchUpdatePlan, PatchUpdatePlanHost, User
from . import _export_helpers as eh

logger = logging.getLogger(__name__)


AUDIT_PATCH_PLAN_EXPORT_REQUESTED = "patch_plan_export.requested"


# Stable column order for the CSV export. Pinned so external auditor
# scripts can rely on it.
EXPORT_CSV_COLUMNS: Tuple[str, ...] = (
    "id",
    "name",
    "policy_id",
    "policy_slug_snapshot",
    "state",
    "scheduled_start_at",
    "maintenance_window_id",
    "reboot_window_id",
    "block_reason_count",
    "block_reason_codes",
    "host_count",
    "host_planned_count",
    "host_blocked_count",
    "host_other_count",
    "created_by_user_id",
    "created_by_username",
    "created_at",
    "updated_at",
)


# Plan state vocabulary mirrors ``patch_update_plan_service``.
VALID_PLAN_STATES: Tuple[str, ...] = (
    "draft",
    "approved",
    "scheduled",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "blocked",
)


def validate_state(state: Optional[str]) -> Optional[str]:
    return eh.validate_choice(state, field="state", allowed=VALID_PLAN_STATES)


def _plan_row(
    plan: PatchUpdatePlan,
    *,
    policy_slug: Optional[str],
    created_by_username: Optional[str],
    host_counts: Dict[str, int],
) -> Dict[str, Any]:
    snap = plan.policy_snapshot or {}
    block_reasons = plan.block_reasons or []
    reason_codes = sorted(
        {br.get("code") if isinstance(br, dict) else None for br in block_reasons}
        - {None}
    )
    return {
        "id": plan.id,
        "name": plan.name,
        "policy_id": plan.policy_id,
        "policy_slug_snapshot": policy_slug
        or (snap.get("slug") if isinstance(snap, dict) else None),
        "state": plan.state,
        "scheduled_start_at": eh.utc_iso(plan.scheduled_start_at),
        "maintenance_window_id": plan.maintenance_window_id,
        "reboot_window_id": plan.reboot_window_id,
        "block_reason_count": len(block_reasons),
        "block_reason_codes": ",".join(reason_codes),
        "host_count": host_counts.get("total", 0),
        "host_planned_count": host_counts.get("planned", 0),
        "host_blocked_count": host_counts.get("blocked", 0),
        "host_other_count": host_counts.get("other", 0),
        "created_by_user_id": plan.created_by,
        "created_by_username": created_by_username,
        "created_at": eh.utc_iso(plan.created_at),
        "updated_at": eh.utc_iso(plan.updated_at),
    }


def _host_counts_for_plans(
    db: Session, plan_ids: List[int]
) -> Dict[int, Dict[str, int]]:
    """Compute per-plan host count summaries in a single query.

    Returns a dict keyed on plan_id with sub-keys
    ``total`` / ``planned`` / ``blocked`` / ``other`` (everything that
    is not ``planned`` or ``blocked``)."""
    if not plan_ids:
        return {}
    rows = (
        db.query(PatchUpdatePlanHost.plan_id, PatchUpdatePlanHost.state)
        .filter(PatchUpdatePlanHost.plan_id.in_(plan_ids))
        .all()
    )
    out: Dict[int, Dict[str, int]] = {}
    for plan_id, state in rows:
        entry = out.setdefault(
            plan_id, {"total": 0, "planned": 0, "blocked": 0, "other": 0}
        )
        entry["total"] += 1
        if state == "planned":
            entry["planned"] += 1
        elif state == "blocked":
            entry["blocked"] += 1
        else:
            entry["other"] += 1
    return out


def iter_plans_for_export(
    db: Session,
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int] = None,
    state: Optional[str] = None,
) -> Iterable[Tuple[PatchUpdatePlan, Optional[str], Optional[str], Dict[str, int]]]:
    """Yield ``(plan, policy_slug, created_by_username, host_counts)``
    in ascending ``created_at`` order over the review window."""
    q = db.query(PatchUpdatePlan).filter(
        PatchUpdatePlan.created_at >= created_after,
        PatchUpdatePlan.created_at < created_before,
    )
    if policy_id is not None:
        q = q.filter(PatchUpdatePlan.policy_id == policy_id)
    if state is not None:
        q = q.filter(PatchUpdatePlan.state == state)
    q = q.order_by(PatchUpdatePlan.created_at.asc(), PatchUpdatePlan.id.asc())

    chunk: List[PatchUpdatePlan] = []
    for plan in q.yield_per(eh.EXPORT_STREAM_CHUNK):
        chunk.append(plan)
        if len(chunk) >= eh.EXPORT_STREAM_CHUNK:
            yield from _materialize_chunk(db, chunk)
            chunk = []
    if chunk:
        yield from _materialize_chunk(db, chunk)


def _materialize_chunk(
    db: Session, chunk: List[PatchUpdatePlan]
) -> Iterable[Tuple[PatchUpdatePlan, Optional[str], Optional[str], Dict[str, int]]]:
    plan_ids = [p.id for p in chunk]
    user_ids = {p.created_by for p in chunk if p.created_by is not None}
    host_counts = _host_counts_for_plans(db, plan_ids)

    user_map: Dict[int, Optional[str]] = {}
    if user_ids:
        for u in db.query(User).filter(User.id.in_(user_ids)).all():
            user_map[u.id] = getattr(u, "username", None)

    for plan in chunk:
        snap = plan.policy_snapshot or {}
        slug = snap.get("slug") if isinstance(snap, dict) else None
        yield (
            plan,
            slug,
            user_map.get(plan.created_by) if plan.created_by else None,
            host_counts.get(
                plan.id, {"total": 0, "planned": 0, "blocked": 0, "other": 0}
            ),
        )


def collect_export_rows(
    db: Session,
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int] = None,
    state: Optional[str] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for plan, slug, username, host_counts in iter_plans_for_export(
        db,
        created_after=created_after,
        created_before=created_before,
        policy_id=policy_id,
        state=state,
    ):
        out.append(
            _plan_row(
                plan,
                policy_slug=slug,
                created_by_username=username,
                host_counts=host_counts,
            )
        )
        eh.assert_row_cap(len(out), label="patch update plans")
    return out


def filters_for_audit(
    *,
    created_after: datetime,
    created_before: datetime,
    policy_id: Optional[int],
    state: Optional[str],
) -> Dict[str, Any]:
    return eh.filters_snapshot(
        created_after=created_after,
        created_before=created_before,
        policy_id=policy_id,
        state=state,
    )
