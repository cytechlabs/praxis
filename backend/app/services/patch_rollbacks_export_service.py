"""PRA-178 Slice 4 — patch rollback dispatch runs per-execution export.

Read-only service surface for dumping the rollback dispatch runs +
hosts tied to one execution as CSV or JSON. Like the reboot export,
this is execution-scoped — the bound is the parent ``execution_id``,
not a time window.

Hard boundaries (slice locks): no scheduler, worker, queue, broker,
recurring delivery, delivery retry, host mutation, package execution,
reboot execution, rollback execution, OpenSCAP, facts refresh,
package scan, raw SSH, subprocess, or new compliance probe kinds.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Tuple

from sqlalchemy.orm import Session

from ..db.models import (
    PatchRollbackDispatchHost,
    PatchRollbackDispatchRun,
    PatchUpdateExecutionRollback,
)
from . import _export_helpers as eh

logger = logging.getLogger(__name__)


AUDIT_PATCH_ROLLBACK_EXPORT_REQUESTED = "patch_rollback_export.requested"


EXPORT_CSV_COLUMNS: Tuple[str, ...] = (
    "row_kind",
    "id",
    "execution_id",
    "rollback_id",
    "rollback_dispatch_run_id",
    "rollback_host_id",
    "system_id_snapshot",
    "system_hostname_snapshot",
    "state",
    "max_parallel",
    "started_by_user_id",
    "started_at",
    "completed_at",
    "pause_reason",
    "cancel_reason",
    "created_at",
    "updated_at",
)


def _run_row(run: PatchRollbackDispatchRun, *, execution_id: int) -> Dict[str, Any]:
    return {
        "row_kind": "run",
        "id": run.id,
        "execution_id": execution_id,
        "rollback_id": run.rollback_id,
        "rollback_dispatch_run_id": run.id,
        "rollback_host_id": None,
        "system_id_snapshot": None,
        "system_hostname_snapshot": None,
        "state": run.state,
        "max_parallel": run.max_parallel,
        "started_by_user_id": run.started_by,
        "started_at": eh.utc_iso(run.started_at),
        "completed_at": eh.utc_iso(run.completed_at),
        "pause_reason": run.pause_reason,
        "cancel_reason": run.cancel_reason,
        "created_at": eh.utc_iso(run.created_at),
        "updated_at": eh.utc_iso(run.updated_at),
    }


def _host_row(
    host: PatchRollbackDispatchHost,
    *,
    execution_id: int,
    rollback_id: int,
) -> Dict[str, Any]:
    return {
        "row_kind": "host",
        "id": host.id,
        "execution_id": execution_id,
        "rollback_id": rollback_id,
        "rollback_dispatch_run_id": host.rollback_dispatch_run_id,
        "rollback_host_id": host.id,
        "system_id_snapshot": host.system_id_snapshot,
        "system_hostname_snapshot": host.system_hostname_snapshot,
        "state": host.state,
        "max_parallel": None,
        "started_by_user_id": None,
        "started_at": eh.utc_iso(host.started_at),
        "completed_at": eh.utc_iso(host.completed_at),
        "pause_reason": None,
        "cancel_reason": None,
        "created_at": eh.utc_iso(host.created_at),
        "updated_at": eh.utc_iso(host.updated_at),
    }


def iter_rows_for_execution(
    db: Session, *, execution_id: int
) -> Iterable[Dict[str, Any]]:
    """Yield one ``row_kind='run'`` row per dispatch run followed by
    one ``row_kind='host'`` row per dispatched host. The mixed-row
    shape mirrors the existing per-execution rollback detail
    payload so an auditor can correlate the export with the live
    detail page."""
    rollbacks = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id == execution_id)
        .order_by(PatchUpdateExecutionRollback.id.asc())
        .all()
    )
    if not rollbacks:
        return
    rollback_ids = [r.id for r in rollbacks]
    runs = (
        db.query(PatchRollbackDispatchRun)
        .filter(PatchRollbackDispatchRun.rollback_id.in_(rollback_ids))
        .order_by(
            PatchRollbackDispatchRun.rollback_id.asc(),
            PatchRollbackDispatchRun.id.asc(),
        )
        .all()
    )
    if not runs:
        return
    run_ids = [r.id for r in runs]
    hosts = (
        db.query(PatchRollbackDispatchHost)
        .filter(PatchRollbackDispatchHost.rollback_dispatch_run_id.in_(run_ids))
        .order_by(
            PatchRollbackDispatchHost.rollback_dispatch_run_id.asc(),
            PatchRollbackDispatchHost.id.asc(),
        )
        .all()
    )
    hosts_by_run: Dict[int, List[PatchRollbackDispatchHost]] = {}
    for h in hosts:
        hosts_by_run.setdefault(h.rollback_dispatch_run_id, []).append(h)
    for run in runs:
        yield _run_row(run, execution_id=execution_id)
        for h in hosts_by_run.get(run.id, []):
            yield _host_row(h, execution_id=execution_id, rollback_id=run.rollback_id)


def collect_export_rows(db: Session, *, execution_id: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in iter_rows_for_execution(db, execution_id=execution_id):
        out.append(row)
        eh.assert_row_cap(len(out), label="patch rollback runs")
    return out


def filters_for_audit(*, execution_id: int) -> Dict[str, Any]:
    return eh.filters_snapshot(execution_id=execution_id)
