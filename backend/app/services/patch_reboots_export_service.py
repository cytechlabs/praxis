"""PRA-178 Slice 4 — patch reboot queue per-execution export.

Read-only service surface for dumping the reboot queue rows for one
execution as CSV or JSON. The reboot table is execution-scoped, so
the export is naturally bounded by ``execution_id`` rather than a
time window. The route layer still enforces the
``EXPORT_MAX_ROWS = 50_000`` cap as defense in depth.

Hard boundaries (slice locks): no scheduler, worker, queue, broker,
recurring delivery, delivery retry, host mutation, package execution,
reboot execution, rollback execution, OpenSCAP, facts refresh,
package scan, raw SSH, subprocess, or new compliance probe kinds.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Tuple

from sqlalchemy.orm import Session

from ..db.models import PatchUpdateExecutionReboot
from . import _export_helpers as eh

logger = logging.getLogger(__name__)


AUDIT_PATCH_REBOOT_EXPORT_REQUESTED = "patch_reboot_export.requested"


EXPORT_CSV_COLUMNS: Tuple[str, ...] = (
    "id",
    "execution_id",
    "execution_host_id",
    "plan_id_snapshot",
    "system_id_snapshot",
    "system_hostname_snapshot",
    "wave_index",
    "state",
    "reboot_policy_snapshot",
    "reboot_window_id_snapshot",
    "reboot_required_fact",
    "decision_code",
    "scheduled_for_at",
    "started_at",
    "completed_at",
    "verified_at",
    "transport_kind",
    "exit_signal_kind",
    "created_at",
    "updated_at",
)


def _reboot_row(row: PatchUpdateExecutionReboot) -> Dict[str, Any]:
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
        "scheduled_for_at": eh.utc_iso(row.scheduled_for_at),
        "started_at": eh.utc_iso(row.started_at),
        "completed_at": eh.utc_iso(row.completed_at),
        "verified_at": eh.utc_iso(row.verified_at),
        "transport_kind": row.transport_kind,
        "exit_signal_kind": row.exit_signal_kind,
        "created_at": eh.utc_iso(row.created_at),
        "updated_at": eh.utc_iso(row.updated_at),
    }


def iter_reboots_for_export(
    db: Session, *, execution_id: int
) -> Iterable[PatchUpdateExecutionReboot]:
    q = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution_id)
        .order_by(
            PatchUpdateExecutionReboot.wave_index.asc(),
            PatchUpdateExecutionReboot.id.asc(),
        )
    )
    yield from q.yield_per(eh.EXPORT_STREAM_CHUNK)


def collect_export_rows(db: Session, *, execution_id: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in iter_reboots_for_export(db, execution_id=execution_id):
        out.append(_reboot_row(row))
        eh.assert_row_cap(len(out), label="patch reboot queue")
    return out


def filters_for_audit(*, execution_id: int) -> Dict[str, Any]:
    return eh.filters_snapshot(execution_id=execution_id)
