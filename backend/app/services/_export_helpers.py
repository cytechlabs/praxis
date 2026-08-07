"""PRA-178 Slice 4 — shared export helper utilities.

Each Slice 1 export module (``patch_reports_service``,
``compliance_remediation_export_service``) ships its own copy of the
window resolver, format validator, row-cap guard, audit emitter, and
filters-for-audit shape. Slice 4 adds five more export classes; this
helper module keeps the boilerplate centralized so each new service
module can focus on its iterator + row shape + CSV column list.

The functions here are intentionally **stateless**. Each export
service still owns its own ``EXPORT_CSV_COLUMNS`` tuple, its own
audit-event constant, and its own ``iter_*_for_export`` generator —
they call into these helpers for the things every export does the
same way.

Hard boundaries (slice locks):

* No scheduler, worker, queue, broker, or recurring delivery.
* No delivery retry behavior changes.
* No host mutation, package/remediation execution, reboot, rollback,
  facts refresh, package scan, raw SSH, subprocess, or new compliance
  probe kinds.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared window + size guards
# ---------------------------------------------------------------------------

# Mirror the Slice 1 values exactly so all PRA-178 exports honor the
# same operator contract.
EXPORT_WINDOW_MAX_DAYS = 366
EXPORT_DEFAULT_WINDOW_DAYS = 30
EXPORT_MAX_ROWS = 50_000
EXPORT_STREAM_CHUNK = 500
VALID_EXPORT_FORMATS: Tuple[str, ...] = ("csv", "json")


class ExportError(ValueError):
    """Raised when an export request is rejected for semantic reasons
    (bad window, unsupported format/state filter, row cap exceeded).

    Each export module is free to subclass this for clearer route-layer
    error mapping; the route layer maps the base class to HTTP 422.
    """


# ---------------------------------------------------------------------------
# Window resolution + validation
# ---------------------------------------------------------------------------


def resolve_export_window(
    after: Optional[datetime],
    before: Optional[datetime],
    *,
    after_name: str = "started_after",
    before_name: str = "started_before",
    default_days: int = EXPORT_DEFAULT_WINDOW_DAYS,
    max_days: int = EXPORT_WINDOW_MAX_DAYS,
) -> Tuple[datetime, datetime]:
    """Default + validate a review window. Defaults to ``default_days``
    when both bounds are omitted; refuses inverted or oversized windows
    with :class:`ExportError`."""
    now = datetime.utcnow()
    if before is None:
        before = now
    if after is None:
        after = before - timedelta(days=default_days)
    if before <= after:
        raise ExportError(f"{before_name} must be strictly greater than {after_name}")
    if (before - after) > timedelta(days=max_days):
        raise ExportError(f"export window must be <= {max_days} days")
    return after, before


def validate_format(fmt: Optional[str]) -> str:
    if fmt is None or fmt == "":
        return "csv"
    if not isinstance(fmt, str):
        raise ExportError("format must be a string")
    lowered = fmt.lower()
    if lowered not in VALID_EXPORT_FORMATS:
        raise ExportError(f"format must be one of: {list(VALID_EXPORT_FORMATS)}")
    return lowered


def validate_choice(
    value: Optional[str],
    *,
    field: str,
    allowed: Tuple[str, ...],
) -> Optional[str]:
    """Validate an optional enum-style filter value. Returns the
    validated value or None. Raises :class:`ExportError` for any
    string outside ``allowed``."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ExportError(f"{field} must be a string")
    if value not in allowed:
        raise ExportError(f"{field} must be one of: {list(allowed)}")
    return value


# ---------------------------------------------------------------------------
# Bounded row collection — shared cap so a misclicked unbounded GET
# cannot dump millions of rows.
# ---------------------------------------------------------------------------


def assert_row_cap(
    out_len: int, *, label: str, max_rows: int = EXPORT_MAX_ROWS
) -> None:
    """Raise :class:`ExportError` when ``out_len`` exceeds the cap.

    Callers maintain their own list and append per row; this helper
    keeps the message wording consistent so the route layer can map
    every overflow to the same operator-readable 422.
    """
    if out_len > max_rows:
        raise ExportError(
            f"{label} export would exceed {max_rows} rows; narrow the "
            "review window or apply additional filters"
        )


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def emit_export_requested(
    *,
    action: str,
    target_kind: str,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    export_format: str,
    filters: Dict[str, Any],
    row_count: int,
    target_id: Optional[str] = None,
    target_system_id: Optional[int] = None,
) -> None:
    """Emit a ``*_export.requested`` audit event after the export body
    has materialized. Uses ``safe_emit`` with no ``db=`` per the
    session-boundary lock."""
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind=target_kind,
        target_id=target_id,
        target_system_id=target_system_id,
        context={
            "format": export_format,
            "filters": filters,
            "row_count": row_count,
        },
    )


def utc_iso(value: Optional[datetime]) -> Optional[str]:
    """Render a naive-UTC datetime as ``...Z``. Mirrors the Slice 1
    helpers so every PRA-178 export wire shape uses the same
    timestamp serialization."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat() + "Z"
    return value.isoformat()


# ---------------------------------------------------------------------------
# Filter snapshot helper
# ---------------------------------------------------------------------------


def filters_snapshot(**fields: Any) -> Dict[str, Any]:
    """Build a bounded operator-supplied filter snapshot for the audit
    event ``context`` and Slice 2 ``report_runs.filters_snapshot``.
    Datetime values are normalized to ``...Z`` via :func:`utc_iso`;
    everything else is passed through.
    """
    out: Dict[str, Any] = {}
    for k, v in fields.items():
        if isinstance(v, datetime):
            out[k] = utc_iso(v)
        else:
            out[k] = v
    return out
