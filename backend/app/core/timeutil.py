"""Timestamp serialization helpers for the API wire contract (PRA-347).

The DB convention across Praxis is *naive UTC* ``DateTime`` columns (see the
``datetime.utcnow`` column defaults in ``db/models.py``). When such a value is
serialized with a bare ``.isoformat()`` it produces a string like
``2026-08-04T21:24:56`` with no zone marker. A browser then parses that as
*local* time, so a timezone-aware formatter (``formatTimestamp`` in the frontend)
labels the local wall-clock as, e.g., EDT — displaying a UTC instant four hours
ahead of the real local time.

``utc_iso`` makes the wire shape unambiguous: it appends ``Z`` to naive values
and normalizes tz-aware values to ``...Z``. This mirrors the existing
``patch_reboot_service.utc_iso`` / ``report_run_service._utc_iso`` pattern; it is
centralized here so frontend-facing routes can share one contract.
"""

from datetime import datetime, timezone
from typing import Optional


def utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Serialize a datetime as an absolute-UTC ISO 8601 string ending in ``Z``.

    ``None`` passes through as ``None``. Naive datetimes (the DB convention) are
    treated as UTC and get a ``Z`` suffix. Timezone-aware datetimes are converted
    to UTC and rendered with ``Z`` rather than ``+00:00``.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
