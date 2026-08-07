"""PRA-155 + PRA-156: shared freshness verdict for the host_facts row.

The freshness verdict (``missing`` / ``stale`` / ``fresh``) is the
single source-of-truth for "is this host's inventory current enough to
trust." Three surfaces consume it and must agree:

  * ``GET /systems/{id}/facts`` — the facts read endpoint.
  * ``GET /systems/{id}/lifecycle`` — the PRA-156 lifecycle read.
  * Smart-group ``lifecycle.*`` predicates (PRA-156 #3c) — stale or
    missing facts collapse to ``status=unknown`` for membership.

PRA-155 #2c locked the verdict and the 24h threshold. PRA-156 #3c
extracts the constant + helper out of ``app.api.routes.facts`` so
multiple consumers don't drift apart by one tweaking the rule
without the others.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

# Locked default: 24h. Per the PRA-155 #2c lock, configurability via
# app_settings is deferred until an operator asks. The constant is the
# single source — every freshness verdict derives from it.
STALENESS_THRESHOLD_SECONDS = 24 * 60 * 60


def freshness_of(
    collected_at: Optional[datetime],
    threshold_seconds: int = STALENESS_THRESHOLD_SECONDS,
    *,
    now: Optional[datetime] = None,
) -> str:
    """Return ``"missing"`` / ``"stale"`` / ``"fresh"`` for a facts row.

    Args:
        collected_at: The ``host_facts.collected_at`` value, or
            ``None`` when no row exists.
        threshold_seconds: Age in seconds beyond which a row is
            considered stale. Defaults to the locked 24h.
        now: Reference time for the age calculation. Tests pass a
            fixed datetime to drive boundary states; production
            callers leave it as ``None`` and pick up
            ``datetime.utcnow()`` so the verdict slides with the
            wall clock.
    """
    if collected_at is None:
        return "missing"
    reference = now if now is not None else datetime.utcnow()
    age = (reference - collected_at).total_seconds()
    if age > threshold_seconds:
        return "stale"
    return "fresh"
