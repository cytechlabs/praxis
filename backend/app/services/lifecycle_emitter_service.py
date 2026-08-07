"""PRA-156 #3e-c: lifecycle notification emitter.

Iterates the lifecycle index and fires ``host_eol_approaching`` or
``host_eol_reached`` events for hosts that have crossed a threshold
since the last run. Dedup state lives in
``lifecycle_notification_state`` so each (system, event_type,
threshold, effective_eol_date) combination notifies exactly once.

Locked behavior:

  * **Approaching thresholds**: ``0 < days_to_eol <= threshold`` for
    each of ``[90, 30, 7]``. Strict ``> 0`` lower bound so day-zero
    fires only the ``host_eol_reached`` event, never an "approaching"
    duplicate on the same daily run.
  * **Reached**: ``days_to_eol == 0`` only — not negative. A host
    that's already past EOL and unsupported won't re-trigger
    ``host_eol_reached`` because the dedup key (system,
    effective_eol_date) is satisfied from the day-zero firing.
  * **Skip unknown verdicts** and verdicts without ``eol_date``. The
    emitter has nothing meaningful to say about hosts whose facts
    are missing or whose distro isn't in the lifecycle table.
  * ``effective_eol_date = verdict.eol_date`` — the post-override
    date, so an extension (Ubuntu Pro, RHEL ELS) resets the
    threshold sequence by changing the dedup key.
  * **Dedup means "Praxis emitted"**, not "external delivery
    succeeded". The emitter writes state AFTER ``send_alert``
    returns; ``send_alert`` swallows delivery exceptions and may
    have zero matching configs. Operators wanting at-least-once
    delivery rely on the existing ``alert_history`` retry sweep.
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import LifecycleNotificationState
from . import alert_service, lifecycle_service

logger = logging.getLogger(__name__)

# Locked thresholds. Order does not affect correctness — each is
# independently dedup'd — but iterating large-to-small keeps the
# audit log readable when a freshly-enrolled host crosses multiple
# thresholds in its first run.
APPROACHING_THRESHOLDS: Tuple[int, ...] = (90, 30, 7)

# Sentinel ``threshold_days`` value for ``host_eol_reached``. Locked
# to 0 (the day-zero boundary) so the dedup UNIQUE constraint works
# without depending on Postgres NULLS NOT DISTINCT semantics.
REACHED_THRESHOLD = 0

EVENT_APPROACHING = "host_eol_approaching"
EVENT_REACHED = "host_eol_reached"


def emit_for_all_systems(
    db: Session,
    *,
    today: Optional[date] = None,
) -> List[Tuple[int, str, int]]:
    """Fire any new lifecycle threshold crossings.

    Returns a list of ``(system_id, event_type, threshold_days)``
    tuples for events that were emitted on this run — useful for
    the scheduler log line and tests. An empty list means nothing
    crossed (or everything has already been notified).

    Args:
        db: Active session.
        today: Reference date for the EOL math. Defaults to
            ``datetime.utcnow().date()``; tests pass a fixed date
            to drive deterministic threshold crossings.
    """
    today = today or datetime.utcnow().date()
    index = lifecycle_service.compute_for_all_systems(db, today=today)

    fired: List[Tuple[int, str, int]] = []
    for system_id, verdict in index.items():
        # Skip unknown verdicts and verdicts without eol_date — the
        # emitter has nothing useful to say.
        if verdict.eol_date is None:
            continue
        if verdict.status == lifecycle_service.LIFECYCLE_UNKNOWN:
            continue
        if verdict.days_to_eol is None:
            continue

        days = verdict.days_to_eol

        # host_eol_reached: day-zero only. Negative days_to_eol means
        # the host is already past EOL — the day-zero firing handled
        # that, and the dedup key (system, effective_eol_date) is
        # already satisfied so a re-fire would no-op anyway.
        if days == 0:
            if _fire_if_new(
                db,
                system_id=system_id,
                event_type=EVENT_REACHED,
                threshold_days=REACHED_THRESHOLD,
                effective_eol_date=verdict.eol_date,
            ):
                fired.append((system_id, EVENT_REACHED, REACHED_THRESHOLD))

        # host_eol_approaching: 0 < days <= threshold for each
        # locked threshold. Strict > 0 lower bound so day-zero is
        # not double-counted as both approaching AND reached.
        for threshold in APPROACHING_THRESHOLDS:
            if 0 < days <= threshold:
                if _fire_if_new(
                    db,
                    system_id=system_id,
                    event_type=EVENT_APPROACHING,
                    threshold_days=threshold,
                    effective_eol_date=verdict.eol_date,
                ):
                    fired.append((system_id, EVENT_APPROACHING, threshold))

    if fired:
        logger.info(
            "lifecycle emitter fired %d new event(s) on %s",
            len(fired),
            today.isoformat(),
        )
    return fired


def _fire_if_new(
    db: Session,
    *,
    system_id: int,
    event_type: str,
    threshold_days: int,
    effective_eol_date: date,
) -> bool:
    """Check dedup; if not previously notified, fire the alert and
    record dedup state. Returns True if the event was emitted.

    Recording state happens AFTER ``send_alert`` returns. ``send_alert``
    swallows delivery exceptions (the alert_history retry sweep is
    the catch-all), so the dedup row asserts "Praxis emitted this
    lifecycle event" — NOT "every external destination received it."
    """
    existing = (
        db.query(LifecycleNotificationState)
        .filter(
            LifecycleNotificationState.system_id == system_id,
            LifecycleNotificationState.event_type == event_type,
            LifecycleNotificationState.threshold_days == threshold_days,
            LifecycleNotificationState.effective_eol_date == effective_eol_date,
        )
        .one_or_none()
    )
    if existing is not None:
        return False

    title, message, severity = _format_event(
        event_type=event_type,
        threshold_days=threshold_days,
        effective_eol_date=effective_eol_date,
        system_id=system_id,
    )
    try:
        alert_service.send_alert(
            db,
            event_type=event_type,
            title=title,
            message=message,
            severity=severity,
            system_id=system_id,
        )
    except Exception:  # pylint: disable=broad-except
        # send_alert is supposed to swallow internally; if something
        # genuinely escapes, log and DO NOT record dedup state — the
        # next emitter run will retry. This is a deliberate choice:
        # if an unexpected crash happens before send_alert has even
        # enqueued an alert_history row, we'd rather re-fire than
        # silently lose the notification.
        logger.exception(
            "lifecycle emitter: send_alert raised for system_id=%s event=%s "
            "threshold=%s — will retry on next run",
            system_id,
            event_type,
            threshold_days,
        )
        return False

    db.add(
        LifecycleNotificationState(
            system_id=system_id,
            event_type=event_type,
            threshold_days=threshold_days,
            effective_eol_date=effective_eol_date,
        )
    )
    db.commit()
    return True


def _format_event(
    *,
    event_type: str,
    threshold_days: int,
    effective_eol_date: date,
    system_id: int,
) -> Tuple[str, str, str]:
    """Return ``(title, message, severity)`` for the alert payload.

    Kept terse — the alert UI will surface the system_id and the
    event metadata; the title/message just need to be human-readable
    in Slack/webhook payloads.
    """
    iso = effective_eol_date.isoformat()
    if event_type == EVENT_REACHED:
        return (
            f"Host #{system_id} reached EOL",
            f"Distro reached end of life on {iso}.",
            "error",
        )
    return (
        f"Host #{system_id} approaching EOL within {threshold_days} days",
        f"Distro EOL on {iso} (within the {threshold_days}-day threshold).",
        "warning",
    )
