"""Alert event building + dispatch for the mirror engine
(PRA-157 #2b, refactored in #2b-a).

**Transaction-decoupled shape.** ``alert_service.send_alert`` commits
``AlertHistory`` rows to the caller's session (and rolls back on
error). If the orchestrator called the alert helper inline on the
sync session, a matching alert config could prematurely commit the
sync finalization, and an alert-service error could roll back the
finalized run/mirror state before the dedup row is written.

The fix: the orchestrator returns a list of ``MirrorAlertEvent``
records and does NOT touch the alert path. The caller (sweep
wrapper / on-demand BackgroundTask) commits the sync state on its
session, then opens a **fresh** session and calls
``dispatch_alert_events`` on that. Alert-service mutations stay
fully isolated from sync-state mutations.

Cooldown semantics are preserved across the refactor — see
``maybe_fire_mirror_alert`` for the per-(mirror, event_type)
``mirror_alert_state`` dedup logic and the PRA-156
lifecycle-emitter rule that we record "Praxis emitted," not
"delivery succeeded."
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List, Optional

from ..db.models import MirrorAlertState, MirrorRepo
from . import alert_service

logger = logging.getLogger(__name__)

DEFAULT_FAILURE_COOLDOWN_HOURS = 24
RECOVERY_COOLDOWN_HOURS = 0  # always fire on transition

EVENT_SYNC_FAILED = "mirror_sync_failed"
EVENT_SYNC_COMPLETED = "mirror_sync_completed"
EVENT_DISK_PRESSURE = "mirror_disk_pressure"
# PRA-158 #4b: upstream signature verification gate refused the sync.
# Same 24h cooldown as sync_failed so a persistently-broken upstream
# doesn't drown the channel.
EVENT_UPSTREAM_INVALID = "mirror_upstream_signature_invalid"


@dataclass(frozen=True)
class MirrorAlertEvent:
    """A pending alert the orchestrator wants the caller to fire on
    a fresh session after committing sync state.
    """

    event_type: str
    title: str
    message: str
    severity: str
    cooldown_hours: int


# ---------------------------------------------------------------------------
# Builders — pure functions, no DB access
# ---------------------------------------------------------------------------


def build_sync_failed_event(mirror: MirrorRepo, error_text: str) -> MirrorAlertEvent:
    return MirrorAlertEvent(
        event_type=EVENT_SYNC_FAILED,
        title=f"Mirror sync failed: {mirror.slug}",
        message=(
            f"Mirror '{mirror.slug}' ({mirror.package_family}, "
            f"{mirror.distribution}) sync failed: {error_text[:512]}"
        ),
        severity="error",
        cooldown_hours=DEFAULT_FAILURE_COOLDOWN_HOURS,
    )


def build_sync_completed_event(mirror: MirrorRepo) -> MirrorAlertEvent:
    return MirrorAlertEvent(
        event_type=EVENT_SYNC_COMPLETED,
        title=f"Mirror sync recovered: {mirror.slug}",
        message=(
            f"Mirror '{mirror.slug}' ({mirror.package_family}, "
            f"{mirror.distribution}) succeeded after a prior failure. "
            "Recovery alert fires once per failure → ok transition."
        ),
        severity="info",
        cooldown_hours=RECOVERY_COOLDOWN_HOURS,
    )


def build_upstream_invalid_event(mirror: MirrorRepo, reason: str) -> MirrorAlertEvent:
    """Pre-sync upstream-signature verification refused the sync
    (PRA-158 #4b).

    Operator-actionable: either the upstream archive key was rotated
    (import the new key into ``mirror_upstream_keys``) or the upstream
    is genuinely compromised (don't sync). Same 24h cooldown as
    sync_failed.
    """
    return MirrorAlertEvent(
        event_type=EVENT_UPSTREAM_INVALID,
        title=f"Mirror upstream signature invalid: {mirror.slug}",
        message=(
            f"Mirror '{mirror.slug}' ({mirror.package_family}, "
            f"{mirror.distribution}) sync refused: upstream signature "
            f"failed verification. Reason: {reason[:512]}"
        ),
        severity="error",
        cooldown_hours=DEFAULT_FAILURE_COOLDOWN_HOURS,
    )


def build_disk_pressure_event(mirror: MirrorRepo, reason: str) -> MirrorAlertEvent:
    return MirrorAlertEvent(
        event_type=EVENT_DISK_PRESSURE,
        title=f"Mirror disk-pressure: {mirror.slug}",
        message=(
            f"Mirror '{mirror.slug}' sync refused by free-space gate. "
            f"Reason: {reason[:512]}"
        ),
        severity="warning",
        cooldown_hours=DEFAULT_FAILURE_COOLDOWN_HOURS,
    )


# ---------------------------------------------------------------------------
# Dispatcher — runs on a fresh Session decoupled from sync state
# ---------------------------------------------------------------------------


def maybe_fire_mirror_alert(
    db,
    mirror: MirrorRepo,
    event: MirrorAlertEvent,
    *,
    now: Optional[datetime] = None,
) -> bool:
    """Fire ``alert_service.send_alert`` if the cooldown has elapsed
    for ``(mirror.id, event.event_type)``.

    Returns ``True`` if the alert was fired (or attempted — see
    PRA-156 semantics: dedup records the attempt, not delivery
    success), ``False`` if suppressed by cooldown. Does not commit;
    caller commits.

    **Must be called on a fresh session** — never on the same Session
    that's mutating sync state. ``alert_service.send_alert`` commits
    ``AlertHistory`` and may roll back on error, so caller-state
    isolation is the contract.
    """
    now = now or datetime.utcnow()
    cooldown = timedelta(hours=event.cooldown_hours)

    state = (
        db.query(MirrorAlertState)
        .filter(
            MirrorAlertState.mirror_repo_id == mirror.id,
            MirrorAlertState.event_type == event.event_type,
        )
        .one_or_none()
    )

    if (
        event.cooldown_hours > 0
        and state is not None
        and (now - state.last_fired_at) < cooldown
    ):
        logger.debug(
            "mirror alert suppressed by cooldown: mirror=%s event=%s "
            "last_fired_at=%s cooldown=%dh",
            mirror.slug,
            event.event_type,
            state.last_fired_at.isoformat(),
            event.cooldown_hours,
        )
        return False

    try:
        alert_service.send_alert(
            db,
            event_type=event.event_type,
            title=event.title,
            message=event.message,
            severity=event.severity,
            system_id=None,  # mirrors are content-plane, not host-bound
        )
    except Exception as exc:  # pylint: disable=broad-except
        # Match PRA-156 lifecycle-emitter semantics: dedup the
        # *attempt*, not the delivery success.
        logger.warning(
            "alert_service.send_alert raised for mirror=%s event=%s: %s",
            mirror.slug,
            event.event_type,
            exc,
        )

    if state is None:
        db.add(
            MirrorAlertState(
                mirror_repo_id=mirror.id,
                event_type=event.event_type,
                last_fired_at=now,
            )
        )
    else:
        state.last_fired_at = now

    return True


# ---------------------------------------------------------------------------
# Convenience event-shaped wrappers — for unit tests + ad-hoc callers
# ---------------------------------------------------------------------------
#
# Production paths (perform_sync_for_mirror + claim_and_sync_one_mirror)
# go through the build_*_event + dispatch_alert_events split so the
# alert session stays decoupled from the sync session. These helpers
# are kept for tests + for callers that already control their session
# boundary and want a one-call shape.


def alert_sync_failed(
    db, mirror: MirrorRepo, error_text: str, *, now: Optional[datetime] = None
) -> bool:
    return maybe_fire_mirror_alert(
        db, mirror, build_sync_failed_event(mirror, error_text), now=now
    )


def alert_sync_completed(
    db, mirror: MirrorRepo, *, now: Optional[datetime] = None
) -> bool:
    return maybe_fire_mirror_alert(
        db, mirror, build_sync_completed_event(mirror), now=now
    )


def alert_disk_pressure(
    db, mirror: MirrorRepo, reason: str, *, now: Optional[datetime] = None
) -> bool:
    return maybe_fire_mirror_alert(
        db, mirror, build_disk_pressure_event(mirror, reason), now=now
    )


def dispatch_alert_events(
    db,
    mirror: MirrorRepo,
    events: Iterable[MirrorAlertEvent],
    *,
    now: Optional[datetime] = None,
) -> List[bool]:
    """Convenience: fire each event in order, return the per-event
    fired-or-suppressed list. Caller commits.

    Best-effort per event — an exception in one event's helper is
    logged and the loop continues so a single misbehaving config
    doesn't suppress unrelated alerts.
    """
    results: List[bool] = []
    for event in events:
        try:
            results.append(maybe_fire_mirror_alert(db, mirror, event, now=now))
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception(
                "mirror alert dispatch raised for mirror=%s event=%s: %s",
                mirror.slug,
                event.event_type,
                exc,
            )
            results.append(False)
    return results
