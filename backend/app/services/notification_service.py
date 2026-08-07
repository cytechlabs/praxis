"""
Unified notification service (PRA-99, PRA-100).

Single entry point for all in-app notifications AND external alert delivery.
Respects per-user notification preferences when a target user_id is set.
"""

import json
import logging
from typing import Optional

from sqlalchemy.orm import Session

from ..db.models import Notification, NotificationPreference
from .alert_service import send_alert

logger = logging.getLogger(__name__)


def _is_type_disabled(db: Session, user_id: int, event_type: str) -> bool:
    """Return True if *user_id* has opted out of *event_type*."""
    prefs = (
        db.query(NotificationPreference)
        .filter(NotificationPreference.user_id == user_id)
        .first()
    )
    if not prefs:
        return False
    disabled = json.loads(prefs.disabled_types)
    return event_type in disabled


def create_notification(
    db: Session,
    type: str,  # noqa: A002 — matches model column name
    title: str,
    message: str,
    severity: str = "info",
    user_id: Optional[int] = None,
    related_job_id: Optional[int] = None,
    system_id: Optional[int] = None,
) -> Optional[Notification]:
    """Create an in-app notification AND trigger external alerts.

    Args:
        db: SQLAlchemy session.
        type: Event type (e.g. ``job_failed``, ``system_unreachable``).
        title: Short human-readable title.
        message: Longer description.
        severity: ``info``, ``warning``, or ``error``.
        user_id: Target user (None = broadcast to all).
        related_job_id: Optional FK to jobs table.
        system_id: Optional host id for per-event smart-group scoping
            (PRA-126). When set, ``send_alert`` honors the configured
            ``scope_smart_group_id`` membership check; when None, only
            non-scoped configs receive the event. Required for any
            host-scoped PRA-178 lifecycle event so scoped alert
            configs match.

    Returns:
        The newly created Notification instance, or ``None`` if the target
        user has disabled this event type.
    """
    # PRA-100: Skip if the targeted user opted out of this type.
    # Broadcasts (user_id=None) are always created; filtering happens
    # at read time in the notifications list endpoint.
    if user_id is not None and _is_type_disabled(db, user_id, type):
        logger.debug(
            "Skipping notification type=%s for user_id=%d (opted out)", type, user_id
        )
        # Still send external alerts even if in-app is suppressed
        try:
            send_alert(
                db,
                event_type=type,
                title=title,
                message=message,
                severity=severity,
                system_id=system_id,
            )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("External alert delivery failed: %s", e)
        return None

    # 1. In-app notification
    notification = Notification(
        type=type,
        title=title,
        message=message,
        severity=severity,
        user_id=user_id,
        related_job_id=related_job_id,
    )
    db.add(notification)
    db.commit()

    # 2. External alert delivery (best-effort, never crashes caller)
    try:
        send_alert(
            db,
            event_type=type,
            title=title,
            message=message,
            severity=severity,
            system_id=system_id,
        )
    except Exception as e:  # pylint: disable=broad-except
        logger.error("External alert delivery failed: %s", e)

    return notification


# PRA-344: connection states that represent a host being offline / in a problem
# state. A transition FROM one of these TO "connected" is a genuine recovery.
# "auth_failed" is deliberately EXCLUDED — reachable-but-not-managed (PRA-322),
# not a recovery by itself.
_OFFLINE_CONNECTION_STATES = ("disconnected", "unreachable", "error")


def notify_host_recovered(
    db: Session,
    system,
    previous_status: Optional[str],
    new_status: Optional[str],
) -> None:
    """Emit a single ``system_recovered`` alert on an offline→connected transition.

    Shared by ``HealthService`` and ``SSHService`` (PRA-344) so a recovery alert
    fires no matter which backend path first observes the host reconnecting (a
    health check, a package scan, a command, a file transfer, …). It is
    idempotent per transition — a no-op unless ``previous_status`` is an offline
    state and ``new_status`` is ``"connected"`` — so repeated successful
    connections on an already-connected host never spam recovery alerts.

    Alert delivery is isolated: a notification/alert failure is swallowed here so
    it can never roll back or break the caller's committed host-state update.
    """
    if new_status != "connected" or previous_status not in _OFFLINE_CONNECTION_STATES:
        return
    try:
        create_notification(
            db,
            type="system_recovered",
            title=f"System '{system.hostname}' recovered",
            message="Connectivity restored",
            severity="info",
            system_id=system.id,
        )
    except Exception:  # pylint: disable=broad-except
        logger.exception(
            "Failed to emit system_recovered alert for system %s",
            getattr(system, "id", "?"),
        )
