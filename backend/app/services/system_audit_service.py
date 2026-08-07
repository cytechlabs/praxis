"""
System audit helper service (PRA-14/PRA-16).

Provides a tiny helper for appending SystemAudit rows from
mutation code paths. The caller owns the transaction and is
responsible for committing.
"""

import json
import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from ..db.models import SystemAudit

logger = logging.getLogger(__name__)


def _stringify(value: Any) -> Optional[str]:
    """Coerce an arbitrary value to a string suitable for audit storage."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, default=str)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def record_audit(
    db: Session,
    system_id: int,
    user_id: int,
    operation: str,
    audit_type: str,
    old_value: Any = None,
    new_value: Any = None,
) -> SystemAudit:
    """
    Append a row to system_audits.

    Caller is responsible for db.commit() — this function only
    adds the row to the session so it slots into an existing
    transaction.
    """
    audit = SystemAudit(
        system_id=system_id,
        audit_type=audit_type,
        changed_by=user_id,
        changed_at=datetime.utcnow(),
        old_value=_stringify(old_value),
        new_value=_stringify(new_value),
        operation=operation,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(audit)

    # PRA-125: fire webhook for audit events (opt-in via event_type filter)
    try:
        from .alert_service import send_alert

        send_alert(
            db,
            event_type="audit_event",
            title=f"Audit: {operation} on system {system_id}",
            message=(
                f"type={audit_type} user_id={user_id} "
                f"old={_stringify(old_value)} new={_stringify(new_value)}"
            ),
            severity="info",
        )
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Audit webhook dispatch failed: %s", e)

    return audit


def snapshot_system(system) -> dict:
    """Produce a JSON-serializable snapshot of a System for audit logging."""
    return {
        "id": getattr(system, "id", None),
        "hostname": getattr(system, "hostname", None),
        "ip_address": (
            str(system.ip_address) if getattr(system, "ip_address", None) else None
        ),
        "status": getattr(system, "status", None),
        "group_id": getattr(system, "group_id", None),
        "distro_id": getattr(system, "distro_id", None),
        "os_version": getattr(system, "os_version", None),
        "credentials_id": getattr(system, "credentials_id", None),
        "update_policy": getattr(system, "update_policy", None),
    }
