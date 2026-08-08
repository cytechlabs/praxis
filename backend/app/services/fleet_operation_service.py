"""
Fleet operation audit trail service (PRA-115).

Thin helper for recording bulk fleet actions. Each public function opens
its own SessionLocal so it is safe to call from background/parallel
workers that shouldn't share a request-bound session.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from ..db.models import FleetOperation, FleetOperationResult
from ..db.session import SessionLocal

logger = logging.getLogger(__name__)


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def start_operation(
    operation_type: str,
    user_id: int,
    target_count: int,
    parameters: Optional[Dict[str, Any]] = None,
) -> int:
    """Create a new FleetOperation in 'running' state. Returns its id."""
    db = SessionLocal()
    try:
        op = FleetOperation(
            operation_type=operation_type,
            user_id=user_id,
            target_count=target_count,
            success_count=0,
            failure_count=0,
            parameters=json.dumps(_json_safe(parameters)) if parameters else None,
            status="running",
            created_at=datetime.utcnow(),
        )
        db.add(op)
        db.commit()
        db.refresh(op)
        return op.id
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Failed to start fleet operation: %s", e)
        db.rollback()
        raise
    finally:
        db.close()


def record_result(
    fleet_operation_id: int,
    system_id: Optional[int],
    status: str,
    error_message: Optional[str] = None,
) -> None:
    """Append a per-system result row to a FleetOperation."""
    db = SessionLocal()
    try:
        result = FleetOperationResult(
            fleet_operation_id=fleet_operation_id,
            system_id=system_id,
            status=status,
            error_message=error_message,
            created_at=datetime.utcnow(),
        )
        db.add(result)
        db.commit()
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Failed to record fleet operation result: %s", e)
        db.rollback()
    finally:
        db.close()


def complete_operation(
    fleet_operation_id: int,
    success_count: int,
    failure_count: int,
    status: Optional[str] = None,
) -> None:
    """
    Mark a FleetOperation as finished. If status is not provided, it is
    derived from the success/failure counts.
    """
    db = SessionLocal()
    try:
        op = (
            db.query(FleetOperation)
            .filter(FleetOperation.id == fleet_operation_id)
            .first()
        )
        if not op:
            logger.warning("complete_operation: id=%s not found", fleet_operation_id)
            return

        if status is None:
            if failure_count == 0 and success_count > 0:
                status = "completed"
            elif success_count == 0 and failure_count > 0:
                status = "failed"
            elif success_count > 0 and failure_count > 0:
                status = "partial"
            else:
                status = "completed"

        op.success_count = success_count
        op.failure_count = failure_count
        op.status = status
        op.completed_at = datetime.utcnow()
        db.commit()

        # PRA-125: fire webhook for fleet operation completion
        try:
            from .alert_service import send_alert

            severity = (
                "error"
                if status == "failed"
                else "warning" if status == "partial" else "info"
            )
            send_alert(
                db,
                event_type="fleet_operation_complete",
                title=f"Fleet operation {status}: {op.operation_type}",
                message=(
                    f"Operation #{op.id} finished: {success_count} succeeded, "
                    f"{failure_count} failed (of {op.target_count} targets)."
                ),
                severity=severity,
            )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Fleet operation webhook dispatch failed: %s", e)
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Failed to complete fleet operation: %s", e)
        db.rollback()
    finally:
        db.close()
