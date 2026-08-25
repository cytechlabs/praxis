"""Security-scan provenance for fleet security state.

A security scan answers a different question than an ordinary package scan: it
asks the package manager which pending updates carry a security advisory. An
inventory scan never asks that question, so it can never make a security count
trustworthy, and the absence of security update rows means "not asked" just as
often as it means "none pending".

Provenance is therefore derived from the operation audit trail, where every
security scan (single host or cohort) is recorded with its per-host outcome:

* ``success`` - the host was scanned and every advisory row was stored.
* ``partial`` - the host was scanned but part of the result could not be read
  or stored, so its count is a floor, not a total.
* ``failure`` - the scan did not produce a usable result for that host.
* ``skipped`` - no scan ran for that host (another operation held the host).

A host is covered only while its most recent recorded outcome is a success, so
a later failure removes the trustworthiness an earlier success granted rather
than leaving a stale green state behind.

Counts are only trustworthy when every in-scope host is covered. Any mixture of
never-scanned, failed, partial, or in-flight hosts yields a state the caller
must render as incomplete instead of as a number.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import false, func
from sqlalchemy.orm import Session

from ..core.redaction import redact_text
from ..db.models import FleetOperation, FleetOperationResult, System

logger = logging.getLogger(__name__)

# Operation types that record an explicit security scan. Inventory scans are
# deliberately absent: they classify nothing as security related.
SECURITY_SCAN_OPERATION_SINGLE = "security_scan"
SECURITY_SCAN_OPERATION_COHORT = "cohort_security_scan"
SECURITY_SCAN_OPERATION_TYPES = (
    SECURITY_SCAN_OPERATION_SINGLE,
    SECURITY_SCAN_OPERATION_COHORT,
)

# Per-host outcome recorded on the operation's result row.
RESULT_SUCCESS = "success"
RESULT_PARTIAL = "partial"
RESULT_FAILURE = "failure"
RESULT_SKIPPED = "skipped"
RECORDED_OUTCOMES = (RESULT_SUCCESS, RESULT_PARTIAL, RESULT_FAILURE)

# Security state of a single scan result and of a whole fleet scope.
STATE_NOT_SCANNED = "not_scanned"
STATE_SCANNING = "scanning"
STATE_FAILED = "failed"
STATE_PARTIAL = "partial"
STATE_COMPLETE = "complete"

# A scan runs inside the request that started it, so an operation still marked
# running long afterwards belongs to a process that died mid-scan. Treat those
# hosts as no longer scanning instead of leaving them in flight forever.
RUNNING_SCAN_MAX_AGE = timedelta(minutes=30)

# Failure text can carry remote package-manager output, so it is redacted,
# flattened, and bounded before it reaches a dashboard.
FAILURE_DETAIL_MAX_CHARS = 200

# A retired host cannot be scanned, so counting it as uncovered would hold the
# fleet in an incomplete state that no operator action can clear.
DECOMMISSIONED_STATUS = "Decommissioned"

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _scope(query, column, system_ids: Optional[Set[int]]):
    """Constrain a fleet-aggregate query to a caller's fleet scope.

    ``system_ids is None`` means tenant-wide (admin) - no filter. An explicit
    set is an allow-list; an empty set yields zero rows, so a scoped caller
    never sees state for systems outside their grants.
    """
    if system_ids is None:
        return query
    if not system_ids:
        return query.filter(false())
    return query.filter(column.in_(system_ids))


def sanitize_detail(message: Optional[str]) -> Optional[str]:
    """Redact, flatten, and bound operator-facing scan failure text.

    The stored message is whatever the scan path recorded, which for an SSH or
    remote-command failure can be an exception string carrying a credential, a
    token, or a repository URL with inline credentials. Every dashboard reader
    in scope receives this text, so the canonical redaction pass runs here at
    the display boundary regardless of what a producer stored.

    Redaction runs before flattening and truncation, on the text as recorded:
    the patterns key off quoting and `key=value` structure, and a secret that
    straddles the character bound must be removed rather than merely cut in
    half. Non-secret diagnostics such as an authentication-method list or an
    unresolved hostname are left intact, because they are what makes the
    message worth showing.
    """
    if not message:
        return None
    text = redact_text(message)
    text = _CONTROL_CHARS_RE.sub(" ", text)
    text = " ".join(text.split())
    if not text:
        return None
    if len(text) > FAILURE_DETAIL_MAX_CHARS:
        text = text[: FAILURE_DETAIL_MAX_CHARS - 3].rstrip() + "..."
    return text


def redact_result_message(message: Optional[str]) -> Optional[str]:
    """Redact a security-scan result message before it is recorded.

    The display boundary redacts unconditionally, so this is defense in depth
    for the rows this scan path writes: an SSH or remote-command failure string
    can carry a credential, and there is no reason to persist one when the text
    is only ever read back as operator diagnostics. Flattening and the length
    bound stay at the display boundary, so the stored row keeps its full
    diagnostic shape.
    """
    if not message:
        return message
    return redact_text(message)


def result_status_for_scan(summary: Dict[str, Any]) -> str:
    """Map a per-host scan summary to the outcome recorded for that host.

    A scan that completed but could not read or store part of its result is
    recorded as ``partial`` so its host never counts as covered.
    """
    status = summary.get("status")
    if status == "already_running":
        return RESULT_SKIPPED
    if status != "success":
        return RESULT_FAILURE
    if summary.get("scan_state") == STATE_PARTIAL:
        return RESULT_PARTIAL
    return RESULT_SUCCESS


def _operation_system_ids(operation: FleetOperation) -> List[int]:
    """Read the target host ids snapshotted on an operation."""
    if not operation.parameters:
        return []
    try:
        parameters = json.loads(operation.parameters)
    except (TypeError, ValueError):
        logger.warning(
            "Security scan operation %s has unreadable parameters", operation.id
        )
        return []
    if not isinstance(parameters, dict):
        return []
    raw_ids = parameters.get("system_ids")
    if not isinstance(raw_ids, list):
        return []
    return [value for value in raw_ids if isinstance(value, int)]


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value else None


def _latest_outcomes(
    db: Session, system_ids: Optional[Set[int]]
) -> Dict[int, FleetOperationResult]:
    """Most recent recorded security-scan outcome per in-scope host."""
    latest_ids = [
        row[0]
        for row in _scope(
            db.query(func.max(FleetOperationResult.id)).join(
                FleetOperation,
                FleetOperation.id == FleetOperationResult.fleet_operation_id,
            ),
            FleetOperationResult.system_id,
            system_ids,
        )
        .filter(
            FleetOperation.operation_type.in_(SECURITY_SCAN_OPERATION_TYPES),
            FleetOperationResult.system_id.isnot(None),
            FleetOperationResult.status.in_(RECORDED_OUTCOMES),
        )
        .group_by(FleetOperationResult.system_id)
        .all()
    ]
    if not latest_ids:
        return {}
    rows = (
        db.query(FleetOperationResult)
        .filter(FleetOperationResult.id.in_(latest_ids))
        .all()
    )
    return {row.system_id: row for row in rows}


def _scanning_system_ids(
    db: Session, system_ids: Optional[Set[int]], now: datetime
) -> Set[int]:
    """Hosts targeted by a security scan that is still in flight."""
    running = (
        db.query(FleetOperation)
        .filter(
            FleetOperation.operation_type.in_(SECURITY_SCAN_OPERATION_TYPES),
            FleetOperation.status == "running",
            FleetOperation.created_at >= now - RUNNING_SCAN_MAX_AGE,
        )
        .all()
    )
    scanning: Set[int] = set()
    for operation in running:
        for candidate in _operation_system_ids(operation):
            if system_ids is None or candidate in system_ids:
                scanning.add(candidate)
    return scanning


def _last_outcome_time(
    db: Session, system_ids: Optional[Set[int]], statuses: tuple
) -> Optional[datetime]:
    return (
        _scope(
            db.query(func.max(FleetOperationResult.created_at)).join(
                FleetOperation,
                FleetOperation.id == FleetOperationResult.fleet_operation_id,
            ),
            FleetOperationResult.system_id,
            system_ids,
        )
        .filter(
            FleetOperation.operation_type.in_(SECURITY_SCAN_OPERATION_TYPES),
            FleetOperationResult.status.in_(statuses),
        )
        .scalar()
    )


def _last_failure_detail(db: Session, system_ids: Optional[Set[int]]) -> Optional[str]:
    row = (
        _scope(
            db.query(FleetOperationResult).join(
                FleetOperation,
                FleetOperation.id == FleetOperationResult.fleet_operation_id,
            ),
            FleetOperationResult.system_id,
            system_ids,
        )
        .filter(
            FleetOperation.operation_type.in_(SECURITY_SCAN_OPERATION_TYPES),
            FleetOperationResult.status.in_((RESULT_FAILURE, RESULT_PARTIAL)),
            FleetOperationResult.error_message.isnot(None),
        )
        .order_by(FleetOperationResult.id.desc())
        .first()
    )
    return sanitize_detail(row.error_message) if row else None


def _coverage_detail(state: str, counts: Dict[str, int]) -> str:
    total = counts["systems_total"]
    scanned = counts["systems_scanned"]
    if total == 0:
        return "No systems in scope."
    if state == STATE_COMPLETE:
        return f"All {total} systems have a completed security scan."
    if state == STATE_SCANNING:
        return (
            f"Security scan running on {counts['systems_scanning']} of "
            f"{total} systems."
        )
    if state == STATE_NOT_SCANNED:
        return f"No security scan has completed for any of the {total} systems."
    return (
        f"{scanned} of {total} systems have a completed security scan "
        f"({counts['systems_failed']} failed, {counts['systems_partial']} partial, "
        f"{counts['systems_never_scanned']} never scanned)."
    )


def get_security_scan_coverage(
    db: Session,
    system_ids: Optional[Set[int]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Derive security-scan coverage for a fleet scope.

    ``system_ids is None`` is tenant-wide; an explicit set is the caller's
    authorized hosts, so every count and timestamp below is scoped to hosts the
    caller may see.
    """
    now = now or datetime.utcnow()

    in_scope = {
        row[0]
        for row in _scope(
            db.query(System.id).filter(System.status != DECOMMISSIONED_STATUS),
            System.id,
            system_ids,
        ).all()
    }
    outcomes = _latest_outcomes(db, system_ids)
    scanning_ids = _scanning_system_ids(db, system_ids, now) & in_scope

    scanned = partial = failed = never_scanned = 0
    for system_id in in_scope:
        if system_id in scanning_ids:
            continue
        outcome = outcomes.get(system_id)
        if outcome is None:
            never_scanned += 1
        elif outcome.status == RESULT_SUCCESS:
            scanned += 1
        elif outcome.status == RESULT_PARTIAL:
            partial += 1
        else:
            failed += 1

    counts = {
        "systems_total": len(in_scope),
        "systems_scanned": scanned,
        "systems_partial": partial,
        "systems_failed": failed,
        "systems_scanning": len(scanning_ids),
        "systems_never_scanned": never_scanned,
    }

    if not in_scope:
        state = STATE_NOT_SCANNED
    elif scanning_ids:
        state = STATE_SCANNING
    elif scanned == len(in_scope):
        state = STATE_COMPLETE
    elif scanned == 0 and partial == 0:
        state = STATE_FAILED if failed else STATE_NOT_SCANNED
    else:
        state = STATE_PARTIAL

    coverage_complete = bool(in_scope) and scanned == len(in_scope)
    return {
        "state": state,
        "coverage_complete": coverage_complete,
        "counts_trustworthy": state == STATE_COMPLETE,
        **counts,
        "last_successful_scan_at": _iso(
            _last_outcome_time(db, system_ids, (RESULT_SUCCESS,))
        ),
        "last_scan_at": _iso(_last_outcome_time(db, system_ids, RECORDED_OUTCOMES)),
        "last_failure_detail": _last_failure_detail(db, system_ids),
        "coverage_detail": _coverage_detail(state, counts),
    }


def build_security_posture(
    db: Session,
    *,
    system_ids: Optional[Set[int]] = None,
    systems_with_security_updates: int = 0,
    pending_security_updates: int = 0,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Security-scan coverage plus the counts it does or does not vouch for.

    The counts are carried alongside their provenance so a caller cannot render
    them without also knowing whether a scan ever established them.
    """
    posture = get_security_scan_coverage(db, system_ids=system_ids, now=now)
    posture["systems_with_security_updates"] = systems_with_security_updates
    posture["pending_security_updates"] = pending_security_updates
    return posture
