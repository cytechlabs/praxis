"""Compliance remediation request service (PRA-167 Slice 1).

Non-executing remediation substrate. Slice 1 captures operator intent
to remediate a failing compliance evidence row plus the approval-gate
state that later slices will read before any host-changing work runs.

Hard scope (PRA-167 Slice 1):

* No host mutation, remote command execution, package install/remove,
  rollback, reboot, OpenSCAP, package scan, or facts refresh — this
  module only writes to the database.
* ``approve_request`` flips a request's ``state`` to ``approved``; it
  does **not** dispatch, queue, or run anything. Later slices will
  consume the approved state to drive execution.
* Sister to :mod:`patch_approval_service` in spirit (vote-only, never
  auto-execute) but kept deliberately separate so a future change to
  command-style approvals can't accidentally make compliance
  remediation auto-run.

Snapshot semantics:

* At request time the service freezes ``policy_slug`` /
  ``policy_version`` / ``check_slug`` / ``check_kind`` /
  ``severity_snapshot`` / ``verdict_snapshot`` /
  ``verdict_reason_snapshot`` / ``remediation_guidance_snapshot`` so
  later execution does not depend on live (possibly-edited) policy
  text. ``remediation_guidance_snapshot`` falls back to the policy's
  guidance when the check has none, and is bounded to the same 16384
  characters used by the policy/check fields.
* ``evidence_id`` is recorded by FK; if a retention sweep later
  prunes that row the FK SET NULLs and the snapshot columns continue
  to read cleanly.

Approval gate:

* The default approval rule is two-person: the approver must not be
  the same user that filed the request. This matches the SOC 2 CC6.3
  "separation of duties" pattern that the compliance evidence map
  already advertises. The rule fails closed at the service layer and
  is recorded in audit context so an operator can prove the gate.

Audit-row semantics follow ``feedback_safe_emit_session_boundary``:
``safe_emit`` is invoked AFTER the service commits its own
transaction, with no ``db=`` argument so it opens its own
``SessionLocal``.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from app.services.access_authorization_service import scope_in_clause

from ..db.models import (
    CompliancePolicy,
    CompliancePolicyCheck,
    CompliancePolicyEvidence,
    ComplianceRemediationRequest,
    System,
    User,
)
from . import compliance_labels
from .audit_event_service import safe_emit
from .compliance_evaluation_service import VALID_VERDICTS
from .compliance_service import (
    VALID_SEVERITIES,
    ComplianceError,
    runner_owner_for_kind,
    utc_iso,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabulary — kept local so the patch-approval / command-approval
# services cannot accidentally couple back into compliance remediation.
# ---------------------------------------------------------------------------

STATE_REQUESTED = "requested"
STATE_APPROVED = "approved"
STATE_REJECTED = "rejected"
STATE_CANCELLED = "cancelled"

VALID_STATES: Tuple[str, ...] = (
    STATE_REQUESTED,
    STATE_APPROVED,
    STATE_REJECTED,
    STATE_CANCELLED,
)

TERMINAL_STATES: Tuple[str, ...] = (
    STATE_APPROVED,
    STATE_REJECTED,
    STATE_CANCELLED,
)

# Bounds — keep persisted payloads small and explicit.
MAX_JUSTIFICATION_CHARS = 4096
MAX_DECIDED_REASON_CHARS = 4096
MAX_REMEDIATION_GUIDANCE_CHARS = 16384


# ---------------------------------------------------------------------------
# Audit event-type strings — PRA-165 reserved the
# ``compliance_remediation.*`` namespace; Slice 1 wires the first
# concrete events here.
# ---------------------------------------------------------------------------

AUDIT_COMPLIANCE_REMEDIATION_REQUESTED = "compliance_remediation.requested"
AUDIT_COMPLIANCE_REMEDIATION_APPROVED = "compliance_remediation.approved"
AUDIT_COMPLIANCE_REMEDIATION_REJECTED = "compliance_remediation.rejected"
AUDIT_COMPLIANCE_REMEDIATION_CANCELLED = "compliance_remediation.cancelled"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _err(msg: str) -> ComplianceError:
    return ComplianceError(msg)


def _require_user(db: Session, user_id: int, *, field: str) -> User:
    if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0:
        raise _err(f"{field} must be a positive integer")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise _err(f"{field}={user_id} does not reference a user")
    return user


def _require_request(db: Session, request_id: int) -> ComplianceRemediationRequest:
    row = (
        db.query(ComplianceRemediationRequest)
        .filter(ComplianceRemediationRequest.id == request_id)
        .first()
    )
    if row is None:
        raise _err(f"compliance remediation request id={request_id} not found")
    return row


def _bounded_str(
    value: Any,
    *,
    field: str,
    max_chars: int,
    allow_none: bool = True,
) -> Optional[str]:
    if value is None:
        if allow_none:
            return None
        raise _err(f"{field} must be a non-empty string")
    if not isinstance(value, str):
        raise _err(f"{field} must be a string")
    if len(value) > max_chars:
        raise _err(f"{field} exceeds {max_chars} characters")
    return value


def _request_audit_context(
    row: ComplianceRemediationRequest,
    *,
    extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "policy_id": row.policy_id,
        "policy_slug": row.policy_slug,
        "policy_version": row.policy_version,
        "check_id": row.check_id,
        "check_slug": row.check_slug,
        "check_kind": row.check_kind,
        "system_id": row.system_id,
        "evidence_id": row.evidence_id,
        "evaluation_run_id": row.evaluation_run_id,
        "verdict_snapshot": row.verdict_snapshot,
        "severity_snapshot": row.severity_snapshot,
        "state": row.state,
        "requested_by": row.requested_by,
        "decided_by": row.decided_by,
    }
    if extras:
        ctx.update(extras)
    return ctx


# ---------------------------------------------------------------------------
# Read envelope — single canonical shape used by routes + tests.
# ---------------------------------------------------------------------------


def remediation_request_read_envelope(
    row: ComplianceRemediationRequest,
) -> Dict[str, Any]:
    """Serialize a remediation request with absolute-UTC timestamps.

    ``runner_owner`` is recomputed from ``check_kind`` so the read
    surface advertises whose runner would eventually act on the
    snapshot (Slice 1 itself never runs anything).
    """
    try:
        runner_owner = runner_owner_for_kind(row.check_kind)
    except ComplianceError:
        runner_owner = "unknown"
    return {
        "id": row.id,
        "policy_id": row.policy_id,
        "check_id": row.check_id,
        "system_id": row.system_id,
        "evidence_id": row.evidence_id,
        "policy_slug": row.policy_slug,
        "policy_version": row.policy_version,
        "check_slug": row.check_slug,
        "check_kind": row.check_kind,
        "runner_owner": runner_owner,
        # PRA-346: product-facing siblings for the carried-forward evidence
        # snapshot. Raw enums stay stable; the UI renders these.
        "runner_label": compliance_labels.runner_label(runner_owner),
        "verdict_label": compliance_labels.verdict_label(row.verdict_snapshot),
        "verdict_reason_snapshot_label": compliance_labels.verdict_reason_label(
            row.verdict_reason_snapshot
        ),
        "evaluation_run_id": row.evaluation_run_id,
        "verdict_snapshot": row.verdict_snapshot,
        "verdict_reason_snapshot": row.verdict_reason_snapshot,
        "severity_snapshot": row.severity_snapshot,
        "remediation_guidance_snapshot": row.remediation_guidance_snapshot,
        "state": row.state,
        "justification": row.justification,
        "requested_by": row.requested_by,
        "decided_by": row.decided_by,
        "decided_at": utc_iso(row.decided_at),
        "decided_reason": row.decided_reason,
        "created_at": utc_iso(row.created_at),
        "updated_at": utc_iso(row.updated_at),
    }


# ---------------------------------------------------------------------------
# Snapshot resolution
# ---------------------------------------------------------------------------


def _resolve_snapshot_from_evidence(
    db: Session, evidence_id: int
) -> Tuple[
    CompliancePolicy,
    Optional[CompliancePolicyCheck],
    CompliancePolicyEvidence,
    System,
]:
    """Resolve the snapshot fields by following the evidence row.

    Caller passes ``evidence_id``; this function loads the evidence,
    its policy, its (optionally-deleted) check, and its target
    system. Raises :class:`ComplianceError` with a "not found" message
    if any required row is missing — the FastAPI layer maps the
    family to 404.
    """
    evidence = (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.id == evidence_id)
        .first()
    )
    if evidence is None:
        raise _err(f"compliance evidence id={evidence_id} not found")
    policy = (
        db.query(CompliancePolicy)
        .filter(CompliancePolicy.id == evidence.policy_id)
        .first()
    )
    if policy is None:
        # Should be impossible given the FK CASCADE, but stay loud if
        # an out-of-band SQL deleted the policy and orphaned evidence.
        raise _err(
            f"compliance policy id={evidence.policy_id} for evidence "
            f"id={evidence_id} not found"
        )
    check: Optional[CompliancePolicyCheck] = None
    if evidence.check_id is not None:
        check = (
            db.query(CompliancePolicyCheck)
            .filter(CompliancePolicyCheck.id == evidence.check_id)
            .first()
        )
    system = db.query(System).filter(System.id == evidence.system_id).first()
    if system is None:
        raise _err(f"system id={evidence.system_id} not found")
    return policy, check, evidence, system


def _resolve_guidance(
    *,
    policy: CompliancePolicy,
    check: Optional[CompliancePolicyCheck],
) -> Optional[str]:
    """Pick the most specific remediation guidance available.

    Check-level guidance wins; policy-level guidance is the fallback
    so a starter-pack policy with only a policy-wide guidance string
    still produces a useful snapshot. ``None`` when neither layer set
    guidance — the snapshot column stays NULL and the route returns
    ``remediation_guidance_snapshot: null``.
    """
    if check is not None and check.remediation_guidance:
        return check.remediation_guidance[:MAX_REMEDIATION_GUIDANCE_CHARS]
    if policy.remediation_guidance:
        return policy.remediation_guidance[:MAX_REMEDIATION_GUIDANCE_CHARS]
    return None


# ---------------------------------------------------------------------------
# Public API — create
# ---------------------------------------------------------------------------


def create_request(
    db: Session,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    evidence_id: int,
    justification: Optional[str] = None,
) -> ComplianceRemediationRequest:
    """Open a remediation request for a failing compliance evidence row.

    Fails closed when the evidence verdict is not ``fail`` (passing
    rows have nothing to remediate; ``error`` rows mean the runner
    couldn't evaluate, so remediation intent would be ambiguous).
    Both restrictions are explicit so a later slice can relax them
    intentionally rather than by accident.
    """
    requester = _require_user(db, actor_user_id, field="actor_user_id")

    if not isinstance(evidence_id, int) or isinstance(evidence_id, bool):
        raise _err("evidence_id must be an integer")
    if evidence_id <= 0:
        raise _err("evidence_id must be a positive integer")

    policy, check, evidence, system = _resolve_snapshot_from_evidence(db, evidence_id)

    if evidence.verdict not in VALID_VERDICTS:
        # Defensive — Slice 2 evaluation_service writes only valid
        # verdicts, but a raw-SQL import could land an invalid one.
        raise _err(
            f"evidence verdict {evidence.verdict!r} is not in the "
            f"compliance vocabulary"
        )
    if evidence.verdict != "fail":
        raise _err(
            "remediation requests may only be opened for evidence with "
            f"verdict='fail' (got {evidence.verdict!r})"
        )

    severity = evidence.severity
    if severity not in VALID_SEVERITIES:
        raise _err(
            f"evidence severity {severity!r} is not in the compliance " "vocabulary"
        )

    justification_clean = _bounded_str(
        justification,
        field="justification",
        max_chars=MAX_JUSTIFICATION_CHARS,
        allow_none=True,
    )

    guidance_snapshot = _resolve_guidance(policy=policy, check=check)

    row = ComplianceRemediationRequest(
        policy_id=policy.id,
        check_id=check.id if check is not None else None,
        system_id=system.id,
        evidence_id=evidence.id,
        policy_slug=evidence.policy_slug,
        policy_version=evidence.policy_version,
        check_slug=evidence.check_slug,
        check_kind=evidence.check_kind,
        evaluation_run_id=evidence.evaluation_run_id,
        verdict_snapshot=evidence.verdict,
        verdict_reason_snapshot=evidence.verdict_reason,
        severity_snapshot=severity,
        remediation_guidance_snapshot=guidance_snapshot,
        state=STATE_REQUESTED,
        justification=justification_clean,
        requested_by=requester.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_REQUESTED,
        outcome="success",
        actor_user_id=requester.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_request",
        target_id=str(row.id),
        target_system_id=row.system_id,
        context=_request_audit_context(
            row,
            extras={
                "has_guidance_snapshot": guidance_snapshot is not None,
                "justification_length": (
                    len(justification_clean) if justification_clean else 0
                ),
            },
        ),
    )
    # PRA-178 Slice 3: emit the remediation.requested notification beside
    # the existing audit event. Best-effort — a notification/alert failure
    # cannot unwind the request that was already committed above.
    from . import notification_events

    notification_events.emit_remediation_requested(
        db,
        request_id=row.id,
        policy_slug=row.policy_slug,
        check_slug=row.check_slug,
        system_id=row.system_id,
        requested_by=row.requested_by,
    )
    return row


# ---------------------------------------------------------------------------
# Public API — read / list
# ---------------------------------------------------------------------------


def get_request(db: Session, request_id: int) -> Optional[ComplianceRemediationRequest]:
    return (
        db.query(ComplianceRemediationRequest)
        .filter(ComplianceRemediationRequest.id == request_id)
        .first()
    )


def list_requests(
    db: Session,
    *,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    state: Optional[str] = None,
    offset: int = 0,
    limit: int = 100,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Tuple[List[ComplianceRemediationRequest], int]:
    """Paginated list. ``state`` filter is normalized + range-checked
    here so route layers can pass user input straight through.

    ``allowed_system_ids`` (PRA-281) restricts rows AND the total to the
    caller's fleet scope (``None`` = admin; empty = nothing).

    Returns ``(rows, total_matching_filter)``. Rows are newest first
    so paged consumers see "most recent" without re-sorting.
    """
    if offset < 0:
        raise _err("offset must be >= 0")
    if not (1 <= limit <= 500):
        raise _err("limit must be in 1..500")
    if state is not None and state not in VALID_STATES:
        raise _err(f"state must be one of: {list(VALID_STATES)}")
    if policy_id is not None and (
        isinstance(policy_id, bool) or not isinstance(policy_id, int) or policy_id <= 0
    ):
        raise _err("policy_id must be a positive integer")
    if system_id is not None and (
        isinstance(system_id, bool) or not isinstance(system_id, int) or system_id <= 0
    ):
        raise _err("system_id must be a positive integer")

    q = db.query(ComplianceRemediationRequest)
    if policy_id is not None:
        q = q.filter(ComplianceRemediationRequest.policy_id == policy_id)
    if system_id is not None:
        q = q.filter(ComplianceRemediationRequest.system_id == system_id)
    if state is not None:
        q = q.filter(ComplianceRemediationRequest.state == state)
    scope_clause = scope_in_clause(
        ComplianceRemediationRequest.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)

    total = q.with_entities(ComplianceRemediationRequest.id).count()
    rows = (
        q.order_by(
            ComplianceRemediationRequest.created_at.desc(),
            ComplianceRemediationRequest.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


# ---------------------------------------------------------------------------
# Public API — state transitions (NEVER auto-execute)
# ---------------------------------------------------------------------------


def _assert_pending(row: ComplianceRemediationRequest) -> None:
    """Fail closed on any non-pending transition. Slice 1 states are
    strict: once a request is approved/rejected/cancelled, no further
    transition is allowed from this service. Re-opening would require
    a fresh request so the audit trail records the new intent
    explicitly.
    """
    if row.state == STATE_REQUESTED:
        return
    raise _err(
        f"remediation request {row.id} is in state {row.state!r}; "
        "only requests in state 'requested' can transition"
    )


def approve_request(
    db: Session,
    request_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    decided_reason: Optional[str] = None,
) -> ComplianceRemediationRequest:
    """Mark the request approved. **Does not run any commands** —
    later slices read the approved state and decide whether to
    execute.

    Enforces approver != requester (separation of duties). This rule
    is recorded in the audit context for the SOC 2 CC6.3 evidence
    map.
    """
    decider = _require_user(db, actor_user_id, field="actor_user_id")
    row = _require_request(db, request_id)
    _assert_pending(row)
    if row.requested_by == decider.id:
        raise _err("approver must not be the requester (separation of duties)")

    reason_clean = _bounded_str(
        decided_reason,
        field="decided_reason",
        max_chars=MAX_DECIDED_REASON_CHARS,
        allow_none=True,
    )

    row.state = STATE_APPROVED
    row.decided_by = decider.id
    row.decided_at = datetime.utcnow()
    row.decided_reason = reason_clean
    db.commit()
    db.refresh(row)

    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_APPROVED,
        outcome="success",
        actor_user_id=decider.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_request",
        target_id=str(row.id),
        target_system_id=row.system_id,
        context=_request_audit_context(
            row,
            extras={
                "separation_of_duties_enforced": True,
                "decided_reason_length": (len(reason_clean) if reason_clean else 0),
            },
        ),
    )
    return row


def reject_request(
    db: Session,
    request_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    decided_reason: Optional[str] = None,
) -> ComplianceRemediationRequest:
    """Mark the request rejected. Terminal. The same approver !=
    requester rule applies so a requester can't unilaterally
    short-circuit their own approval gate with a self-reject.
    """
    decider = _require_user(db, actor_user_id, field="actor_user_id")
    row = _require_request(db, request_id)
    _assert_pending(row)
    if row.requested_by == decider.id:
        raise _err("rejector must not be the requester (use cancel to withdraw)")

    reason_clean = _bounded_str(
        decided_reason,
        field="decided_reason",
        max_chars=MAX_DECIDED_REASON_CHARS,
        allow_none=True,
    )

    row.state = STATE_REJECTED
    row.decided_by = decider.id
    row.decided_at = datetime.utcnow()
    row.decided_reason = reason_clean
    db.commit()
    db.refresh(row)

    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_REJECTED,
        outcome="success",
        actor_user_id=decider.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_request",
        target_id=str(row.id),
        target_system_id=row.system_id,
        context=_request_audit_context(
            row,
            extras={
                "decided_reason_length": (len(reason_clean) if reason_clean else 0),
            },
        ),
    )
    return row


def cancel_request(
    db: Session,
    request_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    decided_reason: Optional[str] = None,
) -> ComplianceRemediationRequest:
    """Cancel a request. Allowed for the requester (self-withdraw) so
    operator-driven cleanup doesn't need a second admin. Approvers
    can also cancel; the audit context records which case applied.
    """
    actor = _require_user(db, actor_user_id, field="actor_user_id")
    row = _require_request(db, request_id)
    _assert_pending(row)

    reason_clean = _bounded_str(
        decided_reason,
        field="decided_reason",
        max_chars=MAX_DECIDED_REASON_CHARS,
        allow_none=True,
    )

    self_cancel = row.requested_by == actor.id
    row.state = STATE_CANCELLED
    row.decided_by = actor.id
    row.decided_at = datetime.utcnow()
    row.decided_reason = reason_clean
    db.commit()
    db.refresh(row)

    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_CANCELLED,
        outcome="success",
        actor_user_id=actor.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_request",
        target_id=str(row.id),
        target_system_id=row.system_id,
        context=_request_audit_context(
            row,
            extras={
                "self_cancel": self_cancel,
                "decided_reason_length": (len(reason_clean) if reason_clean else 0),
            },
        ),
    )
    return row
