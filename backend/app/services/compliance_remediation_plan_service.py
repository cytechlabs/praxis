"""Compliance remediation plan preview service (PRA-167 Slice 2).

Builds and reads non-executing remediation execution-plan previews
for approved compliance remediation requests. Slice 2 stays strictly
inside the data-model substrate: plan rows describe what a later
execution slice *would* do, in bounded structured form, but nothing
here calls SSH, dispatches jobs, refreshes facts, scans packages,
mutates hosts, or auto-runs anything on approval.

Boundaries:

* Building a plan does NOT mutate the source remediation request.
  The request stays in state ``approved``; only the plan row is
  written.
* Building is idempotent. There is at most one plan row per request
  (unique constraint enforced at the DB and recomputed in the
  service). Re-building overwrites the previous plan content but
  keeps the row id stable.
* The plan is gated on ``request.state == 'approved'``. Requests in
  any other state (``requested``, ``rejected``, ``cancelled``) raise
  :class:`ComplianceError` so the gate fails closed.
* ``plan_steps`` is a JSON list of operator-readable intent objects,
  not executable shell. The service caps both the step count and
  the serialized payload size.
* Plan kinds are explicit per existing PRA-165/166 check kind. For
  check kinds whose remediation is fundamentally an operator
  decision (file/command/fact checks), the plan is still produced
  but its ``plan_kind`` is one of the ``*_review_required``
  vocabulary values and ``plan_steps`` carries a single review
  intent.

Audit:

* ``compliance_remediation_plan.built`` fires on first creation.
* ``compliance_remediation_plan.refreshed`` fires when an existing
  plan is rebuilt.
* ``compliance_remediation_plan.unsupported`` fires when the plan
  resolves to the ``unsupported`` state.
* All emits go through ``safe_emit`` AFTER the service commits
  (session-boundary pattern, no ``db=``).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from app.services.access_authorization_service import scope_in_clause

from ..db.models import (
    CompliancePolicyCheck,
    ComplianceRemediationPlan,
    ComplianceRemediationRequest,
    System,
    User,
)
from .audit_event_service import safe_emit
from .compliance_remediation_service import STATE_APPROVED, ComplianceError
from .compliance_service import utc_iso

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabulary — local; no coupling to other approval services.
# ---------------------------------------------------------------------------

PLAN_STATE_PLANNED = "planned"
PLAN_STATE_UNSUPPORTED = "unsupported"
PLAN_STATE_FAILED = "failed"

VALID_PLAN_STATES: Tuple[str, ...] = (
    PLAN_STATE_PLANNED,
    PLAN_STATE_UNSUPPORTED,
    PLAN_STATE_FAILED,
)

# Plan kind vocabulary. Each maps 1:1 to a PRA-165/166 check kind
# (or to a catch-all for unknown kinds). ``*_review_required`` means
# Slice 2 produced an explicit "operator decides" preview rather
# than an actionable one — there is no safe automated remediation
# without operator input.
PLAN_KIND_PACKAGE_INSTALL = "package_install_preview"
PLAN_KIND_PACKAGE_REMOVE = "package_remove_preview"
PLAN_KIND_PACKAGE_UPGRADE = "package_upgrade_preview"
PLAN_KIND_FACTS_REVIEW = "facts_review_required"
PLAN_KIND_FILE_REVIEW = "file_review_required"
PLAN_KIND_COMMAND_REVIEW = "command_review_required"
PLAN_KIND_UNSUPPORTED = "unsupported"

VALID_PLAN_KINDS: Tuple[str, ...] = (
    PLAN_KIND_PACKAGE_INSTALL,
    PLAN_KIND_PACKAGE_REMOVE,
    PLAN_KIND_PACKAGE_UPGRADE,
    PLAN_KIND_FACTS_REVIEW,
    PLAN_KIND_FILE_REVIEW,
    PLAN_KIND_COMMAND_REVIEW,
    PLAN_KIND_UNSUPPORTED,
)

# Bounds — keep persisted plan payloads small and explicit.
MAX_PLAN_STEPS = 32
MAX_PLAN_STEPS_SERIALIZED_BYTES = 16_384
MAX_UNSUPPORTED_REASON_CHARS = 512
MAX_ERROR_MESSAGE_CHARS = 512
MAX_PLAN_STEP_TEXT_CHARS = 1_024


# ---------------------------------------------------------------------------
# Audit event-type strings — under the PRA-165-reserved
# ``compliance_remediation.*`` namespace, suffixed for the plan
# substrate so consumers can distinguish request from plan events.
# ---------------------------------------------------------------------------

AUDIT_COMPLIANCE_REMEDIATION_PLAN_BUILT = "compliance_remediation_plan.built"
AUDIT_COMPLIANCE_REMEDIATION_PLAN_REFRESHED = "compliance_remediation_plan.refreshed"
AUDIT_COMPLIANCE_REMEDIATION_PLAN_UNSUPPORTED = (
    "compliance_remediation_plan.unsupported"
)
# PRA-167 Slice 3 lifecycle audit actions.
AUDIT_COMPLIANCE_REMEDIATION_PLAN_ACKNOWLEDGED = (
    "compliance_remediation_plan.acknowledged"
)
AUDIT_COMPLIANCE_REMEDIATION_PLAN_SUPERSEDED = "compliance_remediation_plan.superseded"


# Plan kinds that a future execution slice can act on without
# operator-provided remediation content. The Slice 3 readiness gate
# uses this to short-circuit ``ready_for_execution`` for the
# review-required / unsupported kinds — those need human input before
# any execution layer would have something to run.
EXECUTABLE_PLAN_KINDS: Tuple[str, ...] = (
    PLAN_KIND_PACKAGE_INSTALL,
    PLAN_KIND_PACKAGE_REMOVE,
    PLAN_KIND_PACKAGE_UPGRADE,
)


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
    if (
        not isinstance(request_id, int)
        or isinstance(request_id, bool)
        or request_id <= 0
    ):
        raise _err("request_id must be a positive integer")
    row = (
        db.query(ComplianceRemediationRequest)
        .filter(ComplianceRemediationRequest.id == request_id)
        .first()
    )
    if row is None:
        raise _err(f"compliance remediation request id={request_id} not found")
    return row


def _bounded_text(value: Optional[str], *, max_chars: int) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    if len(value) > max_chars:
        return value[: max_chars - 1] + "…"
    return value


def _validate_plan_steps_payload(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Cap step count and serialized size, then re-emit a normalized
    list. Truncation is loud (a ``safety_notes`` entry is appended)
    so a downstream consumer cannot mistake a truncated plan for a
    complete one.
    """
    if not isinstance(steps, list):
        raise _err("plan_steps must be a JSON list of step objects")
    truncated = False
    if len(steps) > MAX_PLAN_STEPS:
        steps = steps[:MAX_PLAN_STEPS]
        truncated = True
    serialized = json.dumps(steps, separators=(",", ":"), default=str)
    if len(serialized.encode("utf-8")) > MAX_PLAN_STEPS_SERIALIZED_BYTES:
        # Truncate until under the cap by dropping trailing steps.
        while (
            steps
            and len(
                json.dumps(steps, separators=(",", ":"), default=str).encode("utf-8")
            )
            > MAX_PLAN_STEPS_SERIALIZED_BYTES
        ):
            steps = steps[:-1]
            truncated = True
    if truncated:
        steps.append(
            {
                "action_intent": "review_required",
                "reason": "plan truncated to fit bounded preview payload",
                "safety_notes": ["non-executing preview only; operator must verify"],
            }
        )
    return steps


def _request_snapshot_dict(
    request: ComplianceRemediationRequest,
) -> Dict[str, Any]:
    return {
        "policy_id": request.policy_id,
        "check_id": request.check_id,
        "system_id": request.system_id,
        "policy_slug": request.policy_slug,
        "policy_version": request.policy_version,
        "check_slug": request.check_slug,
        "check_kind": request.check_kind,
        "severity_snapshot": request.severity_snapshot,
    }


def _live_check_definition(
    db: Session, check_id: Optional[int]
) -> Optional[Dict[str, Any]]:
    """Return the live check's ``definition_json`` if the row still
    exists. ``None`` when the check has been deleted (Slice 1's
    SET-NULL FK semantics) — the builders fall back to review-
    required plans in that case.
    """
    if check_id is None:
        return None
    check = (
        db.query(CompliancePolicyCheck)
        .filter(CompliancePolicyCheck.id == check_id)
        .first()
    )
    if check is None:
        return None
    return dict(check.definition_json or {})


def _system_descriptor(db: Session, system_id: int) -> Dict[str, Any]:
    system = db.query(System).filter(System.id == system_id).first()
    return {
        "system_id": system_id,
        "system_hostname": system.hostname if system else None,
    }


# ---------------------------------------------------------------------------
# Slice 3 lifecycle helpers — fingerprint, current/superseded, staleness,
# readiness gate. All operate on the stored plan + the live (read-only)
# check definition; nothing here runs anything on a host.
# ---------------------------------------------------------------------------


def _fingerprint_check_definition(
    definition: Optional[Dict[str, Any]]
) -> Optional[str]:
    """Return a deterministic 64-char SHA-256 hex digest of the
    canonical-JSON form of ``definition``, or ``None`` when the
    definition is unavailable.

    Canonical = ``sort_keys=True``, no whitespace, default str
    fallback. The fingerprint is the only thing stored to detect
    stale plans; we deliberately do not persist the full live check
    definition twice.
    """
    if definition is None:
        return None
    canonical = json.dumps(
        definition, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _is_current(plan: ComplianceRemediationPlan) -> bool:
    return plan.superseded_by_plan_id is None


def _is_stale(db: Session, plan: ComplianceRemediationPlan) -> bool:
    """A plan is stale when its captured fingerprint no longer matches
    the live check definition. If the live check has been deleted we
    treat the plan as stale — a later execution slice cannot derive a
    fresh plan from missing source state.

    Plans whose ``check_definition_fingerprint`` is null at build
    time (built against an already-deleted check) are also considered
    stale: there is nothing to compare against, so the safe default
    is "operator must review" rather than "presumed fresh".
    """
    if plan.check_definition_fingerprint is None:
        return True
    live_def = _live_check_definition(db, plan.check_id)
    if live_def is None:
        return True
    return _fingerprint_check_definition(live_def) != plan.check_definition_fingerprint


def _is_acknowledged(plan: ComplianceRemediationPlan) -> bool:
    return plan.acknowledged_at is not None


def _ready_for_execution(
    db: Session,
    plan: ComplianceRemediationPlan,
    *,
    request: Optional[ComplianceRemediationRequest] = None,
) -> bool:
    """Slice 3 readiness gate. Metadata only — does NOT touch hosts.

    A plan is ready when every gate below passes:
      * source request is still approved
      * plan is current (not superseded)
      * plan state is ``planned``
      * plan is acknowledged
      * plan is not stale
      * plan_kind is one a future execution slice can act on
        (i.e. not ``*_review_required`` / ``unsupported``)
    """
    if not _is_current(plan):
        return False
    if plan.state != PLAN_STATE_PLANNED:
        return False
    if not _is_acknowledged(plan):
        return False
    if plan.plan_kind not in EXECUTABLE_PLAN_KINDS:
        return False
    if _is_stale(db, plan):
        return False
    if request is None:
        request = (
            db.query(ComplianceRemediationRequest)
            .filter(ComplianceRemediationRequest.id == plan.request_id)
            .first()
        )
    if request is None or request.state != STATE_APPROVED:
        return False
    return True


def _get_current_plan_row(
    db: Session, request_id: int
) -> Optional[ComplianceRemediationPlan]:
    """Return the current (non-superseded) plan row for a request, or
    ``None`` when no plan has ever been built. The partial unique
    index in the Slice 3 migration guarantees at most one such row.
    """
    return (
        db.query(ComplianceRemediationPlan)
        .filter(
            ComplianceRemediationPlan.request_id == request_id,
            ComplianceRemediationPlan.superseded_by_plan_id.is_(None),
        )
        .first()
    )


# ---------------------------------------------------------------------------
# Per-check-kind builders. Each returns a tuple of
# ``(plan_kind, plan_steps)`` and never raises — unknown kinds route
# through :func:`_build_unsupported` so the caller can still persist
# a plan row.
# ---------------------------------------------------------------------------


def _safety_notes() -> List[str]:
    return [
        "non-executing preview only; no host change",
        "operator must approve actual execution in a later slice",
    ]


def _build_package_install(
    db: Session,
    request: ComplianceRemediationRequest,
    live_def: Optional[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]]]:
    target = _system_descriptor(db, request.system_id)
    package_name = None
    if live_def:
        package_name = live_def.get("package")
    return (
        PLAN_KIND_PACKAGE_INSTALL,
        [
            {
                "action_intent": "package_install",
                "target": target,
                "package": package_name,
                "expected_value": "installed",
                "safety_notes": _safety_notes(),
            }
        ],
    )


def _build_package_remove(
    db: Session,
    request: ComplianceRemediationRequest,
    live_def: Optional[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]]]:
    target = _system_descriptor(db, request.system_id)
    package_name = live_def.get("package") if live_def else None
    return (
        PLAN_KIND_PACKAGE_REMOVE,
        [
            {
                "action_intent": "package_remove",
                "target": target,
                "package": package_name,
                "expected_value": "absent",
                "safety_notes": _safety_notes(),
            }
        ],
    )


def _build_package_upgrade(
    db: Session,
    request: ComplianceRemediationRequest,
    live_def: Optional[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]]]:
    target = _system_descriptor(db, request.system_id)
    package_name = live_def.get("package") if live_def else None
    min_version = live_def.get("min_version") if live_def else None
    return (
        PLAN_KIND_PACKAGE_UPGRADE,
        [
            {
                "action_intent": "package_upgrade",
                "target": target,
                "package": package_name,
                "expected_value": (f">= {min_version}" if min_version else "installed"),
                "safety_notes": _safety_notes(),
            }
        ],
    )


def _build_facts_review(
    db: Session,
    request: ComplianceRemediationRequest,
    live_def: Optional[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]]]:
    target = _system_descriptor(db, request.system_id)
    fact_key = live_def.get("fact_key") if live_def else None
    return (
        PLAN_KIND_FACTS_REVIEW,
        [
            {
                "action_intent": "review_required",
                "reason": (
                    "fact-based checks describe observed host state; "
                    "remediation requires an operator-defined change "
                    "(e.g. update OS image, edit config) rather than an "
                    "automated runner action"
                ),
                "target": target,
                "fact_key": fact_key,
                "expected_value": (
                    str(live_def.get("expected"))
                    if live_def and "expected" in live_def
                    else None
                ),
                "safety_notes": _safety_notes(),
            }
        ],
    )


def _build_file_review(
    db: Session,
    request: ComplianceRemediationRequest,
    live_def: Optional[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]]]:
    target = _system_descriptor(db, request.system_id)
    path = live_def.get("path") if live_def else None
    expected_sha = live_def.get("sha256") if live_def else None
    return (
        PLAN_KIND_FILE_REVIEW,
        [
            {
                "action_intent": "review_required",
                "reason": (
                    "file checks do not carry source content for "
                    "automated restoration; operator must supply the "
                    "intended file body"
                ),
                "target": {**target, "path": path},
                "expected_value": (
                    f"sha256={expected_sha}" if expected_sha else "exists"
                ),
                "safety_notes": _safety_notes(),
            }
        ],
    )


def _build_command_review(
    db: Session,
    request: ComplianceRemediationRequest,
    live_def: Optional[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]]]:
    target = _system_descriptor(db, request.system_id)
    return (
        PLAN_KIND_COMMAND_REVIEW,
        [
            {
                "action_intent": "review_required",
                "reason": (
                    "command-based checks observe a probe result, not "
                    "a configuration delta; remediation requires an "
                    "operator-defined change"
                ),
                "target": target,
                "safety_notes": _safety_notes(),
            }
        ],
    )


_BUILDERS = {
    "package_installed": _build_package_install,
    "package_absent": _build_package_remove,
    "package_version_min": _build_package_upgrade,
    "fact_equals": _build_facts_review,
    "fact_present": _build_facts_review,
    "fact_absent": _build_facts_review,
    "file_exists": _build_file_review,
    "file_sha256": _build_file_review,
    "command_stdout_contains": _build_command_review,
    "command_exit_code": _build_command_review,
}


def _build_unsupported(
    request: ComplianceRemediationRequest,
) -> Tuple[str, List[Dict[str, Any]], str]:
    reason = (
        f"check_kind {request.check_kind!r} has no Slice 2 plan-preview "
        "shape; operator must provide remediation manually"
    )
    return (
        PLAN_KIND_UNSUPPORTED,
        [
            {
                "action_intent": "unsupported",
                "reason": reason,
                "safety_notes": _safety_notes(),
            }
        ],
        reason,
    )


# ---------------------------------------------------------------------------
# Read envelope
# ---------------------------------------------------------------------------


def remediation_plan_read_envelope(
    plan: ComplianceRemediationPlan,
    *,
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """Serialize a plan with Slice 3 lifecycle fields included.

    ``is_stale`` and ``ready_for_execution`` are computed on read
    rather than persisted, so the live check definition is
    authoritative. ``db`` is required for those derived flags;
    callers that don't have a session may pass ``None`` and the
    flags fall back to safe defaults (``is_stale=True``,
    ``ready_for_execution=False``).
    """
    if db is not None:
        is_stale = _is_stale(db, plan)
        ready = _ready_for_execution(db, plan)
    else:
        is_stale = True
        ready = False
    return {
        "id": plan.id,
        "request_id": plan.request_id,
        "policy_id": plan.policy_id,
        "check_id": plan.check_id,
        "system_id": plan.system_id,
        "policy_slug": plan.policy_slug,
        "policy_version": plan.policy_version,
        "check_slug": plan.check_slug,
        "check_kind": plan.check_kind,
        "severity_snapshot": plan.severity_snapshot,
        "state": plan.state,
        "plan_kind": plan.plan_kind,
        "plan_steps": list(plan.plan_steps or []),
        "unsupported_reason": plan.unsupported_reason,
        "error_message": plan.error_message,
        "check_definition_fingerprint": plan.check_definition_fingerprint,
        "is_current": _is_current(plan),
        "superseded_by_plan_id": plan.superseded_by_plan_id,
        "acknowledged_at": utc_iso(plan.acknowledged_at),
        "acknowledged_by": plan.acknowledged_by,
        "is_stale": is_stale,
        "ready_for_execution": ready,
        "created_by": plan.created_by,
        "created_at": utc_iso(plan.created_at),
        "updated_at": utc_iso(plan.updated_at),
    }


# ---------------------------------------------------------------------------
# Public API — build / refresh
# ---------------------------------------------------------------------------


def build_or_refresh_plan(
    db: Session,
    *,
    request_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> ComplianceRemediationPlan:
    """Build or refresh the plan preview for a remediation request.

    Fails closed when the source request is not in state ``approved``.
    Building does NOT mutate the request; it only writes / updates
    the plan row.
    """
    actor = _require_user(db, actor_user_id, field="actor_user_id")
    request = _require_request(db, request_id)

    if request.state != STATE_APPROVED:
        raise _err(
            "remediation plan previews can only be built for requests in "
            f"state 'approved' (request {request.id} is {request.state!r})"
        )

    builder = _BUILDERS.get(request.check_kind)
    unsupported_reason: Optional[str] = None
    error_message: Optional[str] = None
    state: str
    if builder is None:
        plan_kind, plan_steps, unsupported_reason = _build_unsupported(request)
        state = PLAN_STATE_UNSUPPORTED
    else:
        try:
            live_def = _live_check_definition(db, request.check_id)
            plan_kind, plan_steps = builder(db, request, live_def)
            state = PLAN_STATE_PLANNED
        except Exception as exc:  # pylint: disable=broad-except
            # Builders are total over the known vocabulary, but a DB
            # row vanishing mid-build is a possible edge case. Fail
            # closed by persisting a ``failed`` plan rather than
            # raising — auditors can read the failure reason.
            logger.warning(
                "compliance remediation plan build failed for request %s: %s",
                request.id,
                exc,
            )
            plan_kind = PLAN_KIND_UNSUPPORTED
            plan_steps = [
                {
                    "action_intent": "failed",
                    "reason": "builder error during plan preview",
                    "safety_notes": _safety_notes(),
                }
            ]
            state = PLAN_STATE_FAILED
            error_message = _bounded_text(str(exc), max_chars=MAX_ERROR_MESSAGE_CHARS)

    plan_steps = _validate_plan_steps_payload(plan_steps)
    unsupported_reason = _bounded_text(
        unsupported_reason, max_chars=MAX_UNSUPPORTED_REASON_CHARS
    )

    # Capture the fingerprint of the live check definition used to
    # derive this build. ``None`` when the source check has been
    # deleted — in that case the plan is born stale per the Slice 3
    # staleness rule.
    live_def = _live_check_definition(db, request.check_id)
    fingerprint = _fingerprint_check_definition(live_def)

    existing = _get_current_plan_row(db, request.id)
    superseded_plan_id: Optional[int] = None

    if existing is None:
        # First-ever plan for this request.
        plan = ComplianceRemediationPlan(
            request_id=request.id,
            policy_id=request.policy_id,
            check_id=request.check_id,
            system_id=request.system_id,
            policy_slug=request.policy_slug,
            policy_version=request.policy_version,
            check_slug=request.check_slug,
            check_kind=request.check_kind,
            severity_snapshot=request.severity_snapshot,
            state=state,
            plan_kind=plan_kind,
            plan_steps=plan_steps,
            unsupported_reason=unsupported_reason,
            error_message=error_message,
            check_definition_fingerprint=fingerprint,
            created_by=actor.id,
        )
        db.add(plan)
        refreshed = False
    elif _is_acknowledged(existing):
        # Acknowledged plan: do NOT mutate. Create a new current
        # plan and point the old row's ``superseded_by_plan_id`` at
        # it. The partial unique index makes this safe — between
        # inserting the new row and pointing the old one at it we'd
        # technically have two ``superseded_by_plan_id IS NULL``
        # rows for the same request, so we flush in the right order
        # below.
        plan = ComplianceRemediationPlan(
            request_id=request.id,
            policy_id=request.policy_id,
            check_id=request.check_id,
            system_id=request.system_id,
            policy_slug=request.policy_slug,
            policy_version=request.policy_version,
            check_slug=request.check_slug,
            check_kind=request.check_kind,
            severity_snapshot=request.severity_snapshot,
            state=state,
            plan_kind=plan_kind,
            plan_steps=plan_steps,
            unsupported_reason=unsupported_reason,
            error_message=error_message,
            check_definition_fingerprint=fingerprint,
            created_by=actor.id,
        )
        # Point the old current row forward FIRST so the partial
        # unique index never sees two ``superseded_by_plan_id IS
        # NULL`` rows for this request at once. We flush in two
        # steps: stamp the old row with a sentinel-less SET (we
        # don't know the new id yet, but the unique constraint is
        # only on rows where superseded_by_plan_id IS NULL, so as
        # soon as it's non-null the constraint is satisfied).
        # Trick: stamp old row with old.id first (self-link is fine
        # transiently — it's not the active plan anymore), insert
        # the new row, then repoint old to the new id.
        old_plan_id = existing.id
        existing.superseded_by_plan_id = old_plan_id  # self-link, transient
        db.flush()
        db.add(plan)
        db.flush()  # populates plan.id
        existing.superseded_by_plan_id = plan.id
        superseded_plan_id = old_plan_id
        refreshed = False
    else:
        # Current draft plan (not acknowledged): preserve Slice 2
        # overwrite-in-place semantics so the unchanged callers
        # see the same row id back. Snapshot identity is immutable
        # — only state/plan_kind/payload/messages/fingerprint
        # change.
        existing.state = state
        existing.plan_kind = plan_kind
        existing.plan_steps = plan_steps
        existing.unsupported_reason = unsupported_reason
        existing.error_message = error_message
        existing.check_definition_fingerprint = fingerprint
        plan = existing
        refreshed = True

    db.commit()
    db.refresh(plan)

    audit_action = (
        AUDIT_COMPLIANCE_REMEDIATION_PLAN_REFRESHED
        if refreshed
        else AUDIT_COMPLIANCE_REMEDIATION_PLAN_BUILT
    )
    safe_emit(
        action=audit_action,
        outcome="success",
        actor_user_id=actor.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_plan",
        target_id=str(plan.id),
        target_system_id=plan.system_id,
        context={
            **_request_snapshot_dict(request),
            "request_id": request.id,
            "plan_state": plan.state,
            "plan_kind": plan.plan_kind,
            "step_count": len(plan.plan_steps or []),
            "refreshed": refreshed,
            "superseded_plan_id": superseded_plan_id,
        },
    )
    if superseded_plan_id is not None:
        safe_emit(
            action=AUDIT_COMPLIANCE_REMEDIATION_PLAN_SUPERSEDED,
            outcome="success",
            actor_user_id=actor.id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="compliance_remediation_plan",
            target_id=str(superseded_plan_id),
            target_system_id=plan.system_id,
            context={
                **_request_snapshot_dict(request),
                "request_id": request.id,
                "superseded_by_plan_id": plan.id,
            },
        )
    if plan.state == PLAN_STATE_UNSUPPORTED:
        safe_emit(
            action=AUDIT_COMPLIANCE_REMEDIATION_PLAN_UNSUPPORTED,
            outcome="success",
            actor_user_id=actor.id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="compliance_remediation_plan",
            target_id=str(plan.id),
            target_system_id=plan.system_id,
            context={
                **_request_snapshot_dict(request),
                "request_id": request.id,
                "unsupported_reason": plan.unsupported_reason,
            },
        )
    return plan


# ---------------------------------------------------------------------------
# Public API — acknowledge
# ---------------------------------------------------------------------------


def acknowledge_plan(
    db: Session,
    *,
    plan_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> ComplianceRemediationPlan:
    """Acknowledge an operator-reviewed plan.

    Fails closed on:

    * unknown plan id (not found)
    * non-current plan (already superseded)
    * already-acknowledged plan (idempotent re-ack is intentionally
      refused so the audit trail records a single acknowledgement
      moment)
    * non-``planned`` state (cannot acknowledge ``unsupported`` /
      ``failed`` previews)
    * stale plan (live check definition no longer matches the
      fingerprint, or the source check is gone)
    * non-approved source request (defense-in-depth — the plan
      could only have been built when approved, but operator could
      have rejected/cancelled the request between build and ack)

    Acknowledgement does NOT trigger execution; it only flips the
    metadata so a future execution slice can check the readiness
    gate.
    """
    actor = _require_user(db, actor_user_id, field="actor_user_id")
    plan = (
        db.query(ComplianceRemediationPlan)
        .filter(ComplianceRemediationPlan.id == plan_id)
        .first()
    )
    if plan is None:
        raise _err(f"compliance remediation plan id={plan_id} not found")
    if not _is_current(plan):
        raise _err(
            f"plan {plan.id} is superseded (current plan is "
            f"{plan.superseded_by_plan_id}); acknowledge the current plan"
        )
    if _is_acknowledged(plan):
        raise _err(
            f"plan {plan.id} is already acknowledged "
            f"(at {utc_iso(plan.acknowledged_at)} by user "
            f"{plan.acknowledged_by})"
        )
    if plan.state != PLAN_STATE_PLANNED:
        raise _err(
            f"only plans in state 'planned' may be acknowledged "
            f"(plan {plan.id} is {plan.state!r})"
        )
    if _is_stale(db, plan):
        raise _err(
            f"plan {plan.id} is stale (live check definition no longer "
            "matches the build-time fingerprint); rebuild the plan and "
            "acknowledge the fresh row"
        )
    request = (
        db.query(ComplianceRemediationRequest)
        .filter(ComplianceRemediationRequest.id == plan.request_id)
        .first()
    )
    if request is None or request.state != STATE_APPROVED:
        raise _err(
            f"plan {plan.id}'s source request is no longer approved; "
            "acknowledgement refused"
        )

    plan.acknowledged_at = datetime.utcnow()
    plan.acknowledged_by = actor.id
    db.commit()
    db.refresh(plan)

    ready = _ready_for_execution(db, plan, request=request)
    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_PLAN_ACKNOWLEDGED,
        outcome="success",
        actor_user_id=actor.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_plan",
        target_id=str(plan.id),
        target_system_id=plan.system_id,
        context={
            **_request_snapshot_dict(request),
            "request_id": request.id,
            "plan_kind": plan.plan_kind,
            "ready_for_execution": ready,
        },
    )
    # PRA-178 Slice 3: emit remediation.ready beside the acknowledge
    # audit ONLY when the gate flipped to ready_for_execution=true.
    # Acknowledging an unsupported / review-required plan should not
    # claim the plan is ready for dispatch.
    if ready:
        from . import notification_events

        notification_events.emit_remediation_ready(
            db,
            request_id=request.id,
            plan_id=plan.id,
            policy_slug=plan.policy_slug,
            check_slug=plan.check_slug,
            system_id=plan.system_id,
        )
    return plan


# ---------------------------------------------------------------------------
# Public API — read / list
# ---------------------------------------------------------------------------


def get_plan_for_request(
    db: Session, request_id: int
) -> Optional[ComplianceRemediationPlan]:
    """Return the **current** (non-superseded) plan for a request.

    Slice 2 behavior was "one plan per request"; Slice 3 keeps the
    same wire shape by always returning the current row. Superseded
    history is reachable via :func:`list_plans_for_request` (Slice 3
    new helper).
    """
    return _get_current_plan_row(db, request_id)


def list_plans_for_request(
    db: Session, request_id: int
) -> List[ComplianceRemediationPlan]:
    """Return every plan row tied to a request, newest-first.

    Includes the current plan and any superseded history. Used by
    the per-request read surface so an operator can audit the
    acknowledge → supersede → re-acknowledge chain.
    """
    return (
        db.query(ComplianceRemediationPlan)
        .filter(ComplianceRemediationPlan.request_id == request_id)
        .order_by(
            ComplianceRemediationPlan.created_at.desc(),
            ComplianceRemediationPlan.id.desc(),
        )
        .all()
    )


def get_plan(db: Session, plan_id: int) -> Optional[ComplianceRemediationPlan]:
    return (
        db.query(ComplianceRemediationPlan)
        .filter(ComplianceRemediationPlan.id == plan_id)
        .first()
    )


def list_plans(
    db: Session,
    *,
    state: Optional[str] = None,
    plan_kind: Optional[str] = None,
    system_id: Optional[int] = None,
    is_current: Optional[bool] = None,
    acknowledged: Optional[bool] = None,
    ready_for_execution: Optional[bool] = None,
    offset: int = 0,
    limit: int = 100,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Tuple[List[ComplianceRemediationPlan], int]:
    """Paginated plan list. ``allowed_system_ids`` (PRA-281) restricts rows AND
    the total to the caller's fleet scope. Slice 3 adds three lifecycle filters:

    * ``is_current=True/False`` filters rows on
      ``superseded_by_plan_id IS NULL`` / ``IS NOT NULL``.
    * ``acknowledged=True/False`` filters on ``acknowledged_at``.
    * ``ready_for_execution`` is a Python-side post-filter because
      the readiness gate consults the live check definition; it
      narrows the page after SQL filtering.
    """
    if offset < 0:
        raise _err("offset must be >= 0")
    if not (1 <= limit <= 500):
        raise _err("limit must be in 1..500")
    if state is not None and state not in VALID_PLAN_STATES:
        raise _err(f"state must be one of: {list(VALID_PLAN_STATES)}")
    if plan_kind is not None and plan_kind not in VALID_PLAN_KINDS:
        raise _err(f"plan_kind must be one of: {list(VALID_PLAN_KINDS)}")
    if system_id is not None and (
        isinstance(system_id, bool) or not isinstance(system_id, int) or system_id <= 0
    ):
        raise _err("system_id must be a positive integer")
    if is_current is not None and not isinstance(is_current, bool):
        raise _err("is_current must be a boolean")
    if acknowledged is not None and not isinstance(acknowledged, bool):
        raise _err("acknowledged must be a boolean")
    if ready_for_execution is not None and not isinstance(ready_for_execution, bool):
        raise _err("ready_for_execution must be a boolean")

    q = db.query(ComplianceRemediationPlan)
    if state is not None:
        q = q.filter(ComplianceRemediationPlan.state == state)
    if plan_kind is not None:
        q = q.filter(ComplianceRemediationPlan.plan_kind == plan_kind)
    if system_id is not None:
        q = q.filter(ComplianceRemediationPlan.system_id == system_id)
    scope_clause = scope_in_clause(
        ComplianceRemediationPlan.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)
    if is_current is True:
        q = q.filter(ComplianceRemediationPlan.superseded_by_plan_id.is_(None))
    elif is_current is False:
        q = q.filter(ComplianceRemediationPlan.superseded_by_plan_id.isnot(None))
    if acknowledged is True:
        q = q.filter(ComplianceRemediationPlan.acknowledged_at.isnot(None))
    elif acknowledged is False:
        q = q.filter(ComplianceRemediationPlan.acknowledged_at.is_(None))

    if ready_for_execution is None:
        total = q.with_entities(ComplianceRemediationPlan.id).count()
        rows = (
            q.order_by(
                ComplianceRemediationPlan.created_at.desc(),
                ComplianceRemediationPlan.id.desc(),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )
        return rows, total

    # ``ready_for_execution`` is computed against the live DB; apply
    # the SQL filter set first, then narrow in Python. The post-
    # filter respects offset/limit on the **filtered** result so
    # pagination math stays intuitive.
    candidate_rows = q.order_by(
        ComplianceRemediationPlan.created_at.desc(),
        ComplianceRemediationPlan.id.desc(),
    ).all()
    filtered = [
        p for p in candidate_rows if _ready_for_execution(db, p) == ready_for_execution
    ]
    total = len(filtered)
    rows = filtered[offset : offset + limit]
    return rows, total


# ---------------------------------------------------------------------------
# Slice 4 — read-only rollups.
#
# Fleet remediation summary and per-host remediation inventory. Both
# are read-only and metadata-only: no probes, no facts refresh, no
# package scan, no SSH, no dispatch, no host mutation. Counts use
# bounded SQL ``GROUP BY`` where possible; ``ready_for_execution`` /
# ``is_stale`` are computed in Python because they consult the live
# check definition, but only over the (small) current-plan slice.
# ---------------------------------------------------------------------------


def _count_requests_by_state(
    db: Session, *, allowed_system_ids: Optional[Set[int]] = None
) -> Dict[str, int]:
    from sqlalchemy import func

    counts = {s: 0 for s in compliance_remediation_service_states()}
    q = db.query(
        ComplianceRemediationRequest.state,
        func.count(ComplianceRemediationRequest.id),
    )
    scope_clause = scope_in_clause(
        ComplianceRemediationRequest.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)
    rows = q.group_by(ComplianceRemediationRequest.state).all()
    for state_name, count in rows:
        counts[state_name] = int(count)
    return counts


def compliance_remediation_service_states() -> Tuple[str, ...]:
    """Mirror ``compliance_remediation_service.VALID_STATES`` without
    importing it into module top-level (keeps the import graph
    one-way: plan service depends on request-service constants only
    inside function bodies)."""
    from .compliance_remediation_service import VALID_STATES

    return VALID_STATES


def _count_current_plans_by_state(
    db: Session, *, allowed_system_ids: Optional[Set[int]] = None
) -> Dict[str, int]:
    from sqlalchemy import func

    counts = {s: 0 for s in VALID_PLAN_STATES}
    q = db.query(
        ComplianceRemediationPlan.state, func.count(ComplianceRemediationPlan.id)
    ).filter(ComplianceRemediationPlan.superseded_by_plan_id.is_(None))
    scope_clause = scope_in_clause(
        ComplianceRemediationPlan.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)
    rows = q.group_by(ComplianceRemediationPlan.state).all()
    for state_name, count in rows:
        if state_name in counts:
            counts[state_name] = int(count)
    return counts


def _count_requests_by_severity(
    db: Session, *, allowed_system_ids: Optional[Set[int]] = None
) -> List[Dict[str, Any]]:
    from sqlalchemy import func

    q = db.query(
        ComplianceRemediationRequest.severity_snapshot,
        ComplianceRemediationRequest.state,
        func.count(ComplianceRemediationRequest.id),
    )
    scope_clause = scope_in_clause(
        ComplianceRemediationRequest.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)
    rows = q.group_by(
        ComplianceRemediationRequest.severity_snapshot,
        ComplianceRemediationRequest.state,
    ).all()
    by_sev: Dict[str, Dict[str, int]] = {}
    for severity, state_name, count in rows:
        bucket = by_sev.setdefault(
            severity,
            {s: 0 for s in compliance_remediation_service_states()},
        )
        bucket[state_name] = int(count)
    return [
        {
            "severity": sev,
            **buckets,
            "total": sum(buckets.values()),
        }
        for sev, buckets in sorted(by_sev.items())
    ]


def fleet_remediation_summary(
    db: Session,
    *,
    now: Optional[datetime] = None,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    """Fleet-wide remediation rollup. Read-only, metadata-only.

    ``allowed_system_ids`` (PRA-281) scopes every request/plan count to the
    caller's fleet scope (``None`` = admin; empty = all-zero).

    Counts: total requests, per-request-state, per-current-plan-state,
    acknowledged vs unacknowledged current plans, ready vs not-ready
    current plans, and a per-severity rollup keyed on
    ``severity_snapshot`` (from the request row at request time).

    ``ready_for_execution`` and ``is_stale`` are computed in Python
    against the current-plan slice because they consult the live
    check definition. Tradeoff documented inline: the current-plan
    set is bounded by "one row per request", so even at high request
    volume the Python pass remains linear in current-plan count, not
    in evidence history.
    """
    now = now or datetime.utcnow()

    request_state_counts = _count_requests_by_state(
        db, allowed_system_ids=allowed_system_ids
    )
    plan_state_counts = _count_current_plans_by_state(
        db, allowed_system_ids=allowed_system_ids
    )
    per_severity = _count_requests_by_severity(
        db, allowed_system_ids=allowed_system_ids
    )

    # Acknowledge + readiness over the current-plan slice.
    current_plans_q = db.query(ComplianceRemediationPlan).filter(
        ComplianceRemediationPlan.superseded_by_plan_id.is_(None)
    )
    _scope_clause = scope_in_clause(
        ComplianceRemediationPlan.system_id, allowed_system_ids
    )
    if _scope_clause is not None:
        current_plans_q = current_plans_q.filter(_scope_clause)
    current_plans = current_plans_q.all()
    acknowledged_count = 0
    unacknowledged_count = 0
    ready_count = 0
    not_ready_count = 0
    stale_count = 0
    not_stale_count = 0
    for plan in current_plans:
        if _is_acknowledged(plan):
            acknowledged_count += 1
        else:
            unacknowledged_count += 1
        if _ready_for_execution(db, plan):
            ready_count += 1
        else:
            not_ready_count += 1
        if _is_stale(db, plan):
            stale_count += 1
        else:
            not_stale_count += 1

    return {
        "generated_at": utc_iso(now),
        "request_total": sum(request_state_counts.values()),
        "request_counts_by_state": request_state_counts,
        "current_plan_total": sum(plan_state_counts.values()),
        "current_plan_counts_by_state": plan_state_counts,
        "current_plan_acknowledged_count": acknowledged_count,
        "current_plan_unacknowledged_count": unacknowledged_count,
        "current_plan_ready_count": ready_count,
        "current_plan_not_ready_count": not_ready_count,
        "current_plan_stale_count": stale_count,
        "current_plan_not_stale_count": not_stale_count,
        "per_severity": per_severity,
    }


# Per-host inventory bounds. Default is conservative — operators
# can page with explicit query params up to ``INVENTORY_PAGE_MAX``.
# Cap matches the Slice 2 ``list_plans`` ceiling so the operator
# story stays consistent across surfaces.
INVENTORY_PAGE_DEFAULT = 50
INVENTORY_PAGE_MAX = 500


def _bounded_offset(offset: int, *, field_prefix: str) -> int:
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise _err(f"{field_prefix}_offset must be >= 0")
    return offset


def _validate_inventory_limit(limit: int) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise _err("limit must be an integer")
    if not (1 <= limit <= INVENTORY_PAGE_MAX):
        raise _err(f"limit must be in 1..{INVENTORY_PAGE_MAX}")
    return limit


def _page_envelope(
    items: List[Any], *, total: int, offset: int, limit: int
) -> Dict[str, Any]:
    next_offset = offset + len(items) if (offset + len(items)) < total else None
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset,
    }


def host_remediation_inventory(
    db: Session,
    *,
    system_id: int,
    limit: int = INVENTORY_PAGE_DEFAULT,
    open_offset: int = 0,
    approved_offset: int = 0,
    current_plans_offset: int = 0,
    ready_plans_offset: int = 0,
    superseded_offset: int = 0,
) -> Dict[str, Any]:
    """Per-host remediation inventory. Read-only, metadata-only.

    Every section is a bounded paged envelope (``items`` / ``total``
    / ``offset`` / ``limit`` / ``next_offset``) so a single host
    with many outstanding requests or plans cannot produce an
    unbounded response. The shared ``limit`` applies to every
    section; per-section ``*_offset`` query params let operators
    page through one section without disturbing the others.

    Sections:

    * ``open_requests`` — requests in state ``requested`` for this
      host (still awaiting decision).
    * ``approved_requests`` — requests in state ``approved`` for
      this host (decided; may or may not have a plan yet).
    * ``current_plans`` — every non-superseded plan for this host.
    * ``ready_plans`` — current plans where
      ``ready_for_execution=True``.
    * ``superseded_history`` — superseded plan history, newest-first.

    Readiness is computed in Python over the full current-plan set
    for this host (bounded by current-plan count = at most one row
    per request), then the filtered list is paged. This matches the
    Slice 3 ``list_plans(ready_for_execution=...)`` post-filter
    pattern.

    Caller is responsible for the ``system_id`` 404 — this service
    helper does not raise on missing system (it just returns empty
    sections), which keeps the helper composable for future
    internal callers.
    """
    from .compliance_remediation_service import STATE_APPROVED as REQUEST_STATE_APPROVED
    from .compliance_remediation_service import (
        STATE_REQUESTED as REQUEST_STATE_REQUESTED,
    )
    from .compliance_remediation_service import remediation_request_read_envelope

    if not isinstance(system_id, int) or isinstance(system_id, bool) or system_id <= 0:
        raise _err("system_id must be a positive integer")
    limit = _validate_inventory_limit(limit)
    open_offset = _bounded_offset(open_offset, field_prefix="open")
    approved_offset = _bounded_offset(approved_offset, field_prefix="approved")
    current_plans_offset = _bounded_offset(
        current_plans_offset, field_prefix="current_plans"
    )
    ready_plans_offset = _bounded_offset(ready_plans_offset, field_prefix="ready_plans")
    superseded_offset = _bounded_offset(superseded_offset, field_prefix="superseded")

    def _paged_requests(state_value: str, offset: int) -> Dict[str, Any]:
        q = (
            db.query(ComplianceRemediationRequest)
            .filter(
                ComplianceRemediationRequest.system_id == system_id,
                ComplianceRemediationRequest.state == state_value,
            )
            .order_by(
                ComplianceRemediationRequest.created_at.desc(),
                ComplianceRemediationRequest.id.desc(),
            )
        )
        total = q.with_entities(ComplianceRemediationRequest.id).count()
        rows = q.offset(offset).limit(limit).all()
        items = [remediation_request_read_envelope(r) for r in rows]
        return _page_envelope(items, total=total, offset=offset, limit=limit)

    open_section = _paged_requests(REQUEST_STATE_REQUESTED, open_offset)
    approved_section = _paged_requests(REQUEST_STATE_APPROVED, approved_offset)

    # Current plans: SQL pagination is straightforward —
    # ``superseded_by_plan_id IS NULL`` is indexable per the Slice 3
    # partial unique index.
    current_q = (
        db.query(ComplianceRemediationPlan)
        .filter(
            ComplianceRemediationPlan.system_id == system_id,
            ComplianceRemediationPlan.superseded_by_plan_id.is_(None),
        )
        .order_by(
            ComplianceRemediationPlan.created_at.desc(),
            ComplianceRemediationPlan.id.desc(),
        )
    )
    current_total = current_q.with_entities(ComplianceRemediationPlan.id).count()
    current_rows = current_q.offset(current_plans_offset).limit(limit).all()
    current_items = [remediation_plan_read_envelope(p, db=db) for p in current_rows]
    current_section = _page_envelope(
        current_items,
        total=current_total,
        offset=current_plans_offset,
        limit=limit,
    )

    # Ready plans: readiness gate is Python-side; filter over the
    # full current-plan set for this host, then page the filtered
    # list. Same shape as Slice 3 ``list_plans`` post-filter.
    all_current = current_q.all()
    ready_full = [p for p in all_current if _ready_for_execution(db, p)]
    ready_total = len(ready_full)
    ready_slice = ready_full[ready_plans_offset : ready_plans_offset + limit]
    ready_items = [remediation_plan_read_envelope(p, db=db) for p in ready_slice]
    ready_section = _page_envelope(
        ready_items, total=ready_total, offset=ready_plans_offset, limit=limit
    )

    superseded_q = (
        db.query(ComplianceRemediationPlan)
        .filter(
            ComplianceRemediationPlan.system_id == system_id,
            ComplianceRemediationPlan.superseded_by_plan_id.isnot(None),
        )
        .order_by(
            ComplianceRemediationPlan.created_at.desc(),
            ComplianceRemediationPlan.id.desc(),
        )
    )
    superseded_total = superseded_q.with_entities(ComplianceRemediationPlan.id).count()
    superseded_rows = superseded_q.offset(superseded_offset).limit(limit).all()
    superseded_items = [
        remediation_plan_read_envelope(p, db=db) for p in superseded_rows
    ]
    superseded_section = _page_envelope(
        superseded_items,
        total=superseded_total,
        offset=superseded_offset,
        limit=limit,
    )

    return {
        "system_id": system_id,
        "generated_at": utc_iso(datetime.utcnow()),
        "open_requests": open_section,
        "approved_requests": approved_section,
        "current_plans": current_section,
        "ready_plans": ready_section,
        "superseded_history": superseded_section,
    }
