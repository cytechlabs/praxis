"""Compliance remediation execution-attempt service (PRA-176 Slice 1 + 2).

Slice 1 — durable, pre-dispatch substrate. ``create_attempt`` writes
one ``ComplianceRemediationExecutionAttempt`` row in state ``pending``
and emits one ``compliance_remediation_execution.created`` audit
event. Slice 1 does **not**:

* mutate hosts, run SSH, talk to an agent, or invoke any runner;
* dispatch/queue/enqueue package install/remove/upgrade work;
* refresh facts, scan packages, run OpenSCAP, reboot, or roll back;
* auto-execute on approval;
* fall back to local execution when remote execution is unavailable.

Slice 2 — single-attempt dispatch through the governed PRA-171 patch
transport. ``dispatch_attempt`` consumes one ``pending`` attempt,
re-checks the readiness gate at execution time, derives the package
operation (install / remove / upgrade) for one package on one host,
delegates to ``patch_execution_dispatch_service.default_dispatch``
(or a test-provided ``DispatchCallable``), persists transport,
timing, exit code, bounded stdout/stderr, and a failure reason on
failure, and emits ``.dispatched``, ``.succeeded``, or ``.failed``
audit events.

Slice 2 still does **not** introduce a fleet/batch runner, a job
queue, a rollback or reboot workflow, an OpenSCAP path, a new probe
kind, a facts refresh, a package scan, a local fallback path, or any
raw SSH / subprocess / package-manager execution outside the
PRA-171 governed transport seam.

Fail-closed gate (the same readiness conditions surfaced by the
PRA-167 Slice 3 ``ready_for_execution`` flag, repeated here at write
time so a stale UI cannot bypass them):

* the plan must exist;
* the plan must be current (``superseded_by_plan_id IS NULL``);
* the plan state must be ``planned`` (not ``unsupported`` / ``failed``);
* the plan must be acknowledged;
* the plan must not be stale (fingerprint matches live check, and the
  source check must still exist);
* the plan kind must be one of the executable package kinds
  (``package_install_preview`` / ``package_remove_preview`` /
  ``package_upgrade_preview``); review-required and unsupported
  plans cannot be executed;
* the source remediation request must still be ``approved``.

Each branch raises :class:`ComplianceError` with a distinct human-
readable message so the route layer can map the family to HTTP 422
(or 404 when the message contains ``"not found"``).

Audit-row semantics follow ``feedback_safe_emit_session_boundary``:
``safe_emit`` is invoked AFTER the service commits its own
transaction, with no ``db=`` argument so it opens its own
``SessionLocal``.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from app.services.access_authorization_service import scope_in_clause

from ..db.models import (
    ComplianceRemediationExecutionAttempt,
    ComplianceRemediationPlan,
    ComplianceRemediationRequest,
    HostFacts,
    System,
    User,
)
from .audit_event_service import safe_emit
from .compliance_remediation_plan_service import (
    EXECUTABLE_PLAN_KINDS,
    PLAN_KIND_PACKAGE_INSTALL,
    PLAN_KIND_PACKAGE_REMOVE,
    PLAN_KIND_PACKAGE_UPGRADE,
    PLAN_STATE_PLANNED,
    _is_acknowledged,
    _is_current,
    _is_stale,
)
from .compliance_remediation_service import STATE_APPROVED, ComplianceError
from .compliance_service import utc_iso
from .patch_execution_dispatch_service import (
    ERROR_CODE_PACKAGE_MANAGER_FAILED,
    ERROR_CODE_TRANSPORT_ERROR,
    ERROR_CODE_TRANSPORT_UNAVAILABLE,
    ERROR_CODE_UNSUPPORTED_FAMILY,
    MAX_OUTPUT_BYTES,
    DispatchCallable,
    DispatchResult,
    build_command_for_family,
    build_remove_command_for_family,
    default_dispatch,
)
from .patch_update_plan_service import (
    PACKAGE_MANAGER_FAMILY_UNKNOWN,
    _derive_package_manager_family,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

# Attempt state vocabulary. Slice 1 only writes ``pending`` — the
# transport/dispatch slices that follow will move attempts through the
# rest of the vocabulary without a schema migration.
STATE_PENDING = "pending"
STATE_DISPATCHED = "dispatched"
STATE_SUCCEEDED = "succeeded"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"

VALID_ATTEMPT_STATES: Tuple[str, ...] = (
    STATE_PENDING,
    STATE_DISPATCHED,
    STATE_SUCCEEDED,
    STATE_FAILED,
    STATE_CANCELLED,
)

# Bounds — keep persisted attempt payloads small and explicit.
MAX_PACKAGE_NAME_CHARS = 256
MAX_PACKAGE_VERSION_TARGET_CHARS = 128
MAX_FAILURE_REASON_CHARS = 64
MAX_ERROR_MESSAGE_CHARS = 2048
MAX_TRANSPORT_CHARS = 32

# Pagination bounds — match the PRA-167 plan list ceiling.
LIST_LIMIT_MAX = 500


# ---------------------------------------------------------------------------
# Audit event-type strings — under the
# ``compliance_remediation_execution.*`` namespace reserved by the
# PRA-176 Linear scope. Slice 1 fires ``.created`` only; later slices
# will add ``.dispatched`` / ``.succeeded`` / ``.failed`` etc.
# ---------------------------------------------------------------------------

AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_CREATED = (
    "compliance_remediation_execution.created"
)
# Slice 2 — dispatch lifecycle.
AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_DISPATCHED = (
    "compliance_remediation_execution.dispatched"
)
AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED = (
    "compliance_remediation_execution.succeeded"
)
AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_FAILED = (
    "compliance_remediation_execution.failed"
)
# Slice 3 — batch lifecycle. The per-attempt `.dispatched` / `.succeeded`
# / `.failed` events still fire from ``dispatch_attempt`` for each
# included row; this batch event records the aggregate outcome once
# per operator-triggered batch call.
AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_BATCH_DISPATCHED = (
    "compliance_remediation_execution.batch_dispatched"
)


# Failure reason codes specific to compliance dispatch refusal that
# happens AFTER the readiness gate passed but BEFORE the transport ran.
# These complement the structured codes inherited from
# ``patch_execution_dispatch_service`` (transport_unavailable,
# transport_error, package_manager_failed, unsupported_package_family).
FAILURE_REASON_MISSING_PACKAGE_NAME = "missing_package_name"
FAILURE_REASON_INVALID_VERSION_TARGET = "invalid_version_target"
FAILURE_REASON_MISSING_VERSION_TARGET = "missing_version_target"
FAILURE_REASON_HOST_NOT_FOUND = "host_not_found"


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


def _require_attempt(
    db: Session, attempt_id: int
) -> ComplianceRemediationExecutionAttempt:
    if (
        not isinstance(attempt_id, int)
        or isinstance(attempt_id, bool)
        or attempt_id <= 0
    ):
        raise _err("attempt_id must be a positive integer")
    row = (
        db.query(ComplianceRemediationExecutionAttempt)
        .filter(ComplianceRemediationExecutionAttempt.id == attempt_id)
        .first()
    )
    if row is None:
        raise _err(
            f"compliance remediation execution attempt id={attempt_id} not found"
        )
    return row


def _require_plan(db: Session, plan_id: int) -> ComplianceRemediationPlan:
    if not isinstance(plan_id, int) or isinstance(plan_id, bool) or plan_id <= 0:
        raise _err("plan_id must be a positive integer")
    plan = (
        db.query(ComplianceRemediationPlan)
        .filter(ComplianceRemediationPlan.id == plan_id)
        .first()
    )
    if plan is None:
        raise _err(f"compliance remediation plan id={plan_id} not found")
    return plan


def _extract_package_identifiers(
    plan: ComplianceRemediationPlan,
) -> Tuple[Optional[str], Optional[str]]:
    """Pull ``(package_name, package_version_target)`` from the plan's
    first step. The Slice 2 plan builders always emit one step per
    package plan, with ``package`` and (for upgrade) ``expected_value``
    set. Returns ``(None, None)`` when the plan was built against a
    deleted source check (live-def lookup returned ``None``).
    """
    steps = list(plan.plan_steps or [])
    if not steps:
        return None, None
    step = steps[0]
    if not isinstance(step, dict):
        return None, None
    raw_pkg = step.get("package")
    pkg = raw_pkg if isinstance(raw_pkg, str) else None
    if pkg is not None and len(pkg) > MAX_PACKAGE_NAME_CHARS:
        pkg = pkg[:MAX_PACKAGE_NAME_CHARS]
    raw_version = step.get("expected_value")
    version_target: Optional[str] = None
    if isinstance(raw_version, str) and raw_version not in ("installed", "absent"):
        version_target = raw_version
    if (
        version_target is not None
        and len(version_target) > MAX_PACKAGE_VERSION_TARGET_CHARS
    ):
        version_target = version_target[:MAX_PACKAGE_VERSION_TARGET_CHARS]
    return pkg, version_target


# ---------------------------------------------------------------------------
# Readiness gate — explicit, fail-closed, per-branch error messages.
# ---------------------------------------------------------------------------


def _assert_ready_for_execution(
    db: Session, plan: ComplianceRemediationPlan
) -> ComplianceRemediationRequest:
    """Raise :class:`ComplianceError` with a distinct message on each
    fail-closed branch. Returns the resolved source request on success
    so the caller can snapshot approval lineage.

    The branches mirror the PRA-167 Slice 3
    ``_ready_for_execution`` helper but with named, operator-readable
    refusal text — re-checked at attempt-creation time so a stale UI
    cannot bypass the gate by replaying a previously-true derived flag.
    """
    if not _is_current(plan):
        raise _err(
            f"plan {plan.id} is superseded (current plan is "
            f"{plan.superseded_by_plan_id}); execution attempts must "
            "reference the current plan"
        )
    if plan.state != PLAN_STATE_PLANNED:
        raise _err(
            f"execution attempts may only be created for plans in state "
            f"'planned' (plan {plan.id} is {plan.state!r})"
        )
    if not _is_acknowledged(plan):
        raise _err(
            f"plan {plan.id} is not acknowledged; only acknowledged "
            "plans are eligible for execution"
        )
    if plan.plan_kind not in EXECUTABLE_PLAN_KINDS:
        raise _err(
            "execution attempts require an executable package plan kind "
            f"(got {plan.plan_kind!r}); review-required and unsupported "
            "plans cannot be executed"
        )
    if _is_stale(db, plan):
        raise _err(
            f"plan {plan.id} is stale (live check definition no longer "
            "matches the build-time fingerprint, or the source check is "
            "gone); rebuild and acknowledge a fresh plan before "
            "requesting execution"
        )
    request = (
        db.query(ComplianceRemediationRequest)
        .filter(ComplianceRemediationRequest.id == plan.request_id)
        .first()
    )
    if request is None:
        raise _err(
            f"plan {plan.id}'s source remediation request "
            f"(id={plan.request_id}) not found; execution refused"
        )
    if request.state != STATE_APPROVED:
        raise _err(
            f"plan {plan.id}'s source request is no longer approved "
            f"(state={request.state!r}); execution refused"
        )
    return request


# ---------------------------------------------------------------------------
# Read envelope
# ---------------------------------------------------------------------------


def attempt_read_envelope(
    row: ComplianceRemediationExecutionAttempt,
) -> Dict[str, Any]:
    """Serialize an attempt with absolute-UTC timestamps (Slice 1 read
    lock). All optional timestamps round-trip as ``None`` until later
    slices populate them.
    """
    return {
        "id": row.id,
        "request_id": row.request_id,
        "plan_id": row.plan_id,
        "policy_id": row.policy_id,
        "check_id": row.check_id,
        "system_id": row.system_id,
        "policy_slug": row.policy_slug,
        "policy_version": row.policy_version,
        "check_slug": row.check_slug,
        "check_kind": row.check_kind,
        "severity_snapshot": row.severity_snapshot,
        "plan_kind_snapshot": row.plan_kind_snapshot,
        "package_name": row.package_name,
        "package_version_target": row.package_version_target,
        "approval_decided_by": row.approval_decided_by,
        "approval_decided_at": utc_iso(row.approval_decided_at),
        "state": row.state,
        "transport": row.transport,
        "failure_reason": row.failure_reason,
        "error_message": row.error_message,
        "exit_code": row.exit_code,
        "duration_ms": row.duration_ms,
        "stdout_summary": row.stdout_summary,
        "stderr_summary": row.stderr_summary,
        "dispatched_at": utc_iso(row.dispatched_at),
        "completed_at": utc_iso(row.completed_at),
        # PRA-175 Slice 3: JSONB evidence with the post-sudo-wrap
        # effective argv alongside the planned/raw argv. Always present
        # (server_default ``{}``); ``None`` ``effective_argv`` inside
        # means the dispatcher was a test fake that bypassed the wrap.
        "dispatch_details": dict(row.dispatch_details or {}),
        "created_by": row.created_by,
        "created_at": utc_iso(row.created_at),
        "updated_at": utc_iso(row.updated_at),
    }


# ---------------------------------------------------------------------------
# Public API — create
# ---------------------------------------------------------------------------


def create_attempt(
    db: Session,
    *,
    plan_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> ComplianceRemediationExecutionAttempt:
    """Create one durable execution-attempt row for an
    acknowledged-ready package remediation plan.

    Slice 1 is intentionally pre-dispatch: this call writes one row and
    emits one audit event. It does NOT execute, dispatch, queue, run
    SSH, talk to an agent, mutate a host, refresh facts, or scan
    packages. The readiness gate is re-checked at write time so a stale
    UI cannot bypass it by replaying a previously-true
    ``ready_for_execution`` flag.
    """
    actor = _require_user(db, actor_user_id, field="actor_user_id")
    plan = _require_plan(db, plan_id)
    request = _assert_ready_for_execution(db, plan)

    pkg_name, pkg_version_target = _extract_package_identifiers(plan)

    row = ComplianceRemediationExecutionAttempt(
        request_id=request.id,
        plan_id=plan.id,
        policy_id=plan.policy_id,
        check_id=plan.check_id,
        system_id=plan.system_id,
        policy_slug=plan.policy_slug,
        policy_version=plan.policy_version,
        check_slug=plan.check_slug,
        check_kind=plan.check_kind,
        severity_snapshot=plan.severity_snapshot,
        plan_kind_snapshot=plan.plan_kind,
        package_name=pkg_name,
        package_version_target=pkg_version_target,
        approval_decided_by=request.decided_by,
        approval_decided_at=request.decided_at,
        state=STATE_PENDING,
        # transport / failure_reason / error_message / dispatched_at /
        # completed_at left NULL by design — Slice 1 is pre-dispatch.
        created_by=actor.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_CREATED,
        outcome="success",
        actor_user_id=actor.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_execution_attempt",
        target_id=str(row.id),
        target_system_id=row.system_id,
        context={
            "request_id": row.request_id,
            "plan_id": row.plan_id,
            "policy_id": row.policy_id,
            "check_id": row.check_id,
            "system_id": row.system_id,
            "policy_slug": row.policy_slug,
            "policy_version": row.policy_version,
            "check_slug": row.check_slug,
            "check_kind": row.check_kind,
            "severity_snapshot": row.severity_snapshot,
            "plan_kind_snapshot": row.plan_kind_snapshot,
            "package_name": row.package_name,
            "package_version_target": row.package_version_target,
            "state": row.state,
            "approval_decided_by": row.approval_decided_by,
            "dispatched": False,
        },
    )
    return row


# ---------------------------------------------------------------------------
# Public API — read / list
# ---------------------------------------------------------------------------


def get_attempt(
    db: Session, attempt_id: int
) -> Optional[ComplianceRemediationExecutionAttempt]:
    return (
        db.query(ComplianceRemediationExecutionAttempt)
        .filter(ComplianceRemediationExecutionAttempt.id == attempt_id)
        .first()
    )


def list_attempts(
    db: Session,
    *,
    request_id: Optional[int] = None,
    plan_id: Optional[int] = None,
    system_id: Optional[int] = None,
    state: Optional[str] = None,
    offset: int = 0,
    limit: int = 100,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Tuple[List[ComplianceRemediationExecutionAttempt], int]:
    """Paginated attempt list. Filters are validated here so the route
    layer can pass user input straight through.

    ``allowed_system_ids`` (PRA-281) restricts rows AND the total to the
    caller's fleet scope (``None`` = admin; empty = nothing).

    Returns ``(rows, total_matching_filter)``. Rows are newest first
    so paged consumers see "most recent" without re-sorting.
    """
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise _err("offset must be >= 0")
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not (1 <= limit <= LIST_LIMIT_MAX)
    ):
        raise _err(f"limit must be in 1..{LIST_LIMIT_MAX}")
    if state is not None and state not in VALID_ATTEMPT_STATES:
        raise _err(f"state must be one of: {list(VALID_ATTEMPT_STATES)}")
    if request_id is not None and (
        isinstance(request_id, bool)
        or not isinstance(request_id, int)
        or request_id <= 0
    ):
        raise _err("request_id must be a positive integer")
    if plan_id is not None and (
        isinstance(plan_id, bool) or not isinstance(plan_id, int) or plan_id <= 0
    ):
        raise _err("plan_id must be a positive integer")
    if system_id is not None and (
        isinstance(system_id, bool) or not isinstance(system_id, int) or system_id <= 0
    ):
        raise _err("system_id must be a positive integer")

    q = db.query(ComplianceRemediationExecutionAttempt)
    if request_id is not None:
        q = q.filter(ComplianceRemediationExecutionAttempt.request_id == request_id)
    if plan_id is not None:
        q = q.filter(ComplianceRemediationExecutionAttempt.plan_id == plan_id)
    if system_id is not None:
        q = q.filter(ComplianceRemediationExecutionAttempt.system_id == system_id)
    if state is not None:
        q = q.filter(ComplianceRemediationExecutionAttempt.state == state)
    scope_clause = scope_in_clause(
        ComplianceRemediationExecutionAttempt.system_id, allowed_system_ids
    )
    if scope_clause is not None:
        q = q.filter(scope_clause)

    total = q.with_entities(ComplianceRemediationExecutionAttempt.id).count()
    rows = (
        q.order_by(
            ComplianceRemediationExecutionAttempt.created_at.desc(),
            ComplianceRemediationExecutionAttempt.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


# ---------------------------------------------------------------------------
# Slice 2 — dispatch through the governed PRA-171 patch transport.
# ---------------------------------------------------------------------------


_UPGRADE_TARGET_RE = re.compile(r"^>=\s*([A-Za-z0-9._:+~\-]+)$")
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9._:+~\-]+$")


def _parse_upgrade_version_target(target: Optional[str]) -> str:
    """Parse the Slice 1 ``"">= X""`` shape and return the version part.

    Slice 1 wrote ``package_version_target = "">= X.Y.Z""`` (with a
    leading space) when the source check carried a ``min_version``.
    Slice 2 needs the bare version to pin in the package-manager
    invocation. Any other shape (different operator, missing version,
    whitespace inside the version, empty/None) raises so the
    dispatcher fails closed rather than guessing.
    """
    if not target:
        raise _err("upgrade attempt is missing package_version_target")
    stripped = target.strip()
    match = _UPGRADE_TARGET_RE.match(stripped)
    if match is None:
        raise _err(
            f"package_version_target {target!r} is not in the expected "
            "'>= <version>' form; refusing to guess an upgrade version"
        )
    return match.group(1)


def _validate_package_name(name: Optional[str]) -> str:
    if not name:
        raise _err(
            "attempt has no package_name (plan was built against a deleted "
            "source check); refusing dispatch"
        )
    if not _PACKAGE_NAME_RE.match(name):
        raise _err(
            f"attempt package_name {name!r} contains unsafe characters; "
            "refusing dispatch"
        )
    return name


def _truncate_output(text: str) -> Optional[str]:
    if not text:
        return None
    if len(text.encode("utf-8")) <= MAX_OUTPUT_BYTES:
        return text
    # Truncate by bytes to honor the MAX_OUTPUT_BYTES contract even for
    # multi-byte text.
    encoded = text.encode("utf-8")[:MAX_OUTPUT_BYTES]
    return encoded.decode("utf-8", errors="ignore") + (
        f"...[truncated {len(text.encode('utf-8')) - MAX_OUTPUT_BYTES} bytes]"
    )


def _bounded_error_message(text: str) -> Optional[str]:
    if not text:
        return None
    if len(text) > MAX_ERROR_MESSAGE_CHARS:
        return text[: MAX_ERROR_MESSAGE_CHARS - 1] + "…"
    return text


def _resolve_host_family(db: Session, system_id: int) -> str:
    """Resolve the package-manager family for a host from its
    HostFacts row. Returns ``PACKAGE_MANAGER_FAMILY_UNKNOWN`` when
    facts are missing or do not identify a known family — the caller
    raises a structured refusal in that case.
    """
    facts = db.query(HostFacts).filter(HostFacts.system_id == system_id).first()
    return _derive_package_manager_family(facts)


def _build_dispatch_command(
    family: str,
    *,
    plan_kind: str,
    package_name: str,
    package_version_target: Optional[str],
) -> List[str]:
    """Build the argv to dispatch for this attempt. install / upgrade
    reuse the PRA-171 install builders (upgrade pins to the parsed
    version); remove reuses the PRA-171 remove builders added in
    Slice 2. Raises ``ComplianceError`` for any unparsable version
    target or unsupported family.
    """
    if plan_kind == PLAN_KIND_PACKAGE_REMOVE:
        return build_remove_command_for_family(family, [package_name])
    pinned_version: Optional[str] = None
    if plan_kind == PLAN_KIND_PACKAGE_UPGRADE:
        pinned_version = _parse_upgrade_version_target(package_version_target)
    elif plan_kind == PLAN_KIND_PACKAGE_INSTALL:
        # install plans never pin a version in Slice 1 (expected_value
        # is "installed", which is not a version). Ignore any
        # version-target value rather than risk pinning to a
        # non-version string.
        pinned_version = None
    return build_command_for_family(family, [(package_name, pinned_version)])


def _audit_context(
    attempt: ComplianceRemediationExecutionAttempt,
    *,
    extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "attempt_id": attempt.id,
        "request_id": attempt.request_id,
        "plan_id": attempt.plan_id,
        "policy_id": attempt.policy_id,
        "check_id": attempt.check_id,
        "system_id": attempt.system_id,
        "policy_slug": attempt.policy_slug,
        "policy_version": attempt.policy_version,
        "check_slug": attempt.check_slug,
        "check_kind": attempt.check_kind,
        "severity_snapshot": attempt.severity_snapshot,
        "plan_kind_snapshot": attempt.plan_kind_snapshot,
        "package_name": attempt.package_name,
        "package_version_target": attempt.package_version_target,
        "state": attempt.state,
        "approval_decided_by": attempt.approval_decided_by,
    }
    if extras:
        ctx.update(extras)
    return ctx


def dispatch_attempt(
    db: Session,
    *,
    attempt_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    dispatch_callable: Optional[DispatchCallable] = None,
) -> ComplianceRemediationExecutionAttempt:
    """Dispatch one ``pending`` compliance remediation execution
    attempt through the governed PRA-171 patch transport.

    The readiness gate is re-checked at execution time so a stale UI
    cannot bypass it by replaying a previously-true
    ``ready_for_execution`` flag. The single host mutation is the
    ``apt-get install|remove`` / ``dnf install|remove`` command that
    PRA-171's ``default_dispatch`` runs through the governed
    transport — no raw SSH, subprocess, package-manager, or local
    fallback path is introduced here.

    State machine: ``pending → dispatched → succeeded | failed``.
    ``dispatched`` is committed and audited BEFORE the transport call
    so a transport hang still leaves a durable "we tried" record; the
    terminal state, outcome columns, and ``.succeeded`` /
    ``.failed`` audit event commit AFTER the transport returns.
    """
    actor = _require_user(db, actor_user_id, field="actor_user_id")
    attempt = _require_attempt(db, attempt_id)

    if attempt.state != STATE_PENDING:
        raise _err(
            f"execution attempt {attempt.id} is in state "
            f"{attempt.state!r}; only 'pending' attempts may dispatch"
        )

    if attempt.plan_id is None:
        raise _err(
            f"execution attempt {attempt.id} has no linked plan "
            "(plan_id is null); refusing dispatch"
        )
    plan = _require_plan(db, attempt.plan_id)
    if plan.request_id != attempt.request_id:
        raise _err(
            f"execution attempt {attempt.id} request_id="
            f"{attempt.request_id} does not match linked plan's "
            f"request_id={plan.request_id}; refusing dispatch"
        )

    # Re-check the full Slice 1 readiness gate (current, planned,
    # acknowledged, executable kind, not stale, approved source).
    request = _assert_ready_for_execution(db, plan)

    # Lineage consistency: the attempt's plan_kind snapshot must still
    # match the live plan's plan_kind. A drift here means the stored
    # attempt was for a different operation than the current plan
    # describes — fail closed rather than running the wrong command.
    if plan.plan_kind != attempt.plan_kind_snapshot:
        raise _err(
            f"execution attempt {attempt.id} plan_kind_snapshot="
            f"{attempt.plan_kind_snapshot!r} no longer matches the "
            f"current plan's plan_kind={plan.plan_kind!r}; refusing dispatch"
        )

    # Validate the package identifier and resolve the host's
    # package-manager family BEFORE flipping state to ``dispatched``,
    # so a pre-flight refusal stays in ``pending`` for retry rather
    # than landing as a failed attempt.
    package_name = _validate_package_name(attempt.package_name)
    system_row = db.query(System).filter(System.id == attempt.system_id).first()
    if system_row is None:
        # ON DELETE CASCADE should prevent this; defensive only.
        raise _err(
            f"execution attempt {attempt.id} target system "
            f"(id={attempt.system_id}) not found; refusing dispatch"
        )
    family = _resolve_host_family(db, attempt.system_id)
    if family == PACKAGE_MANAGER_FAMILY_UNKNOWN:
        raise _err(
            f"host {attempt.system_id} package-manager family is "
            "'unknown' (HostFacts missing or unrecognized); refusing "
            "dispatch"
        )

    # Build the argv. Upgrade-version-target parsing fails closed
    # before any host mutation if the stored target is unparsable.
    cmd = _build_dispatch_command(
        family,
        plan_kind=attempt.plan_kind_snapshot,
        package_name=package_name,
        package_version_target=attempt.package_version_target,
    )

    if dispatch_callable is None:
        dispatch_callable = lambda system, argv: default_dispatch(  # noqa: E731
            db, system, argv
        )

    # State -> dispatched + commit + audit BEFORE the transport call.
    dispatched_at = datetime.utcnow()
    attempt.state = STATE_DISPATCHED
    attempt.dispatched_at = dispatched_at
    db.commit()
    db.refresh(attempt)
    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_DISPATCHED,
        outcome="success",
        actor_user_id=actor.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_execution_attempt",
        target_id=str(attempt.id),
        target_system_id=attempt.system_id,
        context=_audit_context(
            attempt,
            extras={
                "package_family": family,
                "command_program": cmd[0] if cmd else None,
            },
        ),
    )

    # Invoke the governed transport. Catch broad exceptions so a
    # transport-level blowup still produces a recorded failure rather
    # than a half-state.
    try:
        result = dispatch_callable(system_row, cmd)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "compliance remediation dispatch adapter raised for " "attempt %s: %s",
            attempt.id,
            exc,
        )
        result = DispatchResult(
            exit_code=-1,
            error=ERROR_CODE_TRANSPORT_ERROR,
            stderr=f"adapter raised: {exc}",
        )

    # Persist outcome columns.
    attempt.transport = result.transport_name or None
    attempt.exit_code = int(result.exit_code)
    attempt.duration_ms = int(result.duration_ms)
    attempt.stdout_summary = _truncate_output(result.stdout)
    attempt.stderr_summary = _truncate_output(result.stderr)
    attempt.completed_at = datetime.utcnow()
    # PRA-175 Slice 3: surface the post-sudo-wrap effective argv (when
    # the default dispatcher ran; ``None`` for test fakes that bypass
    # the wrap) alongside the planned/raw argv the dispatcher built.
    # The sudo password (password mode) NEVER appears here — it
    # flows through ``transport.run_command(stdin=...)`` and is not
    # retained on the result envelope, so simply copying
    # ``result.effective_argv`` and the planned ``cmd`` cannot leak it.
    attempt.dispatch_details = {
        "planned_argv": list(cmd),
        "effective_argv": (
            list(result.effective_argv) if result.effective_argv is not None else None
        ),
        "transport": result.transport_name or None,
        "recorded_at": utc_iso(attempt.completed_at),
    }

    if result.error or result.exit_code != 0:
        failure_reason = result.error or ERROR_CODE_PACKAGE_MANAGER_FAILED
        attempt.state = STATE_FAILED
        attempt.failure_reason = failure_reason
        attempt.error_message = _bounded_error_message(
            result.stderr or result.stdout or failure_reason
        )
        terminal_action = AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_FAILED
    else:
        attempt.state = STATE_SUCCEEDED
        # Successful terminal state has no failure_reason / error_message;
        # leave them null even on a retry of a previously-failed attempt
        # (current vocabulary disallows that transition anyway).
        terminal_action = AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED

    db.commit()
    db.refresh(attempt)
    safe_emit(
        action=terminal_action,
        outcome="success",
        actor_user_id=actor.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_execution_attempt",
        target_id=str(attempt.id),
        target_system_id=attempt.system_id,
        context=_audit_context(
            attempt,
            extras={
                "package_family": family,
                "exit_code": attempt.exit_code,
                "duration_ms": attempt.duration_ms,
                "transport": attempt.transport,
                "failure_reason": attempt.failure_reason,
            },
        ),
    )
    # PRA-178 Slice 3: emit remediation.executed / remediation.failed
    # beside the terminal audit event. Best-effort — a notification
    # failure cannot unwind the just-committed terminal attempt state.
    from . import notification_events

    if attempt.state == STATE_SUCCEEDED:
        notification_events.emit_remediation_executed(
            db,
            attempt_id=attempt.id,
            request_id=attempt.request_id,
            plan_id=attempt.plan_id,
            policy_slug=attempt.policy_slug,
            check_slug=attempt.check_slug,
            system_id=attempt.system_id,
        )
    else:
        notification_events.emit_remediation_failed(
            db,
            attempt_id=attempt.id,
            request_id=attempt.request_id,
            plan_id=attempt.plan_id,
            policy_slug=attempt.policy_slug,
            check_slug=attempt.check_slug,
            system_id=attempt.system_id,
            failure_reason=attempt.failure_reason,
        )
    return attempt


# ---------------------------------------------------------------------------
# Slice 3 — bounded multi-attempt batch dispatch + per-request rollup.
#
# The batch entry point is intentionally additive: it never invents a
# new transport path, never auto-dispatches without an explicit
# operator action, and reuses ``dispatch_attempt`` for every
# host-mutating call so the Slice 2 readiness gate, lineage checks,
# governed transport seam, output bounding, and per-attempt audit
# events all apply unchanged. The loop is serial — predictable audit
# ordering matches the conservative safety posture and mirrors PRA-171
# per-batch dispatch.
# ---------------------------------------------------------------------------


# Bounded batch size. The default and ceiling mirror the PRA-167
# inventory page ceiling so an operator who can list 500 attempts
# can also batch up to 500 in one call without surprising scale.
MAX_BATCH_SIZE = 500

# Attempt-level batch outcome vocabulary for the *batch result envelope*.
# These are NOT new attempt states — the attempt row itself transitions
# through the Slice 2 vocabulary (``pending`` / ``dispatched`` /
# ``succeeded`` / ``failed`` / ``cancelled``). The batch envelope adds
# a transient ``refused`` slot to describe attempts whose dispatch
# raised a pre-flight :class:`ComplianceError` and therefore left the
# attempt row in ``pending`` rather than landing as a failed dispatch.
BATCH_OUTCOME_SUCCEEDED = "succeeded"
BATCH_OUTCOME_FAILED = "failed"
BATCH_OUTCOME_REFUSED = "refused"

MAX_REFUSAL_REASON_CHARS = 1024


def _require_request_row(db: Session, request_id: int) -> ComplianceRemediationRequest:
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


def _pending_attempts_for_request(
    db: Session, request_id: int, *, limit: int
) -> List[ComplianceRemediationExecutionAttempt]:
    return (
        db.query(ComplianceRemediationExecutionAttempt)
        .filter(
            ComplianceRemediationExecutionAttempt.request_id == request_id,
            ComplianceRemediationExecutionAttempt.state == STATE_PENDING,
        )
        .order_by(ComplianceRemediationExecutionAttempt.id.asc())
        .limit(limit)
        .all()
    )


def _bounded_refusal_reason(reason: str) -> str:
    if reason is None:
        return ""
    if len(reason) > MAX_REFUSAL_REASON_CHARS:
        return reason[: MAX_REFUSAL_REASON_CHARS - 1] + "…"
    return reason


def dispatch_attempts_for_request(
    db: Session,
    *,
    request_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    limit: int = MAX_BATCH_SIZE,
    dispatch_callable: Optional[DispatchCallable] = None,
) -> Dict[str, Any]:
    """Dispatch every ``pending`` execution attempt for a single
    remediation request, bounded by ``limit``.

    Each individual dispatch goes through Slice 2's ``dispatch_attempt``
    so the readiness gate, lineage checks, governed PRA-171 transport
    seam, bounded output, and per-attempt audit events are reused
    rather than reimplemented. The loop is serial — one attempt at a
    time, in stable id order — to keep audit ordering predictable and
    match PRA-171's conservative per-batch dispatch posture.

    Continue-on-error is the default semantics. A failed host
    dispatch produces a ``failed`` attempt row (and a per-attempt
    ``compliance_remediation_execution.failed`` audit event); the
    loop continues to the next attempt. A pre-flight
    :class:`ComplianceError` (e.g. the readiness gate flipped between
    batch start and the per-attempt dispatch, or the attempt's
    package_name was nulled out of band) leaves the attempt row in
    ``pending`` and is recorded in the batch envelope as ``refused``
    with the error message — the operator can re-run the batch after
    rebuilding/re-acknowledging the plan, or after another operator
    cancels the now-invalid attempt.

    Emits one ``compliance_remediation_execution.batch_dispatched``
    audit event after commit with the aggregate counts.
    """
    actor = _require_user(db, actor_user_id, field="actor_user_id")
    request = _require_request_row(db, request_id)

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise _err(f"limit must be in 1..{MAX_BATCH_SIZE}")
    if limit > MAX_BATCH_SIZE:
        raise _err(f"limit must be in 1..{MAX_BATCH_SIZE}")

    pending = _pending_attempts_for_request(db, request.id, limit=limit)

    items: List[Dict[str, Any]] = []
    refusals: List[Dict[str, Any]] = []
    succeeded_count = 0
    failed_count = 0
    refused_count = 0
    failure_breakdown: Dict[str, int] = {}

    for row in pending:
        try:
            result = dispatch_attempt(
                db,
                attempt_id=row.id,
                actor_user_id=actor.id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                dispatch_callable=dispatch_callable,
            )
        except ComplianceError as exc:
            # Pre-flight refusal: the attempt row is still ``pending``;
            # record it as ``refused`` in the batch envelope and keep
            # going. No per-attempt audit fires from the refusal path
            # because ``dispatch_attempt`` raises before its first
            # ``safe_emit`` call.
            refused_count += 1
            refusal_entry = {
                "attempt_id": row.id,
                "outcome": BATCH_OUTCOME_REFUSED,
                "reason": _bounded_refusal_reason(str(exc)),
            }
            refusals.append(refusal_entry)
            # Re-fetch to surface the (still-pending) envelope so the
            # caller's items list has a row per processed attempt.
            db.refresh(row)
            items.append(
                {
                    **attempt_read_envelope(row),
                    "batch_outcome": BATCH_OUTCOME_REFUSED,
                    "batch_refusal_reason": refusal_entry["reason"],
                }
            )
            continue

        # Terminal: succeeded / failed. dispatch_attempt already
        # committed + emitted its own per-attempt audit event.
        if result.state == STATE_SUCCEEDED:
            succeeded_count += 1
            outcome = BATCH_OUTCOME_SUCCEEDED
        else:
            failed_count += 1
            outcome = BATCH_OUTCOME_FAILED
            reason = result.failure_reason or "unknown"
            failure_breakdown[reason] = failure_breakdown.get(reason, 0) + 1
        items.append(
            {
                **attempt_read_envelope(result),
                "batch_outcome": outcome,
                "batch_refusal_reason": None,
            }
        )

    now = datetime.utcnow()
    summary: Dict[str, Any] = {
        "request_id": request.id,
        "generated_at": utc_iso(now),
        "limit": limit,
        "total_eligible": len(pending),
        "dispatched_count": succeeded_count + failed_count,
        "succeeded_count": succeeded_count,
        "failed_count": failed_count,
        "refused_count": refused_count,
        "failure_breakdown_by_reason": dict(failure_breakdown),
        "refusals": refusals,
        "items": items,
    }

    safe_emit(
        action=AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_BATCH_DISPATCHED,
        outcome="success",
        actor_user_id=actor.id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_remediation_request",
        target_id=str(request.id),
        target_system_id=request.system_id,
        context={
            "request_id": request.id,
            "policy_id": request.policy_id,
            "policy_slug": request.policy_slug,
            "check_slug": request.check_slug,
            "check_kind": request.check_kind,
            "system_id": request.system_id,
            "limit": limit,
            "total_eligible": summary["total_eligible"],
            "dispatched_count": summary["dispatched_count"],
            "succeeded_count": succeeded_count,
            "failed_count": failed_count,
            "refused_count": refused_count,
            "failure_breakdown_by_reason": summary["failure_breakdown_by_reason"],
        },
    )
    return summary


def _attempts_page_for_request(
    db: Session,
    request_id: int,
    *,
    offset: int,
    limit: int,
) -> List[ComplianceRemediationExecutionAttempt]:
    """One bounded page of attempts for a request, newest-first.
    Slice 3's ``_attempts_for_request`` is now retired in favor of an
    offset/limit page query so the rollup read can paginate cleanly.
    """
    return (
        db.query(ComplianceRemediationExecutionAttempt)
        .filter(ComplianceRemediationExecutionAttempt.request_id == request_id)
        .order_by(
            ComplianceRemediationExecutionAttempt.created_at.desc(),
            ComplianceRemediationExecutionAttempt.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )


def _total_attempts_for_request(db: Session, request_id: int) -> int:
    """Whole-request total attempt count via a single bounded SQL
    ``COUNT(*)`` (no rows materialized in memory)."""
    return (
        db.query(ComplianceRemediationExecutionAttempt.id)
        .filter(ComplianceRemediationExecutionAttempt.request_id == request_id)
        .count()
    )


def _whole_request_counts_by_state(db: Session, request_id: int) -> Dict[str, int]:
    """Whole-request ``state -> count`` aggregation via SQL ``GROUP BY``
    so the rollup numbers reflect the entire request history rather
    than just the returned page."""
    from sqlalchemy import func

    counts: Dict[str, int] = {s: 0 for s in VALID_ATTEMPT_STATES}
    rows = (
        db.query(
            ComplianceRemediationExecutionAttempt.state,
            func.count(ComplianceRemediationExecutionAttempt.id),
        )
        .filter(ComplianceRemediationExecutionAttempt.request_id == request_id)
        .group_by(ComplianceRemediationExecutionAttempt.state)
        .all()
    )
    for state_value, count in rows:
        counts[state_value] = int(count)
    return counts


def _whole_request_counts_by_failure_reason(
    db: Session, request_id: int
) -> Dict[str, int]:
    """Whole-request ``failure_reason -> count`` aggregation, scoped
    to attempts in ``failed`` state with a non-null reason."""
    from sqlalchemy import func

    rows = (
        db.query(
            ComplianceRemediationExecutionAttempt.failure_reason,
            func.count(ComplianceRemediationExecutionAttempt.id),
        )
        .filter(
            ComplianceRemediationExecutionAttempt.request_id == request_id,
            ComplianceRemediationExecutionAttempt.state == STATE_FAILED,
            ComplianceRemediationExecutionAttempt.failure_reason.isnot(None),
        )
        .group_by(ComplianceRemediationExecutionAttempt.failure_reason)
        .all()
    )
    return {reason: int(count) for reason, count in rows}


def attempt_rollup_for_request(
    db: Session,
    *,
    request_id: int,
    offset: int = 0,
    limit: int = MAX_BATCH_SIZE,
) -> Dict[str, Any]:
    """Read-only paginated rollup of every execution attempt tied to one
    remediation request.

    Whole-request totals (``total_attempts``, ``counts_by_state``,
    ``counts_by_failure_reason``) come from bounded SQL ``COUNT`` /
    ``GROUP BY`` queries so the numbers reflect the entire request
    history regardless of the returned page. Page-local counts
    (``page_counts_by_state``, ``page_counts_by_failure_reason``) are
    derived from the returned ``offset..offset+limit`` slice for
    auditors who want "what's on this page" without re-running an
    aggregate.

    Never mutates host or attempt state and never fires an audit
    event. ``offset`` past the end of the request history returns a
    valid empty page rather than an error so paginating tools can
    detect end-of-stream via ``has_more=False`` / ``next_offset=None``.
    """
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise _err("offset must be >= 0")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise _err(f"limit must be in 1..{MAX_BATCH_SIZE}")
    if limit > MAX_BATCH_SIZE:
        raise _err(f"limit must be in 1..{MAX_BATCH_SIZE}")

    request = _require_request_row(db, request_id)

    total_attempts = _total_attempts_for_request(db, request.id)
    counts_by_state = _whole_request_counts_by_state(db, request.id)
    counts_by_failure_reason = _whole_request_counts_by_failure_reason(db, request.id)

    rows = _attempts_page_for_request(db, request.id, offset=offset, limit=limit)

    page_counts_by_state: Dict[str, int] = {s: 0 for s in VALID_ATTEMPT_STATES}
    page_counts_by_failure_reason: Dict[str, int] = {}
    for row in rows:
        if row.state in page_counts_by_state:
            page_counts_by_state[row.state] += 1
        else:
            page_counts_by_state[row.state] = 1
        if row.state == STATE_FAILED and row.failure_reason:
            page_counts_by_failure_reason[row.failure_reason] = (
                page_counts_by_failure_reason.get(row.failure_reason, 0) + 1
            )

    returned_count = len(rows)
    end_index = offset + returned_count
    has_more = end_index < total_attempts
    next_offset = end_index if has_more else None

    return {
        "request_id": request.id,
        "system_id": request.system_id,
        "generated_at": utc_iso(datetime.utcnow()),
        "offset": offset,
        "limit": limit,
        "returned_count": returned_count,
        "total_attempts": total_attempts,
        "next_offset": next_offset,
        "has_more": has_more,
        "counts_by_state": counts_by_state,
        "counts_by_failure_reason": counts_by_failure_reason,
        "page_counts_by_state": page_counts_by_state,
        "page_counts_by_failure_reason": page_counts_by_failure_reason,
        "attempts": [attempt_read_envelope(r) for r in rows],
    }
