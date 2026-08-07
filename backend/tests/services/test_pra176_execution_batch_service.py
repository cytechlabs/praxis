"""PRA-176 Slice 3 — batch dispatch + per-request rollup service tests.

Covers:

* Empty-request batch returns a clean zero-count envelope and
  emits a ``batch_dispatched`` audit event with zeros.
* All-succeeded batch: every pending attempt for the request lands
  in ``succeeded`` state, batch envelope reports succeeded_count=N
  and failure_breakdown_by_reason={}.
* Mixed batch (some succeed, some fail): per-attempt outcomes
  preserved on individual rows, batch envelope reports
  succeeded_count + failed_count + failure_breakdown_by_reason.
* All-failed batch: every attempt lands in ``failed`` with the
  expected failure_reason; batch envelope keeps per-reason counts.
* Pre-flight refusal mid-batch: ``ComplianceError`` from
  ``dispatch_attempt`` is recorded as ``refused`` in the batch
  envelope; the attempt row stays in ``pending``; subsequent
  attempts still process.
* Non-pending attempts are ignored by the batch query (only
  ``pending`` rows are considered).
* Bound enforcement: ``limit`` is required to be 1..MAX_BATCH_SIZE.
* Audit lineage: per-attempt ``.dispatched`` / ``.succeeded`` /
  ``.failed`` still fire from the Slice 2 path; one batch
  ``.batch_dispatched`` event fires per call with aggregates.
* Rollup read covers counts_by_state, counts_by_failure_reason,
  bounded attempt envelopes, and refuses unknown request id.
* Compatibility: PRA-167 + Slice 1/2 read envelopes unchanged after
  a batch dispatch.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

import pytest

from app.db.models import (
    CompliancePolicyEvidence,
    ComplianceRemediationExecutionAttempt,
    Credential,
    Group,
    HostFacts,
    System,
)
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_execution_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
)
from app.services.compliance_remediation_execution_service import (
    AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_BATCH_DISPATCHED,
    AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_DISPATCHED,
    AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_FAILED,
    AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED,
    BATCH_OUTCOME_FAILED,
    BATCH_OUTCOME_SUCCEEDED,
    MAX_BATCH_SIZE,
    STATE_FAILED,
    STATE_PENDING,
    STATE_SUCCEEDED,
    ComplianceError,
)
from app.services.patch_execution_dispatch_service import (
    ERROR_CODE_PACKAGE_MANAGER_FAILED,
    ERROR_CODE_TRANSPORT_UNAVAILABLE,
    DispatchResult,
)

# ---------------------------------------------------------------------------
# Audit capture + fake dispatch helpers
# ---------------------------------------------------------------------------


class AuditCapture:
    def __init__(self):
        self.calls: List[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

    def by_action(self, action):
        return [c for c in self.calls if c["action"] == action]

    def actions(self):
        return [c["action"] for c in self.calls]


@pytest.fixture
def capture_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_remediation_execution_service, "safe_emit", cap)
    return cap


class QueuedDispatch:
    """Fake DispatchCallable that returns a queued DispatchResult per
    call. Empty queue defaults to exit_code=0.
    """

    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, system, cmd):
        self.calls.append({"system_id": system.id, "cmd": list(cmd)})
        if not self.results:
            return DispatchResult(exit_code=0, transport_name="fake")
        return self.results.pop(0)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra176b-host", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra176b-host-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra176b.example.com",
        ip_address="10.0.0.180",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    db.add(
        HostFacts(
            system_id=sys_row.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="agent",
            distro_id_facts="ubuntu",
            package_manager="apt",
        )
    )
    db.flush()
    return sys_row


def _approved_acknowledged_plan(db, admin_user, maintainer_user, host, *, suffix):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug=f"bx-{suffix}", name=f"bx {suffix}"
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"c-{suffix}",
        title=f"c {suffix}",
        kind="package_installed",
        definition={"package": f"missing-{suffix}"},
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    evidence = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == host.id,
            CompliancePolicyEvidence.verdict == "fail",
        )
        .order_by(CompliancePolicyEvidence.id.desc())
        .first()
    )
    req = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    return req, plan


def _make_pending_attempts(db, admin_user, maintainer_user, host, *, suffix, count):
    """Create ``count`` pending attempts on the same acknowledged plan
    (multiple operator clicks → multiple pending attempts on the same
    request). Returns (request, [attempts]).
    """
    req, plan = _approved_acknowledged_plan(
        db, admin_user, maintainer_user, host, suffix=suffix
    )
    attempts = []
    for _ in range(count):
        attempts.append(
            compliance_remediation_execution_service.create_attempt(
                db, plan_id=plan.id, actor_user_id=admin_user.id
            )
        )
    return req, attempts


# ---------------------------------------------------------------------------
# Empty batch
# ---------------------------------------------------------------------------


def test_batch_dispatch_with_no_pending_attempts_returns_zero_envelope(
    db, admin_user, maintainer_user, host, capture_audit
):
    """An approved request with no created attempts produces a clean
    empty rollup; the batch audit event still fires with zeros so the
    audit trail records the operator's empty-batch action."""
    req, _ = _approved_acknowledged_plan(
        db, admin_user, maintainer_user, host, suffix="empty"
    )
    summary = compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=QueuedDispatch([]),
    )
    assert summary["request_id"] == req.id
    assert summary["total_eligible"] == 0
    assert summary["dispatched_count"] == 0
    assert summary["succeeded_count"] == 0
    assert summary["failed_count"] == 0
    assert summary["refused_count"] == 0
    assert summary["failure_breakdown_by_reason"] == {}
    assert summary["items"] == []
    assert summary["generated_at"].endswith("Z")
    batch = capture_audit.by_action(
        AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_BATCH_DISPATCHED
    )
    assert len(batch) == 1
    assert "db" not in batch[0]
    ctx = batch[0]["context"]
    assert ctx["request_id"] == req.id
    assert ctx["dispatched_count"] == 0
    assert ctx["refused_count"] == 0


# ---------------------------------------------------------------------------
# All-succeeded batch
# ---------------------------------------------------------------------------


def test_batch_dispatch_all_succeeded(
    db, admin_user, maintainer_user, host, capture_audit
):
    req, attempts = _make_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="all-ok", count=3
    )
    dispatcher = QueuedDispatch(
        [
            DispatchResult(exit_code=0, transport_name="ssh", duration_ms=10),
            DispatchResult(exit_code=0, transport_name="ssh", duration_ms=11),
            DispatchResult(exit_code=0, transport_name="ssh", duration_ms=12),
        ]
    )
    summary = compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert summary["total_eligible"] == 3
    assert summary["dispatched_count"] == 3
    assert summary["succeeded_count"] == 3
    assert summary["failed_count"] == 0
    assert summary["refused_count"] == 0
    assert summary["failure_breakdown_by_reason"] == {}
    assert all(
        item["batch_outcome"] == BATCH_OUTCOME_SUCCEEDED for item in summary["items"]
    )
    # Per-attempt audit + per-attempt successes + one batch event.
    assert (
        len(capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_DISPATCHED))
        == 3
    )
    assert (
        len(capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED))
        == 3
    )
    batch = capture_audit.by_action(
        AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_BATCH_DISPATCHED
    )
    assert len(batch) == 1
    assert batch[0]["context"]["succeeded_count"] == 3


# ---------------------------------------------------------------------------
# Mixed batch — partial failure
# ---------------------------------------------------------------------------


def test_batch_dispatch_mixed_outcomes(
    db, admin_user, maintainer_user, host, capture_audit
):
    req, attempts = _make_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="mixed", count=3
    )
    dispatcher = QueuedDispatch(
        [
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(
                exit_code=100,
                stderr="E: pkg not found\n",
                transport_name="ssh",
            ),
            DispatchResult(
                exit_code=-1,
                error=ERROR_CODE_TRANSPORT_UNAVAILABLE,
                stderr="no transport",
            ),
        ]
    )
    summary = compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert summary["total_eligible"] == 3
    assert summary["dispatched_count"] == 3
    assert summary["succeeded_count"] == 1
    assert summary["failed_count"] == 2
    assert summary["refused_count"] == 0
    assert summary["failure_breakdown_by_reason"] == {
        ERROR_CODE_PACKAGE_MANAGER_FAILED: 1,
        ERROR_CODE_TRANSPORT_UNAVAILABLE: 1,
    }
    # Per-item outcomes preserve ordering of pending attempts.
    outcomes = [item["batch_outcome"] for item in summary["items"]]
    assert outcomes == [
        BATCH_OUTCOME_SUCCEEDED,
        BATCH_OUTCOME_FAILED,
        BATCH_OUTCOME_FAILED,
    ]
    # Per-attempt audit lineage intact.
    assert (
        len(capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_DISPATCHED))
        == 3
    )
    assert (
        len(capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED))
        == 1
    )
    assert (
        len(capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_FAILED)) == 2
    )


# ---------------------------------------------------------------------------
# All-failed batch
# ---------------------------------------------------------------------------


def test_batch_dispatch_all_failed(db, admin_user, maintainer_user, host):
    req, _ = _make_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="all-fail", count=2
    )
    dispatcher = QueuedDispatch(
        [
            DispatchResult(exit_code=100, stderr="boom", transport_name="ssh"),
            DispatchResult(exit_code=100, stderr="boom", transport_name="ssh"),
        ]
    )
    summary = compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert summary["succeeded_count"] == 0
    assert summary["failed_count"] == 2
    assert summary["failure_breakdown_by_reason"] == {
        ERROR_CODE_PACKAGE_MANAGER_FAILED: 2,
    }


# ---------------------------------------------------------------------------
# Pre-flight refusal mid-batch — the refused attempt stays pending
# and subsequent attempts still process.
# ---------------------------------------------------------------------------


def test_batch_dispatch_records_refusal_without_state_mutation(
    db, admin_user, maintainer_user, host
):
    req, attempts = _make_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="refuse", count=3
    )
    # Sabotage the middle attempt so its dispatch raises a
    # ComplianceError BEFORE the transport call (null package_name).
    attempts[1].package_name = None
    db.commit()

    dispatcher = QueuedDispatch(
        [
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
        ]
    )
    summary = compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert summary["total_eligible"] == 3
    assert summary["dispatched_count"] == 2
    assert summary["succeeded_count"] == 2
    assert summary["refused_count"] == 1
    assert (
        summary["refusals"] and summary["refusals"][0]["attempt_id"] == attempts[1].id
    )
    assert "package_name" in summary["refusals"][0]["reason"]
    # The refused attempt's row stays in ``pending`` (no state mutation).
    db.refresh(attempts[1])
    assert attempts[1].state == STATE_PENDING
    # Subsequent attempt processed.
    db.refresh(attempts[2])
    assert attempts[2].state == STATE_SUCCEEDED


# ---------------------------------------------------------------------------
# Non-pending attempts are ignored by the batch query
# ---------------------------------------------------------------------------


def test_batch_dispatch_skips_non_pending_attempts(
    db, admin_user, maintainer_user, host
):
    req, attempts = _make_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="skipnp", count=2
    )
    # Pre-succeed the first attempt by dispatching it individually.
    compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempts[0].id,
        actor_user_id=admin_user.id,
        dispatch_callable=QueuedDispatch(
            [DispatchResult(exit_code=0, transport_name="ssh")]
        ),
    )
    db.refresh(attempts[0])
    assert attempts[0].state == STATE_SUCCEEDED
    # Now batch — only the remaining pending attempt should be dispatched.
    summary = compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=QueuedDispatch(
            [DispatchResult(exit_code=0, transport_name="ssh")]
        ),
    )
    assert summary["total_eligible"] == 1
    assert summary["dispatched_count"] == 1
    assert summary["succeeded_count"] == 1


# ---------------------------------------------------------------------------
# Bound enforcement + validation
# ---------------------------------------------------------------------------


def test_batch_dispatch_rejects_bad_limit(db, admin_user, maintainer_user, host):
    req, _ = _approved_acknowledged_plan(
        db, admin_user, maintainer_user, host, suffix="bound"
    )
    for bad_limit in (0, -1, MAX_BATCH_SIZE + 1):
        with pytest.raises(ComplianceError) as ei:
            compliance_remediation_execution_service.dispatch_attempts_for_request(
                db,
                request_id=req.id,
                actor_user_id=admin_user.id,
                limit=bad_limit,
                dispatch_callable=QueuedDispatch([]),
            )
        assert "1.." in str(ei.value)


def test_batch_dispatch_unknown_request_returns_not_found(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempts_for_request(
            db,
            request_id=999_999,
            actor_user_id=admin_user.id,
            dispatch_callable=QueuedDispatch([]),
        )
    assert "not found" in str(ei.value)


def test_batch_dispatch_truncates_to_limit(db, admin_user, maintainer_user, host):
    req, _ = _make_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="truncate", count=4
    )
    summary = compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        limit=2,
        dispatch_callable=QueuedDispatch(
            [
                DispatchResult(exit_code=0, transport_name="ssh"),
                DispatchResult(exit_code=0, transport_name="ssh"),
            ]
        ),
    )
    assert summary["limit"] == 2
    assert summary["total_eligible"] == 2  # bounded query
    assert summary["dispatched_count"] == 2
    # The other 2 attempts remain pending.
    remaining = (
        db.query(ComplianceRemediationExecutionAttempt)
        .filter(
            ComplianceRemediationExecutionAttempt.request_id == req.id,
            ComplianceRemediationExecutionAttempt.state == STATE_PENDING,
        )
        .count()
    )
    assert remaining == 2


# ---------------------------------------------------------------------------
# Rollup read
# ---------------------------------------------------------------------------


def test_attempt_rollup_for_request_aggregates_states_and_failures(
    db, admin_user, maintainer_user, host
):
    req, _ = _make_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="rollup", count=3
    )
    # Dispatch the batch with mixed outcomes so the rollup has both
    # succeeded and failed counts to aggregate.
    compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=QueuedDispatch(
            [
                DispatchResult(exit_code=0, transport_name="ssh"),
                DispatchResult(exit_code=100, stderr="boom", transport_name="ssh"),
                DispatchResult(
                    exit_code=-1,
                    error=ERROR_CODE_TRANSPORT_UNAVAILABLE,
                    stderr="no transport",
                ),
            ]
        ),
    )
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id
    )
    assert rollup["request_id"] == req.id
    assert rollup["total_attempts"] == 3
    assert rollup["counts_by_state"][STATE_SUCCEEDED] == 1
    assert rollup["counts_by_state"][STATE_FAILED] == 2
    assert rollup["counts_by_failure_reason"] == {
        ERROR_CODE_PACKAGE_MANAGER_FAILED: 1,
        ERROR_CODE_TRANSPORT_UNAVAILABLE: 1,
    }
    assert rollup["generated_at"].endswith("Z")
    assert len(rollup["attempts"]) == 3
    # Each attempt envelope shape matches the existing Slice 2 read envelope.
    for a in rollup["attempts"]:
        assert "transport" in a and "exit_code" in a


def test_attempt_rollup_unknown_request_returns_not_found(db):
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.attempt_rollup_for_request(
            db, request_id=999_999
        )
    assert "not found" in str(ei.value)


def test_attempt_rollup_for_empty_request_is_clean(
    db, admin_user, maintainer_user, host
):
    req, _ = _approved_acknowledged_plan(
        db, admin_user, maintainer_user, host, suffix="emptyrollup"
    )
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id
    )
    assert rollup["total_attempts"] == 0
    assert rollup["counts_by_state"][STATE_PENDING] == 0
    assert rollup["counts_by_failure_reason"] == {}
    assert rollup["attempts"] == []


def test_attempt_rollup_rejects_bad_limit(db, admin_user, maintainer_user, host):
    req, _ = _approved_acknowledged_plan(
        db, admin_user, maintainer_user, host, suffix="rollupbound"
    )
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.attempt_rollup_for_request(
            db, request_id=req.id, limit=0
        )
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.attempt_rollup_for_request(
            db, request_id=req.id, limit=MAX_BATCH_SIZE + 1
        )


# ---------------------------------------------------------------------------
# Compatibility — Slice 1/2 read envelopes unchanged after a batch
# ---------------------------------------------------------------------------


def test_pra167_request_envelope_unchanged_after_batch_dispatch(
    db, admin_user, maintainer_user, host
):
    req, _ = _make_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="compat", count=2
    )
    before = compliance_remediation_service.remediation_request_read_envelope(req)
    compliance_remediation_execution_service.dispatch_attempts_for_request(
        db,
        request_id=req.id,
        actor_user_id=admin_user.id,
        dispatch_callable=QueuedDispatch(
            [
                DispatchResult(exit_code=0, transport_name="ssh"),
                DispatchResult(exit_code=0, transport_name="ssh"),
            ]
        ),
    )
    db.refresh(req)
    after = compliance_remediation_service.remediation_request_read_envelope(req)
    assert before == after
