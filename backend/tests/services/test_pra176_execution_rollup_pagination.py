"""PRA-176 Slice 4 — explicit execution rollup pagination tests.

Slice 4 makes ``attempt_rollup_for_request`` paginated and separates
whole-request totals from page-local counts. These tests cover:

* First page returns the newest ``limit`` rows and a clean
  ``next_offset`` / ``has_more`` pair.
* Middle page returns the expected slice with offset/limit/returned_count.
* Last page returns the tail with ``next_offset=None`` and ``has_more=False``.
* Empty page beyond the end returns an empty envelope (not an error)
  with whole-request totals still populated.
* Whole-request totals (``total_attempts``, ``counts_by_state``,
  ``counts_by_failure_reason``) reflect the entire request history,
  not just the returned page.
* Page-local counts (``page_counts_by_state`` /
  ``page_counts_by_failure_reason``) reflect only the returned slice.
* Invalid pagination values (negative offset, zero/oversized limit,
  bool / non-int types) raise ``ComplianceError``.
* Empty-request rollup is well-formed.
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
# Fixtures + helpers
# ---------------------------------------------------------------------------


class QueuedDispatch:
    def __init__(self, results):
        self.results = list(results)

    def __call__(self, system, cmd):
        if not self.results:
            return DispatchResult(exit_code=0, transport_name="fake")
        return self.results.pop(0)


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra176p-host", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra176p-host-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra176p.example.com",
        ip_address="10.0.0.182",
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


def _seed_pending_attempts(db, admin_user, maintainer_user, host, *, suffix, count):
    """Seed ``count`` pending attempts on one acknowledged plan."""
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"pg-{suffix}",
        name=f"pg {suffix}",
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
    attempts: List[ComplianceRemediationExecutionAttempt] = []
    for _ in range(count):
        attempts.append(
            compliance_remediation_execution_service.create_attempt(
                db, plan_id=plan.id, actor_user_id=admin_user.id
            )
        )
    return req, attempts


def _dispatch_with_outcomes(db, admin_user, attempts, outcomes):
    """Dispatch each attempt in order with a queued DispatchResult."""
    for attempt, result in zip(attempts, outcomes):
        compliance_remediation_execution_service.dispatch_attempt(
            db,
            attempt_id=attempt.id,
            actor_user_id=admin_user.id,
            dispatch_callable=QueuedDispatch([result]),
        )


# ---------------------------------------------------------------------------
# Pagination — first/middle/last/beyond-end pages
# ---------------------------------------------------------------------------


def test_rollup_first_page_returns_newest_rows_and_has_more(
    db, admin_user, maintainer_user, host
):
    req, attempts = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-first", count=7
    )
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id, offset=0, limit=3
    )
    assert rollup["offset"] == 0
    assert rollup["limit"] == 3
    assert rollup["returned_count"] == 3
    assert rollup["total_attempts"] == 7
    assert rollup["has_more"] is True
    assert rollup["next_offset"] == 3
    # Newest-first ordering: highest attempt id is the first returned row.
    returned_ids = [a["id"] for a in rollup["attempts"]]
    assert returned_ids == sorted(returned_ids, reverse=True)
    assert returned_ids[0] == max(a.id for a in attempts)


def test_rollup_middle_page(db, admin_user, maintainer_user, host):
    req, _ = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-mid", count=10
    )
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id, offset=4, limit=3
    )
    assert rollup["offset"] == 4
    assert rollup["limit"] == 3
    assert rollup["returned_count"] == 3
    assert rollup["total_attempts"] == 10
    assert rollup["has_more"] is True
    assert rollup["next_offset"] == 7


def test_rollup_last_page_clears_has_more(db, admin_user, maintainer_user, host):
    req, _ = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-last", count=7
    )
    # offset=5, limit=3 -> 2 rows returned (5,6), end reached.
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id, offset=5, limit=3
    )
    assert rollup["offset"] == 5
    assert rollup["returned_count"] == 2
    assert rollup["total_attempts"] == 7
    assert rollup["has_more"] is False
    assert rollup["next_offset"] is None


def test_rollup_offset_beyond_end_returns_empty_page(
    db, admin_user, maintainer_user, host
):
    req, _ = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-beyond", count=3
    )
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id, offset=10, limit=5
    )
    assert rollup["offset"] == 10
    assert rollup["limit"] == 5
    assert rollup["returned_count"] == 0
    assert rollup["attempts"] == []
    assert rollup["total_attempts"] == 3  # whole-request total unaffected
    assert rollup["has_more"] is False
    assert rollup["next_offset"] is None
    # Whole-request counts still populated.
    assert rollup["counts_by_state"][STATE_PENDING] == 3


# ---------------------------------------------------------------------------
# Whole-request vs page-local count semantics
# ---------------------------------------------------------------------------


def test_rollup_whole_request_counts_independent_of_page(
    db, admin_user, maintainer_user, host
):
    """Build 6 attempts: 2 succeeded, 2 package-manager failures,
    2 transport-unavailable failures. Whole-request counts must add
    up to 6 across all pages; page-local counts must only describe
    the returned slice.
    """
    req, attempts = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-counts", count=6
    )
    _dispatch_with_outcomes(
        db,
        admin_user,
        attempts,
        [
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=0, transport_name="ssh"),
            DispatchResult(exit_code=100, stderr="boom", transport_name="ssh"),
            DispatchResult(exit_code=100, stderr="boom", transport_name="ssh"),
            DispatchResult(
                exit_code=-1,
                error=ERROR_CODE_TRANSPORT_UNAVAILABLE,
                stderr="no transport",
            ),
            DispatchResult(
                exit_code=-1,
                error=ERROR_CODE_TRANSPORT_UNAVAILABLE,
                stderr="no transport",
            ),
        ],
    )

    # First page (2 rows).
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id, offset=0, limit=2
    )
    assert rollup["total_attempts"] == 6
    assert rollup["counts_by_state"][STATE_SUCCEEDED] == 2
    assert rollup["counts_by_state"][STATE_FAILED] == 4
    assert rollup["counts_by_failure_reason"] == {
        ERROR_CODE_PACKAGE_MANAGER_FAILED: 2,
        ERROR_CODE_TRANSPORT_UNAVAILABLE: 2,
    }
    # Page-local counts: only the first 2 rows (newest-first → the two
    # transport-unavailable rows).
    assert rollup["page_counts_by_state"][STATE_FAILED] == 2
    assert rollup["page_counts_by_state"][STATE_SUCCEEDED] == 0
    assert rollup["page_counts_by_failure_reason"] == {
        ERROR_CODE_TRANSPORT_UNAVAILABLE: 2,
    }

    # Second page (2 rows). Whole-request counts must be byte-equal.
    rollup2 = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id, offset=2, limit=2
    )
    assert rollup2["total_attempts"] == rollup["total_attempts"]
    assert rollup2["counts_by_state"] == rollup["counts_by_state"]
    assert rollup2["counts_by_failure_reason"] == rollup["counts_by_failure_reason"]
    # Page-local: rows 2 and 3 (newest-first) are the two package-manager failures.
    assert rollup2["page_counts_by_state"][STATE_FAILED] == 2
    assert rollup2["page_counts_by_failure_reason"] == {
        ERROR_CODE_PACKAGE_MANAGER_FAILED: 2,
    }

    # Third page (2 rows) — the two succeeded ones.
    rollup3 = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id, offset=4, limit=2
    )
    assert rollup3["page_counts_by_state"][STATE_SUCCEEDED] == 2
    assert rollup3["page_counts_by_failure_reason"] == {}


# ---------------------------------------------------------------------------
# Invalid pagination values
# ---------------------------------------------------------------------------


def test_rollup_rejects_negative_offset(db, admin_user, maintainer_user, host):
    req, _ = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-badoff", count=1
    )
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.attempt_rollup_for_request(
            db, request_id=req.id, offset=-1, limit=10
        )
    assert "offset" in str(ei.value)


def test_rollup_rejects_zero_and_overlimit(db, admin_user, maintainer_user, host):
    req, _ = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-badlim", count=1
    )
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.attempt_rollup_for_request(
            db, request_id=req.id, offset=0, limit=0
        )
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.attempt_rollup_for_request(
            db,
            request_id=req.id,
            offset=0,
            limit=MAX_BATCH_SIZE + 1,
        )


def test_rollup_rejects_bool_pagination_values(db, admin_user, maintainer_user, host):
    """``isinstance(True, int)`` is True, so the validator must
    explicitly refuse bool values — otherwise True/False would silently
    coerce to limit=1 / limit=0."""
    req, _ = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-bool", count=1
    )
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.attempt_rollup_for_request(
            db, request_id=req.id, offset=True, limit=10
        )
    with pytest.raises(ComplianceError):
        compliance_remediation_execution_service.attempt_rollup_for_request(
            db, request_id=req.id, offset=0, limit=True
        )


# ---------------------------------------------------------------------------
# Empty request — well-formed envelope
# ---------------------------------------------------------------------------


def test_rollup_empty_request_paginated(db, admin_user, maintainer_user, host):
    """A request with zero attempts should return offset/limit/total
    that look like an empty stream rather than raising."""
    req, _ = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-empty", count=0
    )
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id, offset=0, limit=10
    )
    assert rollup["total_attempts"] == 0
    assert rollup["returned_count"] == 0
    assert rollup["attempts"] == []
    assert rollup["has_more"] is False
    assert rollup["next_offset"] is None
    assert rollup["counts_by_state"][STATE_PENDING] == 0
    assert rollup["counts_by_failure_reason"] == {}
    assert rollup["page_counts_by_state"][STATE_PENDING] == 0
    assert rollup["page_counts_by_failure_reason"] == {}


def test_rollup_default_offset_is_zero(db, admin_user, maintainer_user, host):
    """The service helper should default offset=0 / limit=MAX_BATCH_SIZE
    so callers that don't supply pagination get the existing
    Slice-3-style first page."""
    req, _ = _seed_pending_attempts(
        db, admin_user, maintainer_user, host, suffix="pg-default", count=2
    )
    rollup = compliance_remediation_execution_service.attempt_rollup_for_request(
        db, request_id=req.id
    )
    assert rollup["offset"] == 0
    assert rollup["limit"] == MAX_BATCH_SIZE
    assert rollup["returned_count"] == 2
    assert rollup["total_attempts"] == 2
    assert rollup["has_more"] is False
