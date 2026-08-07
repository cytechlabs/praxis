"""Tests for PRA-161 slice 1a — patch_approval_service.

Covers the state machine, sweeper, and the deliberate
divergences from ``command_approval_service``:

* ``record_vote`` never dispatches background work.
* ``required_approvals`` rejects 0, negatives, and bool-as-int.
* ``subject_kind`` is locked to the migration-allowed set.
* Local ``PatchApprovalVoteError`` does not leak from
  command_approval_service.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import PatchApproval, PatchApprovalVote
from app.services import command_approval_service, patch_approval_service

# -- request_approval --------------------------------------------------------


def test_request_approval_creates_pending_row(db, admin_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=1,
        requested_by=admin_user.id,
        required_approvals=1,
    )
    assert approval.id is not None
    assert approval.status == "pending"
    assert approval.subject_kind == "policy"
    assert approval.subject_id == 1
    assert approval.required_approvals == 1


@pytest.mark.parametrize("kind", ["plan", "rollback"])
def test_request_approval_accepts_all_locked_subject_kinds(db, admin_user, kind):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind=kind,
        subject_id=42,
        requested_by=admin_user.id,
    )
    assert approval.subject_kind == kind


@pytest.mark.parametrize("kind", ["", "ring", "Policy", "PLAN"])
def test_request_approval_rejects_unknown_subject_kinds(db, admin_user, kind):
    with pytest.raises(patch_approval_service.PatchApprovalVoteError):
        patch_approval_service.request_approval(
            db,
            subject_kind=kind,
            subject_id=1,
            requested_by=admin_user.id,
        )


@pytest.mark.parametrize("bad", [0, -1, -100, True, False, 1.5, "1", None])
def test_request_approval_rejects_bad_required_approvals(db, admin_user, bad):
    """Bool-as-int trap: ``True`` is an int subclass; reject explicitly."""
    with pytest.raises(patch_approval_service.PatchApprovalVoteError):
        patch_approval_service.request_approval(
            db,
            subject_kind="policy",
            subject_id=1,
            requested_by=admin_user.id,
            required_approvals=bad,
        )


@pytest.mark.parametrize("bad", [0, -1, True, False, 1.0, "1", None])
def test_request_approval_rejects_bad_subject_id(db, admin_user, bad):
    with pytest.raises(patch_approval_service.PatchApprovalVoteError):
        patch_approval_service.request_approval(
            db,
            subject_kind="policy",
            subject_id=bad,
            requested_by=admin_user.id,
        )


# -- record_vote: single approver --------------------------------------------


def test_single_approve_flips_to_approved_with_no_dispatch(db, admin_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=1,
        requested_by=admin_user.id,
    )
    result = patch_approval_service.record_vote(
        db, approval.id, admin_user.id, "approve", "lgtm"
    )
    assert result["status"] == "approved"
    db.refresh(approval)
    assert approval.status == "approved"
    assert approval.decided_by == admin_user.id


def test_record_vote_does_not_call_command_execute_in_background(
    db, admin_user, monkeypatch
):
    """Tripwire: if anyone wires patch approvals to command-side
    auto-execute, this test fails loudly."""
    called = {"hit": False}

    def _boom(_id):
        called["hit"] = True

    monkeypatch.setattr(command_approval_service, "_execute_in_background", _boom)
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="plan",
        subject_id=2,
        requested_by=admin_user.id,
    )
    patch_approval_service.record_vote(db, approval.id, admin_user.id, "approve")
    assert called["hit"] is False


# -- record_vote: multi-level ------------------------------------------------


def test_multi_level_requires_n_distinct_approves(db, admin_user, maintainer_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=7,
        requested_by=admin_user.id,
        required_approvals=2,
    )
    r1 = patch_approval_service.record_vote(db, approval.id, admin_user.id, "approve")
    assert r1["status"] == "pending"
    assert r1["approves"] == 1
    assert r1["required"] == 2

    # Same user voting again is rejected.
    with pytest.raises(patch_approval_service.PatchApprovalVoteError):
        patch_approval_service.record_vote(db, approval.id, admin_user.id, "approve")

    r2 = patch_approval_service.record_vote(
        db, approval.id, maintainer_user.id, "approve"
    )
    assert r2["status"] == "approved"
    assert r2["approves"] == 2


def test_reject_short_circuits_regardless_of_threshold(db, admin_user, maintainer_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="rollback",
        subject_id=9,
        requested_by=admin_user.id,
        required_approvals=3,
    )
    result = patch_approval_service.record_vote(
        db, approval.id, maintainer_user.id, "reject", "no"
    )
    assert result["status"] == "rejected"
    db.refresh(approval)
    assert approval.status == "rejected"
    assert approval.decided_by == maintainer_user.id


def test_invalid_decision_rejected(db, admin_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=1,
        requested_by=admin_user.id,
    )
    with pytest.raises(patch_approval_service.PatchApprovalVoteError):
        patch_approval_service.record_vote(db, approval.id, admin_user.id, "abstain")


def test_voting_on_already_decided_request_raises(db, admin_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=1,
        requested_by=admin_user.id,
    )
    patch_approval_service.record_vote(db, approval.id, admin_user.id, "approve")
    with pytest.raises(patch_approval_service.PatchApprovalVoteError):
        patch_approval_service.record_vote(db, approval.id, admin_user.id, "approve")


def test_voting_on_unknown_id_raises(db, admin_user):
    with pytest.raises(patch_approval_service.PatchApprovalVoteError):
        patch_approval_service.record_vote(db, 99999, admin_user.id, "approve")


# -- expiration --------------------------------------------------------------


def test_voting_after_expiry_seals_and_raises(db, admin_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=1,
        requested_by=admin_user.id,
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )
    with pytest.raises(patch_approval_service.PatchApprovalVoteError):
        patch_approval_service.record_vote(db, approval.id, admin_user.id, "approve")
    db.refresh(approval)
    assert approval.status == "expired"


def test_expire_stale_sweeps_only_pending_past_expiry(db, admin_user):
    fresh = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=1,
        requested_by=admin_user.id,
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    stale = patch_approval_service.request_approval(
        db,
        subject_kind="plan",
        subject_id=1,
        requested_by=admin_user.id,
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )
    no_expiry = patch_approval_service.request_approval(
        db,
        subject_kind="rollback",
        subject_id=1,
        requested_by=admin_user.id,
        expires_at=None,
    )

    n = patch_approval_service.expire_stale(db)
    assert n == 1

    db.refresh(fresh)
    db.refresh(stale)
    db.refresh(no_expiry)
    assert fresh.status == "pending"
    assert stale.status == "expired"
    assert no_expiry.status == "pending"


def test_get_approval_status_lazily_expires_pending(db, admin_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=55,
        requested_by=admin_user.id,
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )
    status = patch_approval_service.get_approval_status(
        db, subject_kind="policy", subject_id=55
    )
    assert status is not None
    assert status["status"] == "expired"
    db.refresh(approval)
    assert approval.status == "expired"


def test_get_approval_status_returns_none_when_no_subject(db):
    assert (
        patch_approval_service.get_approval_status(
            db, subject_kind="plan", subject_id=12345
        )
        is None
    )


def test_get_approval_status_returns_newest_when_multiple(db, admin_user):
    older = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=99,
        requested_by=admin_user.id,
    )
    # Force differing created_at; rely on monotonic clock for the newer row.
    older.created_at = datetime.utcnow() - timedelta(hours=2)
    db.flush()
    newer = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=99,
        requested_by=admin_user.id,
    )
    status = patch_approval_service.get_approval_status(
        db, subject_kind="policy", subject_id=99
    )
    assert status is not None
    assert status["approval_id"] == newer.id


# -- decoupling tripwires ----------------------------------------------------


def test_local_exception_is_not_command_approval_error():
    """Lock #3 — exception classes must stay local. Importing the
    command-side error must NOT bind to the patch-side error."""
    assert (
        patch_approval_service.PatchApprovalVoteError
        is not command_approval_service.ApprovalVoteError
    )
    assert not issubclass(
        patch_approval_service.PatchApprovalVoteError,
        command_approval_service.ApprovalVoteError,
    )


def test_vote_records_are_persisted(db, admin_user):
    approval = patch_approval_service.request_approval(
        db,
        subject_kind="policy",
        subject_id=1,
        requested_by=admin_user.id,
    )
    patch_approval_service.record_vote(
        db, approval.id, admin_user.id, "approve", "ship it"
    )
    votes = (
        db.query(PatchApprovalVote)
        .filter(PatchApprovalVote.approval_id == approval.id)
        .all()
    )
    assert len(votes) == 1
    assert votes[0].decision == "approve"
    assert votes[0].comment == "ship it"


def test_subject_kind_check_constraint_at_db_level(db, admin_user):
    """Belt-and-suspenders: even if service validation were bypassed,
    the DB CHECK constraint blocks unknown subject kinds."""
    bad = PatchApproval(
        subject_kind="ring",  # not in {policy, plan, rollback}
        subject_id=1,
        status="pending",
        required_approvals=1,
        requested_by=admin_user.id,
    )
    db.add(bad)
    with pytest.raises(Exception):  # IntegrityError wrapping CHECK violation
        db.flush()
    db.rollback()
