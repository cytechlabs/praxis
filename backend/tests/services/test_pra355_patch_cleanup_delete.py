"""PRA-355 — patch cleanup delete + archive/retire guards.

Covers the 1.0 cleanup model added in PRA-355 (incl. the review
follow-up fixes):

* patch policy delete succeeds for an unused/test policy;
* patch policy delete refuses the fleet-default policy with a bounded,
  operator-readable error (previously a raw HTTP 500 via the RESTRICT FK
  from ``patch_update_plans``);
* patch policy delete refuses a policy linked to an ACTIVE update plan, but
  succeeds when the only remaining links are ARCHIVED plans (detached, not
  destroyed);
* patch update plan delete succeeds only for a TRUE pre-history plan;
* patch update plan delete refuses execution / approval / schedule history
  (retained as immutable audit data) — including the superseded-with-approval
  regression from code review;
* patch update plan delete refuses a plan in a non-deletable state;
* admin archive/retire preserves every evidence row, hides the plan from
  normal lists, and is idempotency-guarded.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    PatchApproval,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdatePlan,
    PatchUpdatePlanApproval,
    System,
)
from app.services import patch_policy_service, patch_update_plan_service
from app.services.patch_policy_service import PatchPolicyError
from app.services.patch_update_plan_service import (
    PLAN_STATE_APPROVED,
    PatchUpdatePlanError,
)

# ---------------------------------------------------------------------------
# Fixtures (mirror the per-file host stack used across the PRA-16x plan tests)
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="pra355-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra355-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def host_factory(db, seed_distro, static_group, credentials):
    counter = {"n": 0}

    def make(hostname: Optional[str] = None) -> System:
        counter["n"] += 1
        s = System(
            hostname=hostname or f"pra355-host-{counter['n']}.example.com",
            ip_address=f"10.0.20.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        return s

    return make


def _make_policy(
    db, admin_user, slug: str, *, requires_approval: bool = False
) -> PatchPolicy:
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="security_only",
        requires_approval=requires_approval,
    )


def _make_plan(db, admin_user, policy: PatchPolicy, host) -> PatchUpdatePlan:
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )
    return patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=policy.id,
        name=f"plan-{policy.slug}",
        target_system_ids=[host.id],
    )


# -- patch policy delete ----------------------------------------------------


def test_delete_unused_policy_succeeds(db, admin_user):
    pol = _make_policy(db, admin_user, "pra355-unused")
    patch_policy_service.delete_policy(db, pol.id)
    assert db.query(PatchPolicy).filter(PatchPolicy.id == pol.id).first() is None


def test_delete_fleet_default_policy_refused(db, admin_user):
    pol = _make_policy(db, admin_user, "pra355-default")
    patch_policy_service.set_fleet_default(db, pol.id, actor_user_id=admin_user.id)
    with pytest.raises(PatchPolicyError, match="fleet default"):
        patch_policy_service.delete_policy(db, pol.id)
    # Refusal must not destroy the policy.
    assert db.query(PatchPolicy).filter(PatchPolicy.id == pol.id).first() is not None


def test_delete_policy_in_use_by_plan_refused(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-inuse")
    host = host_factory()
    _make_plan(db, admin_user, pol, host)
    with pytest.raises(PatchPolicyError, match="update plan"):
        patch_policy_service.delete_policy(db, pol.id)
    assert db.query(PatchPolicy).filter(PatchPolicy.id == pol.id).first() is not None


# -- patch update plan delete ----------------------------------------------


def test_delete_draft_plan_succeeds(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-plan-ok")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    assert plan.state in patch_update_plan_service.DELETABLE_STATES
    patch_update_plan_service.delete_plan(db, plan.id, actor_user_id=admin_user.id)
    assert (
        db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan.id).first() is None
    )


def test_delete_plan_with_execution_history_refused(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-plan-exec")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    execution = PatchUpdateExecution(
        plan_id=plan.id,
        state="succeeded",
        started_by=admin_user.id,
        started_at=datetime(2026, 1, 1, 0, 0, 0),
        max_parallel_per_wave=1,
        plan_state_snapshot=plan.state,
    )
    db.add(execution)
    db.commit()
    with pytest.raises(PatchUpdatePlanError, match="execution history"):
        patch_update_plan_service.delete_plan(db, plan.id, actor_user_id=admin_user.id)
    # Executed lifecycle history is immutable — nothing destroyed.
    assert (
        db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan.id).first()
        is not None
    )


def test_delete_non_deletable_state_plan_refused(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-plan-state")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    # Force a post-draft state (no executions) so the state guard fires.
    plan.state = PLAN_STATE_APPROVED
    db.add(plan)
    db.commit()
    with pytest.raises(PatchUpdatePlanError, match="cannot be deleted"):
        patch_update_plan_service.delete_plan(db, plan.id, actor_user_id=admin_user.id)
    assert (
        db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan.id).first()
        is not None
    )


def test_delete_plan_with_approval_history_refused(db, admin_user, host_factory):
    """Approval history alone blocks hard-delete (would orphan the surviving
    PatchApproval row against a deleted plan id)."""
    pol = _make_policy(db, admin_user, "pra355-appr", requires_approval=True)
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)
    with pytest.raises(PatchUpdatePlanError, match="approval history"):
        patch_update_plan_service.delete_plan(db, plan.id, actor_user_id=admin_user.id)
    assert (
        db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan.id).first()
        is not None
    )


def test_delete_plan_with_schedule_history_refused(db, admin_user, host_factory):
    """A scheduled_start_at (schedule evidence) blocks hard-delete."""
    pol = _make_policy(db, admin_user, "pra355-sched")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    plan.scheduled_start_at = datetime(2026, 2, 1, 0, 0, 0)
    db.add(plan)
    db.commit()
    with pytest.raises(PatchUpdatePlanError, match="schedule history"):
        patch_update_plan_service.delete_plan(db, plan.id, actor_user_id=admin_user.id)
    assert (
        db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan.id).first()
        is not None
    )


def test_delete_superseded_plan_with_approval_history_refused(
    db, admin_user, host_factory
):
    """Regression: draft -> request approval -> supersede ->
    hard-delete must return a bounded refusal and leave the plan AND its
    PatchApproval evidence intact (no cascade-orphan)."""
    pol = _make_policy(db, admin_user, "pra355-sup-appr", requires_approval=True)
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)
    patch_update_plan_service.supersede_plan(db, plan.id, actor_user_id=admin_user.id)
    db.refresh(plan)
    assert plan.state == "superseded"
    approval_id = (
        db.query(PatchUpdatePlanApproval.approval_id)
        .filter(PatchUpdatePlanApproval.plan_id == plan.id)
        .scalar()
    )
    assert approval_id is not None

    with pytest.raises(PatchUpdatePlanError, match="approval history"):
        patch_update_plan_service.delete_plan(db, plan.id, actor_user_id=admin_user.id)

    # Plan and its approval audit evidence survive the refusal.
    assert (
        db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan.id).first()
        is not None
    )
    assert (
        db.query(PatchApproval).filter(PatchApproval.id == approval_id).first()
        is not None
    )


# -- patch update plan archive / retire -------------------------------------


def test_archive_plan_preserves_evidence_and_hides_from_list(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "pra355-arch", requires_approval=True)
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)
    patch_update_plan_service.supersede_plan(db, plan.id, actor_user_id=admin_user.id)
    db.add(
        PatchUpdateExecution(
            plan_id=plan.id,
            state="succeeded",
            started_by=admin_user.id,
            started_at=datetime(2026, 1, 1, 0, 0, 0),
            max_parallel_per_wave=1,
            plan_state_snapshot="superseded",
        )
    )
    db.commit()

    archived = patch_update_plan_service.archive_plan(
        db, plan.id, actor_user_id=admin_user.id, reason="test cleanup"
    )
    assert archived.archived_at is not None
    assert archived.archived_by == admin_user.id
    assert archived.archive_reason == "test cleanup"
    # prior operational state is preserved (tombstone prior_state).
    assert archived.state == "superseded"

    # Every evidence row is retained.
    assert (
        db.query(PatchUpdatePlanApproval)
        .filter(PatchUpdatePlanApproval.plan_id == plan.id)
        .count()
        == 1
    )
    assert (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.plan_id == plan.id)
        .count()
        == 1
    )

    # Hidden from the default list, visible with include_archived.
    default_rows, _ = patch_update_plan_service.list_plans(db)
    assert plan.id not in [p.id for p in default_rows]
    archived_rows, _ = patch_update_plan_service.list_plans(db, include_archived=True)
    assert plan.id in [p.id for p in archived_rows]


def test_archive_already_archived_refused(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-arch2")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    patch_update_plan_service.archive_plan(db, plan.id, actor_user_id=admin_user.id)
    with pytest.raises(PatchUpdatePlanError, match="already archived"):
        patch_update_plan_service.archive_plan(db, plan.id, actor_user_id=admin_user.id)


def test_archived_plan_cannot_be_hard_deleted(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-arch-del")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    patch_update_plan_service.archive_plan(db, plan.id, actor_user_id=admin_user.id)
    with pytest.raises(PatchUpdatePlanError, match="archived"):
        patch_update_plan_service.delete_plan(db, plan.id, actor_user_id=admin_user.id)
    assert (
        db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan.id).first()
        is not None
    )


# -- patch policy delete: active vs archived links --------------------------


def test_delete_policy_blocked_by_active_plan(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-active")
    host = host_factory()
    _make_plan(db, admin_user, pol, host)
    with pytest.raises(PatchPolicyError, match="active"):
        patch_policy_service.delete_policy(db, pol.id)
    assert db.query(PatchPolicy).filter(PatchPolicy.id == pol.id).first() is not None


def test_delete_policy_allowed_when_only_archived_plans(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-archived-only")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    patch_update_plan_service.archive_plan(db, plan.id, actor_user_id=admin_user.id)

    # Only an archived plan links the policy now -> admin delete succeeds.
    patch_policy_service.delete_policy(db, pol.id)
    assert db.query(PatchPolicy).filter(PatchPolicy.id == pol.id).first() is None

    # The archived tombstone survives, detached (policy_id NULL), with its
    # policy identity preserved in the snapshot.
    survived = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan.id).first()
    assert survived is not None
    assert survived.policy_id is None
    assert survived.policy_snapshot.get("slug") == "pra355-archived-only"


# -- cleanup action flags (delete vs archive) -------------------------------


def test_flags_pure_draft_prefers_delete(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-flags-draft")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    has_hist = patch_update_plan_service.plan_has_lifecycle_history(db, plan)
    flags = patch_update_plan_service.plan_action_flags(
        plan, has_lifecycle_history=has_hist
    )
    assert has_hist is False
    assert flags["can_hard_delete"] is True
    assert flags["can_archive"] is False


def test_flags_blocked_with_approval_history_prefers_archive(
    db, admin_user, host_factory
):
    """Regression (service level): a blocked plan that retains approval
    history reports can_archive, not a dead-end can_hard_delete."""
    pol = _make_policy(db, admin_user, "pra355-flags-blocked", requires_approval=True)
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)
    # Approval-rejection outcome: blocked, approval link retained.
    plan.state = "blocked"
    db.add(plan)
    db.commit()
    db.refresh(plan)

    has_hist = patch_update_plan_service.plan_has_lifecycle_history(db, plan)
    flags = patch_update_plan_service.plan_action_flags(
        plan, has_lifecycle_history=has_hist
    )
    assert has_hist is True
    assert flags["can_hard_delete"] is False
    assert flags["can_archive"] is True

    # Batch helper agrees with the per-plan path.
    hist_map = patch_update_plan_service.lifecycle_history_by_plan(db, [plan])
    assert hist_map[plan.id] is True


def test_flags_archived_plan_offers_no_actions(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "pra355-flags-arch")
    host = host_factory()
    plan = _make_plan(db, admin_user, pol, host)
    patch_update_plan_service.archive_plan(db, plan.id, actor_user_id=admin_user.id)
    db.refresh(plan)
    flags = patch_update_plan_service.plan_action_flags(
        plan,
        has_lifecycle_history=patch_update_plan_service.plan_has_lifecycle_history(
            db, plan
        ),
    )
    assert flags["can_hard_delete"] is False
    assert flags["can_archive"] is False
