"""PRA-164 slice 4 — approval state machine + audit-export service tests.

Covers the Slice 4 transitions wired through ``patch_approval_service``
(PRA-161) and the audit-export bundle helper:

* ``request_approval`` flips ``draft`` -> ``awaiting_approval`` and
  creates the linked ``patch_approvals`` row only for policies that
  require approval.
* ``approve_directly`` flips ``draft`` -> ``approved`` only for
  policies that do NOT require approval.
* ``record_approval_vote`` advances the approval row through the
  PRA-161 service; on threshold-reached ``approved``, the plan
  transitions to ``approved`` and the audit event fires; on
  ``rejected``, the plan transitions to ``blocked`` with the
  ``approval_rejected`` block reason appended.
* ``schedule_plan`` flips ``approved`` -> ``scheduled`` and
  validates plan-level MW overrides via the existing Slice 1a
  ``_validate_plan_window`` helper.
* ``supersede_plan`` is explicit-only — no auto-supersede on
  newer-plan approval per the user decision.
* ``build_export_bundle`` returns a canonical JSON envelope
  (plan + hosts + selected packages + preflight + approval +
  audit events) with deterministic ordering and emits
  ``patch_update_plan.exported``.

All audit emission goes through ``safe_emit`` with no ``db=``
argument per the established session-boundary lock. None of the
flows trigger package execution, SSH, agent invocation, live
package collection, probes, reboot, rollback, mirror mutation, or
airgap behavior.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

import pytest

from app.db.models import (
    Credential,
    Group,
    PatchApproval,
    PatchPolicy,
    PatchUpdatePlanApproval,
    System,
)
from app.services import (
    patch_approval_service,
    patch_policy_service,
    patch_update_plan_service,
)
from app.services.patch_update_plan_service import (
    AUDIT_PLAN_APPROVAL_REQUESTED,
    AUDIT_PLAN_APPROVED,
    AUDIT_PLAN_EXPORTED,
    AUDIT_PLAN_REJECTED,
    AUDIT_PLAN_SCHEDULED,
    AUDIT_PLAN_SUPERSEDED,
    BLOCK_APPROVAL_REJECTED,
    PLAN_STATE_APPROVED,
    PLAN_STATE_AWAITING_APPROVAL,
    PLAN_STATE_BLOCKED,
    PLAN_STATE_CANCELED,
    PLAN_STATE_DRAFT,
    PLAN_STATE_SCHEDULED,
    PLAN_STATE_SUPERSEDED,
    PatchUpdatePlanError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="aproval-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="approval-test-cred",
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

    def make() -> System:
        counter["n"] += 1
        s = System(
            hostname=f"approval-host-{counter['n']}.example.com",
            ip_address=f"10.0.70.{counter['n']}",
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
    db,
    admin_user,
    slug: str,
    *,
    requires_approval: bool = False,
    required_approvals: int = 1,
) -> PatchPolicy:
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="security_only",
        rollout_cadence="immediate",
        requires_approval=requires_approval,
        required_approvals=required_approvals,
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _draft_plan(db, admin_user, policy, host, name="p"):
    return patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=policy.id,
        name=name,
        target_system_ids=[host.id],
    )


# ---------------------------------------------------------------------------
# request_approval / approve_directly
# ---------------------------------------------------------------------------


def test_request_approval_flips_draft_to_awaiting_and_creates_link(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "req-ok", requires_approval=True)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    assert plan.state == PLAN_STATE_DRAFT

    plan = patch_update_plan_service.request_approval(
        db, plan.id, actor_user_id=admin_user.id
    )
    assert plan.state == PLAN_STATE_AWAITING_APPROVAL

    link = (
        db.query(PatchUpdatePlanApproval)
        .filter(PatchUpdatePlanApproval.plan_id == plan.id)
        .first()
    )
    assert link is not None
    approval = (
        db.query(PatchApproval).filter(PatchApproval.id == link.approval_id).first()
    )
    assert approval is not None
    assert approval.subject_kind == "plan"
    assert approval.subject_id == plan.id
    assert approval.status == patch_approval_service.STATUS_PENDING


def test_request_approval_refuses_when_policy_does_not_require_approval(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "req-no", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)

    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.request_approval(
            db, plan.id, actor_user_id=admin_user.id
        )
    assert "does not require approval" in str(exc.value)


def test_request_approval_refuses_for_non_draft_plan(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "req-bad", requires_approval=True)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.cancel_plan(db, plan.id, actor_user_id=admin_user.id)
    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.request_approval(
            db, plan.id, actor_user_id=admin_user.id
        )
    assert "canceled" in str(exc.value)


def test_approve_directly_for_non_approval_policy(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "dir-ok", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)

    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    assert plan.state == PLAN_STATE_APPROVED


def test_approve_directly_refuses_when_approval_required(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "dir-no", requires_approval=True)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)

    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.approve_directly(
            db, plan.id, actor_user_id=admin_user.id
        )
    assert "requires approval" in str(exc.value)


# ---------------------------------------------------------------------------
# record_approval_vote
# ---------------------------------------------------------------------------


def test_record_approval_vote_approved_threshold_flips_plan(
    db, admin_user, host_factory
):
    pol = _make_policy(
        db, admin_user, "vote-ok", requires_approval=True, required_approvals=1
    )
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)

    plan = patch_update_plan_service.record_approval_vote(
        db, plan.id, actor_user_id=admin_user.id, decision="approve"
    )
    assert plan.state == PLAN_STATE_APPROVED


def test_record_approval_vote_below_threshold_keeps_plan_in_awaiting(
    db, admin_user, seed_roles, host_factory
):
    pol = _make_policy(
        db, admin_user, "vote-low", requires_approval=True, required_approvals=2
    )
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)

    plan = patch_update_plan_service.record_approval_vote(
        db, plan.id, actor_user_id=admin_user.id, decision="approve"
    )
    # Threshold of 2 not reached after 1 approve vote.
    assert plan.state == PLAN_STATE_AWAITING_APPROVAL


def test_record_approval_vote_rejected_blocks_plan_with_reason(
    db, admin_user, host_factory
):
    pol = _make_policy(
        db, admin_user, "vote-rej", requires_approval=True, required_approvals=1
    )
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)

    plan = patch_update_plan_service.record_approval_vote(
        db,
        plan.id,
        actor_user_id=admin_user.id,
        decision="reject",
        comment="not safe",
    )
    assert plan.state == PLAN_STATE_BLOCKED
    codes = [r["code"] for r in plan.block_reasons]
    assert BLOCK_APPROVAL_REJECTED in codes


def test_record_approval_vote_refuses_for_non_awaiting_plan(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "vote-bad", requires_approval=True)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    # Plan still draft; no approval row yet.

    with pytest.raises(PatchUpdatePlanError):
        patch_update_plan_service.record_approval_vote(
            db, plan.id, actor_user_id=admin_user.id, decision="approve"
        )


def test_record_approval_vote_invalid_decision_raises(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "vote-bad-dec", requires_approval=True)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)
    with pytest.raises(PatchUpdatePlanError):
        patch_update_plan_service.record_approval_vote(
            db, plan.id, actor_user_id=admin_user.id, decision="maybe"
        )


# ---------------------------------------------------------------------------
# schedule_plan
# ---------------------------------------------------------------------------


def test_schedule_plan_flips_approved_to_scheduled(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "sched-ok", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.approve_directly(db, plan.id, actor_user_id=admin_user.id)

    when = datetime(2030, 1, 1, 2, 0, 0)
    plan = patch_update_plan_service.schedule_plan(
        db,
        plan.id,
        actor_user_id=admin_user.id,
        scheduled_start_at=when,
    )
    assert plan.state == PLAN_STATE_SCHEDULED
    assert plan.scheduled_start_at == when


def test_schedule_plan_refuses_for_non_approved_plan(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "sched-bad", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    with pytest.raises(PatchUpdatePlanError):
        patch_update_plan_service.schedule_plan(
            db,
            plan.id,
            actor_user_id=admin_user.id,
            scheduled_start_at=datetime(2030, 1, 1),
        )


def test_schedule_plan_unknown_window_raises(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "sched-mw-bad", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.approve_directly(db, plan.id, actor_user_id=admin_user.id)
    with pytest.raises(PatchUpdatePlanError) as exc:
        patch_update_plan_service.schedule_plan(
            db,
            plan.id,
            actor_user_id=admin_user.id,
            scheduled_start_at=datetime(2030, 1, 1),
            maintenance_window_id=999_999,
        )
    assert "maintenance_window_id" in str(exc.value)


# ---------------------------------------------------------------------------
# supersede_plan (explicit-only)
# ---------------------------------------------------------------------------


def test_supersede_plan_flips_to_superseded(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "sup-ok", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    plan = patch_update_plan_service.supersede_plan(
        db, plan.id, actor_user_id=admin_user.id, comment="newer plan replaces this"
    )
    assert plan.state == PLAN_STATE_SUPERSEDED


def test_supersede_plan_refuses_terminal_state(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "sup-bad", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.cancel_plan(db, plan.id, actor_user_id=admin_user.id)
    assert plan.state == PLAN_STATE_CANCELED
    with pytest.raises(PatchUpdatePlanError):
        patch_update_plan_service.supersede_plan(
            db, plan.id, actor_user_id=admin_user.id
        )


def test_supersede_does_not_auto_fire_on_newer_plan_approval(
    db, admin_user, host_factory
):
    """Slice 4 user decision: supersede is explicit-only. Approving a
    newer plan for the same policy must NOT auto-flip the older
    plan to superseded — the older plan stays in its current state."""
    pol = _make_policy(db, admin_user, "sup-noauto", requires_approval=False)
    h_a = host_factory()
    h_b = host_factory()
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)

    plan_old = _draft_plan(db, admin_user, pol, h_a, name="old")
    plan_old = patch_update_plan_service.approve_directly(
        db, plan_old.id, actor_user_id=admin_user.id
    )
    assert plan_old.state == PLAN_STATE_APPROVED

    plan_new = _draft_plan(db, admin_user, pol, h_b, name="new")
    patch_update_plan_service.approve_directly(
        db, plan_new.id, actor_user_id=admin_user.id
    )

    refreshed_old = patch_update_plan_service.get_plan(db, plan_old.id)
    assert refreshed_old.state == PLAN_STATE_APPROVED  # NOT superseded


# ---------------------------------------------------------------------------
# Audit emission for the five new plan-state events
# ---------------------------------------------------------------------------


def test_audit_emitted_for_full_lifecycle(db, admin_user, host_factory, monkeypatch):
    captured: List[dict] = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_update_plan_service, "safe_emit", fake_safe_emit)

    pol = _make_policy(
        db, admin_user, "aud-life", requires_approval=True, required_approvals=1
    )
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)
    patch_update_plan_service.record_approval_vote(
        db, plan.id, actor_user_id=admin_user.id, decision="approve"
    )
    patch_update_plan_service.schedule_plan(
        db,
        plan.id,
        actor_user_id=admin_user.id,
        scheduled_start_at=datetime(2030, 1, 1),
    )
    patch_update_plan_service.supersede_plan(db, plan.id, actor_user_id=admin_user.id)

    actions = [c["action"] for c in captured]
    assert AUDIT_PLAN_APPROVAL_REQUESTED in actions
    assert AUDIT_PLAN_APPROVED in actions
    assert AUDIT_PLAN_SCHEDULED in actions
    assert AUDIT_PLAN_SUPERSEDED in actions
    # safe_emit session-boundary lock: no db= argument.
    for c in captured:
        assert "db" not in c


def test_audit_rejected_on_reject_vote(db, admin_user, host_factory, monkeypatch):
    captured: List[dict] = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_update_plan_service, "safe_emit", fake_safe_emit)

    pol = _make_policy(db, admin_user, "aud-rej", requires_approval=True)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)
    patch_update_plan_service.record_approval_vote(
        db, plan.id, actor_user_id=admin_user.id, decision="reject"
    )
    actions = [c["action"] for c in captured]
    assert AUDIT_PLAN_REJECTED in actions
    assert AUDIT_PLAN_APPROVED not in actions


# ---------------------------------------------------------------------------
# build_export_bundle
# ---------------------------------------------------------------------------


def test_export_bundle_returns_canonical_envelope(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "exp-ok", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.approve_directly(db, plan.id, actor_user_id=admin_user.id)

    bundle = patch_update_plan_service.build_export_bundle(
        db, plan.id, actor_user_id=admin_user.id
    )
    assert bundle["praxis_patch_update_plan_export_version"] == 1
    assert bundle["plan"]["id"] == plan.id
    assert bundle["plan"]["state"] == PLAN_STATE_APPROVED
    assert isinstance(bundle["hosts"], list) and len(bundle["hosts"]) == 1
    assert bundle["hosts"][0]["system_id"] == h.id
    assert isinstance(bundle["audit_events"], list)
    # Approval is None for non-approval-required policies (no link row).
    assert bundle["approval"] is None


def test_export_bundle_emits_exported_audit(db, admin_user, host_factory, monkeypatch):
    captured: List[dict] = []

    def fake_safe_emit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(patch_update_plan_service, "safe_emit", fake_safe_emit)

    pol = _make_policy(db, admin_user, "exp-aud", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.build_export_bundle(
        db, plan.id, actor_user_id=admin_user.id
    )
    actions = [c["action"] for c in captured]
    assert AUDIT_PLAN_EXPORTED in actions


def test_export_bundle_includes_its_own_export_event(
    db, admin_user, host_factory, monkeypatch
):
    """Slice 4a fix: the export event must be emitted BEFORE
    ``audit_events`` is read so the downloaded JSON includes the
    current export action — the bundle is a self-complete record of
    every plan event up to and including the export itself.

    Test isolation: production ``safe_emit`` opens its own
    ``SessionLocal`` and commits independently, which works in prod
    (READ COMMITTED) but fails here because the test's
    ``admin_user`` lives in an uncommitted savepoint that the
    separate connection cannot see (FK violation). To test the
    *ordering* invariant, patch ``safe_emit`` to write directly to
    the test session via the ``AuditEvent`` ORM. If the production
    code reads before emitting, the patched-and-flushed row won't
    appear in the bundle; if it emits before reading (the fix), the
    row is in the bundle.
    """
    from datetime import datetime as _dt
    from uuid import uuid4

    from app.db.models import AuditEvent

    def fake_safe_emit(**kwargs):
        kwargs.pop("db", None)
        db.add(
            AuditEvent(
                schema_version=1,
                event_uuid=str(uuid4()),
                timestamp=_dt.utcnow(),
                action=kwargs["action"],
                outcome=kwargs.get("outcome", "success"),
                actor_user_id=kwargs.get("actor_user_id"),
                actor_username=kwargs.get("actor_username"),
                actor_ip=kwargs.get("actor_ip"),
                target_kind=kwargs.get("target_kind"),
                target_id=kwargs.get("target_id"),
            )
        )
        db.flush()

    monkeypatch.setattr(patch_update_plan_service, "safe_emit", fake_safe_emit)

    pol = _make_policy(db, admin_user, "exp-self", requires_approval=False)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)

    bundle = patch_update_plan_service.build_export_bundle(
        db, plan.id, actor_user_id=admin_user.id
    )
    actions = [ev["action"] for ev in bundle["audit_events"]]
    assert AUDIT_PLAN_EXPORTED in actions, (
        "downloaded export bundle must include its own "
        f"patch_update_plan.exported event (got actions={actions})"
    )


def test_export_bundle_includes_approval_for_approval_required_plans(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "exp-aprv", requires_approval=True)
    h = host_factory()
    _bind(db, admin_user, pol, h)
    plan = _draft_plan(db, admin_user, pol, h)
    patch_update_plan_service.request_approval(db, plan.id, actor_user_id=admin_user.id)

    bundle = patch_update_plan_service.build_export_bundle(
        db, plan.id, actor_user_id=admin_user.id
    )
    assert bundle["approval"] is not None
    assert bundle["approval"]["status"] == patch_approval_service.STATUS_PENDING
    assert bundle["approval"]["requested_by"] == admin_user.id


def test_export_bundle_unknown_plan_raises(db, admin_user):
    with pytest.raises(PatchUpdatePlanError):
        patch_update_plan_service.build_export_bundle(
            db, 999_999, actor_user_id=admin_user.id
        )
