"""PRA-312 Slice 1 — compliance run correctness + operator control.

Proves:
- a newly enabled policy with ``last_run_at=NULL`` (incl. starter-pack policies) is
  evaluated on the NEXT sweep, deterministically, without waiting a full interval;
- ``run_policy_now`` triggers an immediate evaluation and records the success outcome;
- a disabled policy is refused;
- a failed evaluation records ``last_run_status='error'`` WITHOUT advancing
  ``last_run_at`` (so the policy stays due and retries);
- evidence/retention behavior is preserved (evidence rows still written).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import CompliancePolicy, Credential, Group, Package, System
from app.services import compliance_evaluation_service as evalsvc
from app.services import compliance_service
from app.services.compliance_service import ComplianceError


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra312-eval", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra312-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra312-host.example.com",
        ip_address="10.0.0.61",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _policy_with_check(db, admin_user, host, *, slug="p312", enabled=True):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug=slug, name=slug.upper(), enabled=enabled
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"{slug}-chk",
        title="openssl installed",
        kind="package_installed",
        definition={"package": "openssl"},
    )
    pkg = Package(system_id=host.id, name="openssl", installed_version="3.0.2")
    db.add(pkg)
    db.flush()
    return policy


# ------------------------------------------------- eligibility (the live blocker)


def test_newly_enabled_policy_is_due_immediately_and_evaluates(db, admin_user, host):
    """A just-enabled policy (last_run_at NULL) must be evaluated on the very next
    sweep — not after its 24h interval."""
    policy = _policy_with_check(db, admin_user, host, slug="due-now")
    assert policy.last_run_at is None

    now = datetime(2026, 7, 31, 12, 0, 0)
    # It is due immediately (NULL last_run_at), NOT gated on the 24h interval.
    due = evalsvc.list_due_policies(db, now=now)
    assert policy.id in {p.id for p in due}

    summaries = evalsvc.evaluate_due_policies(db, now=now)
    assert policy.id in summaries  # evaluated on this sweep

    db.refresh(policy)
    assert policy.last_run_at == now
    assert policy.last_run_status == "success"
    # Evidence preserved: a row was written for the host/check.
    from app.db.models import CompliancePolicyEvidence

    assert (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.policy_id == policy.id)
        .count()
        >= 1
    )


def test_starter_pack_policies_evaluate_on_first_sweep(db, admin_user, host):
    """Seeded starter policies are enabled with last_run_at NULL, so the first sweep
    evaluates them — reproducing + fixing the live blocker deterministically."""
    compliance_service.seed_starter_pack(db, actor_user_id=admin_user.id)
    starters = (
        db.query(CompliancePolicy)
        .filter(CompliancePolicy.starter_pack_key.isnot(None))
        .all()
    )
    assert starters, "starter pack should have seeded policies"
    assert all(p.enabled and p.last_run_at is None for p in starters)

    now = datetime(2026, 7, 31, 12, 0, 0)
    due_ids = {p.id for p in evalsvc.list_due_policies(db, now=now)}
    assert {p.id for p in starters} <= due_ids  # all starters due on first sweep

    evalsvc.evaluate_due_policies(db, now=now)
    for p in starters:
        db.refresh(p)
        assert p.last_run_at == now  # ran now, not 24h later
        assert p.last_run_status == "success"


# --------------------------------------------------------------- run now


def test_run_policy_now_evaluates_immediately(db, admin_user, host):
    policy = _policy_with_check(db, admin_user, host, slug="run-now")
    summary = evalsvc.run_policy_now(
        db, policy_id=policy.id, actor_user_id=admin_user.id
    )
    assert summary.policy_id == policy.id and summary.evidence_count >= 1
    db.refresh(policy)
    assert policy.last_run_at is not None
    assert policy.last_run_status == "success"


def test_run_policy_now_refuses_disabled(db, admin_user, host):
    policy = _policy_with_check(db, admin_user, host, slug="disabled", enabled=False)
    with pytest.raises(ComplianceError) as ei:
        evalsvc.run_policy_now(db, policy_id=policy.id, actor_user_id=admin_user.id)
    assert "disabled" in str(ei.value)


def test_run_policy_now_missing_policy_raises(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        evalsvc.run_policy_now(db, policy_id=999999, actor_user_id=admin_user.id)
    assert "not found" in str(ei.value)


# --------------------------------------------------------------- error outcome


def test_sweep_error_marks_status_without_advancing_last_run(
    db, admin_user, host, monkeypatch
):
    policy = _policy_with_check(db, admin_user, host, slug="boom")
    now = datetime(2026, 7, 31, 12, 0, 0)

    def _boom(*_a, **_k):
        raise RuntimeError("evaluation blew up")

    monkeypatch.setattr(evalsvc, "evaluate_policy_for_fleet", _boom)
    evalsvc.evaluate_due_policies(db, now=now)

    db.refresh(policy)
    assert policy.last_run_status == "error"
    # last_run_at NOT advanced -> policy stays due and retries next sweep.
    assert policy.last_run_at is None


# --------------------------------------------------------------- read surface


def test_policy_read_exposes_run_status(db, admin_user, host):
    policy = _policy_with_check(db, admin_user, host, slug="readme")
    never = compliance_service.policy_read_envelope(policy)
    assert never["never_run"] is True
    assert never["last_run_at"] is None and never["next_run_at"] is None
    assert never["last_run_status"] is None

    evalsvc.run_policy_now(db, policy_id=policy.id, actor_user_id=admin_user.id)
    db.refresh(policy)
    after = compliance_service.policy_read_envelope(policy)
    assert after["never_run"] is False
    assert after["last_run_status"] == "success"
    assert after["last_run_at"] and after["next_run_at"]
    # next_run = last_run + schedule_interval_hours.
    expected = policy.last_run_at + timedelta(hours=policy.schedule_interval_hours)
    assert after["next_run_at"].startswith(expected.strftime("%Y-%m-%dT%H:%M"))
