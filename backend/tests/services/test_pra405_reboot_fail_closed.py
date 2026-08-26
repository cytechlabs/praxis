"""PRA-405: the reboot queue fails closed on unknown evidence.

Covers the decision contract on top of the evidence primitive:

* a stale pre-update negative cannot produce ``not_required``;
* only a fresh successful negative clears a host;
* a fresh positive queues one;
* missing, unsupported, timed-out, transport-failed, and malformed
  observations stay queued as unknown and keep dependent waves blocked;
* repeated reconciles and probe retries are idempotent;
* ``never`` and ``always`` keep their semantics and are not probed;
* a reconcile failure is recorded, audited, notified, and reported by
  the read surface even when there is no later wave to block.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionReboot,
    PatchUpdatePlan,
    System,
)
from app.services import patch_reboot_service, reboot_evidence_service
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_FAILED,
    EXECUTION_HOST_STATE_SUCCEEDED,
    EXECUTION_STATE_SUCCEEDED,
)
from app.services.patch_reboot_service import (
    REBOOT_DECISION_EVIDENCE_UNKNOWN,
    REBOOT_DECISION_FACT_NOT_REQUIRED,
    REBOOT_DECISION_HOST_FACT_REBOOT_REQUIRED,
    REBOOT_DECISION_POLICY_ALWAYS,
    REBOOT_DECISION_POLICY_NEVER,
    REBOOT_POLICY_ALWAYS,
    REBOOT_POLICY_IF_REQUIRED,
    REBOOT_POLICY_NEVER,
    REBOOT_STATE_NOT_REQUIRED,
    REBOOT_STATE_PENDING,
    REBOOT_STATE_SKIPPED,
)
from app.services.patch_update_plan_service import PLAN_STATE_APPROVED

NOW = datetime(2026, 8, 24, 12, 0, 0)
HOST_DONE_AT = NOW - timedelta(minutes=1)


# ---------------------------------------------------------------------------
# Substrate
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="pra405-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra405-cred",
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

    def make(*, reboot_required: Optional[bool] = None) -> System:
        counter["n"] += 1
        s = System(
            hostname=f"pra405-host-{counter['n']}.example.com",
            ip_address=f"10.0.96.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        if reboot_required is not None:
            db.add(
                HostFacts(
                    system_id=s.id,
                    schema_version=1,
                    collected_at=datetime.utcnow(),
                    source_transport="ssh",
                    reboot_required=reboot_required,
                )
            )
            db.flush()
        return s

    return make


def _policy(db, slug, admin_user, *, reboot_policy=REBOOT_POLICY_IF_REQUIRED):
    p = PatchPolicy(
        slug=slug,
        name=slug,
        scope_kind="full",
        scope_packages=[],
        reboot_policy=reboot_policy,
        reboot_window_id=None,
        maintenance_window_id=None,
        rollout_cadence="immediate",
        failure_policy="continue",
        requires_approval=False,
        required_approvals=1,
        enabled=True,
        is_fleet_default=False,
        created_by=admin_user.id,
    )
    db.add(p)
    db.flush()
    return p


def _plan(db, policy, admin_user):
    plan = PatchUpdatePlan(
        policy_id=policy.id,
        name=f"plan-{policy.slug}",
        state=PLAN_STATE_APPROVED,
        reboot_window_id=None,
        policy_snapshot={
            "id": policy.id,
            "slug": policy.slug,
            "name": policy.name,
            "reboot_policy": policy.reboot_policy,
            "reboot_window_id": policy.reboot_window_id,
        },
        ring_sequence_snapshot=[],
        request_snapshot={},
        block_reasons=[],
        created_by=admin_user.id,
    )
    db.add(plan)
    db.flush()
    return plan


def _execution(db, plan, admin_user, *, state=EXECUTION_STATE_SUCCEEDED):
    now = datetime.utcnow()
    e = PatchUpdateExecution(
        plan_id=plan.id,
        state=state,
        started_by=admin_user.id,
        started_at=now,
        completed_at=now,
        max_parallel_per_wave=1,
        failure_threshold_percent=None,
        plan_state_snapshot=plan.state,
        policy_snapshot=dict(plan.policy_snapshot or {}),
        execution_config_snapshot={},
        progress_summary={},
    )
    db.add(e)
    db.flush()
    return e


def _execution_host(
    db,
    execution,
    system,
    *,
    state=EXECUTION_HOST_STATE_SUCCEEDED,
    wave_index=0,
    completed_at=HOST_DONE_AT,
):
    from app.db.models import PatchUpdatePlanHost

    ph = PatchUpdatePlanHost(
        plan_id=execution.plan_id,
        system_id=system.id,
        system_hostname_snapshot=system.hostname,
        policy_resolution_kind="direct_host",
        ring_resolution_status="resolved",
        wave_index=wave_index,
        content_profile_state="resolved",
        content_profile_conflict_snapshot=[],
        state="planned",
        block_reasons=[],
    )
    db.add(ph)
    db.flush()
    h = PatchUpdateExecutionHost(
        execution_id=execution.id,
        plan_host_id=ph.id,
        system_id_snapshot=system.id,
        system_hostname_snapshot=system.hostname,
        wave_index=wave_index,
        state=state,
        selected_package_count=1,
        skip_reasons=[],
        error_details={},
        completed_at=completed_at,
    )
    db.add(h)
    db.flush()
    return h


def _runner(**result):
    def _run(system, argv):
        _run.calls.append(system.id)
        return dict(result)

    _run.calls = []
    return _run


def _positive():
    return _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=true")


def _negative():
    return _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=false")


def _reconcile(db, execution, runner):
    return patch_reboot_service.reconcile_reboot_queue(
        db, execution.id, now=NOW, evidence_runner=runner
    )


# ---------------------------------------------------------------------------
# The defect: a stale stored fact must not decide the row
# ---------------------------------------------------------------------------


def test_stale_negative_fact_cannot_produce_not_required(db, admin_user, host_factory):
    """The host's stored fact says no reboot is needed because it was
    collected before the update. The update installed a new kernel, so
    the host now says otherwise. The fresh observation must win."""
    policy = _policy(db, "pra405-stale", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    system = host_factory(reboot_required=False)
    _execution_host(db, execution, system)

    rows = _reconcile(db, execution, _positive())

    assert len(rows) == 1
    assert rows[0].state == REBOOT_STATE_PENDING
    assert rows[0].decision_code == REBOOT_DECISION_HOST_FACT_REBOOT_REQUIRED
    assert rows[0].reboot_required_fact is True
    # The stored fact is untouched and unread; the decision is the
    # observation's.
    facts = db.query(HostFacts).filter(HostFacts.system_id == system.id).one()
    assert facts.reboot_required is False


def test_fresh_negative_evidence_produces_not_required(db, admin_user, host_factory):
    policy = _policy(db, "pra405-fresh-neg", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    system = host_factory(reboot_required=True)
    _execution_host(db, execution, system)

    rows = _reconcile(db, execution, _negative())

    assert rows[0].state == REBOOT_STATE_NOT_REQUIRED
    assert rows[0].decision_code == REBOOT_DECISION_FACT_NOT_REQUIRED
    assert rows[0].reboot_required_fact is False


def test_fresh_positive_evidence_queues_the_host(db, admin_user, host_factory):
    policy = _policy(db, "pra405-fresh-pos", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())

    rows = _reconcile(db, execution, _positive())

    assert rows[0].state == REBOOT_STATE_PENDING
    assert rows[0].decision_code == REBOOT_DECISION_HOST_FACT_REBOOT_REQUIRED


# ---------------------------------------------------------------------------
# Unknown evidence fails closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "runner_kwargs,expected_outcome",
    [
        (
            {"exit_code": 0, "stdout": "PRAXIS_REBOOT_PROBE=unsupported"},
            reboot_evidence_service.OUTCOME_UNSUPPORTED,
        ),
        (
            {"outcome": reboot_evidence_service.OUTCOME_TIMEOUT},
            reboot_evidence_service.OUTCOME_TIMEOUT,
        ),
        (
            {"outcome": reboot_evidence_service.OUTCOME_TRANSPORT_ERROR},
            reboot_evidence_service.OUTCOME_TRANSPORT_ERROR,
        ),
        (
            {"exit_code": 0, "stdout": "garbage from a login banner"},
            reboot_evidence_service.OUTCOME_MALFORMED_OUTPUT,
        ),
        (
            {"exit_code": 127, "stderr": "sh: not found"},
            reboot_evidence_service.OUTCOME_PROBE_FAILED,
        ),
    ],
)
def test_unknown_evidence_never_becomes_not_required(
    db, admin_user, host_factory, runner_kwargs, expected_outcome
):
    policy = _policy(db, f"pra405-unk-{expected_outcome}", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    # A stored fact that would previously have cleared the host.
    _execution_host(db, execution, host_factory(reboot_required=False))

    rows = _reconcile(db, execution, _runner(**runner_kwargs))

    row = rows[0]
    assert row.state == REBOOT_STATE_PENDING
    assert row.decision_code == REBOOT_DECISION_EVIDENCE_UNKNOWN
    assert row.reboot_required_fact is None
    block = row.decision_details[patch_reboot_service.EVIDENCE_DETAIL_KEY]
    assert block["outcome"] == expected_outcome
    assert block["value"] is None


def test_unknown_evidence_records_the_full_observation(db, admin_user, host_factory):
    """Value, source, collection time, and outcome are all persisted so
    the decision can be audited after the fact."""
    policy = _policy(db, "pra405-record", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())

    rows = _reconcile(db, execution, _positive())

    block = rows[0].decision_details[patch_reboot_service.EVIDENCE_DETAIL_KEY]
    assert block["value"] is True
    assert block["source"] == reboot_evidence_service.SOURCE_DEBIAN_MARKER
    assert block["outcome"] == reboot_evidence_service.OUTCOME_SUCCESS
    assert block["collected_at"].endswith("Z")


def test_host_with_no_system_row_is_unknown_not_cleared(db, admin_user, host_factory):
    policy = _policy(db, "pra405-nosystem", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    host = _execution_host(db, execution, host_factory())
    host.system_id_snapshot = None
    db.flush()

    runner = _negative()
    rows = _reconcile(db, execution, runner)

    assert runner.calls == []
    assert rows[0].state == REBOOT_STATE_PENDING
    assert rows[0].decision_code == REBOOT_DECISION_EVIDENCE_UNKNOWN


def test_unknown_rows_block_a_dependent_wave(db, admin_user, host_factory):
    policy = _policy(db, "pra405-gate", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory(), wave_index=0)

    _reconcile(db, execution, _runner(outcome="timeout"))

    blocker = patch_reboot_service.is_wave_blocked_by_reboot_gate(
        db, execution.id, wave_index=1
    )
    assert blocker is not None
    assert (
        blocker["reason"] == patch_reboot_service.WAVE_GATE_REASON_REBOOTS_IN_PROGRESS
    )


def test_cleared_rows_do_not_block_a_dependent_wave(db, admin_user, host_factory):
    policy = _policy(db, "pra405-gate-ok", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory(), wave_index=0)

    _reconcile(db, execution, _negative())

    assert (
        patch_reboot_service.is_wave_blocked_by_reboot_gate(
            db, execution.id, wave_index=1
        )
        is None
    )


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_repeated_reconcile_reuses_fresh_evidence_and_adds_no_rows(
    db, admin_user, host_factory
):
    policy = _policy(db, "pra405-idem", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())

    runner = _negative()
    first = _reconcile(db, execution, runner)
    second = _reconcile(db, execution, runner)

    assert len(runner.calls) == 1, "a fresh observation must not be re-taken"
    assert [r.id for r in first] == [r.id for r in second]
    assert (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .count()
        == 1
    )


def test_reconcile_retries_after_an_inconclusive_observation(
    db, admin_user, host_factory
):
    """An unknown result is not something to cache: the next pass must
    ask again rather than keeping the host unknown forever."""
    policy = _policy(db, "pra405-retry", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())

    failing = _runner(outcome=reboot_evidence_service.OUTCOME_TRANSPORT_ERROR)
    rows = _reconcile(db, execution, failing)
    assert rows[0].decision_code == REBOOT_DECISION_EVIDENCE_UNKNOWN

    recovering = _negative()
    rows = _reconcile(db, execution, recovering)

    assert len(recovering.calls) == 1
    assert rows[0].state == REBOOT_STATE_NOT_REQUIRED
    assert (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .count()
        == 1
    )


def test_evidence_predating_the_package_work_is_re_taken(db, admin_user, host_factory):
    policy = _policy(db, "pra405-notbefore", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    host = _execution_host(db, execution, host_factory())

    runner = _negative()
    _reconcile(db, execution, runner)
    assert len(runner.calls) == 1

    # The host finished its package work after the observation was
    # taken, so the observation no longer describes the current host.
    host.completed_at = NOW + timedelta(minutes=1)
    db.flush()

    _reconcile(db, execution, runner)
    assert len(runner.calls) == 2


# ---------------------------------------------------------------------------
# never / always are preserved and unprobed
# ---------------------------------------------------------------------------


def test_never_policy_is_skipped_without_probing(db, admin_user, host_factory):
    policy = _policy(db, "pra405-never", admin_user, reboot_policy=REBOOT_POLICY_NEVER)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())

    runner = _positive()
    rows = _reconcile(db, execution, runner)

    assert runner.calls == []
    assert rows[0].state == REBOOT_STATE_SKIPPED
    assert rows[0].decision_code == REBOOT_DECISION_POLICY_NEVER
    block = rows[0].decision_details[patch_reboot_service.EVIDENCE_DETAIL_KEY]
    assert block["outcome"] == reboot_evidence_service.OUTCOME_NOT_COLLECTED


def test_always_policy_still_queues_without_probing(db, admin_user, host_factory):
    policy = _policy(
        db, "pra405-always", admin_user, reboot_policy=REBOOT_POLICY_ALWAYS
    )
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())

    runner = _negative()
    rows = _reconcile(db, execution, runner)

    assert runner.calls == []
    assert rows[0].state == REBOOT_STATE_PENDING
    assert rows[0].decision_code == REBOOT_DECISION_POLICY_ALWAYS


def test_failed_host_is_skipped_without_probing(db, admin_user, host_factory):
    policy = _policy(db, "pra405-failedhost", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory(), state=EXECUTION_HOST_STATE_FAILED)

    runner = _positive()
    rows = _reconcile(db, execution, runner)

    assert runner.calls == []
    assert rows[0].state == REBOOT_STATE_SKIPPED


# ---------------------------------------------------------------------------
# Reconciliation failure is visible
# ---------------------------------------------------------------------------


def test_queue_read_reports_a_healthy_reconciliation(db, admin_user, host_factory):
    policy = _policy(db, "pra405-recon-ok", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    _reconcile(db, execution, _negative())

    _, _, summary = patch_reboot_service.get_reboot_queue(db, execution.id)

    assert summary["reconciliation"]["status"] == "ok"
    assert summary["reconciliation"]["action_required"] is False
    assert summary["reconciliation"]["missing_row_count"] == 0


def test_missing_rows_on_the_final_wave_are_reported_as_incomplete(
    db, admin_user, host_factory
):
    """There is no later wave to gate here, so the coverage gap has to
    surface on the read surface or nowhere."""
    policy = _policy(db, "pra405-recon-gap", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory(), wave_index=0)
    _execution_host(db, execution, host_factory(), wave_index=0)
    _reconcile(db, execution, _negative())

    # One row disappears the way a rolled-back reconcile would leave it.
    victim = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    db.delete(victim)
    db.flush()

    _, _, summary = patch_reboot_service.get_reboot_queue(db, execution.id)

    assert summary["reconciliation"]["status"] == "incomplete"
    assert summary["reconciliation"]["action_required"] is True
    assert summary["reconciliation"]["missing_row_count"] == 1


def test_a_recorded_failure_is_reported_by_the_queue_read(db, admin_user, host_factory):
    policy = _policy(db, "pra405-recon-fail", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    _reconcile(db, execution, _negative())
    db.commit()

    patch_reboot_service.record_reconciliation_failure(
        db,
        execution.id,
        reason="database went away",
        phase="auto_reconcile",
        now=NOW,
    )
    db.expire_all()

    _, _, summary = patch_reboot_service.get_reboot_queue(db, execution.id)

    block = summary["reconciliation"]
    assert block["status"] == "failed"
    assert block["action_required"] is True
    assert block["last_failure"]["reason"] == "database went away"
    assert block["last_failure"]["phase"] == "auto_reconcile"


def test_a_clean_pass_clears_a_previously_recorded_failure(
    db, admin_user, host_factory
):
    policy = _policy(db, "pra405-recon-clear", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    patch_reboot_service.record_reconciliation_failure(
        db, execution.id, reason="transient", phase="auto_reconcile", now=NOW
    )
    db.expire_all()

    patch_reboot_service.auto_reconcile_on_terminal(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        evidence_runner=_negative(),
    )
    db.expire_all()

    _, _, summary = patch_reboot_service.get_reboot_queue(db, execution.id)
    assert summary["reconciliation"]["status"] == "ok"


def test_reconcile_failure_is_recorded_audited_and_notified(
    db, admin_user, host_factory, monkeypatch
):
    """A failure that only reached the log would leave an operator with
    no reboot workflow and no signal that one is missing."""
    policy = _policy(db, "pra405-recon-surface", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    audits = []
    monkeypatch.setattr(
        patch_reboot_service,
        "safe_emit",
        lambda **kwargs: audits.append(kwargs),
    )

    from app.services import notification_events

    notifications = []
    monkeypatch.setattr(
        notification_events,
        "emit_patch_reboot_reconcile_failed",
        lambda db_arg, **kwargs: notifications.append(kwargs),
    )

    def _explode(db_arg, execution_id, **kwargs):
        raise RuntimeError("reconcile blew up")

    monkeypatch.setattr(patch_reboot_service, "reconcile_reboot_queue", _explode)

    patch_reboot_service.auto_reconcile_on_terminal(
        db, execution.id, actor_user_id=admin_user.id
    )
    db.expire_all()

    failure_audits = [
        a
        for a in audits
        if a["action"] == patch_reboot_service.AUDIT_REBOOT_RECONCILE_FAILED
    ]
    assert len(failure_audits) == 1
    assert failure_audits[0]["outcome"] == "failure"
    assert "reconcile blew up" in failure_audits[0]["context"]["reason"]

    assert len(notifications) == 1
    assert notifications[0]["execution_id"] == execution.id

    _, _, summary = patch_reboot_service.get_reboot_queue(db, execution.id)
    assert summary["reconciliation"]["status"] == "failed"
    assert summary["reconciliation"]["action_required"] is True


def test_reconcile_failure_does_not_propagate(
    db, admin_user, host_factory, monkeypatch
):
    """The terminal state the caller already committed must survive."""
    policy = _policy(db, "pra405-recon-nothrow", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    def _explode(db_arg, execution_id, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(patch_reboot_service, "reconcile_reboot_queue", _explode)

    patch_reboot_service.auto_reconcile_on_terminal(
        db, execution.id, actor_user_id=admin_user.id
    )


def test_unknown_evidence_notification_names_the_unknown_state(
    db, admin_user, host_factory, monkeypatch
):
    policy = _policy(db, "pra405-notify-unknown", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    monkeypatch.setattr(patch_reboot_service, "safe_emit", lambda **kwargs: None)

    from app.services import notification_events

    emitted = []
    monkeypatch.setattr(
        notification_events,
        "emit_patch_reboot_required",
        lambda db_arg, **kwargs: emitted.append(kwargs),
    )

    patch_reboot_service.auto_reconcile_on_terminal(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        evidence_runner=_runner(outcome=reboot_evidence_service.OUTCOME_TIMEOUT),
    )

    assert len(emitted) == 1
    assert emitted[0]["evidence_unknown"] is True


def test_repeated_auto_reconcile_does_not_re_notify(
    db, admin_user, host_factory, monkeypatch
):
    policy = _policy(db, "pra405-notify-once", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    monkeypatch.setattr(patch_reboot_service, "safe_emit", lambda **kwargs: None)

    from app.services import notification_events

    emitted = []
    monkeypatch.setattr(
        notification_events,
        "emit_patch_reboot_required",
        lambda db_arg, **kwargs: emitted.append(kwargs),
    )

    runner = _positive()
    patch_reboot_service.auto_reconcile_on_terminal(
        db, execution.id, actor_user_id=admin_user.id, evidence_runner=runner
    )
    patch_reboot_service.auto_reconcile_on_terminal(
        db, execution.id, actor_user_id=admin_user.id, evidence_runner=runner
    )

    assert len(emitted) == 1
    assert len(runner.calls) == 1
    assert (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .count()
        == 1
    )


def test_a_recorded_reconcile_failure_blocks_a_dependent_wave(
    db, admin_user, host_factory
):
    """Rows can all be present and still not describe the run. Until a
    clean pass clears the failure, no prior wave counts as proven."""
    policy = _policy(db, "pra405-gate-failed", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory(), wave_index=0)
    _reconcile(db, execution, _negative())
    assert (
        patch_reboot_service.is_wave_blocked_by_reboot_gate(
            db, execution.id, wave_index=1
        )
        is None
    )

    patch_reboot_service.record_reconciliation_failure(
        db, execution.id, reason="promote failed", phase="auto_reconcile", now=NOW
    )

    blocker = patch_reboot_service.is_wave_blocked_by_reboot_gate(
        db, execution.id, wave_index=1
    )
    assert blocker is not None
    assert blocker["reason"] == patch_reboot_service.WAVE_GATE_REASON_RECONCILE_FAILED
    assert blocker["reconciliation_failure"]["reason"] == "promote failed"


def test_wave_zero_is_never_gated_by_a_recorded_failure(db, admin_user, host_factory):
    policy = _policy(db, "pra405-gate-wave0", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory(), wave_index=0)

    patch_reboot_service.record_reconciliation_failure(
        db, execution.id, reason="anything", phase="auto_reconcile", now=NOW
    )

    assert (
        patch_reboot_service.is_wave_blocked_by_reboot_gate(
            db, execution.id, wave_index=0
        )
        is None
    )


# ---------------------------------------------------------------------------
# Redaction across the persisted queue and its operator-facing surfaces
# ---------------------------------------------------------------------------


LEAKY_STDERR = "connect failed: postgresql://praxis:sup3rs3cr3t@db:5432/praxis"


def test_probe_secrets_do_not_reach_the_persisted_queue_row(
    db, admin_user, host_factory
):
    policy = _policy(db, "pra405-redact-row", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())

    rows = _reconcile(
        db, execution, _runner(exit_code=1, stdout="", stderr=LEAKY_STDERR)
    )

    row = rows[0]
    assert "sup3rs3cr3t" not in str(row.decision_details)
    block = row.decision_details[patch_reboot_service.EVIDENCE_DETAIL_KEY]
    # The operator still learns what happened and why.
    assert block["outcome"] == reboot_evidence_service.OUTCOME_PROBE_FAILED
    assert "connect failed" in block["detail"]


def test_probe_secrets_do_not_reach_the_queue_read(db, admin_user, host_factory):
    policy = _policy(db, "pra405-redact-read", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    _reconcile(db, execution, _runner(exit_code=1, stdout="", stderr=LEAKY_STDERR))

    _, rows, summary = patch_reboot_service.get_reboot_queue(db, execution.id)

    payload = str([r.decision_details for r in rows]) + str(summary)
    assert "sup3rs3cr3t" not in payload


def test_probe_secrets_do_not_reach_the_reboot_audit(
    db, admin_user, host_factory, monkeypatch
):
    policy = _policy(db, "pra405-redact-audit", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    audits = []
    monkeypatch.setattr(
        patch_reboot_service, "safe_emit", lambda **kwargs: audits.append(kwargs)
    )
    from app.services import notification_events

    monkeypatch.setattr(
        notification_events, "emit_patch_reboot_required", lambda *a, **k: None
    )

    patch_reboot_service.auto_reconcile_on_terminal(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        evidence_runner=_runner(exit_code=1, stdout="", stderr=LEAKY_STDERR),
    )

    assert audits
    assert "sup3rs3cr3t" not in str(audits)


def test_reconcile_failure_reason_is_redacted_everywhere_it_is_shown(
    db, admin_user, host_factory, monkeypatch
):
    """A raised database error carries its connection URL. It reaches the
    execution row, the audit context, and a notification, so it is redacted
    before any of them."""
    policy = _policy(db, "pra405-redact-recon", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    audits = []
    monkeypatch.setattr(
        patch_reboot_service, "safe_emit", lambda **kwargs: audits.append(kwargs)
    )
    from app.services import notification_events

    notifications = []
    monkeypatch.setattr(
        notification_events,
        "emit_patch_reboot_reconcile_failed",
        lambda db_arg, **kwargs: notifications.append(kwargs),
    )

    def _explode(db_arg, execution_id, **kwargs):
        raise RuntimeError(
            "could not connect: postgresql://praxis:sup3rs3cr3t@db:5432/praxis"
        )

    monkeypatch.setattr(patch_reboot_service, "reconcile_reboot_queue", _explode)

    patch_reboot_service.auto_reconcile_on_terminal(
        db, execution.id, actor_user_id=admin_user.id
    )
    db.expire_all()

    assert "sup3rs3cr3t" not in str(audits)
    assert "sup3rs3cr3t" not in str(notifications)

    _, _, summary = patch_reboot_service.get_reboot_queue(db, execution.id)
    assert "sup3rs3cr3t" not in str(summary)
    # The operator still sees what failed.
    assert "could not connect" in summary["reconciliation"]["last_failure"]["reason"]


def test_evidence_export_columns_carry_no_secrets(db, admin_user, host_factory):
    from app.services import patch_reboots_export_service

    policy = _policy(db, "pra405-redact-export", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    rows = _reconcile(
        db, execution, _runner(exit_code=1, stdout="", stderr=LEAKY_STDERR)
    )

    exported = patch_reboots_export_service._reboot_row(rows[0])

    assert "sup3rs3cr3t" not in str(exported)
    assert exported["reboot_evidence_outcome"] == "probe_failed"
    assert exported["reboot_evidence_source"] == "debian_reboot_required_marker"
    assert exported["reboot_evidence_collected_at"].endswith("Z")


# ---------------------------------------------------------------------------
# Log paths
#
# Redacting before persistence is worth nothing if the same exception is
# logged verbatim first. These paths log the exception category only.
# ---------------------------------------------------------------------------


@contextmanager
def capturing_warnings(caplog, *loggers):
    """Capture WARNING records from the given module loggers.

    Running migrations configures logging through ``logging.config.fileConfig``,
    which disables every logger that already exists, so a module logger is
    inert for the rest of the session unless a test re-enables it.
    """
    previous = [(lg, lg.disabled) for lg in loggers]
    for lg, _ in previous:
        lg.disabled = False
    try:
        with caplog.at_level(logging.WARNING):
            yield
    finally:
        for lg, was_disabled in previous:
            lg.disabled = was_disabled


def test_auto_reconcile_failure_is_not_logged_verbatim(
    db, admin_user, host_factory, monkeypatch, caplog
):
    policy = _policy(db, "pra405-log-recon", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    monkeypatch.setattr(patch_reboot_service, "safe_emit", lambda **kwargs: None)
    from app.services import notification_events

    monkeypatch.setattr(
        notification_events, "emit_patch_reboot_reconcile_failed", lambda *a, **k: None
    )

    class _LeakyError(RuntimeError):
        pass

    def _explode(db_arg, execution_id, **kwargs):
        raise _LeakyError(
            "could not connect: postgresql://praxis:sup3rs3cr3t@db:5432/praxis"
        )

    monkeypatch.setattr(patch_reboot_service, "reconcile_reboot_queue", _explode)

    with capturing_warnings(caplog, patch_reboot_service.logger):
        patch_reboot_service.auto_reconcile_on_terminal(
            db, execution.id, actor_user_id=admin_user.id
        )

    assert caplog.records, "the failure must still be logged"
    assert "sup3rs3cr3t" not in caplog.text
    assert "postgresql://" not in caplog.text
    assert "_LeakyError" in caplog.text
    assert str(execution.id) in caplog.text


def test_marker_write_failure_is_not_logged_verbatim(
    db, admin_user, host_factory, monkeypatch, caplog
):
    """The marker write is what failed here, so no redacted copy of the text
    exists anywhere. The log must not become the one place it lands."""
    policy = _policy(db, "pra405-log-marker", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    db.commit()

    class _LeakyError(RuntimeError):
        pass

    def _explode(*args, **kwargs):
        raise _LeakyError("dsn postgresql://praxis:sup3rs3cr3t@db:5432/praxis")

    monkeypatch.setattr(db, "commit", _explode)

    with capturing_warnings(caplog, patch_reboot_service.logger):
        marker = patch_reboot_service.record_reconciliation_failure(
            db,
            execution.id,
            reason="password=hunter2trombone",
            phase="auto_reconcile",
            now=NOW,
        )

    assert marker is None
    assert "sup3rs3cr3t" not in caplog.text
    assert "hunter2trombone" not in caplog.text
    assert "_LeakyError" in caplog.text


def test_notification_failure_is_not_logged_verbatim(
    db, admin_user, host_factory, monkeypatch, caplog
):
    policy = _policy(db, "pra405-log-notify", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    db.commit()

    monkeypatch.setattr(patch_reboot_service, "safe_emit", lambda **kwargs: None)
    from app.services import notification_events

    class _LeakyError(RuntimeError):
        pass

    def _explode(db_arg, **kwargs):
        raise _LeakyError("smtp postgresql://praxis:sup3rs3cr3t@db:5432/praxis")

    monkeypatch.setattr(
        notification_events, "emit_patch_reboot_reconcile_failed", _explode
    )

    with capturing_warnings(caplog, patch_reboot_service.logger):
        patch_reboot_service.surface_reconciliation_failure(
            db,
            execution.id,
            reason="boom",
            phase="auto_reconcile",
            actor_user_id=admin_user.id,
        )

    assert "sup3rs3cr3t" not in caplog.text
    assert "_LeakyError" in caplog.text


def test_no_reboot_log_path_carries_a_dsn_or_credential(
    db, admin_user, host_factory, monkeypatch, caplog
):
    """One sweep over the whole reconcile flow: whatever is logged, none of
    it may carry secret-shaped material."""
    policy = _policy(db, "pra405-log-sweep", admin_user)
    plan = _plan(db, policy, admin_user)
    execution = _execution(db, plan, admin_user)
    _execution_host(db, execution, host_factory())
    db.commit()

    monkeypatch.setattr(patch_reboot_service, "safe_emit", lambda **kwargs: None)
    from app.services import notification_events

    monkeypatch.setattr(
        notification_events, "emit_patch_reboot_required", lambda *a, **k: None
    )

    leaky_probe = _runner(
        exit_code=1,
        stdout="",
        stderr="auth failed password=hunter2trombone "
        "postgresql://praxis:sup3rs3cr3t@db:5432/praxis",
    )

    with capturing_warnings(
        caplog, patch_reboot_service.logger, reboot_evidence_service.logger
    ):
        patch_reboot_service.auto_reconcile_on_terminal(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            evidence_runner=leaky_probe,
        )

    for sentinel in ("sup3rs3cr3t", "hunter2trombone", "postgresql://"):
        assert sentinel not in caplog.text
