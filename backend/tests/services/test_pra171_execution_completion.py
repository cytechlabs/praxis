"""PRA-171 slice 3 — wave/plan completion + failure-threshold auto-pause.

Covers the lifecycle hooks ``dispatch_next_batch`` runs after every
host commit. All tests use the same fake ``DispatchCallable``
pattern as Slice 2 so no real package manager / SSH / agent runs in
CI.

Slice 3 contract verified:

* ``patch_update_execution.wave_completed`` emits exactly once per
  wave when its hosts are all terminal; subsequent dispatch calls
  do not duplicate it.
* When every host across every wave is terminal, the execution
  transitions to ``succeeded`` (no failed hosts) or ``failed``
  (any failed host) and ``patch_update_execution.completed`` emits
  exactly once.
* ``completed_at`` is set at finalization.
* ``failure_threshold_percent`` auto-pauses the execution mid-batch
  when the failure rate exceeds the threshold; remaining hosts
  stay ``pending``; a structured ``failure_threshold_exceeded``
  pause reason is recorded; ``progress_summary.threshold_pause``
  carries the breach context.
* Threshold ``None`` → no auto-pause. Threshold ``0`` → any failure
  breaches.
* Operators can resume a threshold-paused execution and dispatch
  remaining hosts.
* Completed executions cannot dispatch further (existing 422 path).
* All-skipped executions still get a ``completed`` event and end
  in ``succeeded`` (no failures).
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Dict, List, Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    Package,
    PackageUpdate,
    PatchPolicy,
    System,
)
from app.services import (
    patch_execution_dispatch_service,
    patch_execution_service,
    patch_policy_service,
    patch_update_plan_service,
)
from app.services.patch_execution_dispatch_service import (
    AUDIT_EXECUTION_COMPLETED,
    AUDIT_EXECUTION_PAUSED,
    AUDIT_EXECUTION_WAVE_COMPLETED,
    PAUSE_REASON_THRESHOLD_EXCEEDED,
    DispatchResult,
    dispatch_next_batch,
)
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_FAILED,
    EXECUTION_HOST_STATE_PENDING,
    EXECUTION_HOST_STATE_SUCCEEDED,
    EXECUTION_STATE_FAILED,
    EXECUTION_STATE_PAUSED,
    EXECUTION_STATE_RUNNING,
    EXECUTION_STATE_SUCCEEDED,
    PatchUpdateExecutionError,
)

# ---------------------------------------------------------------------------
# Fixtures (parallel to Slice 2 patterns)
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="comp-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="comp-test-cred",
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
            hostname=f"comp-host-{counter['n']}.example.com",
            ip_address=f"10.0.93.{counter['n']}",
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
    failure_threshold_percent: Optional[int] = None,
):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
        requires_approval=False,
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _add_installed(db, system: System, name: str, version: str):
    p = Package(
        system_id=system.id, name=name, installed_version=version, package_type="apt"
    )
    db.add(p)
    db.flush()
    return p


def _add_update(db, system: System, package, available_version: str):
    upd = PackageUpdate(
        package_id=package.id,
        system_id=system.id,
        available_version=available_version,
        update_type="security",
        discovered_on=datetime.utcnow(),
    )
    db.add(upd)
    db.flush()
    return upd


def _seed_host_with_update(
    db, host_factory, suffix: str, *, package_manager: str = "apt"
) -> System:
    h = host_factory()
    p = _add_installed(db, h, f"pkg-{suffix}", "1.0")
    _add_update(db, h, p, "1.1")
    db.add(
        HostFacts(
            system_id=h.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="ssh",
            package_manager=package_manager,
            distro_id_facts="ubuntu" if package_manager == "apt" else "rhel",
        )
    )
    db.flush()
    return h


def _start(
    db,
    admin_user,
    hosts: List[System],
    policy: PatchPolicy,
    *,
    max_parallel: int = 5,
    failure_threshold_percent: Optional[int] = None,
):
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=policy.id,
        name=f"plan-{policy.slug}",
        target_system_ids=[h.id for h in hosts],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    return patch_execution_service.start_execution(
        db,
        plan_id=plan.id,
        actor_user_id=admin_user.id,
        max_parallel_per_wave=max_parallel,
        failure_threshold_percent=failure_threshold_percent,
    )


def _ok_callable() -> Callable:
    def _impl(system, cmd):
        return DispatchResult(exit_code=0, transport_name="fake")

    return _impl


def _fail_callable() -> Callable:
    def _impl(system, cmd):
        return DispatchResult(exit_code=100, stderr="fail", transport_name="fake")

    return _impl


def _alternating_callable(fail_first: int = 1):
    """Returns ``DispatchResult(exit=100)`` for the first ``fail_first``
    calls then exit=0 thereafter. Useful for threshold tests."""
    state = {"n": 0}

    def _impl(system, cmd):
        state["n"] += 1
        if state["n"] <= fail_first:
            return DispatchResult(exit_code=100, stderr="x", transport_name="fake")
        return DispatchResult(exit_code=0, transport_name="fake")

    return _impl


def _capture_audit(monkeypatch) -> List[dict]:
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_execution_dispatch_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    return captured


# ---------------------------------------------------------------------------
# Wave completion
# ---------------------------------------------------------------------------


def test_wave_completed_emitted_once_when_wave_drains(
    db, admin_user, host_factory, monkeypatch
):
    captured = _capture_audit(monkeypatch)
    pol = _make_policy(db, admin_user, "comp-wave-once")
    h_a = _seed_host_with_update(db, host_factory, "a")
    h_b = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    execution = _start(db, admin_user, [h_a, h_b], pol, max_parallel=2)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    # Slice 3: the only wave drained → wave_completed + completed
    # both fired in this batch.
    assert summary.completed_wave_indexes == [0]
    assert summary.finalized_state == EXECUTION_STATE_SUCCEEDED

    actions = [c["action"] for c in captured]
    assert actions.count(AUDIT_EXECUTION_WAVE_COMPLETED) == 1
    assert actions.count(AUDIT_EXECUTION_COMPLETED) == 1


def test_wave_completed_idempotent_across_calls(
    db, admin_user, host_factory, monkeypatch
):
    """Once a wave is marked complete, subsequent dispatch calls must
    not re-emit ``wave_completed`` for that wave."""
    captured = _capture_audit(monkeypatch)
    pol = _make_policy(db, admin_user, "comp-wave-idem")
    h_a = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h_a)
    # Add a second host that is intentionally an "all-skipped" host
    # in a *higher* wave (won't materialize as a separate wave with
    # immediate cadence; we'll rely on the single-wave drain instead).
    execution = _start(db, admin_user, [h_a], pol)

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    # Execution is now succeeded; further dispatch calls refuse 422.
    with pytest.raises(PatchUpdateExecutionError):
        dispatch_next_batch(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            dispatch_callable=_ok_callable(),
        )
    # Audit emitted exactly once each.
    actions = [c["action"] for c in captured]
    assert actions.count(AUDIT_EXECUTION_WAVE_COMPLETED) == 1
    assert actions.count(AUDIT_EXECUTION_COMPLETED) == 1


def test_wave_completed_recorded_for_all_skipped_wave(
    db, admin_user, host_factory, monkeypatch
):
    """An execution whose only host is skipped at materialization
    (no preflight family / no selected packages) still gets a
    ``wave_completed`` for the synthetic wave, and the execution
    finalizes to ``succeeded`` (no failures). The first dispatch
    call (which sees no_pending immediately) runs the
    reconciliation pass and emits both events."""
    captured = _capture_audit(monkeypatch)
    pol = _make_policy(db, admin_user, "comp-skip-wave")
    h = host_factory()  # no Package / PackageUpdate / HostFacts -> skipped
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    assert summary.no_pending is True
    assert summary.completed_wave_indexes == [0]
    assert summary.finalized_state == EXECUTION_STATE_SUCCEEDED

    actions = [c["action"] for c in captured]
    assert AUDIT_EXECUTION_WAVE_COMPLETED in actions
    assert AUDIT_EXECUTION_COMPLETED in actions
    # safe_emit session-boundary lock: no db= argument anywhere.
    for c in captured:
        assert "db" not in c


# ---------------------------------------------------------------------------
# Plan completion → succeeded vs failed
# ---------------------------------------------------------------------------


def test_execution_completes_succeeded_when_no_failures(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "comp-succ")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    assert summary.finalized_state == EXECUTION_STATE_SUCCEEDED

    refreshed = patch_execution_service.get_execution(db, execution.id)
    assert refreshed.state == EXECUTION_STATE_SUCCEEDED
    assert refreshed.completed_at is not None


def test_execution_completes_failed_when_any_host_failed(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "comp-fail")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fail_callable(),
    )
    assert summary.finalized_state == EXECUTION_STATE_FAILED

    refreshed = patch_execution_service.get_execution(db, execution.id)
    assert refreshed.state == EXECUTION_STATE_FAILED
    assert refreshed.completed_at is not None


def test_completed_execution_refuses_further_dispatch(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "comp-no-redispatch")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    with pytest.raises(PatchUpdateExecutionError):
        dispatch_next_batch(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            dispatch_callable=_ok_callable(),
        )


# ---------------------------------------------------------------------------
# Failure-threshold auto-pause
# ---------------------------------------------------------------------------


def test_threshold_zero_breaches_on_first_failure(
    db, admin_user, host_factory, monkeypatch
):
    """Threshold of 0 means any failure breaches. With two hosts and
    one failure, the first failed host should auto-pause; the second
    host stays pending."""
    captured = _capture_audit(monkeypatch)
    pol = _make_policy(db, admin_user, "comp-thr-0")
    h_a = _seed_host_with_update(db, host_factory, "a")
    h_b = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    execution = _start(
        db,
        admin_user,
        [h_a, h_b],
        pol,
        max_parallel=2,
        failure_threshold_percent=0,
    )

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_alternating_callable(fail_first=1),
    )
    assert summary.threshold_pause is not None
    assert summary.threshold_pause["code"] == PAUSE_REASON_THRESHOLD_EXCEEDED
    assert summary.threshold_pause["failed_terminal_hosts"] == 1
    # Refresh execution: state == paused, pause_reason set.
    refreshed = patch_execution_service.get_execution(db, execution.id)
    assert refreshed.state == EXECUTION_STATE_PAUSED
    assert refreshed.pause_reason == PAUSE_REASON_THRESHOLD_EXCEEDED
    # progress_summary carries the breach context.
    assert (
        refreshed.progress_summary.get("threshold_pause", {}).get("code")
        == PAUSE_REASON_THRESHOLD_EXCEEDED
    )

    # Second host stayed pending.
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    pending_count = sum(1 for h in hosts if h.state == EXECUTION_HOST_STATE_PENDING)
    assert pending_count == 1

    # Audit: paused emitted for the threshold breach (exactly once).
    actions = [c["action"] for c in captured]
    assert actions.count(AUDIT_EXECUTION_PAUSED) == 1
    # Plan-completion event NOT emitted because we're not done.
    assert AUDIT_EXECUTION_COMPLETED not in actions


def test_threshold_null_never_auto_pauses(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "comp-thr-null")
    h_a = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h_a)
    execution = _start(
        db,
        admin_user,
        [h_a],
        pol,
        failure_threshold_percent=None,
    )

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fail_callable(),
    )
    # No auto-pause, but the only host failed → execution finalizes
    # to ``failed``.
    assert summary.threshold_pause is None
    assert summary.finalized_state == EXECUTION_STATE_FAILED


def test_threshold_50_does_not_breach_at_exactly_50(db, admin_user, host_factory):
    """Threshold semantics: breach when failure_pct > threshold (strict
    greater-than). With 2 hosts where the SECOND fails, after host 1
    the rate is 0% (not a breach), and after host 2 the rate is 50%
    which is exactly the threshold (NOT a breach for ``>``). Both
    hosts complete and the execution finalizes ``failed``."""
    state = {"n": 0}

    def first_succeed_then_fail(system, cmd):
        state["n"] += 1
        if state["n"] == 1:
            return DispatchResult(exit_code=0, transport_name="fake")
        return DispatchResult(exit_code=100, stderr="x", transport_name="fake")

    pol = _make_policy(db, admin_user, "comp-thr-eq")
    h_a = _seed_host_with_update(db, host_factory, "a")
    h_b = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    execution = _start(
        db,
        admin_user,
        [h_a, h_b],
        pol,
        max_parallel=2,
        failure_threshold_percent=50,
    )

    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=first_succeed_then_fail,
    )
    # No auto-pause; both hosts processed; execution finalizes failed.
    assert summary.threshold_pause is None
    assert summary.finalized_state == EXECUTION_STATE_FAILED


def test_threshold_breach_does_not_finalize_execution(db, admin_user, host_factory):
    """The mid-batch threshold pause leaves the execution in ``paused``,
    not in any terminal state. ``completed_at`` must remain None."""
    pol = _make_policy(db, admin_user, "comp-thr-noterm")
    h_a = _seed_host_with_update(db, host_factory, "a")
    h_b = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    execution = _start(
        db,
        admin_user,
        [h_a, h_b],
        pol,
        max_parallel=2,
        failure_threshold_percent=0,
    )

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_alternating_callable(fail_first=1),
    )
    refreshed = patch_execution_service.get_execution(db, execution.id)
    assert refreshed.state == EXECUTION_STATE_PAUSED
    assert refreshed.completed_at is None


def test_resume_after_threshold_pause_can_dispatch_remaining(
    db, admin_user, host_factory
):
    """Operator resume + dispatch-next should drain the remaining
    pending host. The remaining host succeeding then finalizes the
    execution to ``failed`` (one earlier failure)."""
    pol = _make_policy(db, admin_user, "comp-thr-resume")
    h_a = _seed_host_with_update(db, host_factory, "a")
    h_b = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    execution = _start(
        db,
        admin_user,
        [h_a, h_b],
        pol,
        max_parallel=2,
        failure_threshold_percent=0,
    )
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_alternating_callable(fail_first=1),
    )
    # Operator resume (Slice 1 metadata-only transition).
    patch_execution_service.resume_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    # Now dispatch the remaining pending host with a success callable.
    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    # 1-of-2 failures = 50% > 0% threshold → re-pauses immediately
    # after the second host finishes IF the second host failed. Here
    # the second host succeeds, so the failure rate is now still
    # 50% (1 fail / 2 terminal) but every host is terminal so the
    # finalization fires instead of re-pause.
    assert summary.finalized_state == EXECUTION_STATE_FAILED
    refreshed = patch_execution_service.get_execution(db, execution.id)
    assert refreshed.state == EXECUTION_STATE_FAILED


# ---------------------------------------------------------------------------
# Slice 4: cancel-triggered wave-completion reconciliation
# ---------------------------------------------------------------------------


def test_cancel_emits_wave_completed_for_newly_terminal_wave(
    db, admin_user, host_factory, monkeypatch
):
    """When cancel flips a still-``pending`` host to ``canceled`` and
    that flip causes its wave to become fully terminal, the cancel
    path must run the Slice 3 wave-completion reconciliation and
    emit ``patch_update_execution.wave_completed`` for that wave."""
    captured: List[dict] = []
    # Patch BOTH safe_emit references — cancel emits its own
    # ``canceled`` event via patch_execution_service.safe_emit while
    # the reconciliation helper emits ``wave_completed`` via
    # patch_execution_dispatch_service.safe_emit.
    monkeypatch.setattr(
        patch_execution_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    monkeypatch.setattr(
        patch_execution_dispatch_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )

    pol = _make_policy(db, admin_user, "comp-cancel-recon")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    # Do not dispatch — leave the host in ``pending``. The cancel
    # path will flip it to ``canceled`` and the reconciliation
    # helper will see that wave as fully terminal.
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id
    )

    actions = [c["action"] for c in captured]
    assert AUDIT_EXECUTION_WAVE_COMPLETED in actions
    # safe_emit session-boundary lock: no db= argument anywhere.
    for c in captured:
        assert "db" not in c

    refreshed = patch_execution_service.get_execution(db, execution.id)
    assert refreshed.state == "canceled"
    # Reconciliation persisted the completed wave index.
    assert 0 in (refreshed.progress_summary.get("completed_wave_indexes") or [])


def test_cancel_does_not_duplicate_already_recorded_wave_completed(
    db, admin_user, host_factory, monkeypatch
):
    """If a wave was already recorded as completed (because it drained
    via the shared ``completed_wave_indexes`` idempotency marker), a
    subsequent cancel of the execution must NOT re-emit
    ``wave_completed`` for that wave."""
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_execution_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    monkeypatch.setattr(
        patch_execution_dispatch_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )

    pol = _make_policy(db, admin_user, "comp-cancel-noredup")
    h_a = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h_a)
    execution = _start(db, admin_user, [h_a], pol)
    execution.progress_summary = {
        **(execution.progress_summary or {}),
        "completed_wave_indexes": [0],
    }
    db.commit()
    db.refresh(execution)
    captured.clear()  # Drop start-time emits; only count cancel emits.

    # Cancel: the pending host flips to canceled, which makes wave 0
    # fully terminal. Because wave 0 was already recorded in
    # completed_wave_indexes, the shared reconciliation helper must
    # skip it and emit no duplicate wave_completed event.
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    cancel_emit_actions = [c["action"] for c in captured]
    assert cancel_emit_actions.count(AUDIT_EXECUTION_WAVE_COMPLETED) == 0
    assert "patch_update_execution.canceled" in cancel_emit_actions

    refreshed = patch_execution_service.get_execution(db, execution.id)
    assert refreshed.progress_summary.get("completed_wave_indexes") == [0]


def test_cancel_does_not_emit_execution_completed(
    db, admin_user, host_factory, monkeypatch
):
    """Slice 4 contract: cancel is its own terminal event. The Slice 3
    ``patch_update_execution.completed`` event must NOT fire from
    the cancel path even if the cancel flips every host to a
    terminal state."""
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_execution_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    monkeypatch.setattr(
        patch_execution_dispatch_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )

    pol = _make_policy(db, admin_user, "comp-cancel-no-complete")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    actions = [c["action"] for c in captured]
    assert AUDIT_EXECUTION_COMPLETED not in actions

    refreshed = patch_execution_service.get_execution(db, execution.id)
    # State remains canceled (Slice 1's contract); finalize did NOT run.
    assert refreshed.state == "canceled"


def test_cancel_does_not_re_emit_for_pure_pending_execution(
    db, admin_user, host_factory, monkeypatch
):
    """A never-dispatched all-pending execution should record
    ``wave_completed`` exactly once when cancel flips the only wave
    to terminal."""
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_execution_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    monkeypatch.setattr(
        patch_execution_dispatch_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )

    pol = _make_policy(db, admin_user, "comp-cancel-pure-pending")
    h_a = _seed_host_with_update(db, host_factory, "a")
    h_b = _seed_host_with_update(db, host_factory, "b")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    execution = _start(db, admin_user, [h_a, h_b], pol, max_parallel=2)
    # Cancel without any dispatch.
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id
    )
    actions = [c["action"] for c in captured]
    # Exactly one wave_completed for the only wave.
    assert actions.count(AUDIT_EXECUTION_WAVE_COMPLETED) == 1
    # Cancel emits its own canceled event.
    assert "patch_update_execution.canceled" in actions
