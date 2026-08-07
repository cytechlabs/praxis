"""PRA-172 slice 3 — reboot transport + dispatch primitive tests.

Covers:

* ``dispatch_due_reboots`` walks scheduled rows due now and
  transitions them via the exit-signal vocabulary.
* Success signals (``exit_zero`` / ``connection_lost_clean``)
  flip the row to ``rebooting``; failure signals
  (``non_zero`` / ``timeout`` / ``transport_error`` /
  ``transport_unavailable``) flip to ``failed`` directly.
* Not-due rows (``scheduled_for_at > now``) stay ``scheduled``.
* Re-dispatch is idempotent: rows already in ``rebooting`` /
  terminal reboot states / ``not_required`` / ``skipped`` are
  never re-dispatched.
* The reboot-wave failure threshold auto-pauses dispatch with
  structured pause context; remaining due rows stay ``scheduled``.
* The new audit events (``patch_update_execution_reboot.started``
  / ``.dispatch_failed``) emit via ``safe_emit`` no ``db=``
  (session-boundary lock).
* Dispatch ``started_at`` / ``completed_at`` are persisted as
  naive UTC; the route layer formats them as ``...Z`` ISO.
* Refuses non-terminal executions with the standard
  ``PatchUpdateRebootError`` shape.

No test issues a real reboot command — they all pass a fake
``RebootDispatchCallable``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Callable, List, Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    MaintenanceWindow,
    Package,
    PackageUpdate,
    PatchPolicy,
    PatchUpdateExecutionReboot,
    System,
)
from app.services import (
    patch_execution_service,
    patch_policy_service,
    patch_reboot_dispatch_service,
    patch_reboot_service,
    patch_update_plan_service,
)
from app.services.patch_reboot_dispatch_service import (
    AUDIT_REBOOT_DISPATCH_FAILED,
    AUDIT_REBOOT_STARTED,
    EXIT_SIGNAL_CONNECTION_LOST_CLEAN,
    EXIT_SIGNAL_EXIT_ZERO,
    EXIT_SIGNAL_NON_ZERO,
    EXIT_SIGNAL_TIMEOUT,
    EXIT_SIGNAL_TRANSPORT_ERROR,
    EXIT_SIGNAL_TRANSPORT_UNAVAILABLE,
    PAUSE_REASON_REBOOT_THRESHOLD_EXCEEDED,
    TRANSPORT_KIND_SSH,
    RebootDispatchResult,
    dispatch_due_reboots,
)
from app.services.patch_reboot_service import (
    REBOOT_STATE_FAILED,
    REBOOT_STATE_REBOOTING,
    REBOOT_STATE_SCHEDULED,
    REBOOT_STATE_SKIPPED,
    PatchUpdateRebootError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rb3-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rb3-test-cred",
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
            hostname=f"rb3-host-{counter['n']}.example.com",
            ip_address=f"10.0.97.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        db.add(
            HostFacts(
                system_id=s.id,
                schema_version=1,
                collected_at=datetime.utcnow(),
                source_transport="ssh",
                package_manager="apt",
                distro_id_facts="ubuntu",
                reboot_required=reboot_required,
            )
        )
        db.flush()
        return s

    return make


def _make_window(db, admin_user, *, name: str, enabled: bool = True, schedule=None):
    sched = schedule or {
        "day_of_week": [0, 1, 2, 3, 4, 5, 6],
        "start_time": "00:00",
        "end_time": "06:00",
    }
    win = MaintenanceWindow(
        name=name,
        target_type="all",
        target_id=None,
        schedule=json.dumps(sched),
        enabled=enabled,
        created_by=admin_user.id,
    )
    db.add(win)
    db.flush()
    return win


def _make_policy(
    db,
    admin_user,
    slug: str,
    *,
    reboot_policy: str = "always",
    reboot_window_id: Optional[int] = None,
    failure_threshold_percent: Optional[int] = None,
):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
        reboot_policy=reboot_policy,
        reboot_window_id=reboot_window_id,
        requires_approval=False,
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _seed_host_with_update(db, host_factory, suffix: str, **kwargs) -> System:
    h = host_factory(**kwargs)
    p = Package(
        system_id=h.id,
        name=f"pkg-{suffix}",
        installed_version="1.0",
        package_type="apt",
    )
    db.add(p)
    db.flush()
    db.add(
        PackageUpdate(
            package_id=p.id,
            system_id=h.id,
            available_version="1.1",
            update_type="security",
            discovered_on=datetime.utcnow(),
        )
    )
    db.flush()
    return h


def _setup_scheduled_row(
    db,
    admin_user,
    host_factory,
    suffix: str,
    *,
    reboot_window_id: Optional[int] = None,
    scheduled_for_offset_seconds: int = -60,
    failure_threshold_percent: Optional[int] = None,
) -> tuple:
    """Build an execution + canceled-then-reboot-row helper so each
    test can start from a single ``scheduled`` row. Returns
    ``(execution, row)``."""
    pol = _make_policy(
        db,
        admin_user,
        f"rb3-{suffix}",
        reboot_policy="always",
        reboot_window_id=reboot_window_id,
    )
    h = _seed_host_with_update(db, host_factory, suffix)
    _bind(db, admin_user, pol, h)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name=f"plan-rb3-{suffix}",
        target_system_ids=[h.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db,
        plan_id=plan.id,
        actor_user_id=admin_user.id,
        max_parallel_per_wave=5,
        failure_threshold_percent=failure_threshold_percent,
    )
    # Cancel produces a row via auto-reconcile (skipped). We
    # mutate it into ``scheduled`` with the desired
    # ``scheduled_for_at`` so the test can exercise dispatch.
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .one()
    )
    row.state = REBOOT_STATE_SCHEDULED
    row.scheduled_for_at = datetime.utcnow() + timedelta(
        seconds=scheduled_for_offset_seconds
    )
    db.commit()
    return execution, row


def _fake_dispatch(signal: str, *, exit_code: Optional[int] = None) -> Callable:
    def _impl(system, cmd):
        return RebootDispatchResult(
            exit_signal_kind=signal,
            exit_code=exit_code,
            transport_name="fake-ssh",
        )

    return _impl


def _capture_audit(monkeypatch) -> List[dict]:
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_reboot_dispatch_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    return captured


# ---------------------------------------------------------------------------
# Refusal gate
# ---------------------------------------------------------------------------


def test_dispatch_due_refuses_non_terminal_execution(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rb3-running")
    h = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p",
        target_system_ids=[h.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    # Still running.
    with pytest.raises(PatchUpdateRebootError):
        dispatch_due_reboots(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
        )


def test_dispatch_due_refuses_unknown_execution(db, admin_user):
    with pytest.raises(PatchUpdateRebootError) as exc_info:
        dispatch_due_reboots(
            db,
            execution_id=987_654,
            actor_user_id=admin_user.id,
            dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
        )
    assert "not found" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Success signals
# ---------------------------------------------------------------------------


def test_exit_zero_transitions_row_to_rebooting(
    db, admin_user, host_factory, monkeypatch
):
    captured = _capture_audit(monkeypatch)
    execution, row = _setup_scheduled_row(db, admin_user, host_factory, "exit-zero")

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_REBOOTING
    assert row.exit_signal_kind == EXIT_SIGNAL_EXIT_ZERO
    assert row.transport_kind == TRANSPORT_KIND_SSH
    # PRA-175: DEFAULT_REBOOT_COMMAND no longer hardcodes ``sudo``;
    # the planned argv is now ``systemctl reboot`` and privilege
    # escalation is applied at dispatch time per
    # ``credential.sudo_method`` (this fixture's credential defaults
    # to ``sudo_method=none``).
    assert row.command_snapshot == "systemctl reboot"
    assert row.started_at is not None
    assert row.completed_at is None  # rebooting is not terminal
    assert summary.succeeded_count == 1
    assert summary.failed_count == 0
    actions = [c["action"] for c in captured]
    assert AUDIT_REBOOT_STARTED in actions
    # safe_emit session-boundary lock: no db= argument anywhere.
    for c in captured:
        assert "db" not in c


def test_connection_lost_clean_transitions_row_to_rebooting(
    db, admin_user, host_factory, monkeypatch
):
    captured = _capture_audit(monkeypatch)
    execution, row = _setup_scheduled_row(db, admin_user, host_factory, "clean-loss")

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_CONNECTION_LOST_CLEAN),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_REBOOTING
    assert row.exit_signal_kind == EXIT_SIGNAL_CONNECTION_LOST_CLEAN
    assert row.exit_signal_kind in {
        EXIT_SIGNAL_EXIT_ZERO,
        EXIT_SIGNAL_CONNECTION_LOST_CLEAN,
    }
    assert summary.succeeded_count == 1
    actions = [c["action"] for c in captured]
    assert AUDIT_REBOOT_STARTED in actions


# ---------------------------------------------------------------------------
# Failure signals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "signal",
    [
        EXIT_SIGNAL_NON_ZERO,
        EXIT_SIGNAL_TIMEOUT,
        EXIT_SIGNAL_TRANSPORT_ERROR,
        EXIT_SIGNAL_TRANSPORT_UNAVAILABLE,
    ],
)
def test_failure_signals_transition_row_to_failed(
    db, admin_user, host_factory, monkeypatch, signal
):
    captured = _capture_audit(monkeypatch)
    execution, row = _setup_scheduled_row(
        db, admin_user, host_factory, f"fail-{signal}"
    )

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(signal, exit_code=100),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.exit_signal_kind == signal
    assert row.completed_at is not None
    assert summary.failed_count == 1
    actions = [c["action"] for c in captured]
    assert AUDIT_REBOOT_DISPATCH_FAILED in actions


# ---------------------------------------------------------------------------
# Due / not-due filtering
# ---------------------------------------------------------------------------


def test_not_due_rows_are_not_dispatched(db, admin_user, host_factory):
    execution, row = _setup_scheduled_row(
        db,
        admin_user,
        host_factory,
        "not-due",
        scheduled_for_offset_seconds=3600,  # 1h in the future
    )
    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_SCHEDULED
    assert summary.no_due is True
    assert summary.not_due_count == 1
    assert summary.dispatched_count == 0


# ---------------------------------------------------------------------------
# Idempotent re-dispatch
# ---------------------------------------------------------------------------


def test_rebooting_row_is_not_re_dispatched(db, admin_user, host_factory):
    """Once a row is in ``rebooting``, a subsequent dispatch-due
    call must NOT re-dispatch it: the dispatch filter is strictly
    ``state == scheduled AND scheduled_for_at <= now``."""
    execution, row = _setup_scheduled_row(db, admin_user, host_factory, "redisp")

    dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_REBOOTING
    first_started_at = row.started_at

    second = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
    )
    db.refresh(row)
    # No change — row stays rebooting with the original started_at.
    assert row.state == REBOOT_STATE_REBOOTING
    assert row.started_at == first_started_at
    assert second.no_due is True
    assert second.dispatched_count == 0


def test_skipped_row_is_never_dispatched(db, admin_user, host_factory):
    """``skipped`` (and ``not_required``) rows must never reach the
    dispatcher even when ``scheduled_for_at`` would otherwise be due."""
    execution, row = _setup_scheduled_row(db, admin_user, host_factory, "skipped")
    row.state = REBOOT_STATE_SKIPPED
    db.commit()

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_SKIPPED
    assert summary.no_due is True


# ---------------------------------------------------------------------------
# Threshold pause
# ---------------------------------------------------------------------------


def test_threshold_pause_stops_dispatch_mid_batch(
    db, admin_user, host_factory, monkeypatch
):
    """Failing every dispatch with a threshold of 0% should stop
    the batch after the first failure, leaving the remaining due
    rows in ``scheduled`` state."""
    # Build a policy with two hosts, two scheduled rows, threshold 0%.
    pol = _make_policy(db, admin_user, "rb3-thresh-pause")
    h_a = _seed_host_with_update(db, host_factory, "ta")
    h_b = _seed_host_with_update(db, host_factory, "tb")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-rb3-thresh",
        target_system_ids=[h_a.id, h_b.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db,
        plan_id=plan.id,
        actor_user_id=admin_user.id,
        max_parallel_per_wave=5,
        failure_threshold_percent=0,
    )
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    rows = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .order_by(PatchUpdateExecutionReboot.id.asc())
        .all()
    )
    assert len(rows) == 2
    past = datetime.utcnow() - timedelta(seconds=60)
    for r in rows:
        r.state = REBOOT_STATE_SCHEDULED
        r.scheduled_for_at = past
    db.commit()

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_NON_ZERO, exit_code=100),
    )

    # First failure breaches threshold=0 (>0% failure). Second row
    # stays scheduled.
    assert summary.dispatched_count == 1
    assert summary.failed_count == 1
    assert summary.pause_reason == PAUSE_REASON_REBOOT_THRESHOLD_EXCEEDED
    assert summary.threshold_pause is not None
    assert summary.threshold_pause["failure_threshold_percent"] == 0
    assert summary.threshold_pause["failed_count"] == 1

    states = {r.id: r.state for r in rows}
    db.refresh(rows[0])
    db.refresh(rows[1])
    by_state = sorted([rows[0].state, rows[1].state])
    assert by_state == [REBOOT_STATE_FAILED, REBOOT_STATE_SCHEDULED]


def test_no_threshold_means_all_due_rows_dispatch(db, admin_user, host_factory):
    """When ``failure_threshold_percent`` is null, every failure is
    tolerated and the batch runs through every due row."""
    pol = _make_policy(db, admin_user, "rb3-no-thresh")
    h_a = _seed_host_with_update(db, host_factory, "na")
    h_b = _seed_host_with_update(db, host_factory, "nb")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-rb3-no-thresh",
        target_system_ids=[h_a.id, h_b.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db,
        plan_id=plan.id,
        actor_user_id=admin_user.id,
        max_parallel_per_wave=5,
        failure_threshold_percent=None,
    )
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    rows = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .all()
    )
    past = datetime.utcnow() - timedelta(seconds=60)
    for r in rows:
        r.state = REBOOT_STATE_SCHEDULED
        r.scheduled_for_at = past
    db.commit()

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_NON_ZERO, exit_code=100),
    )
    assert summary.dispatched_count == 2
    assert summary.failed_count == 2
    assert summary.pause_reason is None
    assert summary.threshold_pause is None


# ---------------------------------------------------------------------------
# Dispatch details persistence
# ---------------------------------------------------------------------------


def test_dispatch_details_records_structured_outcome(db, admin_user, host_factory):
    execution, row = _setup_scheduled_row(db, admin_user, host_factory, "details")

    dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
    )
    db.refresh(row)
    details = row.dispatch_details
    assert isinstance(details, dict)
    assert details["exit_code"] == 0
    assert details["transport_name"] == "fake-ssh"
    assert details["dispatched_at"].endswith("Z")


# ---------------------------------------------------------------------------
# Best-effort: missing system
# ---------------------------------------------------------------------------


def test_deleted_system_produces_transport_unavailable_failure(
    db, admin_user, host_factory
):
    """A row whose ``system_id_snapshot`` no longer resolves to a
    System produces a structured ``transport_unavailable`` failure
    (not a crash) and transitions to ``failed``."""
    execution, row = _setup_scheduled_row(db, admin_user, host_factory, "deleted")
    # Null out the system reference + system row.
    sys_id = row.system_id_snapshot
    target = db.query(System).filter(System.id == sys_id).one()
    db.delete(target)
    db.commit()

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        # dispatch_callable is irrelevant here — the system isn't found
        # so the transport call is skipped.
        dispatch_callable=_fake_dispatch(EXIT_SIGNAL_EXIT_ZERO, exit_code=0),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.exit_signal_kind == EXIT_SIGNAL_TRANSPORT_UNAVAILABLE
    assert summary.failed_count == 1


# ---------------------------------------------------------------------------
# Dispatcher raises — coerced to transport_error
# ---------------------------------------------------------------------------


def test_dispatcher_exception_is_coerced_to_transport_error(
    db, admin_user, host_factory
):
    """An unexpected exception inside the ``dispatch_callable`` is
    caught and recorded as a structured ``transport_error`` failure
    so the row never lands in an inconsistent state."""
    execution, row = _setup_scheduled_row(db, admin_user, host_factory, "boom")

    def _boom(system, cmd):
        raise RuntimeError("transport blew up")

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_boom,
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.exit_signal_kind == EXIT_SIGNAL_TRANSPORT_ERROR
    assert summary.failed_count == 1


# ---------------------------------------------------------------------------
# P1 regressions (Slice 3a)
# ---------------------------------------------------------------------------


def test_default_reboot_dispatch_uses_ssh_transport_directly(
    db, admin_user, host_factory, monkeypatch
):
    """SSH-only enforcement: ``default_reboot_dispatch`` must bind
    directly to :class:`SSHTransport`, never route through the
    generic ``get_transport`` factory (which can select
    :class:`AgentTransport` for ``transport_preference=agent`` or
    ``auto``-with-healthy-tunnel)."""
    from app.services import patch_reboot_dispatch_service as _mod
    from app.services.transport import ssh as _ssh_mod

    # Build a system whose transport_preference would prefer the
    # agent path through the generic factory.
    h = host_factory()
    h.transport_preference = "agent"
    db.commit()

    # Trip-wire: get_transport must NOT be called from the reboot
    # default dispatcher.
    called = {"get_transport": False}

    def _no_factory(*args, **kwargs):
        called["get_transport"] = True
        raise AssertionError(
            "default_reboot_dispatch must not call generic get_transport"
        )

    monkeypatch.setattr("app.services.transport.get_transport", _no_factory)
    monkeypatch.setattr("app.services.transport.factory.get_transport", _no_factory)

    # Stub SSHService so we never need a real paramiko connection.
    class _FakeSSHService:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_connection(self, system_id):
            return ("fake-client", False)

        def close_all_connections(self):
            return None

    monkeypatch.setattr(_mod, "SSHService", _FakeSSHService, raising=False)
    # patch_reboot_dispatch_service imports SSHService lazily inside
    # default_reboot_dispatch, so monkeypatch the source module too.
    monkeypatch.setattr("app.services.ssh_service.SSHService", _FakeSSHService)

    # Stub SSHTransport.run_command so we don't actually exec.
    async def _fake_run_command(self, cmd, *, stdin=None, timeout_seconds=None):
        from app.services.transport.base import CommandResult

        return CommandResult(exit_code=0, stdout=b"", stderr=b"", duration_ms=10)

    monkeypatch.setattr(_ssh_mod.SSHTransport, "run_command", _fake_run_command)

    result = _mod.default_reboot_dispatch(db, h, list(_mod.DEFAULT_REBOOT_COMMAND))
    assert called["get_transport"] is False
    assert result.exit_signal_kind == EXIT_SIGNAL_EXIT_ZERO
    assert result.transport_name == "ssh"


def test_concurrent_dispatch_claims_each_row_only_once(db, admin_user, host_factory):
    """Atomic claim: two back-to-back ``dispatch_due_reboots`` calls
    over the same ``scheduled`` row must dispatch at most ONCE in
    total. Simulates the concurrent dispatcher race by issuing the
    second call from inside the first call's ``dispatch_callable``
    — exactly the window where the row is loaded
    but not yet claimed."""
    execution, row = _setup_scheduled_row(db, admin_user, host_factory, "claim")

    call_count = {"n": 0}

    def _double_dispatcher(system, cmd):
        # Simulate a concurrent worker arriving mid-dispatch by
        # invoking another full dispatch_due_reboots from inside
        # the dispatch callable. The atomic claim must already
        # have flipped this row to ``rebooting`` before this point,
        # so the concurrent call sees zero due rows and skips.
        call_count["n"] += 1
        nested = dispatch_due_reboots(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            dispatch_callable=_double_dispatcher,
        )
        assert (
            nested.dispatched_count == 0
        ), "concurrent dispatch must skip already-claimed rows"
        return RebootDispatchResult(
            exit_signal_kind=EXIT_SIGNAL_EXIT_ZERO,
            exit_code=0,
            transport_name="fake-ssh",
        )

    summary = dispatch_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_double_dispatcher,
    )

    assert summary.dispatched_count == 1
    assert summary.succeeded_count == 1
    assert call_count["n"] == 1, "transport must run exactly once"
    db.refresh(row)
    assert row.state == REBOOT_STATE_REBOOTING


def test_transport_error_maps_to_transport_error_failure(db, admin_user, host_factory):
    """The default SSH dispatcher must NOT treat a generic
    ``TransportError`` from ``run_command`` as the
    ``connection_lost_clean`` success signal. The current SSH
    transport can't distinguish pre-acceptance failures from
    post-acceptance connection drops, so Slice 3 maps every
    ``TransportError`` to the structured ``transport_error``
    failure. The ``connection_lost_clean`` enum value remains
    available for a future transport refinement (and for test
    fakes), but the production code path never reaches it from
    a generic transport error.

    This test exercises the real default_reboot_dispatch by
    stubbing the SSH layer so ``run_command`` raises
    ``TransportError``; the result must be the failure mapping,
    not the success mapping.
    """
    from app.services import patch_reboot_dispatch_service as _mod
    from app.services.transport import ssh as _ssh_mod
    from app.services.transport.base import TransportError

    h = host_factory()

    class _FakeSSHService:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_connection(self, system_id):
            return ("fake-client", False)

        def close_all_connections(self):
            return None

    import unittest.mock as _mock

    async def _raise_transport_error(self, cmd, *, stdin=None, timeout_seconds=None):
        raise TransportError("ssh: exec failed: connection refused")

    # SSHService is imported lazily inside default_reboot_dispatch
    # via `from .ssh_service import SSHService`; patch the source
    # module so the lazy import picks up the fake.
    with _mock.patch(
        "app.services.ssh_service.SSHService", _FakeSSHService
    ), _mock.patch.object(_ssh_mod.SSHTransport, "run_command", _raise_transport_error):
        result = _mod.default_reboot_dispatch(db, h, list(_mod.DEFAULT_REBOOT_COMMAND))

    assert result.exit_signal_kind == EXIT_SIGNAL_TRANSPORT_ERROR
    assert result.error == "transport_error"
    assert result.exit_signal_kind != EXIT_SIGNAL_CONNECTION_LOST_CLEAN
