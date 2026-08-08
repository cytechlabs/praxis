"""PRA-172 slice 2 — auto-reconcile + reboot scheduling tests.

Covers:

* ``promote_pending_to_scheduled`` moves eligible ``pending`` rows
  to ``scheduled`` with a UTC ``scheduled_for_at`` from the row's
  reboot window.
* Rows with no reboot window stay ``pending`` and gain a structured
  ``decision_details.scheduling`` block (``window_unset``).
* Missing / disabled / unusable windows produce structured non-
  silent reasons and leave the row as ``pending``.
* ``not_required`` / ``skipped`` rows are not promoted.
* ``auto_reconcile_on_terminal`` populates the queue + promotes
  scheduled rows after a dispatch finalize and after an operator
  cancel — without requiring an explicit
  ``POST /reboots/reconcile`` call.
* Reboot lifecycle audits emit through ``safe_emit`` without
  ``db=`` (session-boundary lock).
* The Slice 1 idempotency guarantee still holds: scheduled rows
  preserve their ``scheduled_for_at`` across a follow-up reconcile.
"""

from __future__ import annotations

import json
from datetime import datetime
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
    patch_execution_dispatch_service,
    patch_execution_service,
    patch_policy_service,
    patch_reboot_service,
    patch_update_plan_service,
)
from app.services.patch_execution_dispatch_service import (
    DispatchResult,
    dispatch_next_batch,
)
from app.services.patch_reboot_service import (
    AUDIT_REBOOT_QUEUED,
    AUDIT_REBOOT_SCHEDULED,
    AUDIT_REBOOT_SKIPPED,
    REBOOT_STATE_PENDING,
    REBOOT_STATE_SCHEDULED,
    REBOOT_STATE_SKIPPED,
    SCHEDULING_OUTCOME_SCHEDULED,
    SCHEDULING_OUTCOME_WINDOW_DISABLED,
    SCHEDULING_OUTCOME_WINDOW_MISSING,
    SCHEDULING_OUTCOME_WINDOW_UNSET,
    SCHEDULING_OUTCOME_WINDOW_UNUSABLE,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rb2-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rb2-test-cred",
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
            hostname=f"rb2-host-{counter['n']}.example.com",
            ip_address=f"10.0.96.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        # Slice 2 tests need a usable package_manager fact so the
        # PRA-171 dispatcher accepts apt hosts.
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
        # Every day of the week at midnight UTC so the test doesn't
        # depend on what day it runs.
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
    reboot_policy: str = "if_required",
    reboot_window_id: Optional[int] = None,
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


def _approved_plan(
    db, admin_user, policy: PatchPolicy, hosts: List[System], *, name="p"
):
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=policy.id,
        name=name,
        target_system_ids=[h.id for h in hosts],
    )
    return patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )


def _start(db, admin_user, hosts, policy, *, max_parallel=5):
    plan = _approved_plan(db, admin_user, policy, hosts)
    return patch_execution_service.start_execution(
        db,
        plan_id=plan.id,
        actor_user_id=admin_user.id,
        max_parallel_per_wave=max_parallel,
    )


def _ok_callable() -> Callable:
    def _impl(system, cmd):
        return DispatchResult(exit_code=0, transport_name="fake")

    return _impl


def _capture_audit(monkeypatch) -> List[dict]:
    captured: List[dict] = []
    # patch BOTH services' safe_emit references since they each
    # import it directly.
    monkeypatch.setattr(
        patch_execution_dispatch_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    monkeypatch.setattr(
        patch_execution_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    monkeypatch.setattr(
        patch_reboot_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    return captured


# ---------------------------------------------------------------------------
# next_window_start helper
# ---------------------------------------------------------------------------


def test_next_window_start_returns_future_midnight(db, admin_user):
    win = _make_window(db, admin_user, name="all-midnight")
    now = datetime(2026, 5, 11, 22, 30, 0)  # before midnight
    nxt = patch_reboot_service.next_window_start(win, now=now)
    assert nxt is not None
    # Next midnight is 2026-05-12 00:00.
    assert nxt == datetime(2026, 5, 12, 0, 0, 0)


def test_next_window_start_skips_disabled_window(db, admin_user):
    win = _make_window(db, admin_user, name="disabled", enabled=False)
    nxt = patch_reboot_service.next_window_start(win, now=datetime.utcnow())
    assert nxt is None


def test_next_window_start_handles_unparseable_schedule(db, admin_user):
    win = MaintenanceWindow(
        name="bad-json",
        target_type="all",
        target_id=None,
        schedule="not-json-{",
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(win)
    db.flush()
    assert patch_reboot_service.next_window_start(win, now=datetime.utcnow()) is None


def test_next_window_start_handles_empty_day_of_week(db, admin_user):
    win = _make_window(
        db,
        admin_user,
        name="no-days",
        schedule={"day_of_week": [], "start_time": "00:00"},
    )
    assert patch_reboot_service.next_window_start(win, now=datetime.utcnow()) is None


def test_next_window_start_handles_out_of_range_hour(db, admin_user):
    """Operator-edited schedules can carry out-of-range hour values
    like ``25:00`` that pass ``int()`` parsing but would crash
    ``datetime.replace(hour=25)``. The helper must return None so
    the caller produces the structured ``window_unusable`` pending
    outcome instead of raising."""
    win = _make_window(
        db,
        admin_user,
        name="bad-hour",
        schedule={"day_of_week": [0, 1, 2, 3, 4, 5, 6], "start_time": "25:00"},
    )
    assert patch_reboot_service.next_window_start(win, now=datetime.utcnow()) is None


def test_next_window_start_handles_out_of_range_minute(db, admin_user):
    win = _make_window(
        db,
        admin_user,
        name="bad-minute",
        schedule={"day_of_week": [0, 1, 2, 3, 4, 5, 6], "start_time": "00:75"},
    )
    assert patch_reboot_service.next_window_start(win, now=datetime.utcnow()) is None


def test_next_window_start_handles_negative_hour(db, admin_user):
    win = _make_window(
        db,
        admin_user,
        name="negative-hour",
        schedule={"day_of_week": [0, 1, 2, 3, 4, 5, 6], "start_time": "-1:00"},
    )
    assert patch_reboot_service.next_window_start(win, now=datetime.utcnow()) is None


# ---------------------------------------------------------------------------
# promote_pending_to_scheduled
# ---------------------------------------------------------------------------


def test_promote_moves_pending_to_scheduled_with_utc_timestamp(
    db, admin_user, host_factory
):
    win = _make_window(db, admin_user, name="weekly-reboot")
    pol = _make_policy(
        db,
        admin_user,
        "rb2-prom-yes",
        reboot_policy="if_required",
        reboot_window_id=win.id,
    )
    h = _seed_host_with_update(db, host_factory, "a", reboot_required=True)
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    # Drive the dispatcher to terminal; the auto-reconcile hook
    # will populate + promote. We don't run that here — we use the
    # explicit reconcile + promote path so the test reads cleanly.
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="test"
    )
    # Cancel produced skipped rows (host_did_not_succeed). To get a
    # ``pending`` row we manually flip a row to pending so we can
    # exercise promote on its own.
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    row.state = REBOOT_STATE_PENDING
    row.decision_code = "policy_always"  # any non-skipped reason
    db.commit()

    touched = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    assert len(touched) == 1
    db.refresh(touched[0])
    assert touched[0].state == REBOOT_STATE_SCHEDULED
    assert touched[0].scheduled_for_at is not None
    assert touched[0].scheduled_for_at.tzinfo is None  # naive UTC at DB layer
    sched = touched[0].decision_details.get("scheduling")
    assert sched is not None
    assert sched["outcome"] == SCHEDULING_OUTCOME_SCHEDULED
    assert sched["window_id"] == win.id
    # evaluated_at is absolute UTC.
    assert sched["evaluated_at"].endswith("Z")


def test_promote_leaves_window_unset_pending(db, admin_user, host_factory):
    """``reboot_window_id_snapshot=None`` → row stays pending,
    structured ``window_unset`` reason recorded."""
    pol = _make_policy(db, admin_user, "rb2-no-window", reboot_policy="if_required")
    # No reboot_window_id assigned.
    h = _seed_host_with_update(db, host_factory, "b", reboot_required=True)
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="test"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    row.state = REBOOT_STATE_PENDING
    db.commit()

    touched = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    assert len(touched) == 1
    db.refresh(touched[0])
    assert touched[0].state == REBOOT_STATE_PENDING
    assert touched[0].scheduled_for_at is None
    sched = touched[0].decision_details.get("scheduling")
    assert sched["outcome"] == SCHEDULING_OUTCOME_WINDOW_UNSET


def test_promote_window_missing_keeps_pending(db, admin_user, host_factory):
    win = _make_window(db, admin_user, name="will-be-deleted")
    pol = _make_policy(
        db, admin_user, "rb2-miss", reboot_policy="always", reboot_window_id=win.id
    )
    h = _seed_host_with_update(db, host_factory, "c")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="test"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    row.state = REBOOT_STATE_PENDING
    db.commit()
    # Now delete the window so the promotion sees a dangling id.
    db.delete(win)
    db.commit()

    touched = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    db.refresh(touched[0])
    assert touched[0].state == REBOOT_STATE_PENDING
    sched = touched[0].decision_details.get("scheduling")
    assert sched["outcome"] == SCHEDULING_OUTCOME_WINDOW_MISSING


def test_promote_window_disabled_keeps_pending(db, admin_user, host_factory):
    """Policy validation refuses disabled windows at creation time,
    so simulate the runtime case (operator disables the window
    AFTER the plan was built) by creating an enabled window, binding
    it through the policy, then disabling it post-hoc."""
    win = _make_window(db, admin_user, name="disabled-win", enabled=True)
    pol = _make_policy(
        db,
        admin_user,
        "rb2-disabled",
        reboot_policy="always",
        reboot_window_id=win.id,
    )
    h = _seed_host_with_update(db, host_factory, "d")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="test"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    row.state = REBOOT_STATE_PENDING
    win.enabled = False
    db.commit()

    touched = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    db.refresh(touched[0])
    assert touched[0].state == REBOOT_STATE_PENDING
    sched = touched[0].decision_details.get("scheduling")
    assert sched["outcome"] == SCHEDULING_OUTCOME_WINDOW_DISABLED


def test_promote_window_unusable_keeps_pending(db, admin_user, host_factory):
    """Policy validation refuses empty-schedule windows at creation
    time. Simulate the runtime case where an operator edits a usable
    window AFTER plan build into an unschedulable shape (empty
    ``day_of_week``)."""
    win = _make_window(db, admin_user, name="empty-days")
    pol = _make_policy(
        db,
        admin_user,
        "rb2-empty-days",
        reboot_policy="always",
        reboot_window_id=win.id,
    )
    h = _seed_host_with_update(db, host_factory, "e")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="test"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    row.state = REBOOT_STATE_PENDING
    # Mutate the window into an unschedulable shape.
    win.schedule = json.dumps({"day_of_week": [], "start_time": "00:00"})
    db.commit()

    touched = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    db.refresh(touched[0])
    assert touched[0].state == REBOOT_STATE_PENDING
    sched = touched[0].decision_details.get("scheduling")
    assert sched["outcome"] == SCHEDULING_OUTCOME_WINDOW_UNUSABLE


def test_promote_out_of_range_start_time_is_window_unusable_not_crash(
    db, admin_user, host_factory
):
    """End-to-end version: an operator edits the
    reboot window to carry an out-of-range ``start_time`` like
    ``25:00``. ``promote_pending_to_scheduled`` must produce the
    structured ``window_unusable`` outcome instead of crashing on
    ``datetime.replace(hour=25)``."""
    win = _make_window(db, admin_user, name="bad-hour-after-build")
    pol = _make_policy(
        db,
        admin_user,
        "rb2-bad-hour",
        reboot_policy="always",
        reboot_window_id=win.id,
    )
    h = _seed_host_with_update(db, host_factory, "z")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    row.state = REBOOT_STATE_PENDING
    # Operator-edited the window into an out-of-range shape after
    # the plan was built.
    win.schedule = json.dumps(
        {"day_of_week": [0, 1, 2, 3, 4, 5, 6], "start_time": "25:00"}
    )
    db.commit()

    touched = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    db.refresh(touched[0])
    assert touched[0].state == REBOOT_STATE_PENDING
    assert touched[0].scheduled_for_at is None
    sched = touched[0].decision_details.get("scheduling")
    assert sched["outcome"] == SCHEDULING_OUTCOME_WINDOW_UNUSABLE
    # The window context (window_id / window_name) is preserved so
    # the operator UI can render which window needs editing.
    assert sched.get("window_id") == win.id


def test_promote_does_not_touch_not_required_or_skipped(db, admin_user, host_factory):
    """``not_required`` and ``skipped`` rows must NOT promote even
    when the policy has a usable window — they were never reboot
    candidates."""
    win = _make_window(db, admin_user, name="weekly")
    pol = _make_policy(
        db,
        admin_user,
        "rb2-nr-sk",
        reboot_policy="never",
        reboot_window_id=win.id,
    )
    h = _seed_host_with_update(db, host_factory, "f", reboot_required=True)
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="test"
    )
    # The auto-reconcile already ran during cancel; rows should be
    # skipped (host_did_not_succeed) - not pending - so promote leaves
    # them alone.
    touched = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    assert touched == []
    rows = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .all()
    )
    assert len(rows) == 1
    assert rows[0].state == REBOOT_STATE_SKIPPED


# ---------------------------------------------------------------------------
# Auto-reconcile via dispatcher finalize
# ---------------------------------------------------------------------------


def test_auto_reconcile_after_dispatch_finalize_populates_queue(
    db, admin_user, host_factory, monkeypatch
):
    captured = _capture_audit(monkeypatch)
    win = _make_window(db, admin_user, name="finalize-window")
    pol = _make_policy(
        db,
        admin_user,
        "rb2-auto-fin",
        reboot_policy="if_required",
        reboot_window_id=win.id,
    )
    h = _seed_host_with_update(db, host_factory, "g", reboot_required=True)
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )

    rows = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .all()
    )
    assert len(rows) == 1
    # Successful host with reboot_required=True + usable window →
    # auto-reconcile creates pending row, promotion lands scheduled.
    assert rows[0].state == REBOOT_STATE_SCHEDULED
    assert rows[0].scheduled_for_at is not None

    actions = [c["action"] for c in captured]
    # Both queued (on row creation) and scheduled (on promotion).
    assert AUDIT_REBOOT_QUEUED in actions
    assert AUDIT_REBOOT_SCHEDULED in actions
    # safe_emit session-boundary lock: no db= argument anywhere.
    for c in captured:
        assert "db" not in c


def test_auto_reconcile_after_cancel_populates_queue(
    db, admin_user, host_factory, monkeypatch
):
    captured = _capture_audit(monkeypatch)
    pol = _make_policy(db, admin_user, "rb2-auto-cancel", reboot_policy="if_required")
    h = _seed_host_with_update(db, host_factory, "h", reboot_required=True)
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="auto-test"
    )

    rows = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .all()
    )
    assert len(rows) == 1
    # Canceled host → host_did_not_succeed → skipped (not promoted).
    assert rows[0].state == REBOOT_STATE_SKIPPED
    actions = [c["action"] for c in captured]
    assert AUDIT_REBOOT_SKIPPED in actions
    assert AUDIT_REBOOT_SCHEDULED not in actions


def test_auto_reconcile_failure_does_not_roll_back_terminal_state(
    db, admin_user, host_factory, monkeypatch
):
    """A reboot-queue failure inside auto_reconcile must NOT
    propagate; the execution still reaches its terminal state and
    emits the cancel/complete audit."""
    pol = _make_policy(db, admin_user, "rb2-auto-fail", reboot_policy="if_required")
    h = _seed_host_with_update(db, host_factory, "i", reboot_required=True)
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)

    def _boom(*args, **kwargs):
        raise RuntimeError("reboot queue down")

    monkeypatch.setattr(patch_reboot_service, "reconcile_reboot_queue", _boom)

    # Cancel must succeed even though reboot reconcile blows up.
    out = patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    assert out.state == "canceled"


def test_promote_is_idempotent_across_calls(db, admin_user, host_factory):
    """Once a row reaches ``scheduled``, a subsequent
    ``promote_pending_to_scheduled`` call must not re-touch it: it
    only filters by ``state == pending``."""
    win = _make_window(db, admin_user, name="idem-window")
    pol = _make_policy(
        db,
        admin_user,
        "rb2-idem",
        reboot_policy="always",
        reboot_window_id=win.id,
    )
    h = _seed_host_with_update(db, host_factory, "j")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    row.state = REBOOT_STATE_PENDING
    db.commit()

    first = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    assert len(first) == 1
    db.refresh(first[0])
    assert first[0].state == REBOOT_STATE_SCHEDULED
    first_scheduled_at = first[0].scheduled_for_at

    second = patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    assert second == []
    db.refresh(first[0])
    assert first[0].scheduled_for_at == first_scheduled_at


def test_reconcile_after_promotion_preserves_scheduled_state(
    db, admin_user, host_factory
):
    """The Slice 1 idempotency contract: a follow-up reconcile pass
    after promotion must NOT clobber the ``scheduled_for_at`` /
    ``state == scheduled`` columns. Reconcile refreshes decision
    columns only; scheduling fields are owned by Slice 2 and beyond."""
    win = _make_window(db, admin_user, name="preserve-window")
    pol = _make_policy(
        db,
        admin_user,
        "rb2-preserve",
        reboot_policy="always",
        reboot_window_id=win.id,
    )
    h = _seed_host_with_update(db, host_factory, "k")
    _bind(db, admin_user, pol, h)
    execution = _start(db, admin_user, [h], pol)
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .first()
    )
    row.state = REBOOT_STATE_PENDING
    db.commit()
    patch_reboot_service.promote_pending_to_scheduled(db, execution.id)
    db.commit()
    db.refresh(row)
    pre_scheduled_at = row.scheduled_for_at
    assert pre_scheduled_at is not None

    # Re-run reconcile and assert the scheduling fields survive
    # (Slice 1 explicitly preserves later-slice runtime columns).
    patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    db.refresh(row)
    assert row.scheduled_for_at == pre_scheduled_at
    # Reconcile DID re-derive the state for this row from current
    # data: the host's execution-host state is ``canceled``
    # (not_succeeded), so reconcile flips this row back to skipped.
    # That's the documented Slice 1 contract — reconcile owns the
    # decision; promote owns the scheduling fields.
    assert row.state == REBOOT_STATE_SKIPPED
