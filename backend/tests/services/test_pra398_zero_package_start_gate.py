"""PRA-398 - the patch-execution start gate refuses zero-package runs.

Before this gate, a plan whose hosts all resolved to zero selected
packages still materialized a ``running`` execution. Every host row was
``skipped``, so the first dispatch call found the run already terminal
and finalized it ``succeeded``: a patch run that installed nothing,
recorded as a successful patch run.

Covered here:

* Manual and scheduled starts are refused with the stable
  ``no_selected_packages`` code when no host would dispatch.
* Nothing is written by a refused start, so a retry keeps refusing
  instead of inheriting a half-built run.
* No ``patch_update_execution.started`` audit event is emitted.
* Refusal details tell apart a plan that selected nothing, a plan whose
  selected packages lost the hosts that could receive them, work an
  earlier run really applied, and an earlier run that attempted packages
  and failed. Per-package result rows are written for failures too, so
  their existence alone is never read as success.
* Selected-package counts report what the plan holds, not only the
  dispatchable subset, so a refusal cannot imply nothing was selected.
* Mixed plans are unaffected: empty hosts are still skipped per host and
  the hosts with work still dispatch to a real ``succeeded`` run.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable, List

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    Package,
    PackageUpdate,
    PatchPolicy,
    PatchUpdateExecution,
    PatchUpdateExecutionHostPackage,
    PatchUpdatePlanHost,
    System,
)
from app.services import (
    patch_execution_service,
    patch_policy_service,
    patch_update_plan_service,
)
from app.services.patch_execution_dispatch_service import (
    DispatchResult,
    dispatch_next_batch,
)
from app.services.patch_execution_service import (
    AUDIT_EXECUTION_STARTED,
    EXECUTION_HOST_STATE_PENDING,
    EXECUTION_HOST_STATE_SKIPPED,
    EXECUTION_STATE_FAILED,
    EXECUTION_STATE_SUCCEEDED,
    NO_WORK_REASON_ALREADY_COMPLETED,
    NO_WORK_REASON_NEVER_SELECTED,
    NO_WORK_REASON_NO_DISPATCHABLE_HOSTS,
    NO_WORK_REASON_PRIOR_ATTEMPT_FAILED,
    SKIP_REASON_NO_SELECTED_PACKAGES,
    SKIP_REASON_PLAN_HOST_TARGETLESS,
    START_REFUSAL_FUTURE_SCHEDULE,
    START_REFUSAL_NO_SELECTED_PACKAGES,
    PatchUpdateExecutionError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="zerowork-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="zerowork-test-cred",
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
            hostname=f"zerowork-host-{counter['n']}.example.com",
            ip_address=f"10.0.98.{counter['n']}",
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


def _make_policy(db, admin_user, slug: str) -> PatchPolicy:
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


def _empty_host(db, host_factory, suffix: str) -> System:
    """A host with an installed package and no available update, so
    selection resolves it to zero selected packages."""
    h = host_factory()
    db.add(
        Package(
            system_id=h.id,
            name=f"pkg-{suffix}",
            installed_version="1.0",
            package_type="apt",
        )
    )
    db.flush()
    return h


def _host_with_update(db, host_factory, suffix: str) -> System:
    """A host with one available update plus the HostFacts row the
    preflight resolver needs to derive a real package family."""
    h = host_factory()
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
    db.add(
        HostFacts(
            system_id=h.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="ssh",
            package_manager="apt",
            distro_id_facts="ubuntu",
        )
    )
    db.flush()
    return h


def _approved_plan(db, admin_user, policy: PatchPolicy, hosts: List[System]):
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=policy.id,
        name=f"plan-{policy.slug}",
        target_system_ids=[h.id for h in hosts],
    )
    return patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )


def _ok_callable() -> Callable:
    def _impl(system, cmd):
        return DispatchResult(exit_code=0, transport_name="fake")

    return _impl


def _failing_callable() -> Callable:
    """DispatchCallable whose package-manager command always exits
    non-zero, so the dispatcher records failed per-package rows."""

    def _impl(system, cmd):
        return DispatchResult(
            exit_code=100,
            stderr="package manager refused",
            transport_name="fake",
        )

    return _impl


def _callable_failing_for(failing_hostname: str) -> Callable:
    """DispatchCallable that fails only for one host, producing a run
    that applied some packages and failed others."""

    def _impl(system, cmd):
        if system.hostname == failing_hostname:
            return DispatchResult(
                exit_code=100,
                stderr="package manager refused",
                transport_name="fake",
            )
        return DispatchResult(exit_code=0, transport_name="fake")

    return _impl


def _execution_count(db, plan_id: int) -> int:
    return (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.plan_id == plan_id)
        .count()
    )


def _detach_plan_host(db, plan_id: int, system_id: int) -> None:
    """Null the plan host's ``system_id`` the way the ``ON DELETE SET
    NULL`` foreign key does when the target system is deleted. The
    plan-time selection rows survive, so the host still carries a
    non-zero selected-package count while being undispatchable."""
    row = (
        db.query(PatchUpdatePlanHost)
        .filter(
            PatchUpdatePlanHost.plan_id == plan_id,
            PatchUpdatePlanHost.system_id == system_id,
        )
        .one()
    )
    row.system_id = None
    db.flush()


# ---------------------------------------------------------------------------
# Refusal
# ---------------------------------------------------------------------------


def test_start_refuses_plan_where_no_host_has_selected_packages(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "zw-refuse-basic")
    h = _empty_host(db, host_factory, "a")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])

    with pytest.raises(PatchUpdateExecutionError) as exc:
        patch_execution_service.start_execution(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )

    assert START_REFUSAL_NO_SELECTED_PACKAGES in str(exc.value)
    # The route layer maps only "not found" wording to 404; this refusal
    # must stay a 422.
    assert "not found" not in str(exc.value)


def test_refused_start_creates_no_execution_row(db, admin_user, host_factory):
    """A refused start must not leave a run behind. A zero-work
    execution that reached ``running`` would be finalized ``succeeded``
    by the first dispatch call."""
    pol = _make_policy(db, admin_user, "zw-no-row")
    h = _empty_host(db, host_factory, "b")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])

    with pytest.raises(PatchUpdateExecutionError):
        patch_execution_service.start_execution(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )

    assert _execution_count(db, plan.id) == 0
    assert patch_execution_service.latest_execution_for_plan(db, plan.id) is None


def test_repeated_start_attempts_keep_refusing(db, admin_user, host_factory):
    """Retrying a scheduled start must not converge on success: each
    attempt refuses with the same code and still writes nothing."""
    pol = _make_policy(db, admin_user, "zw-retry")
    h = _empty_host(db, host_factory, "c")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])

    for _ in range(3):
        with pytest.raises(PatchUpdateExecutionError) as exc:
            patch_execution_service.start_execution(
                db, plan_id=plan.id, actor_user_id=admin_user.id
            )
        assert START_REFUSAL_NO_SELECTED_PACKAGES in str(exc.value)

    assert _execution_count(db, plan.id) == 0


def test_refused_start_emits_no_started_audit(
    db, admin_user, host_factory, monkeypatch
):
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_execution_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )

    pol = _make_policy(db, admin_user, "zw-no-audit")
    h = _empty_host(db, host_factory, "d")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])

    with pytest.raises(PatchUpdateExecutionError):
        patch_execution_service.start_execution(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )

    assert [c["action"] for c in captured] == []
    assert AUDIT_EXECUTION_STARTED not in [c.get("action") for c in captured]


def test_started_audit_records_the_work_the_run_committed_to(
    db, admin_user, host_factory, monkeypatch
):
    """The gate guarantees a started run has work, so the started event
    carries the counts that prove it."""
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_execution_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )

    pol = _make_policy(db, admin_user, "zw-audit-context")
    h_work = _host_with_update(db, host_factory, "p")
    _bind(db, admin_user, pol, h_work)
    h_empty = _empty_host(db, host_factory, "q")
    _bind(db, admin_user, pol, h_empty)
    plan = _approved_plan(db, admin_user, pol, [h_work, h_empty])

    patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=2
    )

    started = [c for c in captured if c["action"] == AUDIT_EXECUTION_STARTED]
    assert len(started) == 1
    context = started[0]["context"]
    assert context["host_count"] == 2
    assert context["pending_host_count"] == 1
    assert context["selected_package_count"] == 1
    # safe_emit session-boundary lock: no db= argument.
    assert "db" not in started[0]


def test_scheduled_plan_with_zero_work_is_refused(db, admin_user, host_factory):
    """The scheduled path runs the same gate as the manual one: a
    scheduled plan whose start time has arrived is still refused when it
    has nothing to dispatch."""
    pol = _make_policy(db, admin_user, "zw-scheduled")
    h = _empty_host(db, host_factory, "e")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])
    plan = patch_update_plan_service.schedule_plan(
        db,
        plan.id,
        scheduled_start_at=datetime.utcnow() - timedelta(minutes=5),
        actor_user_id=admin_user.id,
    )
    assert plan.state == "scheduled"

    with pytest.raises(PatchUpdateExecutionError) as exc:
        patch_execution_service.start_execution(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )

    assert START_REFUSAL_NO_SELECTED_PACKAGES in str(exc.value)
    assert _execution_count(db, plan.id) == 0


def test_zero_work_refusal_precedes_future_schedule_refusal(
    db, admin_user, host_factory
):
    """An empty plan stays empty, so waiting for the start time would
    only send the operator back to the same refusal. The zero-work code
    is the one reported."""
    pol = _make_policy(db, admin_user, "zw-before-schedule")
    h = _empty_host(db, host_factory, "f")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])
    patch_update_plan_service.schedule_plan(
        db,
        plan.id,
        scheduled_start_at=datetime.utcnow() + timedelta(days=1),
        actor_user_id=admin_user.id,
    )

    with pytest.raises(PatchUpdateExecutionError) as exc:
        patch_execution_service.start_execution(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )

    assert START_REFUSAL_NO_SELECTED_PACKAGES in str(exc.value)
    assert START_REFUSAL_FUTURE_SCHEDULE not in str(exc.value)


def test_start_refuses_when_selected_packages_belong_to_targetless_hosts(
    db, admin_user, host_factory
):
    """Selected-package rows survive their host losing its system. The
    gate counts only hosts that would really dispatch, so a plan holding
    selection rows for nothing but detached hosts is refused."""
    pol = _make_policy(db, admin_user, "zw-targetless")
    h = _host_with_update(db, host_factory, "g")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])
    _detach_plan_host(db, plan.id, h.id)

    with pytest.raises(PatchUpdateExecutionError) as exc:
        patch_execution_service.start_execution(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )

    assert START_REFUSAL_NO_SELECTED_PACKAGES in str(exc.value)
    assert _execution_count(db, plan.id) == 0

    # The plan really did select a package; it just lost the host that
    # could receive it. Neither the reason nor the count may imply the
    # plan selected nothing.
    refusal = patch_execution_service._evaluate_selected_work_gate(db, plan)
    assert refusal["details"]["reason"] == NO_WORK_REASON_NO_DISPATCHABLE_HOSTS
    assert refusal["details"]["selected_package_count"] == 1
    assert refusal["details"]["dispatchable_selected_package_count"] == 0
    assert refusal["details"]["dispatchable_host_count"] == 0
    assert refusal["details"]["skip_reason_counts"] == {
        SKIP_REASON_PLAN_HOST_TARGETLESS: 1
    }
    assert "no plan host can receive them" in refusal["message"]


# ---------------------------------------------------------------------------
# Refusal reason: nothing selected / nothing reachable / applied / failed
# ---------------------------------------------------------------------------


def test_refusal_reports_never_selected_without_prior_work(
    db, admin_user, host_factory
):
    pol = _make_policy(db, admin_user, "zw-never")
    h = _empty_host(db, host_factory, "h")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])

    refusal = patch_execution_service._evaluate_selected_work_gate(db, plan)

    assert refusal is not None
    assert refusal["code"] == START_REFUSAL_NO_SELECTED_PACKAGES
    assert refusal["details"]["reason"] == NO_WORK_REASON_NEVER_SELECTED
    assert refusal["details"]["dispatchable_host_count"] == 0
    assert refusal["details"]["selected_package_count"] == 0
    assert refusal["details"]["dispatchable_selected_package_count"] == 0
    assert refusal["details"]["prior_execution_id"] is None
    assert refusal["details"]["prior_package_result_count"] == 0
    assert refusal["details"]["prior_succeeded_package_count"] == 0
    assert refusal["details"]["skip_reason_counts"] == {
        SKIP_REASON_NO_SELECTED_PACKAGES: 1
    }


def test_refusal_reports_already_completed_after_real_work(
    db, admin_user, host_factory
):
    """Once a run has really installed packages, a later start with
    nothing left to do must say the work is done rather than claim the
    plan never selected anything."""
    pol = _make_policy(db, admin_user, "zw-already")
    h_work = _host_with_update(db, host_factory, "i")
    _bind(db, admin_user, pol, h_work)
    h_empty = _empty_host(db, host_factory, "j")
    _bind(db, admin_user, pol, h_empty)
    plan = _approved_plan(db, admin_user, pol, [h_work, h_empty])

    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=2
    )
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    db.refresh(execution)
    assert execution.state == EXECUTION_STATE_SUCCEEDED
    assert (
        db.query(PatchUpdateExecutionHostPackage)
        .filter(PatchUpdateExecutionHostPackage.outcome == "succeeded")
        .count()
        > 0
    ), "the prior run must have succeeded per-package results to count as applied"

    # The patched host is decommissioned; nothing is left to dispatch.
    _detach_plan_host(db, plan.id, h_work.id)

    with pytest.raises(PatchUpdateExecutionError) as exc:
        patch_execution_service.start_execution(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    assert START_REFUSAL_NO_SELECTED_PACKAGES in str(exc.value)

    refusal = patch_execution_service._evaluate_selected_work_gate(db, plan)
    assert refusal["details"]["reason"] == NO_WORK_REASON_ALREADY_COMPLETED
    assert refusal["details"]["prior_execution_id"] == execution.id
    assert refusal["details"]["prior_execution_state"] == EXECUTION_STATE_SUCCEEDED
    assert refusal["details"]["prior_succeeded_package_count"] == 1
    assert "already applied" in refusal["message"]

    # Still exactly the one real run; the refusal added nothing.
    assert _execution_count(db, plan.id) == 1


def test_refusal_does_not_claim_application_after_a_failed_dispatch(
    db, admin_user, host_factory
):
    """Per-package rows are written for failures too. A run that failed
    to install anything must never be reported as having applied the
    plan's package work.
    """
    pol = _make_policy(db, admin_user, "zw-failed-attempt")
    h_work = _host_with_update(db, host_factory, "r")
    _bind(db, admin_user, pol, h_work)
    h_empty = _empty_host(db, host_factory, "s")
    _bind(db, admin_user, pol, h_empty)
    plan = _approved_plan(db, admin_user, pol, [h_work, h_empty])

    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=2
    )
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_failing_callable(),
    )
    db.refresh(execution)
    assert execution.state == EXECUTION_STATE_FAILED
    # The failed dispatch still wrote per-package result rows, which is
    # exactly what makes "rows exist" an unsafe proxy for success.
    assert (
        db.query(PatchUpdateExecutionHostPackage)
        .filter(PatchUpdateExecutionHostPackage.outcome == "failed")
        .count()
        > 0
    )
    assert (
        db.query(PatchUpdateExecutionHostPackage)
        .filter(PatchUpdateExecutionHostPackage.outcome == "succeeded")
        .count()
        == 0
    )

    _detach_plan_host(db, plan.id, h_work.id)

    with pytest.raises(PatchUpdateExecutionError) as exc:
        patch_execution_service.start_execution(
            db, plan_id=plan.id, actor_user_id=admin_user.id
        )
    message = str(exc.value)
    assert START_REFUSAL_NO_SELECTED_PACKAGES in message
    assert "already applied" not in message

    refusal = patch_execution_service._evaluate_selected_work_gate(db, plan)
    assert refusal["details"]["reason"] == NO_WORK_REASON_PRIOR_ATTEMPT_FAILED
    assert refusal["details"]["prior_execution_id"] == execution.id
    assert refusal["details"]["prior_execution_state"] == EXECUTION_STATE_FAILED
    assert refusal["details"]["prior_package_result_count"] == 1
    assert refusal["details"]["prior_succeeded_package_count"] == 0
    assert "without applying any packages" in refusal["message"]
    assert _execution_count(db, plan.id) == 1


def test_partial_application_is_reported_as_incomplete_not_applied(
    db, admin_user, host_factory
):
    """A run where one host installed and another failed ends
    ``failed``. It applied some work, so the refusal must say the plan
    may be incomplete rather than claim it is done."""
    pol = _make_policy(db, admin_user, "zw-partial")
    h_ok = _host_with_update(db, host_factory, "t")
    _bind(db, admin_user, pol, h_ok)
    h_bad = _host_with_update(db, host_factory, "u")
    _bind(db, admin_user, pol, h_bad)
    plan = _approved_plan(db, admin_user, pol, [h_ok, h_bad])

    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=2
    )
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_callable_failing_for(h_bad.hostname),
    )
    db.refresh(execution)
    assert execution.state == EXECUTION_STATE_FAILED

    _detach_plan_host(db, plan.id, h_ok.id)
    _detach_plan_host(db, plan.id, h_bad.id)

    refusal = patch_execution_service._evaluate_selected_work_gate(db, plan)
    assert refusal["details"]["reason"] == NO_WORK_REASON_PRIOR_ATTEMPT_FAILED
    assert refusal["details"]["prior_succeeded_package_count"] == 1
    assert refusal["details"]["prior_package_result_count"] == 2
    assert "may be incomplete" in refusal["message"]
    assert "already applied" not in refusal["message"]


# ---------------------------------------------------------------------------
# Mixed and non-empty plans are unaffected
# ---------------------------------------------------------------------------


def test_mixed_plan_starts_and_skips_only_the_empty_host(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "zw-mixed-start")
    h_work = _host_with_update(db, host_factory, "k")
    _bind(db, admin_user, pol, h_work)
    h_empty = _empty_host(db, host_factory, "l")
    _bind(db, admin_user, pol, h_empty)
    plan = _approved_plan(db, admin_user, pol, [h_work, h_empty])

    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=2
    )
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    by_id = {h.system_id_snapshot: h for h in hosts}

    assert by_id[h_work.id].state == EXECUTION_HOST_STATE_PENDING
    assert by_id[h_work.id].selected_package_count == 1
    assert by_id[h_empty.id].state == EXECUTION_HOST_STATE_SKIPPED
    assert by_id[h_empty.id].selected_package_count == 0
    assert SKIP_REASON_NO_SELECTED_PACKAGES in [
        s["code"] for s in by_id[h_empty.id].skip_reasons
    ]


def test_mixed_plan_dispatches_real_work_to_succeeded(db, admin_user, host_factory):
    """The gate must not disturb a run that has work: the host with
    updates dispatches, per-package rows are written, and the execution
    finalizes ``succeeded`` on genuine work."""
    pol = _make_policy(db, admin_user, "zw-mixed-dispatch")
    h_work = _host_with_update(db, host_factory, "m")
    _bind(db, admin_user, pol, h_work)
    h_empty = _empty_host(db, host_factory, "n")
    _bind(db, admin_user, pol, h_empty)
    plan = _approved_plan(db, admin_user, pol, [h_work, h_empty])

    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=2
    )
    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )

    assert summary.dispatched_count == 1
    assert summary.finalized_state == EXECUTION_STATE_SUCCEEDED
    db.refresh(execution)
    assert execution.progress_summary["package_outcome_counts"]["succeeded"] == 1


def test_single_host_plan_with_updates_still_starts(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "zw-plain")
    h = _host_with_update(db, host_factory, "o")
    _bind(db, admin_user, pol, h)
    plan = _approved_plan(db, admin_user, pol, [h])

    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )

    assert execution.progress_summary["selected_package_count"] == 1
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    assert [h.state for h in hosts] == [EXECUTION_HOST_STATE_PENDING]
