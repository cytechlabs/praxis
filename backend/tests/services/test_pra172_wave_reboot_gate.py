"""PRA-172 slice 5 — dependent-wave reboot gate tests.

Covers:

* `reconcile_wave_reboots` creates reboot rows for one wave's
  hosts without requiring the parent execution to be terminal.
* `is_wave_blocked_by_reboot_gate` returns a structured blocker
  when prior-wave reboot rows are still in
  ``pending`` / ``scheduled`` / ``rebooting`` / ``verifying``
  states, or when any prior-wave row is ``failed``.
* `is_wave_blocked_by_reboot_gate` returns ``None`` when prior-
  wave rows are all in the safe set
  (``not_required`` / ``healthy`` / ``skipped``).
* The dispatcher's wave-completion hook auto-runs the per-wave
  reconcile so the gate has rows to inspect.
* The dispatcher's `dispatch_next_batch` refuses to advance to
  wave N+1 when wave N's reboot rows aren't safe, returning a
  structured ``pause_reason="reboot_gate_pending"`` summary.
* Once wave N's reboot rows reach healthy/not_required/skipped,
  the next ``dispatch_next_batch`` call proceeds with wave N+1.
* ``not_required`` / ``skipped`` rows are explicit and do not
  block the next wave (the gate only blocks on unsafe states).
* The blocker context recorded on ``execution.progress_summary``
  is cleared when the gate resolves.

No test issues a real reboot command — fakes are used throughout.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    Package,
    PackageUpdate,
    PatchUpdateExecutionReboot,
    System,
)
from app.services import (
    patch_execution_service,
    patch_policy_service,
    patch_reboot_service,
    patch_update_plan_service,
    reboot_evidence_service,
)
from app.services.patch_execution_dispatch_service import (
    DispatchResult,
    dispatch_next_batch,
)
from app.services.patch_reboot_service import (
    REBOOT_STATE_FAILED,
    REBOOT_STATE_HEALTHY,
    REBOOT_STATE_NOT_REQUIRED,
    REBOOT_STATE_PENDING,
    REBOOT_STATE_REBOOTING,
    REBOOT_STATE_SCHEDULED,
    REBOOT_STATE_SKIPPED,
    REBOOT_STATE_VERIFYING,
    WAVE_GATE_REASON_REBOOT_FAILURES,
    WAVE_GATE_REASON_REBOOT_ROWS_MISSING,
    WAVE_GATE_REASON_REBOOTS_IN_PROGRESS,
    is_wave_blocked_by_reboot_gate,
    reconcile_wave_reboots,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def hosts_report_no_reboot_needed(monkeypatch):
    """Make every reboot-evidence probe answer "no reboot needed".

    The dispatcher path collects the answer from the host itself, and
    these tests exercise the wave gate rather than the transport, so
    the observation is supplied instead of attempting a connection.
    """

    def _runner(db_arg):
        def _run(system, argv):
            return {"exit_code": 0, "stdout": "PRAXIS_REBOOT_PROBE=false"}

        return _run

    monkeypatch.setattr(reboot_evidence_service, "dispatch_runner", _runner)


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rb5-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rb5-test-cred",
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
            hostname=f"rb5-host-{counter['n']}.example.com",
            ip_address=f"10.0.99.{counter['n']}",
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


def _make_policy(db, admin_user, slug, *, reboot_policy="if_required"):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
        reboot_policy=reboot_policy,
        requires_approval=False,
    )


def _bind(db, admin_user, policy, host):
    patch_policy_service.bind_host(
        db,
        policy_id=policy.id,
        system_id=host.id,
        actor_user_id=admin_user.id,
    )


def _seed_host_with_update(db, host_factory, suffix, **kwargs) -> System:
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


def _ok_callable() -> Callable:
    def _impl(system, cmd):
        return DispatchResult(exit_code=0, transport_name="fake")

    return _impl


# ---------------------------------------------------------------------------
# Unit tests for is_wave_blocked_by_reboot_gate
# ---------------------------------------------------------------------------


def _build_minimal_reboot_row(
    db,
    *,
    execution_id: int,
    execution_host_id: int,
    plan_id: int,
    system_id: Optional[int],
    wave_index: int,
    state: str,
    decision_code: str = "policy_always",
    reboot_policy_snapshot: str = "always",
) -> PatchUpdateExecutionReboot:
    row = PatchUpdateExecutionReboot(
        execution_id=execution_id,
        execution_host_id=execution_host_id,
        plan_id_snapshot=plan_id,
        system_id_snapshot=system_id,
        wave_index=wave_index,
        state=state,
        reboot_policy_snapshot=reboot_policy_snapshot,
        decision_code=decision_code,
        decision_details={},
    )
    db.add(row)
    db.flush()
    return row


def test_gate_blocks_when_prior_wave_rows_missing(db, admin_user, host_factory):
    """PRA-172 Slice 5a: fail-closed. The prior wave
    has execution-host rows but NO reboot-queue rows (e.g., the
    per-wave reconcile hook failed/rolled back silently). The
    gate must block instead of returning ``None``, because we
    cannot prove the prior wave's reboot health from missing
    rows."""
    pol = _make_policy(db, admin_user, "rb5-missing-rows")
    h = _seed_host_with_update(db, host_factory, "miss")
    _bind(db, admin_user, pol, h)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-miss",
        target_system_ids=[h.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    # Execution-host row exists in wave 0; no reboot row created
    # (simulating a per-wave reconcile failure that rolled back).
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    assert len(hosts) == 1
    assert hosts[0].wave_index == 0
    # No reboot rows exist yet.
    assert (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .count()
        == 0
    )

    blocker = is_wave_blocked_by_reboot_gate(db, execution.id, wave_index=1)
    assert blocker is not None
    assert blocker["reason"] == WAVE_GATE_REASON_REBOOT_ROWS_MISSING
    assert blocker["blocked_wave_index"] == 1
    missing = blocker["missing_by_wave"]
    assert 0 in missing
    assert missing[0]["host_count"] == 1
    assert missing[0]["reboot_row_count"] == 0
    assert missing[0]["missing_row_count"] == 1


def test_gate_blocks_when_prior_wave_partial_coverage(db, admin_user, host_factory):
    """Partial coverage: prior wave has 2 hosts but only 1
    reboot row. Fail-closed still applies — we don't know the
    health of the un-reconciled host."""
    pol = _make_policy(db, admin_user, "rb5-partial")
    h_a = _seed_host_with_update(db, host_factory, "pa")
    h_b = _seed_host_with_update(db, host_factory, "pb")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-partial",
        target_system_ids=[h_a.id, h_b.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    assert len(hosts) == 2
    # Create a reboot row for only ONE of the two wave-0 hosts.
    _build_minimal_reboot_row(
        db,
        execution_id=execution.id,
        execution_host_id=hosts[0].id,
        plan_id=execution.plan_id,
        system_id=hosts[0].system_id_snapshot,
        wave_index=0,
        state=REBOOT_STATE_HEALTHY,
    )

    blocker = is_wave_blocked_by_reboot_gate(db, execution.id, wave_index=1)
    assert blocker is not None
    assert blocker["reason"] == WAVE_GATE_REASON_REBOOT_ROWS_MISSING
    assert blocker["missing_by_wave"][0]["missing_row_count"] == 1


def test_gate_passes_when_prior_wave_has_no_hosts(db, admin_user, host_factory):
    """Coverage check: an empty prior wave (no execution_hosts)
    is genuinely safe (nothing to reboot). The fail-closed
    coverage check must not false-positive on it."""
    # Build an execution whose hosts all sit in wave_index=1; no
    # wave_index=0 hosts exist. Gate inspection at wave_index=1
    # should return None (no prior wave to gate).
    pol = _make_policy(db, admin_user, "rb5-empty-prior")
    h = _seed_host_with_update(db, host_factory, "ep")
    _bind(db, admin_user, pol, h)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-empty-prior",
        target_system_ids=[h.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    # Force the single host's wave to 1 so wave 0 is empty.
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    hosts[0].wave_index = 1
    db.commit()

    # Wave 1 gate: no wave-0 hosts at all → no coverage gap → safe.
    blocker = is_wave_blocked_by_reboot_gate(db, execution.id, wave_index=1)
    assert blocker is None


def test_gate_returns_none_for_wave_zero(db):
    """Wave 0 has no prior wave; the gate must return None
    regardless of any state."""
    blocker = is_wave_blocked_by_reboot_gate(db, execution_id=999, wave_index=0)
    assert blocker is None


def test_gate_returns_none_when_no_prior_rows(db):
    """An execution with no reboot rows yet must not block —
    the gate has nothing to inspect, which is structurally safe."""
    blocker = is_wave_blocked_by_reboot_gate(db, execution_id=12345, wave_index=2)
    assert blocker is None


def test_gate_blocks_when_prior_wave_has_pending_rows(db, admin_user, host_factory):
    """A prior-wave row in ``pending`` blocks the next wave."""
    # Build minimal execution + host substrate.
    pol = _make_policy(db, admin_user, "rb5-pending-gate")
    h = _seed_host_with_update(db, host_factory, "g")
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

    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    _build_minimal_reboot_row(
        db,
        execution_id=execution.id,
        execution_host_id=hosts[0].id,
        plan_id=execution.plan_id,
        system_id=h.id,
        wave_index=0,
        state=REBOOT_STATE_PENDING,
    )

    blocker = is_wave_blocked_by_reboot_gate(db, execution.id, wave_index=1)
    assert blocker is not None
    assert blocker["reason"] == WAVE_GATE_REASON_REBOOTS_IN_PROGRESS
    assert blocker["in_progress_row_count"] == 1
    assert blocker["failed_row_count"] == 0


@pytest.mark.parametrize(
    "in_progress_state",
    [
        REBOOT_STATE_PENDING,
        REBOOT_STATE_SCHEDULED,
        REBOOT_STATE_REBOOTING,
        REBOOT_STATE_VERIFYING,
    ],
)
def test_gate_blocks_for_every_in_progress_state(
    db, admin_user, host_factory, in_progress_state
):
    pol = _make_policy(db, admin_user, f"rb5-prog-{in_progress_state}")
    h = _seed_host_with_update(db, host_factory, f"g{in_progress_state}")
    _bind(db, admin_user, pol, h)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name=f"p-{in_progress_state}",
        target_system_ids=[h.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    _build_minimal_reboot_row(
        db,
        execution_id=execution.id,
        execution_host_id=hosts[0].id,
        plan_id=execution.plan_id,
        system_id=h.id,
        wave_index=0,
        state=in_progress_state,
    )

    blocker = is_wave_blocked_by_reboot_gate(db, execution.id, wave_index=1)
    assert blocker is not None
    assert blocker["reason"] == WAVE_GATE_REASON_REBOOTS_IN_PROGRESS


def test_gate_blocks_with_failure_reason_on_prior_failed(db, admin_user, host_factory):
    """A prior-wave row in ``failed`` blocks the next wave with
    the failure-specific reason code, even if other prior rows
    are healthy."""
    pol = _make_policy(db, admin_user, "rb5-failed")
    h1 = _seed_host_with_update(db, host_factory, "fa")
    h2 = _seed_host_with_update(db, host_factory, "fb")
    _bind(db, admin_user, pol, h1)
    _bind(db, admin_user, pol, h2)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-failed",
        target_system_ids=[h1.id, h2.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    _build_minimal_reboot_row(
        db,
        execution_id=execution.id,
        execution_host_id=hosts[0].id,
        plan_id=execution.plan_id,
        system_id=hosts[0].system_id_snapshot,
        wave_index=0,
        state=REBOOT_STATE_FAILED,
    )
    _build_minimal_reboot_row(
        db,
        execution_id=execution.id,
        execution_host_id=hosts[1].id,
        plan_id=execution.plan_id,
        system_id=hosts[1].system_id_snapshot,
        wave_index=0,
        state=REBOOT_STATE_HEALTHY,
    )

    blocker = is_wave_blocked_by_reboot_gate(db, execution.id, wave_index=1)
    assert blocker is not None
    assert blocker["reason"] == WAVE_GATE_REASON_REBOOT_FAILURES
    assert blocker["failed_row_count"] == 1


@pytest.mark.parametrize(
    "safe_state",
    [
        REBOOT_STATE_NOT_REQUIRED,
        REBOOT_STATE_HEALTHY,
        REBOOT_STATE_SKIPPED,
    ],
)
def test_gate_passes_when_all_prior_rows_safe(db, admin_user, host_factory, safe_state):
    pol = _make_policy(db, admin_user, f"rb5-safe-{safe_state}")
    h = _seed_host_with_update(db, host_factory, f"s{safe_state}")
    _bind(db, admin_user, pol, h)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name=f"p-{safe_state}",
        target_system_ids=[h.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    _build_minimal_reboot_row(
        db,
        execution_id=execution.id,
        execution_host_id=hosts[0].id,
        plan_id=execution.plan_id,
        system_id=h.id,
        wave_index=0,
        state=safe_state,
    )

    blocker = is_wave_blocked_by_reboot_gate(db, execution.id, wave_index=1)
    assert blocker is None


# ---------------------------------------------------------------------------
# reconcile_wave_reboots
# ---------------------------------------------------------------------------


def test_reconcile_wave_reboots_requires_wave_complete(db, admin_user, host_factory):
    """Per-wave reconcile must refuse if the wave isn't fully
    terminal — the gate's whole purpose is to wait for those
    rows, so reconciling a half-complete wave would lie."""
    pol = _make_policy(db, admin_user, "rb5-pre-complete", reboot_policy="always")
    h = _seed_host_with_update(db, host_factory, "x")
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
    # Host is still ``pending`` — wave is not complete.
    with pytest.raises(patch_reboot_service.PatchUpdateRebootError):
        reconcile_wave_reboots(db, execution.id, wave_index=0)


def test_reconcile_wave_reboots_scopes_to_one_wave(db, admin_user, host_factory):
    """Per-wave reconcile only touches rows for that wave; other
    waves stay untouched."""
    pol = _make_policy(db, admin_user, "rb5-wave-scope", reboot_policy="always")
    h_a = _seed_host_with_update(db, host_factory, "a")
    _bind(db, admin_user, pol, h_a)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-scope",
        target_system_ids=[h_a.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    # Drive wave 0 to terminal via cancel (turns hosts ->
    # canceled, which is terminal so the wave is "complete").
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    # Wave 0 is complete and the auto-reconcile-on-terminal hook
    # already created a row. Per-wave reconcile must be
    # idempotent and not duplicate.
    rows = reconcile_wave_reboots(db, execution.id, wave_index=0)
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# Dispatcher integration
# ---------------------------------------------------------------------------


def _seed_two_wave_plan(db, admin_user, host_factory):
    """Build a plan with two policies producing two waves.

    Two rings with distinct sort orders so PRA-164 sorts each
    host into a different wave_index.
    """
    from app.db.models import PatchPolicyRingBinding, PatchRing

    # Wave 0 ring + policy.
    ring0 = PatchRing(
        slug="rb5-ring-a",
        name="rb5-ring-a",
        sort_order=10,
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(ring0)
    db.flush()
    pol0 = _make_policy(db, admin_user, "rb5-w0-pol", reboot_policy="always")
    db.add(
        PatchPolicyRingBinding(
            policy_id=pol0.id, ring_id=ring0.id, created_by=admin_user.id
        )
    )

    # Wave 1 ring + policy.
    ring1 = PatchRing(
        slug="rb5-ring-b",
        name="rb5-ring-b",
        sort_order=20,
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(ring1)
    db.flush()
    pol1 = _make_policy(db, admin_user, "rb5-w1-pol", reboot_policy="always")
    db.add(
        PatchPolicyRingBinding(
            policy_id=pol1.id, ring_id=ring1.id, created_by=admin_user.id
        )
    )
    db.flush()

    return pol0, pol1, ring0, ring1


def test_dispatch_next_batch_blocks_wave_1_when_wave_0_reboots_pending(
    db, admin_user, host_factory, monkeypatch
):
    """End-to-end: dispatch wave 0 → wave_completed fires →
    per-wave reconcile creates wave-0 ``pending`` reboot rows →
    next dispatch_next_batch refuses wave 1 with
    ``pause_reason='reboot_gate_pending'``."""
    pol = _make_policy(db, admin_user, "rb5-gate-block", reboot_policy="always")
    h_a = _seed_host_with_update(db, host_factory, "wa")
    h_b = _seed_host_with_update(db, host_factory, "wb")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-gate-block",
        target_system_ids=[h_a.id, h_b.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=5
    )
    # Both hosts default to wave_index=0 (immediate cadence, no
    # rings), so this is a single-wave execution. To exercise the
    # gate, we force one host into wave 1.
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    hosts[1].wave_index = 1
    db.commit()

    # Process wave 0 to terminal (success → reboot_required
    # captured via HostFacts default of None ⇒ not_required;
    # promote with reboot_policy=always means ``pending``).
    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    # The dispatcher should NOT have advanced into wave 1 — the
    # gate fires on the second dispatch call after wave 0
    # completes. Within the same batch, wave 0's batch finished
    # and the next pending wave is wave 1.
    # The wave-completion hook ran, created the wave 0 reboot
    # row, which is ``pending`` under policy=always.
    rows = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .all()
    )
    assert any(r.state == REBOOT_STATE_PENDING for r in rows)

    # Next dispatch call should see wave 1 as the lowest pending
    # wave and BLOCK on the gate.
    summary2 = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    assert summary2.pause_reason == "reboot_gate_pending"
    assert summary2.threshold_pause is not None
    assert summary2.threshold_pause["reason"] == WAVE_GATE_REASON_REBOOTS_IN_PROGRESS
    assert summary2.dispatched_count == 0

    # And wave 1's host is still pending — the gate did NOT
    # transition any wave-1 hosts.
    db.refresh(hosts[1])
    assert hosts[1].state == "pending"


def test_dispatch_resumes_after_wave_0_reboots_reach_healthy(
    db, admin_user, host_factory
):
    """Once wave 0's reboot rows reach safe states
    (``healthy`` / ``not_required`` / ``skipped``), the next
    ``dispatch_next_batch`` advances into wave 1."""
    pol = _make_policy(db, admin_user, "rb5-gate-resume", reboot_policy="always")
    h_a = _seed_host_with_update(db, host_factory, "ra")
    h_b = _seed_host_with_update(db, host_factory, "rb")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-gate-resume",
        target_system_ids=[h_a.id, h_b.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=5
    )
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    hosts[1].wave_index = 1
    db.commit()

    # Drive wave 0 to terminal + reboot row created.
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )

    # Manually flip wave 0's reboot row(s) to healthy as if the
    # operator dispatched + verified the reboots.
    reboot_rows_wave0 = (
        db.query(PatchUpdateExecutionReboot)
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution.id,
            PatchUpdateExecutionReboot.wave_index == 0,
        )
        .all()
    )
    assert reboot_rows_wave0
    for r in reboot_rows_wave0:
        r.state = REBOOT_STATE_HEALTHY
    db.commit()

    # Next dispatch call should now proceed with wave 1.
    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    assert summary.pause_reason is None
    assert summary.wave_index == 1
    assert summary.dispatched_count >= 1


def test_blocker_context_clears_when_gate_resolves(db, admin_user, host_factory):
    """The ``wave_reboot_gate_blocker`` recorded on
    ``progress_summary`` while the gate is blocking must clear
    on the next dispatch call once the gate resolves."""
    pol = _make_policy(db, admin_user, "rb5-clear", reboot_policy="always")
    h_a = _seed_host_with_update(db, host_factory, "ca")
    h_b = _seed_host_with_update(db, host_factory, "cb")
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-clear",
        target_system_ids=[h_a.id, h_b.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=5
    )
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    hosts[1].wave_index = 1
    db.commit()

    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    # Second call blocks.
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    db.refresh(execution)
    assert (execution.progress_summary or {}).get(
        "wave_reboot_gate_blocker"
    ) is not None

    # Resolve the gate.
    reboot_rows_wave0 = (
        db.query(PatchUpdateExecutionReboot)
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution.id,
            PatchUpdateExecutionReboot.wave_index == 0,
        )
        .all()
    )
    for r in reboot_rows_wave0:
        r.state = REBOOT_STATE_HEALTHY
    db.commit()

    # Next dispatch call proceeds; blocker should clear.
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    db.refresh(execution)
    assert "wave_reboot_gate_blocker" not in (execution.progress_summary or {})


def test_gate_does_not_block_when_only_safe_states_in_prior_wave(
    db, admin_user, host_factory, hosts_report_no_reboot_needed
):
    """When wave 0 hosts produce only ``not_required`` /
    ``skipped`` rows (reboot_policy=if_required and the hosts report
    they do not need a reboot), the gate must NOT block wave 1."""
    pol = _make_policy(db, admin_user, "rb5-safe-only", reboot_policy="if_required")
    h_a = _seed_host_with_update(db, host_factory, "sa", reboot_required=False)
    h_b = _seed_host_with_update(db, host_factory, "sb", reboot_required=False)
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-safe-only",
        target_system_ids=[h_a.id, h_b.id],
    )
    plan = patch_update_plan_service.approve_directly(
        db, plan.id, actor_user_id=admin_user.id
    )
    execution = patch_execution_service.start_execution(
        db, plan_id=plan.id, actor_user_id=admin_user.id, max_parallel_per_wave=5
    )
    hosts = patch_execution_service.list_execution_hosts(db, execution.id)
    hosts[1].wave_index = 1
    db.commit()

    # Wave 0 succeeds; reboot_required=False under if_required →
    # not_required reboot row.
    dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    # Confirm wave 0 row is in a safe state.
    w0_rows = (
        db.query(PatchUpdateExecutionReboot)
        .filter(
            PatchUpdateExecutionReboot.execution_id == execution.id,
            PatchUpdateExecutionReboot.wave_index == 0,
        )
        .all()
    )
    assert w0_rows
    assert all(
        r.state in (REBOOT_STATE_NOT_REQUIRED, REBOOT_STATE_SKIPPED) for r in w0_rows
    )

    # Next dispatch should proceed to wave 1 without blocking.
    summary = dispatch_next_batch(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_ok_callable(),
    )
    assert summary.pause_reason is None
    assert summary.wave_index == 1
