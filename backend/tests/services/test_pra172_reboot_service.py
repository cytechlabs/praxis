"""PRA-172 slice 1 — reboot queue service tests.

Covers the Slice 1 contract:

* ``reconcile_reboot_queue`` initializes one queue row per
  ``patch_update_execution_hosts`` row, in idempotent fashion.
* Policy gating is correct for ``never`` / ``if_required`` /
  ``always``; missing/invalid policy snapshots produce explicit
  ``policy_missing`` / ``policy_invalid`` decisions, not silent
  pending rows.
* The eligibility derivation reads ``host_facts.reboot_required``
  and treats null/false as "not required" under ``if_required``.
* Hosts whose execution-host state is not ``succeeded`` are
  represented as ``skipped`` with ``host_did_not_succeed`` (not
  silently omitted).
* Reboot-window context (``reboot_window_id_snapshot``) is recorded
  on every row plus an explicit ``reboot_window_status`` detail
  key so missing window context is structured, not silent.
* Persisted timestamps are absolute UTC (naive datetimes per the
  rest of the patch lifecycle codebase).
* The summary rollup contains every DB-valid state with zero
  counts when absent.

Slice 1 deliberately stops before any real reboot execution —
these tests assert the queue substrate, not the (non-existent)
reboot transport, scheduling, or verification.
"""

from __future__ import annotations

from datetime import datetime
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
    System,
)
from app.services import patch_reboot_service
from app.services.patch_execution_service import (
    EXECUTION_HOST_STATE_FAILED,
    EXECUTION_HOST_STATE_SKIPPED,
    EXECUTION_HOST_STATE_SUCCEEDED,
    EXECUTION_STATE_CANCELED,
    EXECUTION_STATE_FAILED,
    EXECUTION_STATE_RUNNING,
    EXECUTION_STATE_SUCCEEDED,
)
from app.services.patch_reboot_service import (
    REBOOT_DECISION_FACT_NOT_REQUIRED,
    REBOOT_DECISION_HOST_DID_NOT_SUCCEED,
    REBOOT_DECISION_HOST_FACT_REBOOT_REQUIRED,
    REBOOT_DECISION_POLICY_ALWAYS,
    REBOOT_DECISION_POLICY_INVALID,
    REBOOT_DECISION_POLICY_MISSING,
    REBOOT_DECISION_POLICY_NEVER,
    REBOOT_POLICY_ALWAYS,
    REBOOT_POLICY_IF_REQUIRED,
    REBOOT_POLICY_NEVER,
    REBOOT_POLICY_UNKNOWN,
    REBOOT_STATE_NOT_REQUIRED,
    REBOOT_STATE_PENDING,
    REBOOT_STATE_SKIPPED,
    PatchUpdateRebootError,
)
from app.services.patch_update_plan_service import PLAN_STATE_APPROVED

# ---------------------------------------------------------------------------
# Fixtures + minimal-substrate helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="reboot-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="reboot-test-cred",
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
            hostname=f"reboot-host-{counter['n']}.example.com",
            ip_address=f"10.0.94.{counter['n']}",
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


def _make_policy_row(
    db, slug: str, admin_user, *, reboot_policy: str = "if_required"
) -> PatchPolicy:
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


def _make_plan_row(db, policy: PatchPolicy, admin_user, *, reboot_window_id=None):
    from app.db.models import PatchUpdatePlan

    plan = PatchUpdatePlan(
        policy_id=policy.id,
        name=f"plan-{policy.slug}",
        state=PLAN_STATE_APPROVED,
        reboot_window_id=reboot_window_id,
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


def _make_execution_row(
    db,
    plan,
    admin_user,
    *,
    state: str = EXECUTION_STATE_SUCCEEDED,
    policy_snapshot: Optional[dict] = None,
) -> PatchUpdateExecution:
    snap = (
        policy_snapshot
        if policy_snapshot is not None
        else dict(plan.policy_snapshot or {})
    )
    now = datetime.utcnow()
    e = PatchUpdateExecution(
        plan_id=plan.id,
        state=state,
        started_by=admin_user.id,
        started_at=now,
        completed_at=now if state != EXECUTION_STATE_RUNNING else None,
        max_parallel_per_wave=1,
        failure_threshold_percent=None,
        plan_state_snapshot=plan.state,
        policy_snapshot=snap,
        execution_config_snapshot={},
        progress_summary={},
    )
    db.add(e)
    db.flush()
    return e


def _make_execution_host_row(
    db,
    execution,
    system,
    *,
    state: str = EXECUTION_HOST_STATE_SUCCEEDED,
    wave_index: int = 0,
) -> PatchUpdateExecutionHost:
    # Synthesize a plan_host_id by adding a minimal PatchUpdatePlanHost row.
    from app.db.models import PatchUpdatePlanHost

    plan_host = PatchUpdatePlanHost(
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
    db.add(plan_host)
    db.flush()
    host = PatchUpdateExecutionHost(
        execution_id=execution.id,
        plan_host_id=plan_host.id,
        system_id_snapshot=system.id,
        system_hostname_snapshot=system.hostname,
        wave_index=wave_index,
        state=state,
        selected_package_count=1,
        skip_reasons=[],
        error_details={},
    )
    db.add(host)
    db.flush()
    return host


# ---------------------------------------------------------------------------
# reconcile_reboot_queue: gate + policy decisions
# ---------------------------------------------------------------------------


def test_reconcile_refuses_non_terminal_execution(db, admin_user, host_factory):
    pol = _make_policy_row(
        db, "rb-non-terminal", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user, state=EXECUTION_STATE_RUNNING)
    host = host_factory(reboot_required=True)
    _make_execution_host_row(db, execution, host, state=EXECUTION_HOST_STATE_SUCCEEDED)

    with pytest.raises(PatchUpdateRebootError):
        patch_reboot_service.reconcile_reboot_queue(db, execution.id)


def test_reconcile_refuses_unknown_execution(db):
    with pytest.raises(PatchUpdateRebootError) as exc_info:
        patch_reboot_service.reconcile_reboot_queue(db, execution_id=999_999)
    assert "not found" in str(exc_info.value)


def test_reconcile_if_required_with_reboot_required_fact(db, admin_user, host_factory):
    pol = _make_policy_row(
        db, "rb-if-req-yes", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user, reboot_window_id=None)
    execution = _make_execution_row(db, plan, admin_user)
    h = host_factory(reboot_required=True)
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    row = rows[0]
    assert row.state == REBOOT_STATE_PENDING
    assert row.decision_code == REBOOT_DECISION_HOST_FACT_REBOOT_REQUIRED
    assert row.reboot_required_fact is True
    assert row.reboot_policy_snapshot == REBOOT_POLICY_IF_REQUIRED
    # Reboot-window context is "unset" but explicit (not silent).
    assert row.decision_details.get("reboot_window_status") == "unset"
    assert row.reboot_window_id_snapshot is None


def test_reconcile_if_required_with_no_reboot_required_fact(
    db, admin_user, host_factory
):
    pol = _make_policy_row(
        db, "rb-if-req-no", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    h = host_factory(reboot_required=False)
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    row = rows[0]
    assert row.state == REBOOT_STATE_NOT_REQUIRED
    assert row.decision_code == REBOOT_DECISION_FACT_NOT_REQUIRED
    assert row.reboot_required_fact is False


def test_reconcile_if_required_with_null_facts(db, admin_user, host_factory):
    """A succeeded host with no HostFacts row is treated as
    "no signal" — recorded as ``not_required``, not silently
    pending. A later slice may re-evaluate after refreshing facts."""
    pol = _make_policy_row(
        db, "rb-if-req-null", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    h = host_factory(reboot_required=None)  # no HostFacts row
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    assert rows[0].state == REBOOT_STATE_NOT_REQUIRED
    assert rows[0].decision_code == REBOOT_DECISION_FACT_NOT_REQUIRED
    assert rows[0].reboot_required_fact is None


def test_reconcile_always_policy_produces_pending(db, admin_user, host_factory):
    pol = _make_policy_row(
        db, "rb-always", admin_user, reboot_policy=REBOOT_POLICY_ALWAYS
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    h = host_factory(reboot_required=False)
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    row = rows[0]
    assert row.state == REBOOT_STATE_PENDING
    assert row.decision_code == REBOOT_DECISION_POLICY_ALWAYS
    assert row.reboot_policy_snapshot == REBOOT_POLICY_ALWAYS


def test_reconcile_never_policy_produces_skipped(db, admin_user, host_factory):
    pol = _make_policy_row(
        db, "rb-never", admin_user, reboot_policy=REBOOT_POLICY_NEVER
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    h = host_factory(reboot_required=True)  # even with fact=True
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    row = rows[0]
    assert row.state == REBOOT_STATE_SKIPPED
    assert row.decision_code == REBOOT_DECISION_POLICY_NEVER
    assert row.reboot_policy_snapshot == REBOOT_POLICY_NEVER


def test_reconcile_non_succeeded_hosts_are_skipped_not_omitted(
    db, admin_user, host_factory
):
    """Hosts whose execution state is not ``succeeded`` are represented
    as ``skipped`` with ``host_did_not_succeed``, not silently
    omitted from the queue."""
    pol = _make_policy_row(
        db, "rb-mixed", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user, state=EXECUTION_STATE_FAILED)
    h_ok = host_factory(reboot_required=True)
    h_failed = host_factory(reboot_required=True)
    h_skipped = host_factory(reboot_required=None)
    _make_execution_host_row(db, execution, h_ok, state=EXECUTION_HOST_STATE_SUCCEEDED)
    _make_execution_host_row(db, execution, h_failed, state=EXECUTION_HOST_STATE_FAILED)
    _make_execution_host_row(
        db, execution, h_skipped, state=EXECUTION_HOST_STATE_SKIPPED
    )

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 3
    by_sysid = {r.system_id_snapshot: r for r in rows}
    assert by_sysid[h_ok.id].state == REBOOT_STATE_PENDING
    assert by_sysid[h_failed.id].state == REBOOT_STATE_SKIPPED
    assert by_sysid[h_failed.id].decision_code == REBOOT_DECISION_HOST_DID_NOT_SUCCEED
    assert by_sysid[h_skipped.id].state == REBOOT_STATE_SKIPPED
    assert by_sysid[h_skipped.id].decision_code == REBOOT_DECISION_HOST_DID_NOT_SUCCEED


def test_reconcile_missing_policy_snapshot_produces_policy_missing(
    db, admin_user, host_factory
):
    pol = _make_policy_row(
        db, "rb-missing", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)
    # Strip the reboot_policy key from the execution's policy snapshot.
    execution = _make_execution_row(
        db, plan, admin_user, policy_snapshot={"id": pol.id, "slug": pol.slug}
    )
    h = host_factory(reboot_required=True)
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    assert rows[0].state == REBOOT_STATE_SKIPPED
    assert rows[0].decision_code == REBOOT_DECISION_POLICY_MISSING
    assert rows[0].reboot_policy_snapshot == REBOOT_POLICY_UNKNOWN


def test_reconcile_invalid_policy_snapshot_produces_policy_invalid(
    db, admin_user, host_factory
):
    pol = _make_policy_row(
        db, "rb-invalid", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(
        db,
        plan,
        admin_user,
        policy_snapshot={
            "id": pol.id,
            "slug": pol.slug,
            "reboot_policy": "every_other_tuesday",
        },
    )
    h = host_factory(reboot_required=True)
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    assert rows[0].state == REBOOT_STATE_SKIPPED
    assert rows[0].decision_code == REBOOT_DECISION_POLICY_INVALID
    assert rows[0].reboot_policy_snapshot == REBOOT_POLICY_UNKNOWN
    # The raw value is preserved for the operator UI.
    assert rows[0].decision_details.get("reboot_policy_raw") == "every_other_tuesday"


def test_reconcile_records_reboot_window_when_present(db, admin_user, host_factory):
    """Reboot-window context is recorded on every row, including
    ``pending`` rows. When the plan carries a ``reboot_window_id``,
    ``reboot_window_status='set'`` and the id snapshot matches."""
    from app.db.models import MaintenanceWindow

    win = MaintenanceWindow(
        name="weekly-reboot",
        target_type="all",
        target_id=None,
        schedule="{}",
        enabled=True,
        created_by=admin_user.id,
    )
    db.add(win)
    db.flush()

    pol = _make_policy_row(
        db, "rb-window", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user, reboot_window_id=win.id)
    execution = _make_execution_row(db, plan, admin_user)
    h = host_factory(reboot_required=True)
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    assert rows[0].state == REBOOT_STATE_PENDING
    assert rows[0].reboot_window_id_snapshot == win.id
    assert rows[0].decision_details.get("reboot_window_status") == "set"


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_reconcile_is_idempotent_and_refreshes_decision(db, admin_user, host_factory):
    """Running reconcile twice keeps the same row id but updates
    the decision when the host's facts change. Later-slice columns
    (``scheduled_for_at`` / ``started_at`` / ``completed_at``) are
    left untouched so they survive a re-reconcile."""
    pol = _make_policy_row(
        db, "rb-idem", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    h = host_factory(reboot_required=False)
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows) == 1
    first_id = rows[0].id
    assert rows[0].state == REBOOT_STATE_NOT_REQUIRED

    # Simulate a later-slice column write that this slice must preserve.
    scheduled = datetime(2026, 5, 12, 4, 0, 0)
    rows[0].scheduled_for_at = scheduled
    db.commit()

    # Flip the facts and re-run.
    facts = db.query(HostFacts).filter(HostFacts.system_id == h.id).one()
    facts.reboot_required = True
    db.commit()

    rows_b = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    assert len(rows_b) == 1
    assert rows_b[0].id == first_id  # same row, not a duplicate
    assert rows_b[0].state == REBOOT_STATE_PENDING
    assert rows_b[0].decision_code == REBOOT_DECISION_HOST_FACT_REBOOT_REQUIRED
    # Later-slice column preserved.
    assert rows_b[0].scheduled_for_at == scheduled

    # Exactly one row in the DB; no duplicate.
    count = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .count()
    )
    assert count == 1


# ---------------------------------------------------------------------------
# Read API
# ---------------------------------------------------------------------------


def test_get_reboot_queue_returns_summary_and_rows(db, admin_user, host_factory):
    pol = _make_policy_row(
        db, "rb-summary", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(db, plan, admin_user)
    h_pending = host_factory(reboot_required=True)
    h_not_required = host_factory(reboot_required=False)
    h_failed = host_factory(reboot_required=True)
    _make_execution_host_row(
        db, execution, h_pending, state=EXECUTION_HOST_STATE_SUCCEEDED
    )
    _make_execution_host_row(
        db, execution, h_not_required, state=EXECUTION_HOST_STATE_SUCCEEDED
    )
    _make_execution_host_row(db, execution, h_failed, state=EXECUTION_HOST_STATE_FAILED)

    patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    execution_out, rows, summary = patch_reboot_service.get_reboot_queue(
        db, execution.id
    )

    assert execution_out.id == execution.id
    assert len(rows) == 3
    assert summary["row_count"] == 3
    # Every DB-valid state is present in the rollup (zero-valued when absent).
    assert summary["state_counts"][REBOOT_STATE_PENDING] == 1
    assert summary["state_counts"][REBOOT_STATE_NOT_REQUIRED] == 1
    assert summary["state_counts"][REBOOT_STATE_SKIPPED] == 1
    assert summary["state_counts"]["scheduled"] == 0
    assert summary["state_counts"]["rebooting"] == 0
    assert summary["state_counts"]["verifying"] == 0
    assert summary["state_counts"]["healthy"] == 0
    assert summary["state_counts"]["failed"] == 0


def test_list_reboot_rows_for_execution_404s_on_unknown_id(db):
    with pytest.raises(PatchUpdateRebootError) as exc_info:
        patch_reboot_service.list_reboot_rows_for_execution(db, 987_654)
    assert "not found" in str(exc_info.value)


def test_reconcile_persists_timestamps_in_utc(db, admin_user, host_factory):
    """Slice 1 contract: persisted timestamps stay naive (matching
    the rest of the patch lifecycle DB convention), but the
    decision-detail ``evaluated_at`` ISO string is absolute UTC
    (``...Z``) so consumers cannot mistake it for local time."""
    pol = _make_policy_row(db, "rb-utc", admin_user, reboot_policy=REBOOT_POLICY_ALWAYS)
    plan = _make_plan_row(db, pol, admin_user)
    execution = _make_execution_row(
        db, plan, admin_user, state=EXECUTION_STATE_CANCELED
    )
    h = host_factory(reboot_required=False)
    _make_execution_host_row(db, execution, h, state=EXECUTION_HOST_STATE_SUCCEEDED)

    rows = patch_reboot_service.reconcile_reboot_queue(db, execution.id)
    row = rows[0]
    # DB-layer naive-UTC convention preserved.
    assert row.created_at.tzinfo is None
    assert row.updated_at.tzinfo is None
    # Wire-shape decision_details.evaluated_at is absolute UTC.
    evaluated_at = row.decision_details.get("evaluated_at")
    assert isinstance(evaluated_at, str)
    assert evaluated_at.endswith("Z")
    assert "T" in evaluated_at


def test_utc_iso_handles_naive_and_aware_datetimes():
    """The serialization helper appends ``Z`` to naive-UTC
    datetimes and normalizes ``+00:00`` to ``Z`` for tz-aware
    UTC datetimes. ``None`` passes through unchanged so
    nullable columns serialize as JSON null."""
    from datetime import timezone

    assert patch_reboot_service.utc_iso(None) is None

    naive = datetime(2026, 5, 11, 4, 0, 0)
    out = patch_reboot_service.utc_iso(naive)
    assert out is not None
    assert out.endswith("Z")
    assert out.startswith("2026-05-11T04:00:00")

    aware = datetime(2026, 5, 11, 4, 0, 0, tzinfo=timezone.utc)
    out_aware = patch_reboot_service.utc_iso(aware)
    assert out_aware is not None
    assert out_aware.endswith("Z")
    assert "+00:00" not in out_aware


# ---------------------------------------------------------------------------
# Plan-scoped read API
# ---------------------------------------------------------------------------


def test_get_plan_reboot_queue_404s_on_unknown_plan(db):
    with pytest.raises(PatchUpdateRebootError) as exc_info:
        patch_reboot_service.get_plan_reboot_queue(db, plan_id=987_654)
    assert "not found" in str(exc_info.value)


def test_get_plan_reboot_queue_returns_empty_when_no_executions(
    db, admin_user, host_factory
):
    """A plan with no executions started yet returns a zero-count
    aggregate summary and empty executions/rows lists — the read
    surface must not require a prior reconcile to render."""
    pol = _make_policy_row(
        db, "rb-plan-empty", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)

    plan_out, executions, rows, summary = patch_reboot_service.get_plan_reboot_queue(
        db, plan.id
    )
    assert plan_out.id == plan.id
    assert executions == []
    assert rows == []
    assert summary["row_count"] == 0
    assert summary["state_counts"][REBOOT_STATE_PENDING] == 0
    assert summary["state_counts"][REBOOT_STATE_NOT_REQUIRED] == 0
    assert summary["state_counts"][REBOOT_STATE_SKIPPED] == 0


def test_get_plan_reboot_queue_aggregates_across_executions(
    db, admin_user, host_factory
):
    """The aggregate summary rolls across every execution row in
    the plan; per-execution rollups stay accessible via the
    ``executions`` list."""
    pol = _make_policy_row(
        db, "rb-plan-aggr", admin_user, reboot_policy=REBOOT_POLICY_IF_REQUIRED
    )
    plan = _make_plan_row(db, pol, admin_user)

    e_a = _make_execution_row(db, plan, admin_user, state=EXECUTION_STATE_SUCCEEDED)
    h_a = host_factory(reboot_required=True)
    _make_execution_host_row(db, e_a, h_a, state=EXECUTION_HOST_STATE_SUCCEEDED)
    patch_reboot_service.reconcile_reboot_queue(db, e_a.id)

    e_b = _make_execution_row(db, plan, admin_user, state=EXECUTION_STATE_FAILED)
    h_b = host_factory(reboot_required=False)
    h_c = host_factory(reboot_required=True)
    _make_execution_host_row(db, e_b, h_b, state=EXECUTION_HOST_STATE_SUCCEEDED)
    _make_execution_host_row(db, e_b, h_c, state=EXECUTION_HOST_STATE_FAILED)
    patch_reboot_service.reconcile_reboot_queue(db, e_b.id)

    plan_out, executions, rows, summary = patch_reboot_service.get_plan_reboot_queue(
        db, plan.id
    )
    assert plan_out.id == plan.id
    assert len(executions) == 2
    assert summary["row_count"] == 3
    # Across the two executions: one pending (e_a/h_a), one
    # not_required (e_b/h_b), one skipped (e_b/h_c).
    assert summary["state_counts"][REBOOT_STATE_PENDING] == 1
    assert summary["state_counts"][REBOOT_STATE_NOT_REQUIRED] == 1
    assert summary["state_counts"][REBOOT_STATE_SKIPPED] == 1
    # Rows are ordered by (execution_id, wave_index, system_id, id).
    exec_ids = [r.execution_id for r in rows]
    assert exec_ids == sorted(exec_ids)
