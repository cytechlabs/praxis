"""PRA-172 slice 4 — post-reboot health verification tests.

Covers:

* ``verify_due_reboots`` walks ``rebooting`` rows past the grace
  period and transitions them via the verification reason vocabulary.
* Reachable + uptime-reset evidence → ``healthy``.
* Reachable + kernel-changed evidence → ``healthy``.
* Reachable + no pre-reboot baseline → ``healthy`` with the
  reachability-only reason recorded explicitly (no silent pass).
* Reachable + no evidence (baseline present, post matches/exceeds
  pre) → ``failed`` with ``no_reboot_evidence``.
* Unreachable (transport error / timeout / system-deleted) →
  ``failed`` with the matching structured reason.
* Grace period: rows whose ``started_at`` is too recent stay
  ``rebooting``.
* Atomic claim: concurrent verify calls cannot double-probe.
* Re-verification is idempotent: terminal rows are never re-probed.
* Verification-failure threshold pauses mid-batch with structured
  context.
* Audits emit via ``safe_emit`` no ``db=``.
* DB timestamps stay naive UTC.
* Refusal gate for non-terminal executions.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    Package,
    PackageUpdate,
    PatchPolicy,
    PatchUpdateExecutionReboot,
    System,
)
from app.services import (
    patch_execution_service,
    patch_policy_service,
    patch_reboot_service,
    patch_reboot_verify_service,
    patch_update_plan_service,
)
from app.services.patch_reboot_dispatch_service import (
    AUDIT_REBOOT_VERIFICATION_FAILED,
    AUDIT_REBOOT_VERIFICATION_PASSED,
)
from app.services.patch_reboot_service import (
    REBOOT_STATE_FAILED,
    REBOOT_STATE_HEALTHY,
    REBOOT_STATE_REBOOTING,
    PatchUpdateRebootError,
)
from app.services.patch_reboot_verify_service import (
    DEFAULT_GRACE_SECONDS,
    PAUSE_REASON_REBOOT_VERIFY_THRESHOLD_EXCEEDED,
    VERIFY_REASON_KERNEL_CHANGED,
    VERIFY_REASON_NO_BASELINE,
    VERIFY_REASON_NO_REBOOT_EVIDENCE,
    VERIFY_REASON_REACHABILITY_FAILED,
    VERIFY_REASON_SYSTEM_DELETED,
    VERIFY_REASON_TRANSPORT_ERROR,
    VERIFY_REASON_UPTIME_RESET,
    RebootHealthProbeResult,
    verify_due_reboots,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="rb4-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="rb4-test-cred",
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

    def make(*, uptime_seconds=None, kernel_version=None) -> System:
        counter["n"] += 1
        s = System(
            hostname=f"rb4-host-{counter['n']}.example.com",
            ip_address=f"10.0.98.{counter['n']}",
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
                uptime_seconds=uptime_seconds,
                kernel_version=kernel_version,
            )
        )
        db.flush()
        return s

    return make


def _make_policy(db, admin_user, slug: str):
    return patch_policy_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug,
        scope_kind="full",
        rollout_cadence="immediate",
        reboot_policy="always",
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


def _setup_rebooting_row(
    db,
    admin_user,
    host_factory,
    suffix: str,
    *,
    pre_uptime=12345,
    pre_kernel="5.15.0-1.azure",
    started_at_offset_seconds=-120,
    failure_threshold_percent=None,
):
    """Build a complete execution + canceled-then-rebooting-row
    helper. Returns ``(execution, system, row)``."""
    pol = _make_policy(db, admin_user, f"rb4-{suffix}")
    h = _seed_host_with_update(
        db,
        host_factory,
        suffix,
        uptime_seconds=pre_uptime,
        kernel_version=pre_kernel,
    )
    _bind(db, admin_user, pol, h)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name=f"plan-rb4-{suffix}",
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
    patch_execution_service.cancel_execution(
        db, execution.id, actor_user_id=admin_user.id, cancel_reason="t"
    )
    row = (
        db.query(PatchUpdateExecutionReboot)
        .filter(PatchUpdateExecutionReboot.execution_id == execution.id)
        .one()
    )
    row.state = REBOOT_STATE_REBOOTING
    row.started_at = datetime.utcnow() + timedelta(seconds=started_at_offset_seconds)
    row.dispatch_details = {
        "pre_reboot_facts": {
            "system_id": h.id,
            "uptime_seconds": pre_uptime,
            "kernel_version": pre_kernel,
        }
    }
    db.commit()
    return execution, h, row


def _fake_probe(
    *,
    reachable: bool,
    post_uptime=None,
    post_kernel=None,
    reason=None,
    error=None,
) -> Callable:
    def _impl(system, pre_facts):
        post: Dict = {}
        if post_uptime is not None or post_kernel is not None:
            post = {
                "system_id": system.id,
                "uptime_seconds": post_uptime,
                "kernel_version": post_kernel,
            }
        return RebootHealthProbeResult(
            reachable=reachable,
            post_reboot_facts=post,
            reason=reason,
            error=error,
        )

    return _impl


def _capture_audit(monkeypatch) -> List[dict]:
    captured: List[dict] = []
    monkeypatch.setattr(
        patch_reboot_verify_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )
    return captured


# ---------------------------------------------------------------------------
# Refusal gate
# ---------------------------------------------------------------------------


def test_verify_due_refuses_non_terminal_execution(db, admin_user, host_factory):
    pol = _make_policy(db, admin_user, "rb4-non-terminal")
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
    with pytest.raises(PatchUpdateRebootError):
        verify_due_reboots(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            health_check_callable=_fake_probe(reachable=True),
        )


def test_verify_due_refuses_unknown_execution(db, admin_user):
    with pytest.raises(PatchUpdateRebootError) as exc_info:
        verify_due_reboots(
            db,
            execution_id=987_654,
            actor_user_id=admin_user.id,
            health_check_callable=_fake_probe(reachable=True),
        )
    assert "not found" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Success: reboot evidence
# ---------------------------------------------------------------------------


def test_uptime_reset_evidence_transitions_to_healthy(
    db, admin_user, host_factory, monkeypatch
):
    captured = _capture_audit(monkeypatch)
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "up")

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=42, post_kernel="5.15.0-1.azure"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_HEALTHY
    assert row.verified_at is not None
    assert row.verified_at.tzinfo is None  # naive UTC at DB layer
    assert row.verification_details["reason"] == VERIFY_REASON_UPTIME_RESET
    assert row.verification_details["evidence"]["rebooted"] is True
    assert summary.succeeded_count == 1
    actions = [c["action"] for c in captured]
    assert AUDIT_REBOOT_VERIFICATION_PASSED in actions
    for c in captured:
        assert "db" not in c


def test_kernel_change_evidence_transitions_to_healthy(db, admin_user, host_factory):
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "kern")

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        # uptime regressed slightly (counter near zero is hard to
        # express across DB write timing); use kernel change as the
        # primary evidence signal.
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=99999, post_kernel="5.15.0-2.azure"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_HEALTHY
    assert row.verification_details["reason"] == VERIFY_REASON_KERNEL_CHANGED
    assert summary.succeeded_count == 1


def test_reachable_without_baseline_fails_with_no_baseline(
    db, admin_user, host_factory
):
    """PRA-172 Slice 4a: missing pre-reboot facts
    baseline is a structured FAILURE, not a success. Reachability
    alone is not proof of reboot — without a baseline to compare,
    the verifier marks the row ``failed`` with ``no_baseline`` so
    operators can investigate / re-establish the facts baseline."""
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "no-base")
    # Wipe the baseline.
    row.dispatch_details = {"pre_reboot_facts": {}}
    db.commit()

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        # Probe reaches the host AND returns fresh facts — but
        # without a pre-reboot baseline, those facts can't prove
        # anything, so the verifier still fails the row.
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=10, post_kernel="any"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.verification_details["reason"] == VERIFY_REASON_NO_BASELINE
    assert summary.failed_count == 1


def test_reachable_with_null_baseline_fields_fails_with_no_baseline(
    db, admin_user, host_factory
):
    """Even when the dispatcher recorded a ``pre_reboot_facts``
    dict, if every comparable field (uptime + kernel) is null
    that's effectively no baseline — verifier fails with
    ``no_baseline`` rather than passing on reachability alone."""
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "null-base")
    row.dispatch_details = {
        "pre_reboot_facts": {
            "system_id": row.system_id_snapshot,
            "uptime_seconds": None,
            "kernel_version": None,
        }
    }
    db.commit()

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=10, post_kernel="x"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.verification_details["reason"] == VERIFY_REASON_NO_BASELINE
    assert summary.failed_count == 1


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


def test_no_reboot_evidence_transitions_to_failed(db, admin_user, host_factory):
    """Reachable + facts say uptime did NOT reset and kernel did
    NOT change → ``no_reboot_evidence`` failure."""
    execution, _h, row = _setup_rebooting_row(
        db,
        admin_user,
        host_factory,
        "no-evid",
        pre_uptime=10_000,
        pre_kernel="5.15.0-1.azure",
    )

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=20_000, post_kernel="5.15.0-1.azure"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.verification_details["reason"] == VERIFY_REASON_NO_REBOOT_EVIDENCE
    assert summary.failed_count == 1


def test_reachability_failure_transitions_to_failed(
    db, admin_user, host_factory, monkeypatch
):
    captured = _capture_audit(monkeypatch)
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "unreach")

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=False,
            reason=VERIFY_REASON_REACHABILITY_FAILED,
            error="connection refused",
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.verification_details["reason"] == VERIFY_REASON_REACHABILITY_FAILED
    assert summary.failed_count == 1
    actions = [c["action"] for c in captured]
    assert AUDIT_REBOOT_VERIFICATION_FAILED in actions


def test_deleted_system_produces_structured_failure(db, admin_user, host_factory):
    execution, h, row = _setup_rebooting_row(db, admin_user, host_factory, "del")
    # Delete the system; the snapshot stays on the row but the
    # System table no longer resolves.
    db.delete(h)
    db.commit()

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(reachable=True),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.verification_details["reason"] == VERIFY_REASON_SYSTEM_DELETED
    assert summary.failed_count == 1


def test_probe_callable_exception_is_coerced_to_transport_error(
    db, admin_user, host_factory
):
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "boom")

    def _boom(system, pre):
        raise RuntimeError("probe blew up")

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_boom,
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.verification_details["reason"] == VERIFY_REASON_TRANSPORT_ERROR
    assert summary.failed_count == 1


# ---------------------------------------------------------------------------
# Grace-period filter
# ---------------------------------------------------------------------------


def test_grace_period_holds_recent_rebooting_rows(db, admin_user, host_factory):
    """A row whose ``started_at`` is inside the grace window must
    stay ``rebooting``."""
    execution, _h, row = _setup_rebooting_row(
        db,
        admin_user,
        host_factory,
        "grace",
        started_at_offset_seconds=-5,  # 5s ago, inside 60s grace
    )

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=10, post_kernel="x"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_REBOOTING
    assert summary.no_due is True
    assert summary.not_due_count == 1


def test_grace_period_can_be_overridden(db, admin_user, host_factory):
    """An explicit ``grace_seconds=0`` lets operators verify
    immediately. Useful for tests + future operator overrides."""
    execution, _h, row = _setup_rebooting_row(
        db,
        admin_user,
        host_factory,
        "no-grace",
        started_at_offset_seconds=-1,
    )

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        grace_seconds=0,
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=5, post_kernel="x"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_HEALTHY
    assert summary.succeeded_count == 1


# ---------------------------------------------------------------------------
# Atomic claim concurrency
# ---------------------------------------------------------------------------


def test_concurrent_verify_claims_row_only_once(db, admin_user, host_factory):
    """Atomic claim: two back-to-back ``verify_due_reboots`` calls
    against the same ``rebooting`` row probe exactly ONCE in
    total. Simulates the race by issuing the second call from
    inside the first call's probe — exactly the window where the
    row is loaded but not yet claimed by the outer caller."""
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "race")

    call_count = {"n": 0}

    def _double_probe(system, pre):
        call_count["n"] += 1
        nested = verify_due_reboots(
            db,
            execution.id,
            actor_user_id=admin_user.id,
            health_check_callable=_double_probe,
        )
        assert (
            nested.verified_count == 0
        ), "concurrent verify must skip already-claimed rows"
        return RebootHealthProbeResult(
            reachable=True,
            post_reboot_facts={
                "uptime_seconds": 10,
                "kernel_version": pre.get("kernel_version"),
            },
        )

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_double_probe,
    )
    assert summary.verified_count == 1
    assert call_count["n"] == 1, "probe must run exactly once"
    db.refresh(row)
    assert row.state == REBOOT_STATE_HEALTHY


# ---------------------------------------------------------------------------
# Idempotent re-verify
# ---------------------------------------------------------------------------


def test_healthy_row_is_not_re_verified(db, admin_user, host_factory):
    """Once a row is ``healthy``, a subsequent verify-due call must
    not re-probe it. The verify filter is strictly
    ``state == rebooting AND started_at <= now - grace``."""
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "ok-idem")

    verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=10, post_kernel="x"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_HEALTHY
    first_verified_at = row.verified_at

    second = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=10, post_kernel="x"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_HEALTHY
    assert row.verified_at == first_verified_at
    assert second.no_due is True


def test_failed_row_is_not_re_verified(db, admin_user, host_factory):
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "fail-idem")

    verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=False, reason=VERIFY_REASON_REACHABILITY_FAILED, error="x"
        ),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    first_verified_at = row.verified_at

    second = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(reachable=True),
    )
    db.refresh(row)
    assert row.state == REBOOT_STATE_FAILED
    assert row.verified_at == first_verified_at
    assert second.no_due is True


# ---------------------------------------------------------------------------
# Threshold pause
# ---------------------------------------------------------------------------


def test_threshold_pause_stops_verify_mid_batch(db, admin_user, host_factory):
    """Failing every verify with threshold=0% must stop the batch
    after the first failure; remaining due rows stay ``rebooting``."""
    pol = _make_policy(db, admin_user, "rb4-thresh-pause")
    h_a = _seed_host_with_update(
        db, host_factory, "ta", uptime_seconds=10000, kernel_version="kA"
    )
    h_b = _seed_host_with_update(
        db, host_factory, "tb", uptime_seconds=10000, kernel_version="kA"
    )
    _bind(db, admin_user, pol, h_a)
    _bind(db, admin_user, pol, h_b)
    plan = patch_update_plan_service.create_plan(
        db,
        actor_user_id=admin_user.id,
        policy_id=pol.id,
        name="p-rb4-thresh",
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
    past = datetime.utcnow() - timedelta(seconds=120)
    for r in rows:
        r.state = REBOOT_STATE_REBOOTING
        r.started_at = past
        r.dispatch_details = {
            "pre_reboot_facts": {
                "uptime_seconds": 10000,
                "kernel_version": "kA",
            }
        }
    db.commit()

    summary = verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=False, reason=VERIFY_REASON_REACHABILITY_FAILED, error="x"
        ),
    )
    assert summary.verified_count == 1
    assert summary.failed_count == 1
    assert summary.pause_reason == PAUSE_REASON_REBOOT_VERIFY_THRESHOLD_EXCEEDED
    assert summary.threshold_pause is not None
    assert summary.threshold_pause["code"] == (
        PAUSE_REASON_REBOOT_VERIFY_THRESHOLD_EXCEEDED
    )
    states = sorted([rows[0].state for rows in [rows]] + [])
    db.refresh(rows[0])
    db.refresh(rows[1])
    by_state = sorted([rows[0].state, rows[1].state])
    assert by_state == [REBOOT_STATE_FAILED, REBOOT_STATE_REBOOTING]


# ---------------------------------------------------------------------------
# UTC wire shape — DB columns stay naive; service writes
# ``verified_at`` ISO via the existing utc_iso helper.
# ---------------------------------------------------------------------------


def test_verification_details_records_utc_z_timestamps(db, admin_user, host_factory):
    execution, _h, row = _setup_rebooting_row(db, admin_user, host_factory, "utc")

    verify_due_reboots(
        db,
        execution.id,
        actor_user_id=admin_user.id,
        health_check_callable=_fake_probe(
            reachable=True, post_uptime=10, post_kernel="x"
        ),
    )
    db.refresh(row)
    assert isinstance(row.verification_details, dict)
    assert row.verification_details["verified_at"].endswith("Z")
    # DB-layer convention preserved.
    assert row.verified_at.tzinfo is None
