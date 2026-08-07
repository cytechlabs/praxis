"""PRA-176 Slice 2 — dispatch_attempt service tests.

Covers:

* Happy-path dispatch for each executable plan kind (install / remove /
  upgrade) with a fake ``DispatchCallable`` that records the argv it
  receives.
* Argv shape per kind: apt-install pins to version for upgrade; remove
  uses ``apt-get remove -y``; install with no version target installs
  the bare package name.
* State transitions ``pending → dispatched → succeeded|failed`` with
  ``dispatched_at`` / ``completed_at`` populated.
* Outcome columns persisted: transport, exit_code, duration_ms,
  bounded stdout/stderr, failure_reason for failed dispatches.
* Audit events ``compliance_remediation_execution.dispatched`` and
  ``.succeeded`` / ``.failed`` fire via ``safe_emit`` AFTER commit
  with no ``db=`` (session-boundary lock).
* Readiness gate re-checks at dispatch time and refuses superseded /
  unacknowledged / stale / non-package / non-approved-source plans
  with the same distinct messages as create_attempt.
* Lineage drift refusals: missing plan id, deleted plan, mismatched
  request_id, plan_kind drift.
* Package-identifier refusals: missing package_name, missing/invalid
  version target for upgrade, unsafe package_name characters.
* Host-derivation refusals: missing/unknown package-manager family.
* Non-``pending`` attempt refusals: already-succeeded / already-failed
  / already-dispatched attempts cannot be re-dispatched.
* Transport error paths: structured ``transport_unavailable`` /
  ``transport_error`` codes from the adapter are written verbatim;
  adapter raising is caught and recorded as a ``transport_error``.
* No-local-fallback property: when the adapter returns
  ``transport_unavailable`` the attempt lands in ``failed`` with the
  exact code; no second dispatch attempt occurs.
* Compatibility: PRA-167 read envelopes are unchanged after a
  successful dispatch.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

import pytest

from app.db.models import (
    CompliancePolicyEvidence,
    Credential,
    Group,
    HostFacts,
    Package,
    System,
)
from app.services import (
    compliance_evaluation_service,
    compliance_remediation_execution_service,
    compliance_remediation_plan_service,
    compliance_remediation_service,
    compliance_service,
)
from app.services.compliance_remediation_execution_service import (
    AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_DISPATCHED,
    AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_FAILED,
    AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED,
    STATE_FAILED,
    STATE_SUCCEEDED,
    ComplianceError,
)
from app.services.patch_execution_dispatch_service import (
    ERROR_CODE_PACKAGE_MANAGER_FAILED,
    ERROR_CODE_TRANSPORT_ERROR,
    ERROR_CODE_TRANSPORT_UNAVAILABLE,
    DispatchResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class AuditCapture:
    def __init__(self):
        self.calls: List[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

    def by_action(self, action):
        return [c for c in self.calls if c["action"] == action]

    def actions(self):
        return [c["action"] for c in self.calls]


@pytest.fixture
def capture_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_remediation_execution_service, "safe_emit", cap)
    return cap


class RecordingDispatch:
    """Fake DispatchCallable that records the (system, cmd) calls and
    returns a queued DispatchResult per call. Allows tests to assert
    on the argv built by the service and to inject transport/PM
    outcomes without touching real SSH/agent code.
    """

    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, system, cmd):
        self.calls.append({"system_id": system.id, "cmd": list(cmd)})
        if not self.results:
            return DispatchResult(exit_code=0, transport_name="fake")
        return self.results.pop(0)


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra176d-host", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra176d-host-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra176d.example.com",
        ip_address="10.0.0.178",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    # Seed an apt-family HostFacts row so the package-manager family
    # resolver returns ``apt``. Tests that need ``dnf`` overwrite.
    db.add(
        HostFacts(
            system_id=sys_row.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="agent",
            distro_id_facts="ubuntu",
            package_manager="apt",
        )
    )
    db.flush()
    return sys_row


def _make_acknowledged_attempt(
    db,
    admin_user,
    maintainer_user,
    host,
    *,
    suffix: str,
    check_kind: str = "package_installed",
    definition: dict | None = None,
    pre_seed=None,
):
    """Build the full PRA-167 chain + Slice 1 attempt creation.
    Returns ``(policy, check, request, plan, attempt)``.
    """
    definition = definition or {"package": f"missing-{suffix}"}
    if pre_seed:
        pre_seed(db, host)
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"dx-{suffix}",
        name=f"dx {suffix}",
    )
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"c-{suffix}",
        title=f"c {suffix}",
        kind=check_kind,
        definition=definition,
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    evidence = (
        db.query(CompliancePolicyEvidence)
        .filter(
            CompliancePolicyEvidence.policy_id == policy.id,
            CompliancePolicyEvidence.system_id == host.id,
            CompliancePolicyEvidence.verdict == "fail",
        )
        .order_by(CompliancePolicyEvidence.id.desc())
        .first()
    )
    assert evidence is not None
    req = compliance_remediation_service.create_request(
        db, actor_user_id=maintainer_user.id, evidence_id=evidence.id
    )
    compliance_remediation_service.approve_request(
        db, req.id, actor_user_id=admin_user.id
    )
    plan = compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    compliance_remediation_plan_service.acknowledge_plan(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    attempt = compliance_remediation_execution_service.create_attempt(
        db, plan_id=plan.id, actor_user_id=admin_user.id
    )
    return policy, check, req, plan, attempt


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_dispatch_install_happy_path_apt(
    db, admin_user, maintainer_user, host, capture_audit
):
    _, _, _, plan, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="install-apt"
    )
    dispatcher = RecordingDispatch(
        [
            DispatchResult(
                exit_code=0,
                stdout="installed missing-install-apt\n",
                stderr="",
                duration_ms=1234,
                transport_name="ssh",
            )
        ]
    )
    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        actor_username="admintest",
        actor_ip="10.0.0.5",
        dispatch_callable=dispatcher,
    )
    assert out.state == STATE_SUCCEEDED
    assert out.transport == "ssh"
    assert out.exit_code == 0
    assert out.duration_ms == 1234
    assert out.stdout_summary == "installed missing-install-apt\n"
    assert out.stderr_summary is None
    assert isinstance(out.dispatched_at, datetime)
    assert isinstance(out.completed_at, datetime)
    assert out.dispatched_at <= out.completed_at
    assert out.failure_reason is None
    assert out.error_message is None
    # Argv built correctly for apt install (no version pin).
    assert len(dispatcher.calls) == 1
    cmd = dispatcher.calls[0]["cmd"]
    assert cmd[:4] == ["apt-get", "install", "-y", "--no-install-recommends"]
    assert "missing-install-apt" in cmd
    # Audit lineage.
    actions = capture_audit.actions()
    assert AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_DISPATCHED in actions
    assert AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED in actions
    succ = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED)
    assert len(succ) == 1
    assert "db" not in succ[0]
    assert succ[0]["target_kind"] == "compliance_remediation_execution_attempt"
    assert succ[0]["target_id"] == str(out.id)
    assert succ[0]["context"]["exit_code"] == 0
    assert succ[0]["context"]["transport"] == "ssh"
    assert succ[0]["context"]["package_family"] == "apt"


def test_dispatch_remove_happy_path_apt(db, admin_user, maintainer_user, host):
    def pre_seed(db, host):
        db.add(
            Package(
                system_id=host.id,
                name="rm-pkg-2",
                installed_version="1.0",
                package_type="apt",
            )
        )
        db.flush()

    _, _, _, _, attempt = _make_acknowledged_attempt(
        db,
        admin_user,
        maintainer_user,
        host,
        suffix="remove-apt",
        check_kind="package_absent",
        definition={"package": "rm-pkg-2"},
        pre_seed=pre_seed,
    )
    dispatcher = RecordingDispatch(
        [DispatchResult(exit_code=0, transport_name="agent", duration_ms=42)]
    )
    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert out.state == STATE_SUCCEEDED
    assert out.plan_kind_snapshot == "package_remove_preview"
    assert dispatcher.calls[0]["cmd"] == ["apt-get", "remove", "-y", "rm-pkg-2"]


def test_dispatch_upgrade_pins_to_parsed_version_apt(
    db, admin_user, maintainer_user, host
):
    def pre_seed(db, host):
        db.add(
            Package(
                system_id=host.id,
                name="up-pkg",
                installed_version="0.1",
                package_type="apt",
            )
        )
        db.flush()

    _, _, _, _, attempt = _make_acknowledged_attempt(
        db,
        admin_user,
        maintainer_user,
        host,
        suffix="upgrade-apt",
        check_kind="package_version_min",
        definition={"package": "up-pkg", "min_version": "2.3.4"},
        pre_seed=pre_seed,
    )
    # Sanity: Slice 1 stored the upgrade target.
    assert attempt.package_version_target == ">= 2.3.4"
    dispatcher = RecordingDispatch([DispatchResult(exit_code=0, transport_name="ssh")])
    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert out.state == STATE_SUCCEEDED
    cmd = dispatcher.calls[0]["cmd"]
    assert "up-pkg=2.3.4" in cmd
    assert cmd[:4] == ["apt-get", "install", "-y", "--no-install-recommends"]


def test_dispatch_install_uses_dnf_when_facts_say_rhel(
    db, admin_user, maintainer_user, host
):
    # Replace the apt HostFacts seeded by the fixture with a dnf row.
    db.query(HostFacts).filter(HostFacts.system_id == host.id).delete()
    db.add(
        HostFacts(
            system_id=host.id,
            schema_version=1,
            collected_at=datetime.utcnow(),
            source_transport="agent",
            distro_id_facts="rhel",
            package_manager="dnf",
        )
    )
    db.flush()
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="install-dnf"
    )
    dispatcher = RecordingDispatch(
        [DispatchResult(exit_code=0, transport_name="agent")]
    )
    compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert dispatcher.calls[0]["cmd"][:3] == ["dnf", "install", "-y"]


# ---------------------------------------------------------------------------
# Failure outcomes — package-manager nonzero exit, transport unavailable,
# adapter raises
# ---------------------------------------------------------------------------


def test_dispatch_records_package_manager_failure(
    db, admin_user, maintainer_user, host, capture_audit
):
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="pmfail"
    )
    dispatcher = RecordingDispatch(
        [
            DispatchResult(
                exit_code=100,
                stdout="",
                stderr="E: Unable to locate package missing-pmfail\n",
                duration_ms=37,
                transport_name="ssh",
            )
        ]
    )
    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert out.state == STATE_FAILED
    assert out.failure_reason == ERROR_CODE_PACKAGE_MANAGER_FAILED
    assert out.exit_code == 100
    assert out.error_message and "Unable to locate package" in out.error_message
    failed = capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_FAILED)
    assert len(failed) == 1
    assert failed[0]["context"]["exit_code"] == 100
    assert failed[0]["context"]["failure_reason"] == ERROR_CODE_PACKAGE_MANAGER_FAILED


def test_dispatch_records_transport_unavailable_no_local_fallback(
    db, admin_user, maintainer_user, host, capture_audit
):
    """When the transport is unavailable, the attempt fails closed with
    the exact ``transport_unavailable`` code. There must be no second
    dispatch call (no local-fallback behavior)."""
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="tunavail"
    )
    dispatcher = RecordingDispatch(
        [
            DispatchResult(
                exit_code=-1,
                error=ERROR_CODE_TRANSPORT_UNAVAILABLE,
                stderr="no transport available",
            )
        ]
    )
    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert out.state == STATE_FAILED
    assert out.failure_reason == ERROR_CODE_TRANSPORT_UNAVAILABLE
    assert out.exit_code == -1
    # No fallback — exactly one dispatch call attempted.
    assert len(dispatcher.calls) == 1
    # .succeeded must NOT fire.
    assert not capture_audit.by_action(AUDIT_COMPLIANCE_REMEDIATION_EXECUTION_SUCCEEDED)


def test_dispatch_records_adapter_exception_as_transport_error(
    db, admin_user, maintainer_user, host
):
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="adapterboom"
    )

    def boom(_system, _cmd):
        raise RuntimeError("transport adapter exploded")

    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=boom,
    )
    assert out.state == STATE_FAILED
    assert out.failure_reason == ERROR_CODE_TRANSPORT_ERROR
    assert out.error_message and "transport adapter exploded" in out.error_message


# ---------------------------------------------------------------------------
# Readiness gate re-check at dispatch time
# ---------------------------------------------------------------------------


def test_dispatch_refuses_superseded_plan_at_dispatch_time(
    db, admin_user, maintainer_user, host
):
    _, check, req, plan, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="dispsupr"
    )
    # Supersede the plan AFTER attempt creation but BEFORE dispatch.
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "v2"}},
        actor_user_id=admin_user.id,
    )
    compliance_remediation_plan_service.build_or_refresh_plan(
        db, request_id=req.id, actor_user_id=admin_user.id
    )
    db.refresh(plan)
    assert plan.superseded_by_plan_id is not None
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "superseded" in str(ei.value)


def test_dispatch_refuses_when_source_request_no_longer_approved(
    db, admin_user, maintainer_user, host
):
    _, _, req, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="dispnotapp"
    )
    # Mutate the request state to simulate out-of-band rejection.
    req.state = "rejected"
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "no longer approved" in str(ei.value)


def test_dispatch_refuses_stale_plan_after_check_drift(
    db, admin_user, maintainer_user, host
):
    _, check, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="dispstale"
    )
    # Mutate the live check without rebuilding — stale.
    compliance_service.update_check(
        db,
        check.id,
        {"definition": {"package": "different-pkg"}},
        actor_user_id=admin_user.id,
    )
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "stale" in str(ei.value)


# ---------------------------------------------------------------------------
# Lineage drift refusals
# ---------------------------------------------------------------------------


def test_dispatch_refuses_unknown_attempt_id(db, admin_user):
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=999_999, actor_user_id=admin_user.id
        )
    assert "not found" in str(ei.value)


def test_dispatch_refuses_non_pending_attempt(db, admin_user, maintainer_user, host):
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="alreadysucceeded"
    )
    dispatcher = RecordingDispatch([DispatchResult(exit_code=0, transport_name="fake")])
    compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    db.refresh(attempt)
    assert attempt.state == STATE_SUCCEEDED
    # Re-dispatch must fail closed.
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db,
            attempt_id=attempt.id,
            actor_user_id=admin_user.id,
            dispatch_callable=dispatcher,
        )
    assert "'pending'" in str(ei.value)


def test_dispatch_refuses_null_plan_id(db, admin_user, maintainer_user, host):
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="nullplan"
    )
    attempt.plan_id = None
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "plan_id is null" in str(ei.value)


def test_dispatch_refuses_request_lineage_mismatch(
    db, admin_user, maintainer_user, host
):
    # Build two independent acknowledged attempts; swap the first
    # attempt's request_id to the second attempt's request_id. Both
    # FKs are valid so we hit the service-layer lineage check rather
    # than a DB FK violation.
    _, _, _, _, attempt_a = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="lineage-a"
    )
    _, _, req_b, _, _ = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="lineage-b"
    )
    assert attempt_a.request_id != req_b.id
    attempt_a.request_id = req_b.id
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt_a.id, actor_user_id=admin_user.id
        )
    assert "request_id" in str(ei.value)


def test_dispatch_refuses_plan_kind_drift(db, admin_user, maintainer_user, host):
    _, _, _, plan, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="kinddrift"
    )
    # Stamp the attempt with a different kind than the plan currently has.
    attempt.plan_kind_snapshot = "package_remove_preview"
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "plan_kind" in str(ei.value)


# ---------------------------------------------------------------------------
# Package-identifier refusals
# ---------------------------------------------------------------------------


def test_dispatch_refuses_missing_package_name(db, admin_user, maintainer_user, host):
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="nopkg"
    )
    attempt.package_name = None
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "package_name" in str(ei.value)


def test_dispatch_refuses_unsafe_package_name(db, admin_user, maintainer_user, host):
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="unsafepkg"
    )
    attempt.package_name = "pkg; rm -rf /"
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "unsafe" in str(ei.value)


def test_dispatch_refuses_missing_version_target_for_upgrade(
    db, admin_user, maintainer_user, host
):
    def pre_seed(db, host):
        db.add(
            Package(
                system_id=host.id,
                name="upver",
                installed_version="0.1",
                package_type="apt",
            )
        )
        db.flush()

    _, _, _, _, attempt = _make_acknowledged_attempt(
        db,
        admin_user,
        maintainer_user,
        host,
        suffix="upmissver",
        check_kind="package_version_min",
        definition={"package": "upver", "min_version": "9.9.9"},
        pre_seed=pre_seed,
    )
    # Strip the version target so the parser can't recover it.
    attempt.package_version_target = None
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "missing" in str(ei.value) or "package_version_target" in str(ei.value)


def test_dispatch_refuses_unparsable_version_target_for_upgrade(
    db, admin_user, maintainer_user, host
):
    def pre_seed(db, host):
        db.add(
            Package(
                system_id=host.id,
                name="upver2",
                installed_version="0.1",
                package_type="apt",
            )
        )
        db.flush()

    _, _, _, _, attempt = _make_acknowledged_attempt(
        db,
        admin_user,
        maintainer_user,
        host,
        suffix="upbadver",
        check_kind="package_version_min",
        definition={"package": "upver2", "min_version": "2.3.4"},
        pre_seed=pre_seed,
    )
    # Mutate to a different operator that the parser must reject.
    attempt.package_version_target = "< 2.3.4"
    db.commit()
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "'>= <version>'" in str(ei.value)


# ---------------------------------------------------------------------------
# Host-family refusal
# ---------------------------------------------------------------------------


def test_dispatch_refuses_unknown_package_family(db, admin_user, maintainer_user, host):
    # Remove HostFacts so the resolver returns 'unknown'.
    db.query(HostFacts).filter(HostFacts.system_id == host.id).delete()
    db.commit()
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="nofam"
    )
    with pytest.raises(ComplianceError) as ei:
        compliance_remediation_execution_service.dispatch_attempt(
            db, attempt_id=attempt.id, actor_user_id=admin_user.id
        )
    assert "unknown" in str(ei.value)


# ---------------------------------------------------------------------------
# Read envelope + compatibility
# ---------------------------------------------------------------------------


def test_read_envelope_includes_outcome_fields(db, admin_user, maintainer_user, host):
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="envelope"
    )
    dispatcher = RecordingDispatch(
        [
            DispatchResult(
                exit_code=0,
                stdout="ok",
                stderr="warn",
                duration_ms=99,
                transport_name="ssh",
            )
        ]
    )
    compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    db.refresh(attempt)
    env = compliance_remediation_execution_service.attempt_read_envelope(attempt)
    assert env["state"] == "succeeded"
    assert env["transport"] == "ssh"
    assert env["exit_code"] == 0
    assert env["duration_ms"] == 99
    assert env["stdout_summary"] == "ok"
    assert env["stderr_summary"] == "warn"
    assert env["dispatched_at"].endswith("Z")
    assert env["completed_at"].endswith("Z")


def test_dispatch_truncates_long_stdout(db, admin_user, maintainer_user, host):
    _, _, _, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="bigout"
    )
    big = "x" * (80 * 1024)  # > MAX_OUTPUT_BYTES (64 KiB)
    dispatcher = RecordingDispatch(
        [DispatchResult(exit_code=0, stdout=big, transport_name="ssh")]
    )
    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    assert out.stdout_summary is not None
    assert len(out.stdout_summary.encode("utf-8")) < len(big.encode("utf-8"))
    assert "truncated" in out.stdout_summary


def test_pra167_plan_envelope_unchanged_after_dispatch(
    db, admin_user, maintainer_user, host
):
    _, _, _, plan, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="plancompat"
    )
    before = compliance_remediation_plan_service.remediation_plan_read_envelope(
        plan, db=db
    )
    dispatcher = RecordingDispatch([DispatchResult(exit_code=0, transport_name="fake")])
    compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    db.refresh(plan)
    after = compliance_remediation_plan_service.remediation_plan_read_envelope(
        plan, db=db
    )
    assert before == after


def test_pra167_request_envelope_unchanged_after_dispatch(
    db, admin_user, maintainer_user, host
):
    _, _, req, _, attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="reqcompat"
    )
    before = compliance_remediation_service.remediation_request_read_envelope(req)
    dispatcher = RecordingDispatch([DispatchResult(exit_code=0, transport_name="fake")])
    compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=dispatcher,
    )
    db.refresh(req)
    after = compliance_remediation_service.remediation_request_read_envelope(req)
    assert before == after
