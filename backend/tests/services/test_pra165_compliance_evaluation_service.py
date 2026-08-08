"""PRA-165 Slice 2 + PRA-166 Slice 1 — compliance evaluation runner tests.

Covers:

* Per-kind verdicts for the six runnable kinds (``package_installed``,
  ``package_absent``, ``package_version_min``, ``fact_equals``,
  ``fact_present``, ``fact_absent``) — pass / fail / error.
* File and command kinds now route through the PRA-166 probe runner
  (see ``test_pra166_compliance_probe_runner.py``). The PRA-165
  tripwires that asserted the legacy ``REASON_DEFERRED_PRA166`` path
  are replaced with bridge tests confirming the probe runner is
  invoked and its outcome flows into the evidence row unchanged.
* Evidence rows snapshot policy slug / version / check identity / severity.
* Disabled checks/policies are skipped (no evidence rows).
* ``list_due_policies`` selects NULL ``last_run_at`` + over-interval rows.
* ``evaluate_due_policies`` stamps ``last_run_at`` and skips
  not-yet-due policies.
* ``retain_evidence`` honors ``evidence_retention_days`` per policy.
* Audit emission uses ``safe_emit`` AFTER commit, no ``db=``.
* Non-execution guard: no SSH/file/command/package_scan/facts_refresh
  module call sites are tripped during a Slice 2 (package/fact) sweep.
"""

from __future__ import annotations

from datetime import datetime, timedelta

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
    compliance_probe_runner_service,
    compliance_service,
)
from app.services.compliance_evaluation_service import (
    AUDIT_COMPLIANCE_EVALUATION_RUN,
    AUDIT_COMPLIANCE_EVIDENCE_PERSISTED,
    AUDIT_COMPLIANCE_EVIDENCE_RETAINED,
    REASON_FACT_KEY_UNMAPPED,
    REASON_FACT_VALUE_NULL,
    REASON_NO_HOST_FACTS,
    REASON_PACKAGE_INSTALLED,
    REASON_PACKAGE_NOT_INSTALLED,
    REASON_VERSION_MISMATCH,
    REASON_VERSION_UNPARSEABLE,
    VERDICT_ERROR,
    VERDICT_FAIL,
    VERDICT_PASS,
    EvaluationSummary,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class AuditCapture:
    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)

    def actions(self):
        return [c["action"] for c in self.calls]

    def by_action(self, action):
        return [c for c in self.calls if c["action"] == action]


@pytest.fixture
def capture_audit(monkeypatch):
    cap = AuditCapture()
    monkeypatch.setattr(compliance_evaluation_service, "safe_emit", cap)
    return cap


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra165-eval", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra165-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="eval-host.example.com",
        ip_address="10.0.0.51",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _make_policy(db, admin_user, slug="p1", **overrides):
    return compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug.upper(),
        **overrides,
    )


def _add_check(db, admin_user, policy, slug, kind, definition, **overrides):
    return compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=slug,
        title=slug,
        kind=kind,
        definition=definition,
        **overrides,
    )


def _install_package(db, system_id, name, version, package_type="apt"):
    pkg = Package(
        system_id=system_id,
        name=name,
        installed_version=version,
        package_type=package_type,
    )
    db.add(pkg)
    db.flush()
    return pkg


def _set_host_facts(db, system_id, **fields):
    row = HostFacts(
        system_id=system_id,
        schema_version=1,
        collected_at=datetime.utcnow(),
        source_transport="agent",
        **fields,
    )
    db.add(row)
    db.flush()
    return row


def _evidence_rows(db, *, policy_id=None, system_id=None):
    q = db.query(CompliancePolicyEvidence)
    if policy_id is not None:
        q = q.filter(CompliancePolicyEvidence.policy_id == policy_id)
    if system_id is not None:
        q = q.filter(CompliancePolicyEvidence.system_id == system_id)
    return q.order_by(CompliancePolicyEvidence.id.asc()).all()


# ---------------------------------------------------------------------------
# Package kinds
# ---------------------------------------------------------------------------


def test_package_installed_pass(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="pkg-pass")
    _add_check(
        db,
        admin_user,
        policy,
        "openssh-installed",
        "package_installed",
        {"package": "openssh-server"},
    )
    _install_package(db, host.id, "openssh-server", "1:9.0p1-1ubuntu1")

    summary = compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    assert isinstance(summary, EvaluationSummary)
    assert summary.counts == {VERDICT_PASS: 1, VERDICT_FAIL: 0, VERDICT_ERROR: 0}
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_PASS
    assert row.policy_slug == "pkg-pass"
    assert row.policy_version == policy.version
    assert row.check_slug == "openssh-installed"
    assert row.check_kind == "package_installed"
    assert row.observed_value == "1:9.0p1-1ubuntu1"
    assert row.severity == policy.severity


def test_package_installed_fail(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="pkg-fail")
    _add_check(
        db,
        admin_user,
        policy,
        "openssh",
        "package_installed",
        {"package": "openssh-server"},
    )
    summary = compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_FAIL
    assert row.verdict_reason == REASON_PACKAGE_NOT_INSTALLED
    assert summary.counts[VERDICT_FAIL] == 1


def test_package_absent_pass(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="abs-pass")
    _add_check(
        db, admin_user, policy, "telnet-gone", "package_absent", {"package": "telnet"}
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_PASS
    assert row.observed_value == "absent"


def test_package_absent_fail(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="abs-fail")
    _add_check(
        db, admin_user, policy, "telnet-here", "package_absent", {"package": "telnet"}
    )
    _install_package(db, host.id, "telnet", "0.17-44build1")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_FAIL
    assert row.verdict_reason == REASON_PACKAGE_INSTALLED
    assert row.observed_value == "0.17-44build1"


def test_package_version_min_pass(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="vmin-pass")
    _add_check(
        db,
        admin_user,
        policy,
        "openssl-min",
        "package_version_min",
        {"package": "openssl", "min_version": "3.0.0"},
    )
    _install_package(db, host.id, "openssl", "3.0.10")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_PASS


def test_package_version_min_fail_below(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="vmin-fail")
    _add_check(
        db,
        admin_user,
        policy,
        "openssl-min",
        "package_version_min",
        {"package": "openssl", "min_version": "3.0.0"},
    )
    _install_package(db, host.id, "openssl", "1.1.1")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_FAIL
    assert row.verdict_reason == REASON_VERSION_MISMATCH


def test_package_version_min_fail_absent(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="vmin-absent")
    _add_check(
        db,
        admin_user,
        policy,
        "openssl-min",
        "package_version_min",
        {"package": "openssl", "min_version": "3.0.0"},
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_FAIL
    assert row.verdict_reason == REASON_PACKAGE_NOT_INSTALLED


def test_package_version_min_error_unparseable(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="vmin-bad")
    _add_check(
        db,
        admin_user,
        policy,
        "openssl-min",
        "package_version_min",
        {"package": "openssl", "min_version": "3.0.0"},
    )
    _install_package(db, host.id, "openssl", "not-a-version")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_VERSION_UNPARSEABLE


# ---------------------------------------------------------------------------
# Fact kinds
# ---------------------------------------------------------------------------


def test_fact_equals_pass(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="fact-pass")
    _add_check(
        db,
        admin_user,
        policy,
        "kver",
        "fact_equals",
        {"fact_key": "host.kernel_version", "expected": "5.15.0-101-generic"},
    )
    _set_host_facts(db, host.id, kernel_version="5.15.0-101-generic")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_PASS
    assert row.observed_value == "5.15.0-101-generic"


def test_fact_equals_fail(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="fact-fail")
    _add_check(
        db,
        admin_user,
        policy,
        "kver",
        "fact_equals",
        {"fact_key": "host.kernel_version", "expected": "6.0"},
    )
    _set_host_facts(db, host.id, kernel_version="5.15.0-101-generic")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_FAIL


def test_fact_equals_error_unmapped_key(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="fact-unmapped")
    _add_check(
        db,
        admin_user,
        policy,
        "future-unmapped",
        "fact_equals",
        # A genuinely unmapped, not-yet-collected key (PRA-359 mapped the SSH /
        # sysctl keys, so use a made-up future key to exercise the unmapped path).
        {"fact_key": "future.not.collected.yet", "expected": "no"},
    )
    _set_host_facts(db, host.id, kernel_version="x")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_FACT_KEY_UNMAPPED


def test_fact_equals_error_no_facts_row(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="fact-no-row")
    _add_check(
        db,
        admin_user,
        policy,
        "kver",
        "fact_equals",
        {"fact_key": "host.kernel_version", "expected": "6.0"},
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_NO_HOST_FACTS


def test_fact_equals_error_null_value(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="fact-null")
    _add_check(
        db,
        admin_user,
        policy,
        "vm",
        "fact_equals",
        {"fact_key": "host.virtualization", "expected": "kvm"},
    )
    # HostFacts row exists but the column is NULL.
    _set_host_facts(db, host.id, kernel_version="x")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_FACT_VALUE_NULL


def test_fact_present_pass(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="present-pass")
    _add_check(
        db,
        admin_user,
        policy,
        "have-kv",
        "fact_present",
        {"fact_key": "host.kernel_version"},
    )
    _set_host_facts(db, host.id, kernel_version="5.15")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_PASS


def test_fact_present_fail_null(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="present-fail")
    _add_check(
        db,
        admin_user,
        policy,
        "have-vm",
        "fact_present",
        {"fact_key": "host.virtualization"},
    )
    _set_host_facts(db, host.id, kernel_version="x")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_FAIL


def test_fact_absent_pass(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="absent-pass")
    _add_check(
        db,
        admin_user,
        policy,
        "no-cloud",
        "fact_absent",
        {"fact_key": "host.cloud_provider"},
    )
    _set_host_facts(db, host.id, kernel_version="x")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_PASS


def test_fact_absent_fail(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="absent-fail")
    _add_check(
        db,
        admin_user,
        policy,
        "no-cloud",
        "fact_absent",
        {"fact_key": "host.cloud_provider"},
    )
    _set_host_facts(db, host.id, cloud_provider="aws")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_FAIL


# ---------------------------------------------------------------------------
# Probe-kind bridge — PRA-166 now wires file/command kinds through the
# probe runner. These bridge tests confirm the evaluation service hands
# off cleanly; deep per-kind behavior lives in the PRA-166 test file.
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_probe(monkeypatch):
    """Replace the probe runner's dispatch table with a stub that
    captures (kind, system_id, definition) and returns a canned outcome.
    Keeps these PRA-165 evaluation tests off the live SSH path.
    """
    calls = []

    def _make_probe(outcome):
        def _probe(db, system_id, definition):
            calls.append({"system_id": system_id, "definition": dict(definition)})
            return outcome

        return _probe

    def _install(outcome):
        for kind in compliance_probe_runner_service.SUPPORTED_KINDS:
            monkeypatch.setitem(
                compliance_probe_runner_service._PROBES,
                kind,
                _make_probe(outcome),
            )

    return _install, calls


def test_file_kind_routes_through_probe_runner(db, admin_user, host, stub_probe):
    install, calls = stub_probe
    install(
        compliance_probe_runner_service.ProbeOutcome(
            verdict=VERDICT_PASS,
            observed_value="exists",
            expected_value="/etc/passwd",
        )
    )
    policy = _make_policy(db, admin_user, slug="probe-file")
    _add_check(
        db,
        admin_user,
        policy,
        "passwd-file",
        "file_exists",
        {"path": "/etc/passwd"},
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_PASS
    assert row.check_kind == "file_exists"
    assert calls and calls[0]["system_id"] == host.id


def test_command_kind_routes_through_probe_runner(db, admin_user, host, stub_probe):
    install, calls = stub_probe
    install(
        compliance_probe_runner_service.ProbeOutcome(
            verdict=VERDICT_FAIL,
            reason=compliance_probe_runner_service.REASON_EXIT_CODE_MISMATCH,
            observed_value="1",
            expected_value="0",
        )
    )
    policy = _make_policy(db, admin_user, slug="probe-cmd")
    _add_check(
        db,
        admin_user,
        policy,
        "true-cmd",
        "command_exit_code",
        {"command": "/bin/true", "expected_exit_code": 0},
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.verdict == VERDICT_FAIL
    assert (
        row.verdict_reason == compliance_probe_runner_service.REASON_EXIT_CODE_MISMATCH
    )
    assert row.observed_value == "1"
    assert row.expected_value == "0"
    assert calls and calls[0]["definition"]["command"] == "/bin/true"


# ---------------------------------------------------------------------------
# Disabled checks/policies + severity override
# ---------------------------------------------------------------------------


def test_disabled_check_is_skipped(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="disabled-check")
    check = _add_check(
        db,
        admin_user,
        policy,
        "skipme",
        "package_installed",
        {"package": "openssh-server"},
    )
    compliance_service.update_check(
        db,
        check.id,
        {"enabled": False},
        actor_user_id=admin_user.id,
    )
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    assert _evidence_rows(db, policy_id=policy.id) == []


def test_severity_override_recorded(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="sev-test", severity="medium")
    _add_check(
        db,
        admin_user,
        policy,
        "high-check",
        "package_installed",
        {"package": "openssh-server"},
        severity_override="critical",
    )
    _install_package(db, host.id, "openssh-server", "9")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = _evidence_rows(db, policy_id=policy.id)
    assert row.severity == "critical"


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def test_audit_emission_uses_session_boundary(db, admin_user, host, capture_audit):
    policy = _make_policy(db, admin_user, slug="audit-test")
    _add_check(
        db,
        admin_user,
        policy,
        "ssh-pkg",
        "package_installed",
        {"package": "openssh-server"},
    )
    _install_package(db, host.id, "openssh-server", "9")
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    runs = capture_audit.by_action(AUDIT_COMPLIANCE_EVALUATION_RUN)
    persists = capture_audit.by_action(AUDIT_COMPLIANCE_EVIDENCE_PERSISTED)
    assert len(runs) == 1
    assert len(persists) == 1
    for call in runs + persists:
        # Session-boundary lock: safe_emit must be called WITHOUT db=
        # so it opens its own SessionLocal.
        assert "db" not in call
    assert runs[0]["context"]["counts"][VERDICT_PASS] == 1
    assert persists[0]["context"]["evidence_count"] == 1


# ---------------------------------------------------------------------------
# Due-policy scheduler sweep
# ---------------------------------------------------------------------------


def test_list_due_policies_picks_null_last_run(db, admin_user):
    p = _make_policy(db, admin_user, slug="never-run")
    due = compliance_evaluation_service.list_due_policies(db)
    assert p.id in {x.id for x in due}


def test_list_due_policies_skips_recently_run(db, admin_user, host):
    p = _make_policy(db, admin_user, slug="just-ran", schedule_interval_hours=24)
    _add_check(db, admin_user, p, "c", "package_installed", {"package": "x"})
    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=p.id)
    db.refresh(p)
    assert p.last_run_at is not None
    due = compliance_evaluation_service.list_due_policies(db)
    assert p.id not in {x.id for x in due}


def test_list_due_policies_skips_disabled(db, admin_user):
    p = _make_policy(db, admin_user, slug="disabled-pol", enabled=False)
    due = compliance_evaluation_service.list_due_policies(db)
    assert p.id not in {x.id for x in due}


def test_list_due_policies_includes_overdue(db, admin_user, host):
    p = _make_policy(db, admin_user, slug="overdue", schedule_interval_hours=1)
    _add_check(db, admin_user, p, "c", "package_installed", {"package": "x"})
    # Force last_run_at well into the past.
    past = datetime.utcnow() - timedelta(hours=24)
    compliance_evaluation_service.evaluate_policy_for_fleet(
        db, policy_id=p.id, now=past
    )
    due = compliance_evaluation_service.list_due_policies(db)
    assert p.id in {x.id for x in due}


def test_evaluate_due_policies_runs_only_due(db, admin_user, host):
    overdue = _make_policy(db, admin_user, slug="due", schedule_interval_hours=1)
    _add_check(db, admin_user, overdue, "c", "package_installed", {"package": "x"})
    past = datetime.utcnow() - timedelta(hours=12)
    compliance_evaluation_service.evaluate_policy_for_fleet(
        db, policy_id=overdue.id, now=past
    )

    fresh = _make_policy(db, admin_user, slug="fresh", schedule_interval_hours=1)
    _add_check(db, admin_user, fresh, "c", "package_installed", {"package": "x"})
    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=fresh.id)

    fresh_rows_before = len(_evidence_rows(db, policy_id=fresh.id))
    overdue_rows_before = len(_evidence_rows(db, policy_id=overdue.id))

    summaries = compliance_evaluation_service.evaluate_due_policies(db)
    assert overdue.id in summaries
    assert fresh.id not in summaries

    assert len(_evidence_rows(db, policy_id=overdue.id)) > overdue_rows_before
    assert len(_evidence_rows(db, policy_id=fresh.id)) == fresh_rows_before


# ---------------------------------------------------------------------------
# Retention sweep
# ---------------------------------------------------------------------------


def test_retain_evidence_prunes_old_rows(db, admin_user, host, capture_audit):
    policy = _make_policy(db, admin_user, slug="retain", evidence_retention_days=30)
    _add_check(
        db, admin_user, policy, "c", "package_installed", {"package": "openssh-server"}
    )
    _install_package(db, host.id, "openssh-server", "9")

    # First run is "old" — backdate.
    old_time = datetime.utcnow() - timedelta(days=60)
    compliance_evaluation_service.evaluate_policy_for_fleet(
        db, policy_id=policy.id, now=old_time
    )
    # Forge the row's evaluated_at to be old (the service stamped it
    # at old_time, but db default created_at is "now"; that's fine —
    # retention prunes by ``evaluated_at`` which IS old_time).
    rows_before = _evidence_rows(db, policy_id=policy.id)
    assert rows_before, "test setup should have produced at least one row"

    # Second run is fresh.
    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=policy.id)

    pruned = compliance_evaluation_service.retain_evidence(db)
    assert policy.id in pruned and pruned[policy.id] >= 1
    remaining = _evidence_rows(db, policy_id=policy.id)
    assert all(
        (datetime.utcnow() - r.evaluated_at) < timedelta(days=30) for r in remaining
    )
    retained_events = capture_audit.by_action(AUDIT_COMPLIANCE_EVIDENCE_RETAINED)
    assert len(retained_events) == 1
    assert retained_events[0]["context"]["deleted_count"] == pruned[policy.id]


def test_retain_evidence_silent_when_nothing_to_prune(
    db, admin_user, host, capture_audit
):
    policy = _make_policy(
        db, admin_user, slug="retain-noop", evidence_retention_days=30
    )
    _add_check(
        db, admin_user, policy, "c", "package_installed", {"package": "openssh-server"}
    )
    _install_package(db, host.id, "openssh-server", "9")
    compliance_evaluation_service.evaluate_policy_for_fleet(db, policy_id=policy.id)

    pruned = compliance_evaluation_service.retain_evidence(db)
    assert pruned == {}
    # No audit row on a zero-prune sweep.
    assert capture_audit.by_action(AUDIT_COMPLIANCE_EVIDENCE_RETAINED) == []


# ---------------------------------------------------------------------------
# Cross-cutting: not-found + per-fleet stamping last_run_at
# ---------------------------------------------------------------------------


def test_evaluate_unknown_policy_raises(db):
    with pytest.raises(compliance_service.ComplianceError):
        compliance_evaluation_service.evaluate_policy_for_host(
            db, policy_id=999_999, system_id=1
        )


def test_evaluate_unknown_system_raises(db, admin_user):
    policy = _make_policy(db, admin_user, slug="x")
    with pytest.raises(compliance_service.ComplianceError):
        compliance_evaluation_service.evaluate_policy_for_host(
            db, policy_id=policy.id, system_id=999_999
        )


def test_evaluate_policy_for_fleet_stamps_last_run_at(db, admin_user, host):
    policy = _make_policy(db, admin_user, slug="stamp")
    _add_check(db, admin_user, policy, "c", "package_installed", {"package": "x"})
    assert policy.last_run_at is None
    summary = compliance_evaluation_service.evaluate_policy_for_fleet(
        db, policy_id=policy.id
    )
    db.refresh(policy)
    assert policy.last_run_at is not None
    assert summary.policy_id == policy.id


# ---------------------------------------------------------------------------
# Non-execution guard
# ---------------------------------------------------------------------------


def test_no_probe_modules_invoked_during_sweep(db, admin_user, host, monkeypatch):
    """Slice 2 boundary: the evaluation runner must not call into any
    SSH/file/command/package-scan/facts-refresh module. We monkeypatch
    the actual call sites that those modules expose; any invocation
    raises AssertionError and fails the test.
    """
    tripped: dict = {}

    def trip(name):
        def _t(*args, **kwargs):
            tripped[name] = True
            raise AssertionError(f"{name} must not run in Slice 2")

        return _t

    monkeypatch.setattr(
        "app.services.facts_service.ingest", trip("facts_service.ingest"), raising=False
    )
    monkeypatch.setattr(
        "app.services.package_service.PackageService.scan_packages",
        trip("PackageService.scan_packages"),
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.ssh_facts_collector_service.collect_facts",
        trip("ssh_facts_collector.collect_facts"),
        raising=False,
    )

    policy = _make_policy(db, admin_user, slug="guard")
    _add_check(
        db, admin_user, policy, "c", "package_installed", {"package": "openssh-server"}
    )
    _install_package(db, host.id, "openssh-server", "9")

    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    assert tripped == {}


def test_evidence_module_not_importing_probe_runners():
    """Hard boundary: the evaluation service module's namespace must
    not surface a probe-runner symbol. Cheap rename-resistant guard.
    """
    forbidden = {
        "subprocess",
        "paramiko",
        "ssh_service",
        "ssh_facts_collector_service",
    }
    leaks = forbidden & set(dir(compliance_evaluation_service))
    assert not leaks, f"evaluation module leaked probe runners: {leaks}"
