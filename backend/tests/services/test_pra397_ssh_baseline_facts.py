"""PRA-397: SSH baseline fact coverage for agent-managed hosts.

Covers the three contracts this change rests on:

* the ingest payload contract is transport-neutral for the two SSH
  baseline scalars, so an agent report persists them exactly as an SSH
  report does;
* a collection that cannot establish an SSH baseline scalar does not
  erase the value an earlier collection established; and
* a collection that could not establish a value evaluates as coverage
  pending rather than as a host pass or failure, whether or not an
  earlier value was retained.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import Credential, Group, HostFacts, System
from app.services import (
    compliance_evaluation_service,
    compliance_labels,
    facts_service,
    ssh_facts_collector_service,
)

SSH_KEYS = ("ssh_permit_root_login", "ssh_password_authentication")

# The two starter-pack checks and the columns behind them. Pinned here so a
# rename on either side breaks a test rather than silently unmapping a check.
FACT_KEY_BY_COLUMN = {
    "ssh_permit_root_login": "ssh.config.PermitRootLogin",
    "ssh_password_authentication": "ssh.config.PasswordAuthentication",
}


@pytest.fixture
def system(db, seed_distro):
    group = Group(name="pra397-facts", description="x")
    db.add(group)
    db.flush()
    cred = Credential(name="cred-pra397", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    row = System(
        hostname="pra397-host.example.com",
        ip_address="192.0.2.97",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(row)
    db.flush()
    db.commit()
    return row


def _payload(collected_at: str, **extra):
    payload = {"schema_version": 1, "collected_at": collected_at, "cpu_cores": 4}
    payload.update(extra)
    return payload


def _facts_row(db, system_id: int) -> HostFacts:
    return db.query(HostFacts).filter(HostFacts.system_id == system_id).one()


# --------------------------------------------------------------- persistence


def test_agent_payload_persists_ssh_baseline_scalars(db, system):
    """The agent transport lands both values. Before the collector had
    these probes the same refresh produced NULL columns, which is what
    made the starter checks unevaluable on agent-managed hosts."""
    result = facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload(
            "2026-08-24T10:00:00",
            ssh_permit_root_login="no",
            ssh_password_authentication="yes",
        ),
        source_transport="agent",
    )

    assert result.status == "upserted"
    row = _facts_row(db, system.id)
    assert row.source_transport == "agent"
    assert row.ssh_permit_root_login == "no"
    assert row.ssh_password_authentication == "yes"


def test_agent_and_ssh_payloads_use_the_same_keys(db, system):
    """Transport parity: the keys the SSH collector parses out of its
    script output are the payload keys the agent emits, both are accepted
    scalars, and both resolve to the columns the starter checks read."""
    parsed = ssh_facts_collector_service.parse_payload(
        "ssh_permit_root_login=bm8=\nssh_password_authentication=bm8=\n"
    )
    assert set(SSH_KEYS).issubset(parsed)

    for column, fact_key in FACT_KEY_BY_COLUMN.items():
        assert column in facts_service._ALLOWED_SCALAR_KEYS
        assert (
            compliance_evaluation_service.FACT_KEY_TO_HOSTFACTS_COLUMN[fact_key]
            == column
        )


def test_transports_write_identical_columns_for_identical_values(db, system):
    """An agent report and an SSH report carrying the same values are
    indistinguishable in the stored row apart from provenance."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload(
            "2026-08-24T10:00:00",
            ssh_permit_root_login="no",
            ssh_password_authentication="no",
        ),
        source_transport="ssh",
    )
    from_ssh = {k: getattr(_facts_row(db, system.id), k) for k in SSH_KEYS}

    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload(
            "2026-08-24T11:00:00",
            ssh_permit_root_login="no",
            ssh_password_authentication="no",
        ),
        source_transport="agent",
    )
    from_agent = {k: getattr(_facts_row(db, system.id), k) for k in SSH_KEYS}

    assert from_ssh == from_agent == {k: "no" for k in SSH_KEYS}


# ------------------------------------------------------------ merge/freshness


def test_refresh_without_ssh_facts_preserves_earlier_evidence(db, system):
    """A later collection that cannot establish the SSH scalars keeps the
    values an earlier collection did. This is the regression: a
    lower-coverage refresh used to overwrite them with NULL."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload(
            "2026-08-24T10:00:00",
            ssh_permit_root_login="no",
            ssh_password_authentication="no",
        ),
        source_transport="ssh",
    )

    result = facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T11:00:00", kernel_version="6.8.0-generic"),
        source_transport="agent",
    )

    assert result.status == "upserted"
    row = _facts_row(db, system.id)
    assert row.ssh_permit_root_login == "no"
    assert row.ssh_password_authentication == "no"
    # The rest of the row is still replaced wholesale.
    assert row.kernel_version == "6.8.0-generic"
    assert row.source_transport == "agent"
    assert result.preserved_keys == sorted(SSH_KEYS)


def test_reported_value_always_wins_over_preserved_value(db, system):
    """Preservation must never mask a real change: a collection that
    reports a value overwrites the stored one, including a worse one."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T10:00:00", ssh_permit_root_login="no"),
        source_transport="ssh",
    )

    result = facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T11:00:00", ssh_permit_root_login="yes"),
        source_transport="agent",
    )

    assert _facts_row(db, system.id).ssh_permit_root_login == "yes"
    assert result.preserved_keys == []


def test_preservation_does_not_invent_values(db, system):
    """A key neither collection established stays NULL."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T10:00:00", ssh_permit_root_login="no"),
        source_transport="ssh",
    )
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T11:00:00"),
        source_transport="agent",
    )

    row = _facts_row(db, system.id)
    assert row.ssh_permit_root_login == "no"
    assert row.ssh_password_authentication is None


def test_non_evidence_scalars_are_still_not_carried_forward(db, system):
    """The carry-forward is scoped to the SSH baseline pair. Inventory
    fields keep the no-silent-merge behavior so collector regressions
    stay visible."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T10:00:00", kernel_version="6.8.0-generic"),
        source_transport="ssh",
    )
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T11:00:00", ssh_permit_root_login="no"),
        source_transport="agent",
    )

    assert _facts_row(db, system.id).kernel_version is None


def test_kernel_sysctls_are_not_preserved(db, system):
    """No collector reports coverage for the sysctls, so a retained value
    could not be told apart from a freshly observed one. They follow the
    ordinary no-carry-forward rule instead."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload(
            "2026-08-24T10:00:00",
            sysctl_kernel_randomize_va_space="2",
            sysctl_net_ipv4_ip_forward="0",
            sysctl_net_ipv4_conf_all_rp_filter="1",
        ),
        source_transport="ssh",
    )
    result = facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T11:00:00", ssh_permit_root_login="no"),
        source_transport="agent",
    )

    row = _facts_row(db, system.id)
    assert row.sysctl_kernel_randomize_va_space is None
    assert row.sysctl_net_ipv4_ip_forward is None
    assert row.sysctl_net_ipv4_conf_all_rp_filter is None
    assert result.preserved_keys == []
    assert facts_service._PRESERVED_EVIDENCE_KEYS == SSH_KEYS


def test_sysctls_are_still_written_when_reported(db, system):
    """Narrowing the exception must not stop the sysctl columns being
    persisted on the collection that does report them."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload(
            "2026-08-24T10:00:00",
            sysctl_kernel_randomize_va_space="2",
            sysctl_net_ipv4_ip_forward="0",
            sysctl_net_ipv4_conf_all_rp_filter="1",
        ),
        source_transport="ssh",
    )

    row = _facts_row(db, system.id)
    assert row.sysctl_kernel_randomize_va_space == "2"
    assert row.sysctl_net_ipv4_ip_forward == "0"
    assert row.sysctl_net_ipv4_conf_all_rp_filter == "1"


def test_force_ingest_clears_preserved_evidence(db, system):
    """``force`` is the deliberate out-of-band correction path, so it
    bypasses preservation and lets an operator clear a stale value."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T10:00:00", ssh_permit_root_login="no"),
        source_transport="ssh",
    )
    result = facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T11:00:00", cpu_cores=8),
        source_transport="manual",
        force=True,
    )

    row = _facts_row(db, system.id)
    assert row.ssh_permit_root_login is None
    # Nothing was retained, so there is no coverage marker either.
    assert row.partial_errors is None
    assert result.preserved_keys == []


def test_stale_refresh_still_cannot_touch_the_row(db, system):
    """Preservation does not weaken stale-write rejection."""
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T12:00:00", ssh_permit_root_login="no"),
        source_transport="ssh",
    )
    result = facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T09:00:00", ssh_permit_root_login="yes"),
        source_transport="agent",
    )

    assert result.status == "rejected_stale"
    assert _facts_row(db, system.id).ssh_permit_root_login == "no"


def test_preserved_keys_are_named_in_the_audit_context(db, system, monkeypatch):
    """The carry-forward is auditable rather than silent."""
    captured = []
    monkeypatch.setattr(
        facts_service,
        "safe_emit",
        lambda **kwargs: captured.append(kwargs),
    )

    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T10:00:00", ssh_permit_root_login="no"),
        source_transport="ssh",
    )
    facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T11:00:00", cpu_cores=8),
        source_transport="agent",
    )

    context = captured[-1]["context"]
    assert context["reason"] == "upserted"
    assert context["preserved_evidence_keys"] == ["ssh_permit_root_login"]


def test_first_ingest_has_nothing_to_preserve(db, system):
    result = facts_service.ingest(
        db,
        system_id=system.id,
        payload=_payload("2026-08-24T10:00:00", ssh_permit_root_login="no"),
        source_transport="agent",
    )
    assert result.preserved_keys == []


# ------------------------------------------------------- starter evaluation


def _evaluate(db, system_id, fact_key, expected="no"):
    return compliance_evaluation_service._evaluate_fact_equals(
        db,
        system_id,
        {"fact_key": fact_key, "expected": expected},
    )


def _ingest_ssh_state(db, system_id, *, offset_hours=0, **extra):
    collected = datetime(2026, 8, 24, 10, 0, 0) + timedelta(hours=offset_hours)
    facts_service.ingest(
        db,
        system_id=system_id,
        payload=_payload(collected.isoformat(), **extra),
        source_transport="agent",
    )


def test_starter_check_passes_on_hardened_host(db, system):
    _ingest_ssh_state(db, system.id, ssh_permit_root_login="no")
    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")

    assert verdict.verdict == compliance_evaluation_service.VERDICT_PASS
    assert verdict.observed_value == "no"


def test_starter_check_fails_on_permissive_host(db, system):
    _ingest_ssh_state(db, system.id, ssh_password_authentication="yes")
    verdict = _evaluate(db, system.id, "ssh.config.PasswordAuthentication")

    assert verdict.verdict == compliance_evaluation_service.VERDICT_FAIL
    assert verdict.observed_value == "yes"


def test_unavailable_evidence_reads_as_coverage_pending_not_failure(db, system):
    """The host was scanned and the probe reported that it could not
    establish a value. That must not present as a host failure, and it
    must not tell the operator to run a scan that cannot help."""
    _ingest_ssh_state(
        db,
        system.id,
        partial_errors=[{"key": "ssh_config", "error": "effective_config_unavailable"}],
    )
    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")

    assert verdict.verdict == compliance_evaluation_service.VERDICT_ERROR
    assert (
        compliance_labels.evidence_status(verdict.verdict, verdict.reason)
        == compliance_labels.STATUS_COVERAGE_PENDING
    )
    assert (
        verdict.reason
        == compliance_evaluation_service.REASON_FACT_COLLECTION_UNAVAILABLE
    )


def test_null_without_a_probe_report_still_reads_as_awaiting_scan(db, system):
    """A host whose collection simply never covered the fact keeps the
    actionable "run a scan" state."""
    _ingest_ssh_state(db, system.id, kernel_version="6.8.0-generic")
    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")

    assert verdict.reason == compliance_evaluation_service.REASON_FACT_VALUE_NULL
    assert (
        compliance_labels.evidence_status(verdict.verdict, verdict.reason)
        == compliance_labels.STATUS_AWAITING_SCAN
    )


def test_passing_host_goes_coverage_pending_when_the_probe_fails(db, system):
    """A host that passed, then a collection that could not establish the
    value: the retained evidence must not be re-reported as a confident
    pass dated to the new collection."""
    _ingest_ssh_state(db, system.id, ssh_permit_root_login="no")
    assert (
        _evaluate(db, system.id, "ssh.config.PermitRootLogin").verdict
        == compliance_evaluation_service.VERDICT_PASS
    )

    _ingest_ssh_state(
        db,
        system.id,
        offset_hours=1,
        partial_errors=[
            {"key": "ssh_permit_root_login", "error": "config_precedence_unknown"}
        ],
    )

    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert (
        compliance_labels.evidence_status(verdict.verdict, verdict.reason)
        == compliance_labels.STATUS_COVERAGE_PENDING
    )
    assert verdict.observed_value is None
    # The evidence is retained for traceability even though the verdict
    # does not use it.
    assert _facts_row(db, system.id).ssh_permit_root_login == "no"


def test_failing_host_goes_coverage_pending_when_the_probe_fails(db, system):
    """The same in the other direction: a retained failing value must not
    keep failing a host the latest collection could not read."""
    _ingest_ssh_state(db, system.id, ssh_permit_root_login="yes")
    assert (
        _evaluate(db, system.id, "ssh.config.PermitRootLogin").verdict
        == compliance_evaluation_service.VERDICT_FAIL
    )

    _ingest_ssh_state(
        db,
        system.id,
        offset_hours=1,
        partial_errors=[
            {"key": "ssh_permit_root_login", "error": "config_precedence_unknown"}
        ],
    )

    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert (
        compliance_labels.evidence_status(verdict.verdict, verdict.reason)
        == compliance_labels.STATUS_COVERAGE_PENDING
    )
    assert verdict.observed_value is None
    assert _facts_row(db, system.id).ssh_permit_root_login == "yes"


def test_a_later_reported_value_wins_over_the_retained_one(db, system):
    """Coverage pending is only for a failed probe. A collection that does
    report a value produces a real verdict from it."""
    _ingest_ssh_state(db, system.id, ssh_permit_root_login="yes")
    _ingest_ssh_state(db, system.id, offset_hours=1, ssh_permit_root_login="no")

    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert verdict.verdict == compliance_evaluation_service.VERDICT_PASS
    assert verdict.observed_value == "no"


def test_a_recovered_probe_restores_a_real_verdict(db, system):
    """Coverage pending is not sticky: once a collection establishes the
    value again the check returns to pass/fail."""
    _ingest_ssh_state(db, system.id, ssh_permit_root_login="no")
    _ingest_ssh_state(
        db,
        system.id,
        offset_hours=1,
        partial_errors=[
            {"key": "ssh_permit_root_login", "error": "config_precedence_unknown"}
        ],
    )
    _ingest_ssh_state(db, system.id, offset_hours=2, ssh_permit_root_login="no")

    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert verdict.verdict == compliance_evaluation_service.VERDICT_PASS


def test_a_gap_in_one_setting_does_not_gate_the_other(db, system):
    """Coverage is recorded per setting, so a host that could report
    PermitRootLogin but not PasswordAuthentication still gets a real
    verdict for the first."""
    _ingest_ssh_state(
        db,
        system.id,
        ssh_permit_root_login="no",
        partial_errors=[
            {
                "key": "ssh_password_authentication",
                "error": "directive_not_in_global_config",
            }
        ],
    )

    established = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert established.verdict == compliance_evaluation_service.VERDICT_PASS
    assert established.observed_value == "no"

    missing = _evaluate(db, system.id, "ssh.config.PasswordAuthentication")
    assert (
        compliance_labels.evidence_status(missing.verdict, missing.reason)
        == compliance_labels.STATUS_COVERAGE_PENDING
    )


def test_whole_probe_failure_gates_both_settings(db, system):
    """When the probe itself failed, neither setting was established, so
    the note is filed against the probe and covers both."""
    _ingest_ssh_state(
        db,
        system.id,
        ssh_permit_root_login="no",
        ssh_password_authentication="no",
    )
    _ingest_ssh_state(
        db,
        system.id,
        offset_hours=1,
        partial_errors=[{"key": "ssh_config", "error": "permission denied"}],
    )

    for fact_key in FACT_KEY_BY_COLUMN.values():
        verdict = _evaluate(db, system.id, fact_key)
        assert (
            compliance_labels.evidence_status(verdict.verdict, verdict.reason)
            == compliance_labels.STATUS_COVERAGE_PENDING
        ), fact_key


# --------------------------------- silently omitted values (both transports)


def _ingest(db, system_id, transport, *, offset_hours=0, **extra):
    collected = datetime(2026, 8, 24, 10, 0, 0) + timedelta(hours=offset_hours)
    return facts_service.ingest(
        db,
        system_id=system_id,
        payload=_payload(collected.isoformat(), **extra),
        source_transport=transport,
    )


@pytest.mark.parametrize("prior_value,prior_verdict", [("no", "pass"), ("yes", "fail")])
@pytest.mark.parametrize("stale_transport", ["agent", "ssh"])
def test_silently_omitted_value_becomes_coverage_pending(
    db, system, prior_value, prior_verdict, stale_transport
):
    """A collector too old or too limited to report the SSH baseline omits
    the field without saying it could not establish one. The retained value
    must not then be scored under the new collection's timestamp, whichever
    transport did the omitting and whichever way the host was previously
    verdicted."""
    _ingest(db, system.id, "ssh", ssh_permit_root_login=prior_value)
    assert _evaluate(db, system.id, "ssh.config.PermitRootLogin").verdict == (
        prior_verdict
    )

    # A real refresh: it reports other facts, and says nothing at all about
    # the SSH baseline.
    result = _ingest(
        db,
        system.id,
        stale_transport,
        offset_hours=1,
        kernel_version="6.8.0-generic",
    )

    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert (
        compliance_labels.evidence_status(verdict.verdict, verdict.reason)
        == compliance_labels.STATUS_COVERAGE_PENDING
    )
    assert verdict.observed_value is None

    row = _facts_row(db, system.id)
    assert row.kernel_version == "6.8.0-generic"
    # Retained for traceability.
    assert row.ssh_permit_root_login == prior_value
    # ...and marked, which is what keeps the verdict above honest.
    assert result.preserved_keys == ["ssh_permit_root_login"]
    assert {
        "key": "ssh_permit_root_login",
        "error": facts_service.PRESERVED_WITHOUT_COVERAGE_REASON,
    } in (row.partial_errors or [])


@pytest.mark.parametrize("recovery_transport", ["agent", "ssh"])
def test_later_successful_report_restores_a_real_verdict(
    db, system, recovery_transport
):
    """The marker is per collection, not sticky: the next collection that
    reports the value scores it normally."""
    _ingest(db, system.id, "ssh", ssh_permit_root_login="yes")
    _ingest(db, system.id, "agent", offset_hours=1, kernel_version="6.8.0-generic")
    assert (
        compliance_labels.evidence_status(
            *_verdict_parts(_evaluate(db, system.id, "ssh.config.PermitRootLogin"))
        )
        == compliance_labels.STATUS_COVERAGE_PENDING
    )

    _ingest(
        db,
        system.id,
        recovery_transport,
        offset_hours=2,
        ssh_permit_root_login="no",
    )

    row = _facts_row(db, system.id)
    assert row.partial_errors is None
    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert verdict.verdict == compliance_evaluation_service.VERDICT_PASS
    assert verdict.observed_value == "no"


def test_only_the_omitted_key_is_marked(db, system):
    """A collection that reports one setting and omits the other marks only
    the omitted one, so the reported setting still scores."""
    _ingest(
        db,
        system.id,
        "ssh",
        ssh_permit_root_login="no",
        ssh_password_authentication="no",
    )
    result = _ingest(db, system.id, "agent", offset_hours=1, ssh_permit_root_login="no")

    reported = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert reported.verdict == compliance_evaluation_service.VERDICT_PASS
    omitted = _evaluate(db, system.id, "ssh.config.PasswordAuthentication")
    assert (
        compliance_labels.evidence_status(omitted.verdict, omitted.reason)
        == compliance_labels.STATUS_COVERAGE_PENDING
    )

    assert result.preserved_keys == ["ssh_password_authentication"]
    marked = {
        entry["key"]
        for entry in (_facts_row(db, system.id).partial_errors or [])
        if entry["error"] == facts_service.PRESERVED_WITHOUT_COVERAGE_REASON
    }
    assert marked == {"ssh_password_authentication"}


def test_marker_is_not_added_when_the_collector_reported_per_key_coverage(db, system):
    """A collector that reports its own gap keeps its reason; ingestion does
    not stack a second entry on top."""
    _ingest(db, system.id, "ssh", ssh_permit_root_login="no")
    _ingest(
        db,
        system.id,
        "agent",
        offset_hours=1,
        partial_errors=[
            {"key": "ssh_permit_root_login", "error": "config_precedence_unknown"}
        ],
    )

    entries = _facts_row(db, system.id).partial_errors
    assert entries == [
        {"key": "ssh_permit_root_login", "error": "config_precedence_unknown"}
    ]


def test_marker_is_not_added_when_the_collector_reported_whole_probe_coverage(
    db, system
):
    """One ``ssh_config`` entry already covers both settings."""
    _ingest(
        db,
        system.id,
        "ssh",
        ssh_permit_root_login="no",
        ssh_password_authentication="no",
    )
    _ingest(
        db,
        system.id,
        "agent",
        offset_hours=1,
        partial_errors=[{"key": "ssh_config", "error": "permission denied"}],
    )

    entries = _facts_row(db, system.id).partial_errors
    assert entries == [{"key": "ssh_config", "error": "permission denied"}]


def test_nothing_is_marked_when_there_was_no_value_to_retain(db, system):
    """No retention means no misleading value, so the ordinary
    awaiting-scan state stands."""
    _ingest(db, system.id, "ssh", kernel_version="6.8.0-generic")
    result = _ingest(db, system.id, "agent", offset_hours=1, cpu_cores=8)

    assert result.preserved_keys == []
    assert _facts_row(db, system.id).partial_errors is None
    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")
    assert verdict.reason == compliance_evaluation_service.REASON_FACT_VALUE_NULL


def _verdict_parts(verdict):
    return verdict.verdict, verdict.reason


def test_fact_present_reports_unavailable_evidence_as_error(db, system):
    """``fact_present`` fails a host for a missing fact. Unavailable
    evidence is not a missing fact, so it must not produce that failure."""
    _ingest_ssh_state(
        db,
        system.id,
        partial_errors=[{"key": "ssh_config", "error": "config_precedence_unknown"}],
    )
    verdict = compliance_evaluation_service._evaluate_fact_present(
        db, system.id, {"fact_key": "ssh.config.PermitRootLogin"}
    )

    assert verdict.verdict == compliance_evaluation_service.VERDICT_ERROR
    assert (
        verdict.reason
        == compliance_evaluation_service.REASON_FACT_COLLECTION_UNAVAILABLE
    )


def test_fact_absent_does_not_pass_on_unavailable_evidence(db, system):
    """A probe that could not read the host is not evidence of absence."""
    _ingest_ssh_state(
        db,
        system.id,
        partial_errors=[{"key": "ssh_config", "error": "config_precedence_unknown"}],
    )
    verdict = compliance_evaluation_service._evaluate_fact_absent(
        db, system.id, {"fact_key": "ssh.config.PermitRootLogin"}
    )

    assert verdict.verdict == compliance_evaluation_service.VERDICT_ERROR
    assert (
        verdict.reason
        == compliance_evaluation_service.REASON_FACT_COLLECTION_UNAVAILABLE
    )


def test_unrelated_partial_error_does_not_mask_a_missing_fact(db, system):
    """Only a probe entry for this fact flips the reason. A partial error
    about some other probe leaves the awaiting-scan state alone."""
    _ingest_ssh_state(
        db,
        system.id,
        partial_errors=[{"key": "cloud_metadata", "error": "no_response"}],
    )
    verdict = _evaluate(db, system.id, "ssh.config.PermitRootLogin")

    assert verdict.reason == compliance_evaluation_service.REASON_FACT_VALUE_NULL
