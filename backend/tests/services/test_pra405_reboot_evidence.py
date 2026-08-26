"""PRA-405: authoritative reboot-required evidence collection.

Covers the evidence primitive on its own: family resolution, the
Debian marker and RPM ``needs-restarting`` semantics including exit
codes, every unknown outcome (unsupported / timeout / transport
failure / malformed output / probe failure), freshness, and the two
transport runners.

No test opens a connection to a real host: every probe runs through an
injected runner or a fake SSH service.
"""

import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import Credential, Group, HostFacts, System
from app.services import reboot_evidence_service as evidence

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def static_group(db) -> Group:
    g = Group(name="evidence-test-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="evidence-test-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def system_factory(db, seed_distro, static_group, credentials):
    counter = {"n": 0}

    def make(*, distro=None, package_manager=None) -> System:
        counter["n"] += 1
        s = System(
            hostname=f"evidence-host-{counter['n']}.example.com",
            ip_address=f"10.0.95.{counter['n']}",
            distro_id=(distro.id if distro is not None else seed_distro.id),
            os_version="22.04",
            status="Active",
            group_id=static_group.id,
            credentials_id=credentials.id,
        )
        db.add(s)
        db.flush()
        if package_manager is not None:
            db.add(
                HostFacts(
                    system_id=s.id,
                    schema_version=1,
                    collected_at=datetime.utcnow(),
                    source_transport="ssh",
                    package_manager=package_manager,
                )
            )
            db.flush()
        return s

    return make


def _runner(**result):
    """A probe runner that returns a fixed completed run."""

    def _run(system, argv):
        _run.calls.append((system.id, list(argv)))
        return dict(result)

    _run.calls = []
    return _run


NOW = datetime(2026, 8, 24, 12, 0, 0)


# ---------------------------------------------------------------------------
# Family resolution
# ---------------------------------------------------------------------------


def test_debian_distro_resolves_to_deb_family(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    assert evidence.resolve_family(db, system) == evidence.FAMILY_DEB


def test_rpm_distro_resolves_to_rpm_family(db, system_factory, seed_distro):
    seed_distro.name = "Rocky Linux"
    db.flush()
    system = system_factory()
    assert evidence.resolve_family(db, system) == evidence.FAMILY_RPM


def test_unrecognized_distro_falls_back_to_collected_package_manager(
    db, system_factory, seed_distro
):
    seed_distro.name = "SomethingUnmapped"
    db.flush()
    system = system_factory(package_manager="dnf")
    assert evidence.resolve_family(db, system) == evidence.FAMILY_RPM


def test_unresolvable_family_is_unknown(db, system_factory, seed_distro):
    seed_distro.name = "SomethingUnmapped"
    db.flush()
    system = system_factory()
    assert evidence.resolve_family(db, system) == evidence.FAMILY_UNKNOWN


def test_unsupported_family_reports_unsupported_without_probing(
    db, system_factory, seed_distro
):
    """An unresolvable family must not guess an indicator, and must not
    spend a round-trip finding out it cannot answer."""
    seed_distro.name = "SomethingUnmapped"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=false")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert runner.calls == []
    assert result.outcome == evidence.OUTCOME_UNSUPPORTED
    assert result.value is None
    assert result.is_conclusive is False


# ---------------------------------------------------------------------------
# Debian semantics
# ---------------------------------------------------------------------------


def test_debian_marker_present_is_a_positive_observation(
    db, system_factory, seed_distro
):
    seed_distro.name = "Debian"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=true\n")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is True
    assert result.outcome == evidence.OUTCOME_SUCCESS
    assert result.source == evidence.SOURCE_DEBIAN_MARKER
    assert result.family == evidence.FAMILY_DEB
    assert result.is_conclusive is True
    # The probe reads both marker paths and nothing else.
    argv = runner.calls[0][1]
    assert argv[0] == "sh"
    assert "/var/run/reboot-required" in argv[2]
    assert "/run/reboot-required" in argv[2]


def test_debian_marker_absent_is_a_negative_observation(
    db, system_factory, seed_distro
):
    seed_distro.name = "Debian"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=false\n")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is False
    assert result.outcome == evidence.OUTCOME_SUCCESS
    assert result.is_conclusive is True


# ---------------------------------------------------------------------------
# RPM semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_exit,expected",
    [(0, False), (1, True)],
)
def test_needs_restarting_documented_exit_codes(
    db, system_factory, seed_distro, tool_exit, expected
):
    """``needs-restarting -r`` answers through its exit status: 0 means
    no reboot needed, 1 means a reboot is needed."""
    seed_distro.name = "AlmaLinux"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout=f"PRAXIS_REBOOT_PROBE=rc:{tool_exit}\n")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is expected
    assert result.outcome == evidence.OUTCOME_SUCCESS
    assert result.source == evidence.SOURCE_RPM_NEEDS_RESTARTING
    assert result.exit_code == tool_exit


def test_needs_restarting_undocumented_exit_code_is_not_an_answer(
    db, system_factory, seed_distro
):
    seed_distro.name = "Rocky"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=rc:3\n")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is None
    assert result.outcome == evidence.OUTCOME_PROBE_FAILED
    assert result.exit_code == 3
    assert result.is_conclusive is False


def test_needs_restarting_missing_is_unsupported_not_negative(
    db, system_factory, seed_distro
):
    """A host without the tool has not told us a reboot is unnecessary."""
    seed_distro.name = "CentOS"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=unsupported\n")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is None
    assert result.outcome == evidence.OUTCOME_UNSUPPORTED
    assert result.is_conclusive is False


def test_rpm_probe_checks_for_the_tool_before_running_it(
    db, system_factory, seed_distro
):
    seed_distro.name = "Fedora"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=rc:0\n")

    evidence.collect(db, system, runner=runner, now=NOW)

    script = runner.calls[0][1][2]
    assert "command -v needs-restarting" in script
    assert "needs-restarting -r" in script


# ---------------------------------------------------------------------------
# Unknown outcomes
# ---------------------------------------------------------------------------


def test_nonzero_script_exit_is_a_probe_failure(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=126, stdout="", stderr="permission denied")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is None
    assert result.outcome == evidence.OUTCOME_PROBE_FAILED
    assert result.exit_code == 126
    assert "permission denied" in result.detail


def test_missing_token_is_malformed_output(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout="motd banner\nwelcome\n")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is None
    assert result.outcome == evidence.OUTCOME_MALFORMED_OUTPUT


def test_unrecognized_token_is_malformed_output(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout="PRAXIS_REBOOT_PROBE=maybe\n")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is None
    assert result.outcome == evidence.OUTCOME_MALFORMED_OUTPUT


def test_timeout_is_reported_as_timeout(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    runner = _runner(outcome=evidence.OUTCOME_TIMEOUT, stderr="wall clock exceeded")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is None
    assert result.outcome == evidence.OUTCOME_TIMEOUT


def test_transport_failure_is_reported_as_transport_error(
    db, system_factory, seed_distro
):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    runner = _runner(
        outcome=evidence.OUTCOME_TRANSPORT_ERROR, stderr="connection refused"
    )

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.value is None
    assert result.outcome == evidence.OUTCOME_TRANSPORT_ERROR


def test_runner_that_raises_is_reported_not_propagated(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()

    def _boom(system_arg, argv):
        raise RuntimeError("socket exploded")

    result = evidence.collect(db, system, runner=_boom, now=NOW)

    assert result.value is None
    assert result.outcome == evidence.OUTCOME_TRANSPORT_ERROR
    assert "socket exploded" in result.detail


def test_detail_is_bounded(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=1, stdout="", stderr="x" * 5000)

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert len(result.detail) <= evidence.MAX_DETAIL_CHARS


# ---------------------------------------------------------------------------
# Serialization and freshness
# ---------------------------------------------------------------------------


def test_evidence_round_trips_through_a_jsonb_block():
    original = evidence.RebootEvidence(
        value=True,
        source=evidence.SOURCE_DEBIAN_MARKER,
        outcome=evidence.OUTCOME_SUCCESS,
        collected_at=NOW,
        family=evidence.FAMILY_DEB,
        exit_code=0,
        detail="",
    )

    restored = evidence.evidence_from_dict(original.to_dict())

    assert restored is not None
    assert restored.value is True
    assert restored.outcome == evidence.OUTCOME_SUCCESS
    assert restored.collected_at == NOW
    assert restored.source == evidence.SOURCE_DEBIAN_MARKER


def test_serialized_timestamp_is_absolute_utc():
    block = evidence.RebootEvidence(
        value=False,
        source=evidence.SOURCE_DEBIAN_MARKER,
        outcome=evidence.OUTCOME_SUCCESS,
        collected_at=NOW,
    ).to_dict()

    assert block["collected_at"].endswith("Z")


@pytest.mark.parametrize("raw", [None, {}, "nope", {"outcome": "success"}])
def test_unusable_persisted_block_is_treated_as_no_evidence(raw):
    assert evidence.evidence_from_dict(raw) is None


def test_inconclusive_evidence_is_never_fresh():
    stale = evidence.RebootEvidence(
        value=None,
        source=evidence.SOURCE_DEBIAN_MARKER,
        outcome=evidence.OUTCOME_TIMEOUT,
        collected_at=NOW,
    )
    assert evidence.is_fresh(stale, now=NOW) is False


def test_evidence_collected_before_the_package_work_is_not_fresh():
    """The whole point of the observation is that it describes the host
    after the update; one taken before it proves nothing."""
    observation = evidence.RebootEvidence(
        value=False,
        source=evidence.SOURCE_DEBIAN_MARKER,
        outcome=evidence.OUTCOME_SUCCESS,
        collected_at=NOW - timedelta(minutes=5),
    )

    assert evidence.is_fresh(observation, now=NOW, not_before=NOW) is False
    assert (
        evidence.is_fresh(observation, now=NOW, not_before=NOW - timedelta(minutes=10))
        is True
    )


def test_evidence_older_than_the_max_age_is_not_fresh():
    observation = evidence.RebootEvidence(
        value=False,
        source=evidence.SOURCE_DEBIAN_MARKER,
        outcome=evidence.OUTCOME_SUCCESS,
        collected_at=NOW - timedelta(seconds=evidence.MAX_EVIDENCE_AGE_SECONDS + 1),
    )

    assert evidence.is_fresh(observation, now=NOW) is False


def test_evidence_from_the_future_is_not_fresh():
    observation = evidence.RebootEvidence(
        value=False,
        source=evidence.SOURCE_DEBIAN_MARKER,
        outcome=evidence.OUTCOME_SUCCESS,
        collected_at=NOW + timedelta(minutes=1),
    )

    assert evidence.is_fresh(observation, now=NOW) is False


def test_not_collected_carries_the_reason_and_no_value():
    record = evidence.not_collected(reason="policy always", now=NOW)

    assert record.value is None
    assert record.outcome == evidence.OUTCOME_NOT_COLLECTED
    assert record.is_conclusive is False
    assert record.detail == "policy always"


# ---------------------------------------------------------------------------
# Transport runners
# ---------------------------------------------------------------------------


class _FakeSSH:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def execute_privileged_command(self, system_id, command, timeout=None):
        self.calls.append((system_id, command, timeout))
        return self.result


def test_ssh_runner_reports_a_successful_run(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    ssh = _FakeSSH(
        {"status": "success", "exit_code": 0, "stdout": "PRAXIS_REBOOT_PROBE=true"}
    )

    result = evidence.collect_over_ssh(db, system, ssh_service=ssh, now=NOW)

    assert result.value is True
    assert result.outcome == evidence.OUTCOME_SUCCESS
    assert ssh.calls[0][0] == system.id
    assert ssh.calls[0][2] == evidence.PROBE_TIMEOUT_SECONDS


def test_ssh_runner_maps_a_command_timeout_to_timeout(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    ssh = _FakeSSH(
        {
            "status": "failed",
            "outcome": "command_timeout",
            "timed_out": True,
            "exit_code": None,
            "stderr": "timed out",
        }
    )

    result = evidence.collect_over_ssh(db, system, ssh_service=ssh, now=NOW)

    assert result.outcome == evidence.OUTCOME_TIMEOUT
    assert result.value is None


def test_ssh_runner_maps_a_connect_failure_to_transport_error(
    db, system_factory, seed_distro
):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    ssh = _FakeSSH(
        {
            "status": "failed",
            "outcome": "connect_refused",
            "exit_code": None,
            "stderr": "connection refused",
        }
    )

    result = evidence.collect_over_ssh(db, system, ssh_service=ssh, now=NOW)

    assert result.outcome == evidence.OUTCOME_TRANSPORT_ERROR
    assert result.value is None


def test_ssh_runner_maps_a_nonzero_exit_to_probe_failure(
    db, system_factory, seed_distro
):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    ssh = _FakeSSH(
        {"status": "warning", "exit_code": 1, "stdout": "", "stderr": "boom"}
    )

    result = evidence.collect_over_ssh(db, system, ssh_service=ssh, now=NOW)

    assert result.outcome == evidence.OUTCOME_PROBE_FAILED
    assert result.value is None


def test_dispatch_runner_maps_transport_unavailable_to_transport_error(
    db, system_factory, seed_distro, monkeypatch
):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()

    from app.services import patch_execution_dispatch_service as dispatch

    def _fake_dispatch(db_arg, system_arg, cmd):
        return dispatch.DispatchResult(
            exit_code=-1,
            error=dispatch.ERROR_CODE_TRANSPORT_UNAVAILABLE,
            stderr="no session",
        )

    monkeypatch.setattr(dispatch, "default_dispatch", _fake_dispatch)

    result = evidence.collect(db, system, runner=evidence.dispatch_runner(db), now=NOW)

    assert result.outcome == evidence.OUTCOME_TRANSPORT_ERROR
    assert result.value is None


def test_dispatch_runner_reports_a_successful_run(
    db, system_factory, seed_distro, monkeypatch
):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()

    from app.services import patch_execution_dispatch_service as dispatch

    def _fake_dispatch(db_arg, system_arg, cmd):
        assert cmd[0] == "sh"
        return dispatch.DispatchResult(
            exit_code=0, stdout="PRAXIS_REBOOT_PROBE=false\n"
        )

    monkeypatch.setattr(dispatch, "default_dispatch", _fake_dispatch)

    result = evidence.collect(db, system, runner=evidence.dispatch_runner(db), now=NOW)

    assert result.outcome == evidence.OUTCOME_SUCCESS
    assert result.value is False


# ---------------------------------------------------------------------------
# Redaction
#
# Probe detail carries remote stdout/stderr and exception text. A host that
# echoes a credential, a banner that prints a token, or a transport error
# that embeds a DSN would otherwise be persisted in JSONB, served by the
# queue API, written to the CSV export, and mailed out in a notification.
# ---------------------------------------------------------------------------


SECRET_SENTINELS = [
    ("password=hunter2trombone", "hunter2trombone"),
    ("vault_token: s.AbCdEfGhIjKlMnOpQrStUvWx", "s.AbCdEfGhIjKlMnOpQrStUvWx"),
    ("Authorization: Bearer abc123.def456-ghi", "abc123.def456-ghi"),
    (
        "connect failed: postgresql://praxis:sup3rs3cr3t@db:5432/praxis",
        "sup3rs3cr3t",
    ),
    (
        "api_key=AKIAIOSFODNN7EXAMPLEKEY",
        "AKIAIOSFODNN7EXAMPLEKEY",
    ),
]


@pytest.mark.parametrize("raw,secret", SECRET_SENTINELS)
def test_probe_failure_detail_is_redacted(db, system_factory, seed_distro, raw, secret):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=1, stdout="", stderr=raw)

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert secret not in result.detail
    assert secret not in str(result.to_dict())
    # The diagnostic is still useful: the outcome and the shape of the
    # failure survive redaction.
    assert result.outcome == evidence.OUTCOME_PROBE_FAILED
    assert result.exit_code == 1
    assert result.detail


@pytest.mark.parametrize("raw,secret", SECRET_SENTINELS)
def test_malformed_output_detail_is_redacted(
    db, system_factory, seed_distro, raw, secret
):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    runner = _runner(exit_code=0, stdout=raw)

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert result.outcome == evidence.OUTCOME_MALFORMED_OUTPUT
    assert secret not in result.detail
    assert secret not in str(result.to_dict())


def test_raised_transport_error_detail_is_redacted(db, system_factory, seed_distro):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()

    def _boom(system_arg, argv):
        raise RuntimeError(
            "could not connect: postgresql://praxis:sup3rs3cr3t@db:5432/praxis"
        )

    result = evidence.collect(db, system, runner=_boom, now=NOW)

    assert result.outcome == evidence.OUTCOME_TRANSPORT_ERROR
    assert "sup3rs3cr3t" not in result.detail
    assert "could not connect" in result.detail


def test_transport_failure_factory_redacts_its_reason():
    record = evidence.transport_failure(
        reason=RuntimeError("ssh failed for password=hunter2trombone"), now=NOW
    )

    assert record.outcome == evidence.OUTCOME_TRANSPORT_ERROR
    assert record.value is None
    assert "hunter2trombone" not in record.detail
    assert "ssh failed" in record.detail


def test_redaction_runs_before_bounding_so_a_long_secret_cannot_survive(
    db, system_factory, seed_distro
):
    """Truncating first could cut a secret into a shape the redactor no
    longer recognizes, leaving the prefix behind."""
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()
    secret = "S" * 400
    runner = _runner(exit_code=1, stdout="", stderr=("x" * 300) + f" password={secret}")

    result = evidence.collect(db, system, runner=runner, now=NOW)

    assert "SSSS" not in result.detail
    assert len(result.detail) <= evidence.MAX_DETAIL_CHARS


# ---------------------------------------------------------------------------
# Timezone normalization
#
# Stored observations use naive UTC. An aware timestamp must be converted
# through UTC, not through whatever zone the backend process runs in, or the
# same instant would produce a different freshness decision per deployment.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "offset_text",
    ["+00:00", "+05:30", "+13:00", "-08:00", "-03:30"],
)
def test_aware_timestamps_normalize_to_the_same_instant(offset_text):
    same_instant = f"2026-08-24T12:00:00{offset_text}"
    restored = evidence.evidence_from_dict(
        {
            "value": False,
            "source": evidence.SOURCE_DEBIAN_MARKER,
            "outcome": evidence.OUTCOME_SUCCESS,
            "collected_at": same_instant,
        }
    )

    assert restored is not None
    expected = (
        datetime.fromisoformat(same_instant)
        .astimezone(timezone.utc)
        .replace(tzinfo=None)
    )
    assert restored.collected_at == expected


@pytest.mark.parametrize("offset_text", ["+05:30", "-08:00", "+13:00", "-03:30"])
def test_freshness_is_the_same_for_one_instant_written_in_any_offset(offset_text):
    """The same moment, written with different offsets, must produce the
    same freshness decision. A conversion through the host's local zone
    would make this depend on where the backend is deployed."""
    utc_form = "2026-08-24T12:00:00Z"
    aware_form = (
        datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        .astimezone(_fixed_offset(offset_text))
        .isoformat()
    )

    def _restore(raw):
        return evidence.evidence_from_dict(
            {
                "value": False,
                "source": evidence.SOURCE_DEBIAN_MARKER,
                "outcome": evidence.OUTCOME_SUCCESS,
                "collected_at": raw,
            }
        )

    from_utc = _restore(utc_form)
    from_aware = _restore(aware_form)
    assert from_utc is not None and from_aware is not None
    assert from_utc.collected_at == from_aware.collected_at

    now = datetime(2026, 8, 24, 12, 30, 0)
    host_done = datetime(2026, 8, 24, 11, 55, 0)
    assert evidence.is_fresh(
        from_utc, now=now, not_before=host_done
    ) is evidence.is_fresh(from_aware, now=now, not_before=host_done)
    assert evidence.is_fresh(from_aware, now=now, not_before=host_done) is True


def _fixed_offset(offset_text: str):
    sign = 1 if offset_text[0] == "+" else -1
    hours, minutes = offset_text[1:].split(":")
    return timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))


def test_an_aware_timestamp_is_not_shifted_into_freshness():
    """A reading taken well before the package work must stay stale no
    matter which offset it was written in."""
    stale = (
        datetime(2026, 8, 24, 6, 0, 0, tzinfo=timezone.utc)
        .astimezone(_fixed_offset("+13:00"))
        .isoformat()
    )
    restored = evidence.evidence_from_dict(
        {
            "value": False,
            "source": evidence.SOURCE_DEBIAN_MARKER,
            "outcome": evidence.OUTCOME_SUCCESS,
            "collected_at": stale,
        }
    )

    assert restored is not None
    assert (
        evidence.is_fresh(
            restored,
            now=datetime(2026, 8, 24, 12, 30, 0),
            not_before=datetime(2026, 8, 24, 11, 55, 0),
        )
        is False
    )


# ---------------------------------------------------------------------------
# Log paths
#
# Redacting before persistence is not enough if the same exception is logged
# verbatim first: logs are collected, shipped, and attached to support
# bundles. The new failure paths log the exception category only.
# ---------------------------------------------------------------------------


LOGGED_SECRET = "postgresql://praxis:sup3rs3cr3t@db:5432/praxis"


@contextmanager
def capturing_warnings(caplog, *loggers):
    """Capture WARNING records from the given module loggers.

    Running migrations configures logging through ``logging.config.fileConfig``,
    which disables every logger that already exists. Module loggers are
    therefore inert for the rest of the session, so a test that asserts on
    what one of them emits has to re-enable it first and restore it after.
    """
    previous = [(lg, lg.disabled) for lg in loggers]
    for lg, _ in previous:
        lg.disabled = False
    try:
        with caplog.at_level(logging.WARNING):
            yield
    finally:
        for lg, was_disabled in previous:
            lg.disabled = was_disabled


def test_a_raised_probe_exception_is_not_logged_verbatim(
    db, system_factory, seed_distro, caplog
):
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()

    class _LeakyError(RuntimeError):
        pass

    def _boom(system_arg, argv):
        raise _LeakyError(f"connect failed: {LOGGED_SECRET}")

    with capturing_warnings(caplog, evidence.logger):
        result = evidence.collect(db, system, runner=_boom, now=NOW)

    assert caplog.records, "the failure must still be logged"
    assert "sup3rs3cr3t" not in caplog.text
    assert "sup3rs3cr3t" not in result.detail
    assert "postgresql://" not in caplog.text
    # The category still identifies what went wrong.
    assert "_LeakyError" in caplog.text


def test_transport_failure_detail_survives_redaction_for_the_operator(
    db, system_factory, seed_distro, caplog
):
    """Redaction must not erase the diagnostic; the operator still needs to
    know the probe could not reach the host."""
    seed_distro.name = "Ubuntu"
    db.flush()
    system = system_factory()

    def _boom(system_arg, argv):
        raise RuntimeError(f"connect failed: {LOGGED_SECRET}")

    with capturing_warnings(caplog, evidence.logger):
        result = evidence.collect(db, system, runner=_boom, now=NOW)

    assert result.outcome == evidence.OUTCOME_TRANSPORT_ERROR
    assert "connect failed" in result.detail
