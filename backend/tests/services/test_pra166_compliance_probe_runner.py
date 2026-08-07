"""PRA-166 Slice 1 — file/command compliance probe runner tests.

Covers, per the slice scope:

* All four owned kinds (``file_exists``, ``file_sha256``,
  ``command_stdout_contains``, ``command_exit_code``) — pass / fail /
  error verdicts.
* Transport / timeout / permission / invalid-result error paths land
  with stable reason codes; nothing crashes the sweep.
* Output bounds: stdout truncation suffix appears on long-running
  probes; evidence ``observed_value`` never exceeds the documented
  cap.
* Non-mutation boundary: the probe runner only invokes
  ``SSHService.execute_command``; it never refreshes facts, scans
  packages, or otherwise mutates the host or DB beyond appending
  evidence rows through the evaluation service.
* Shell command construction quotes file paths POSIX-safely and
  wraps operator-supplied commands through a base64 ``sh -s``
  pipeline so paramiko quoting can't interact with the command body.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from app.db.models import (
    CompliancePolicyEvidence,
    Credential,
    Group,
    System,
    SystemMetadata,
)
from app.services import (
    compliance_evaluation_service,
    compliance_probe_runner_service,
    compliance_service,
)
from app.services.compliance_probe_runner_service import (
    EVIDENCE_OBSERVED_CHAR_CAP,
    PROBE_TIMEOUT_SECONDS,
    REASON_COMMAND_NOT_FOUND,
    REASON_EXIT_CODE_MISMATCH,
    REASON_FILE_NOT_FOUND,
    REASON_FILE_UNREADABLE,
    REASON_INVALID_PROBE_RESULT,
    REASON_PERMISSION_DENIED,
    REASON_PROBE_TIMEOUT,
    REASON_SHA256_MISMATCH,
    REASON_SHA256_UNREADABLE,
    REASON_STDOUT_DID_NOT_CONTAIN,
    REASON_SYSTEM_NOT_FOUND,
    REASON_TRANSPORT_FAILURE,
    REASON_UNSUPPORTED_KIND,
    TRUNCATION_SUFFIX,
    WIRE_STDOUT_BYTE_CAP,
    ProbeOutcome,
    UnsupportedProbeKind,
    _build_file_exists_command,
    _build_file_sha256_command,
    _shell_single_quote,
    _truncate_for_evidence,
    _wrap_command_in_b64_shell,
    run_probe,
)

VERDICT_PASS = compliance_evaluation_service.VERDICT_PASS
VERDICT_FAIL = compliance_evaluation_service.VERDICT_FAIL
VERDICT_ERROR = compliance_evaluation_service.VERDICT_ERROR


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra166-probe", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra166-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="probe-host.example.com",
        ip_address="10.0.0.70",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


class _FakeSSHRecorder:
    """Captures every ``_ssh_execute`` call so tests can assert on the
    exact remote command that crossed the (faked) wire.
    """

    def __init__(self, result: Dict[str, Any]):
        self.result = result
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, db, *, system_id, remote_command, timeout):
        self.calls.append(
            {
                "system_id": system_id,
                "remote_command": remote_command,
                "timeout": timeout,
            }
        )
        return self.result


@pytest.fixture
def patch_ssh(monkeypatch):
    """Install a fake ``_ssh_execute`` and return a builder so tests
    can swap the canned SSH result in-line.
    """

    def _install(result: Dict[str, Any]) -> _FakeSSHRecorder:
        recorder = _FakeSSHRecorder(result)
        monkeypatch.setattr(compliance_probe_runner_service, "_ssh_execute", recorder)
        return recorder

    return _install


# ---------------------------------------------------------------------------
# Shell helpers — unit tests on the pure-function quoting + wrapping
# ---------------------------------------------------------------------------


def test_shell_single_quote_handles_embedded_quote():
    out = _shell_single_quote("a'b")
    # POSIX: close quote, escape literal, reopen quote.
    assert out == "'a'\\''b'"


def test_shell_single_quote_round_trips_typical_paths():
    for raw in ("/etc/passwd", "/var/log/auth log", "/tmp/foo-bar.bin"):
        quoted = _shell_single_quote(raw)
        assert quoted.startswith("'") and quoted.endswith("'")
        assert raw in quoted


def test_build_file_exists_command_uses_quoted_path():
    cmd = _build_file_exists_command("/etc/ssh/sshd_config")
    assert "if [ -e '/etc/ssh/sshd_config' ];" in cmd
    assert "printf exists" in cmd
    assert "printf absent" in cmd


def test_build_file_sha256_command_emits_explicit_error_markers():
    cmd = _build_file_sha256_command("/etc/passwd")
    # Markers chosen to never collide with a real 64-char hex digest.
    assert "__NOT_FOUND__" in cmd
    assert "__UNREADABLE__" in cmd
    assert "sha256sum '/etc/passwd'" in cmd


def test_wrap_command_with_stdout_cap_pipes_through_head():
    wrapped = _wrap_command_in_b64_shell("echo hi", with_stdout_cap=True)
    assert "base64 -d" in wrapped
    assert f"head -c {WIRE_STDOUT_BYTE_CAP}" in wrapped


def test_wrap_command_without_cap_redirects_to_devnull():
    wrapped = _wrap_command_in_b64_shell("/bin/true", with_stdout_cap=False)
    assert ">/dev/null 2>&1" in wrapped
    assert "head -c" not in wrapped


def test_truncate_for_evidence_appends_suffix():
    long_value = "x" * (EVIDENCE_OBSERVED_CHAR_CAP + 50)
    truncated = _truncate_for_evidence(long_value)
    assert truncated.endswith(TRUNCATION_SUFFIX)
    assert len(truncated) == EVIDENCE_OBSERVED_CHAR_CAP + len(TRUNCATION_SUFFIX)


def test_truncate_for_evidence_passes_through_short_values():
    assert _truncate_for_evidence("short") == "short"
    assert _truncate_for_evidence(None) is None


# ---------------------------------------------------------------------------
# run_probe dispatch
# ---------------------------------------------------------------------------


def test_run_probe_rejects_unsupported_kind(db, host):
    with pytest.raises(UnsupportedProbeKind):
        run_probe(db, kind="package_installed", system_id=host.id, definition={})


def test_run_probe_returns_explicit_error_for_missing_system(db, patch_ssh):
    sentinel = patch_ssh({"status": "success", "stdout": "exists", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=987_654_321,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_SYSTEM_NOT_FOUND
    # The probe runner short-circuits before reaching SSH.
    assert sentinel.calls == []


def test_run_probe_wraps_unexpected_handler_exception(db, host, monkeypatch):
    def _boom(db, system_id, definition):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(compliance_probe_runner_service._PROBES, "file_exists", _boom)
    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_INVALID_PROBE_RESULT
    assert "kaboom" in (outcome.observed_value or "")


# ---------------------------------------------------------------------------
# file_exists
# ---------------------------------------------------------------------------


def test_file_exists_pass(db, host, patch_ssh):
    rec = patch_ssh({"status": "success", "stdout": "exists", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_PASS
    assert outcome.observed_value == "exists"
    assert outcome.expected_value == "/etc/passwd"
    # Timeout is the documented compliance probe ceiling.
    assert rec.calls[0]["timeout"] == PROBE_TIMEOUT_SECONDS


def test_file_exists_fail_when_absent(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": "absent", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/ssh/sshd_config"},
    )
    assert outcome.verdict == VERDICT_FAIL
    assert outcome.reason == REASON_FILE_NOT_FOUND
    assert outcome.observed_value == "absent"


def test_file_exists_error_on_invalid_probe_result(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": "garbled-output", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_INVALID_PROBE_RESULT


def test_file_exists_error_on_transport_failure(db, host, patch_ssh):
    patch_ssh({"status": "failed", "stderr": "ECONNREFUSED"})
    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_TRANSPORT_FAILURE


def test_file_exists_error_on_paramiko_timeout(db, host, patch_ssh):
    patch_ssh(
        {"status": "failed", "stderr": "Unexpected error: socket.timeout timed out"}
    )
    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_PROBE_TIMEOUT


# ---------------------------------------------------------------------------
# file_sha256
# ---------------------------------------------------------------------------


_GOOD_HASH = "a" * 64
_OTHER_HASH = "b" * 64


def test_file_sha256_pass(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": _GOOD_HASH, "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_sha256",
        system_id=host.id,
        definition={"path": "/usr/bin/curl", "sha256": _GOOD_HASH},
    )
    assert outcome.verdict == VERDICT_PASS
    assert outcome.observed_value == _GOOD_HASH


def test_file_sha256_fail_on_mismatch(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": _OTHER_HASH, "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_sha256",
        system_id=host.id,
        definition={"path": "/usr/bin/curl", "sha256": _GOOD_HASH},
    )
    assert outcome.verdict == VERDICT_FAIL
    assert outcome.reason == REASON_SHA256_MISMATCH
    assert outcome.observed_value == _OTHER_HASH


def test_file_sha256_fail_on_not_found(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": "__NOT_FOUND__", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_sha256",
        system_id=host.id,
        definition={"path": "/tmp/never", "sha256": _GOOD_HASH},
    )
    assert outcome.verdict == VERDICT_FAIL
    assert outcome.reason == REASON_FILE_NOT_FOUND
    assert outcome.observed_value == "absent"


def test_file_sha256_error_on_unreadable(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": "__UNREADABLE__", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_sha256",
        system_id=host.id,
        definition={"path": "/etc/shadow", "sha256": _GOOD_HASH},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_FILE_UNREADABLE


def test_file_sha256_error_on_empty_output(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": "", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_sha256",
        system_id=host.id,
        definition={"path": "/etc/passwd", "sha256": _GOOD_HASH},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_SHA256_UNREADABLE


def test_file_sha256_error_on_garbage_output(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": "not-a-hash", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="file_sha256",
        system_id=host.id,
        definition={"path": "/etc/passwd", "sha256": _GOOD_HASH},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_INVALID_PROBE_RESULT


def test_file_sha256_error_on_transport_failure(db, host, patch_ssh):
    patch_ssh({"status": "failed", "stderr": "auth fail"})
    outcome = run_probe(
        db,
        kind="file_sha256",
        system_id=host.id,
        definition={"path": "/etc/passwd", "sha256": _GOOD_HASH},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_TRANSPORT_FAILURE


# ---------------------------------------------------------------------------
# command_stdout_contains
# ---------------------------------------------------------------------------


def test_command_stdout_contains_pass(db, host, patch_ssh):
    patch_ssh(
        {
            "status": "success",
            "stdout": "ssh_config\nPermitRootLogin no\n",
            "exit_code": 0,
        }
    )
    outcome = run_probe(
        db,
        kind="command_stdout_contains",
        system_id=host.id,
        definition={
            "command": "sshd -T",
            "expected_substring": "PermitRootLogin no",
        },
    )
    assert outcome.verdict == VERDICT_PASS
    assert "PermitRootLogin no" in outcome.observed_value


def test_command_stdout_contains_fail(db, host, patch_ssh):
    patch_ssh({"status": "success", "stdout": "different stuff", "exit_code": 0})
    outcome = run_probe(
        db,
        kind="command_stdout_contains",
        system_id=host.id,
        definition={
            "command": "sshd -T",
            "expected_substring": "PermitRootLogin no",
        },
    )
    assert outcome.verdict == VERDICT_FAIL
    assert outcome.reason == REASON_STDOUT_DID_NOT_CONTAIN
    assert outcome.observed_value == "different stuff"


def test_command_stdout_contains_truncates_observed_value(db, host, patch_ssh):
    """Stdout longer than the evidence cap MUST land truncated."""
    long_stdout = "x" * (EVIDENCE_OBSERVED_CHAR_CAP * 4)
    patch_ssh({"status": "success", "stdout": long_stdout, "exit_code": 0})
    outcome = run_probe(
        db,
        kind="command_stdout_contains",
        system_id=host.id,
        definition={"command": "cat /var/log/messages", "expected_substring": "nope"},
    )
    assert outcome.verdict == VERDICT_FAIL
    assert outcome.observed_value.endswith(TRUNCATION_SUFFIX)
    # Truncated value MUST fit inside the documented cap + suffix.
    assert len(outcome.observed_value) == EVIDENCE_OBSERVED_CHAR_CAP + len(
        TRUNCATION_SUFFIX
    )


def test_command_stdout_contains_error_on_transport_failure(db, host, patch_ssh):
    patch_ssh({"status": "failed", "stderr": "Connection refused"})
    outcome = run_probe(
        db,
        kind="command_stdout_contains",
        system_id=host.id,
        definition={"command": "true", "expected_substring": "x"},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_TRANSPORT_FAILURE


def test_command_stdout_contains_command_body_crosses_wire_via_b64(db, host, patch_ssh):
    rec = patch_ssh({"status": "success", "stdout": "ok", "exit_code": 0})
    run_probe(
        db,
        kind="command_stdout_contains",
        system_id=host.id,
        definition={"command": "echo ok", "expected_substring": "ok"},
    )
    sent = rec.calls[0]["remote_command"]
    assert "base64 -d" in sent
    assert f"head -c {WIRE_STDOUT_BYTE_CAP}" in sent
    # Raw command text MUST NOT appear verbatim — it travels b64-encoded.
    assert "echo ok" not in sent


# ---------------------------------------------------------------------------
# command_exit_code
# ---------------------------------------------------------------------------


def test_command_exit_code_pass(db, host, patch_ssh):
    patch_ssh({"status": "success", "exit_code": 0, "stdout": ""})
    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "/bin/true", "expected_exit_code": 0},
    )
    assert outcome.verdict == VERDICT_PASS
    assert outcome.observed_value == "0"
    assert outcome.expected_value == "0"


def test_command_exit_code_fail(db, host, patch_ssh):
    patch_ssh({"status": "warning", "exit_code": 1, "stdout": ""})
    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "/bin/false", "expected_exit_code": 0},
    )
    assert outcome.verdict == VERDICT_FAIL
    assert outcome.reason == REASON_EXIT_CODE_MISMATCH
    assert outcome.observed_value == "1"


def test_command_exit_code_classifies_permission_denied(db, host, patch_ssh):
    """POSIX exit 126 = file exists but is not executable / lacks
    permission to execute. The verdict stays ``fail`` (the probe did
    not get the expected exit code) but the reason carries the
    actionable signal."""
    patch_ssh({"status": "warning", "exit_code": 126, "stdout": ""})
    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "/etc/shadow-reader", "expected_exit_code": 0},
    )
    assert outcome.verdict == VERDICT_FAIL
    assert outcome.reason == REASON_PERMISSION_DENIED
    assert outcome.observed_value == "126"


def test_command_exit_code_classifies_command_not_found(db, host, patch_ssh):
    """POSIX exit 127 = command not found on $PATH. Distinguished from
    exit_code_mismatch so operators can spot missing binaries without
    inspecting observed_value."""
    patch_ssh({"status": "warning", "exit_code": 127, "stdout": ""})
    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "no-such-binary", "expected_exit_code": 0},
    )
    assert outcome.verdict == VERDICT_FAIL
    assert outcome.reason == REASON_COMMAND_NOT_FOUND
    assert outcome.observed_value == "127"


def test_command_exit_code_passes_when_expected_is_126(db, host, patch_ssh):
    """If the operator *expects* 126/127 (e.g. checking that a binary
    is intentionally non-executable for an audit), the verdict must
    still be ``pass`` — the classification only refines failures.
    """
    patch_ssh({"status": "warning", "exit_code": 126, "stdout": ""})
    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "/etc/shadow-reader", "expected_exit_code": 126},
    )
    assert outcome.verdict == VERDICT_PASS
    assert outcome.reason is None


def test_command_exit_code_error_on_missing_exit_code(db, host, patch_ssh):
    patch_ssh({"status": "success", "exit_code": None, "stdout": ""})
    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "/bin/true", "expected_exit_code": 0},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_INVALID_PROBE_RESULT


def test_command_exit_code_error_on_transport_failure(db, host, patch_ssh):
    patch_ssh({"status": "failed", "stderr": "auth failed"})
    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "/bin/true", "expected_exit_code": 0},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_TRANSPORT_FAILURE


def test_command_exit_code_discards_stdout_on_wire(db, host, patch_ssh):
    rec = patch_ssh({"status": "success", "exit_code": 0, "stdout": ""})
    run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "noisy-cmd", "expected_exit_code": 0},
    )
    sent = rec.calls[0]["remote_command"]
    # Inner stdout/stderr discarded so a chatty command can't flood
    # the SSH channel; exit code still propagates via the pipeline's
    # last command.
    assert ">/dev/null 2>&1" in sent
    assert "head -c" not in sent


# ---------------------------------------------------------------------------
# Integration with the evaluation runner — bounded, non-mutating,
# writes one evidence row through the existing persistence path.
# ---------------------------------------------------------------------------


def _make_policy(db, admin_user, slug):
    return compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=slug,
        name=slug.upper(),
    )


def _add_check(db, admin_user, policy, slug, kind, definition):
    return compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=slug,
        title=slug,
        kind=kind,
        definition=definition,
    )


def test_evaluation_persists_executed_evidence_for_probe_kinds(
    db, admin_user, host, patch_ssh
):
    """A successful probe MUST produce a single ``runner_executed``
    evidence row with the probe's verdict / reason / observed values
    intact.
    """
    patch_ssh({"status": "success", "stdout": "exists", "exit_code": 0})
    policy = _make_policy(db, admin_user, "probe-integ")
    _add_check(db, admin_user, policy, "passwd", "file_exists", {"path": "/etc/passwd"})

    summary = compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    rows = (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.policy_id == policy.id)
        .all()
    )
    assert len(rows) == 1
    [row] = rows
    assert row.verdict == VERDICT_PASS
    assert row.check_kind == "file_exists"
    payload = compliance_evaluation_service.evidence_export_row(row)
    assert payload["runner_status"] == "runner_executed"
    assert payload["runner_owner"] == "deferred_to_pra166"
    assert summary.counts[VERDICT_PASS] == 1


def test_evaluation_persists_transport_error_evidence_for_probe_kinds(
    db, admin_user, host, patch_ssh
):
    """A transport failure must surface as a ``runner_executed`` error
    row (the runner ran, it just couldn't reach the host) so operators
    can tell "execution failed" apart from "never executed".
    """
    patch_ssh({"status": "failed", "stderr": "ECONNREFUSED"})
    policy = _make_policy(db, admin_user, "probe-transport")
    _add_check(
        db,
        admin_user,
        policy,
        "true",
        "command_exit_code",
        {"command": "/bin/true", "expected_exit_code": 0},
    )

    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    [row] = (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.policy_id == policy.id)
        .all()
    )
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_TRANSPORT_FAILURE
    payload = compliance_evaluation_service.evidence_export_row(row)
    assert payload["runner_status"] == "runner_executed"


def test_probe_runner_does_not_touch_facts_or_packages(
    db, admin_user, host, patch_ssh, monkeypatch
):
    """Non-mutation boundary: a probe sweep must not call into the
    facts collector, facts ingest, or package scanner. Trip those
    call sites if anything regresses.
    """
    tripped: List[str] = []

    def _trip(name):
        def _t(*args, **kwargs):
            tripped.append(name)
            raise AssertionError(f"{name} must not run during a probe sweep")

        return _t

    monkeypatch.setattr(
        "app.services.facts_service.ingest",
        _trip("facts_service.ingest"),
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.ssh_facts_collector_service.collect_and_ingest",
        _trip("ssh_facts_collector_service.collect_and_ingest"),
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.package_service.PackageService.scan_packages",
        _trip("PackageService.scan_packages"),
        raising=False,
    )

    patch_ssh({"status": "success", "stdout": "exists", "exit_code": 0})
    policy = _make_policy(db, admin_user, "probe-nomutation")
    _add_check(db, admin_user, policy, "f", "file_exists", {"path": "/etc/passwd"})

    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    assert tripped == []


def test_probe_runner_uses_documented_timeout(db, host, patch_ssh):
    """Per-probe SSH timeout is the published compliance ceiling and
    must not silently grow."""
    rec = patch_ssh({"status": "success", "stdout": "exists", "exit_code": 0})
    run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/passwd"},
    )
    assert rec.calls[0]["timeout"] == PROBE_TIMEOUT_SECONDS
    assert PROBE_TIMEOUT_SECONDS <= 60  # belt + suspenders


# ---------------------------------------------------------------------------
# Module-level boundary — the evaluation service still does not leak
# probe-runner transport symbols even after wiring.
# ---------------------------------------------------------------------------


def test_evaluation_module_does_not_surface_ssh_symbols():
    import app.services.compliance_evaluation_service as svc

    forbidden = {
        "subprocess",
        "paramiko",
        "ssh_service",
        "ssh_facts_collector_service",
    }
    assert not (forbidden & set(dir(svc)))


def test_unsupported_reason_string_is_stable():
    """Stable reason vocabulary so external auditors can grep
    historical evidence."""
    assert REASON_UNSUPPORTED_KIND == "unsupported_probe_kind"
    assert REASON_PERMISSION_DENIED == "permission_denied"


def test_runner_owner_pra166_string_is_pinned():
    """PRA-166 Slice 3: the runner-owner label ``deferred_to_pra166``
    is intentionally preserved for the PRA-165 wire-shape contract,
    even though the runner shipped in PRA-166 Slice 1. A rename
    would either churn historical evidence rows (compat shim makes
    the wire identical to the legacy string anyway) or break
    external JSONL/CSV consumers (no shim).

    If you tripped this assertion: read the comment block above
    ``RUNNER_OWNER_PRA166`` in ``backend/app/services/compliance_service.py``
    before changing the value.
    """
    from app.services.compliance_service import RUNNER_OWNER_PRA166

    assert (
        RUNNER_OWNER_PRA166 == "deferred_to_pra166"
    ), "runner-owner label changed without a compatibility plan"


# ---------------------------------------------------------------------------
# No-host-mutation regression
# ---------------------------------------------------------------------------


class _FakeChannel:
    def __init__(self, exit_code: int):
        self._exit_code = exit_code

    def recv_exit_status(self) -> int:
        return self._exit_code


class _FakeStream:
    def __init__(self, payload: bytes, channel: _FakeChannel | None = None):
        self._payload = payload
        self.channel = channel

    def read(self) -> bytes:
        return self._payload


class _FakeParamikoClient:
    def __init__(self, exit_code: int, stdout: bytes, stderr: bytes):
        self._exit_code = exit_code
        self._stdout = stdout
        self._stderr = stderr
        self.calls: List[Dict[str, Any]] = []

    def exec_command(self, command: str, timeout: int | None = None):
        self.calls.append({"command": command, "timeout": timeout})
        channel = _FakeChannel(self._exit_code)
        stdout = _FakeStream(self._stdout, channel=channel)
        stderr = _FakeStream(self._stderr)
        return None, stdout, stderr


@pytest.fixture
def host_with_metadata(db, host):
    """Seed a ``SystemMetadata`` row in a known baseline so the
    regression test can prove the probe runner doesn't touch it.
    """
    meta = SystemMetadata(
        system_id=host.id,
        connection_status="never_connected",
        consecutive_failures=3,
    )
    db.add(meta)
    db.flush()
    return host, meta


def test_probe_runner_does_not_mutate_system_metadata_on_success(
    db, host_with_metadata, monkeypatch
):
    """The probe runner must not flip
    ``SystemMetadata.connection_status`` /
    ``SystemMetadata.last_connection`` /
    ``SystemMetadata.consecutive_failures`` /
    ``System.status`` when a probe runs, even on the success path. The
    bypass goes through ``get_connection`` + raw ``client.exec_command``
    rather than ``SSHService.execute_command`` whose status-mutation
    branch is the regression vector.
    """
    host, meta = host_with_metadata
    baseline = {
        "connection_status": meta.connection_status,
        "consecutive_failures": meta.consecutive_failures,
        "last_connection": meta.last_connection,
        "system_status": host.status,
    }

    fake = _FakeParamikoClient(exit_code=0, stdout=b"exists", stderr=b"")

    def _fake_get_connection(self, system_id, force_password_auth=False):
        return fake, False

    monkeypatch.setattr(
        compliance_probe_runner_service.SSHService,
        "get_connection",
        _fake_get_connection,
    )

    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_PASS

    db.refresh(meta)
    db.refresh(host)
    assert meta.connection_status == baseline["connection_status"]
    assert meta.consecutive_failures == baseline["consecutive_failures"]
    assert meta.last_connection == baseline["last_connection"]
    assert host.status == baseline["system_status"]
    assert fake.calls and fake.calls[0]["timeout"] == PROBE_TIMEOUT_SECONDS


def test_probe_runner_does_not_mutate_system_metadata_on_transport_failure(
    db, host_with_metadata, monkeypatch
):
    """Same boundary on the SSHConnectionError path — ``execute_command``
    historically marked the host Inactive/Unreachable and bumped
    ``consecutive_failures``. The bypass must leave both alone.
    """
    host, meta = host_with_metadata
    baseline_status = meta.connection_status
    baseline_failures = meta.consecutive_failures
    baseline_system_status = host.status

    def _boom(self, system_id, force_password_auth=False):
        from app.services.ssh_service import SSHConnectionError

        raise SSHConnectionError("Authentication failed for probe-host")

    monkeypatch.setattr(
        compliance_probe_runner_service.SSHService,
        "get_connection",
        _boom,
    )

    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=host.id,
        definition={"command": "/bin/true", "expected_exit_code": 0},
    )
    assert outcome.verdict == VERDICT_ERROR
    assert outcome.reason == REASON_TRANSPORT_FAILURE

    db.refresh(meta)
    db.refresh(host)
    assert meta.connection_status == baseline_status
    assert meta.consecutive_failures == baseline_failures
    assert host.status == baseline_system_status


def test_probe_runner_does_not_call_execute_command(db, host, monkeypatch):
    """Belt-and-suspenders: trip ``SSHService.execute_command`` so a
    future refactor reintroducing the status-mutating path fails loudly.
    """

    def _explode(self, *args, **kwargs):
        raise AssertionError(
            "compliance probe runner must not call SSHService.execute_command "
            "(it mutates SystemMetadata.connection_status / System.status and "
            "commits mid-evaluation)."
        )

    monkeypatch.setattr(
        compliance_probe_runner_service.SSHService,
        "execute_command",
        _explode,
    )

    fake = _FakeParamikoClient(exit_code=0, stdout=b"exists", stderr=b"")

    def _fake_get_connection(self, system_id, force_password_auth=False):
        return fake, False

    monkeypatch.setattr(
        compliance_probe_runner_service.SSHService,
        "get_connection",
        _fake_get_connection,
    )

    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=host.id,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_PASS


# ---------------------------------------------------------------------------
# Read-only SSH subclass regression
# ---------------------------------------------------------------------------


def _count_ssh_audit_rows(db):
    from app.db.ssh_security_models import SSHHostKey, SSHSecurityLog

    return {
        "security_logs": db.query(SSHSecurityLog).count(),
        "host_keys": db.query(SSHHostKey).count(),
    }


def test_readonly_subclass_overrides_are_no_ops(db, host_with_metadata):
    """Direct unit test: the three overridden seams in
    ``_ReadOnlyComplianceSSHService`` must produce zero SSH-audit
    rows when called explicitly. Catches the case where a future
    refactor removes the no-op body and accidentally re-enables the
    parent's writes.
    """
    host, _ = host_with_metadata
    before = _count_ssh_audit_rows(db)

    svc = compliance_probe_runner_service._ReadOnlyComplianceSSHService(db)
    svc._log_security_event(
        host,
        "connection_success",
        {"username": "root", "source_ip": "127.0.0.1", "success": True},
    )
    svc._store_host_key(host, transport=None)
    svc._update_system_connection_status(host, "connected")

    db.flush()
    after = _count_ssh_audit_rows(db)
    assert after == before


def test_readonly_subclass_refuses_tofu_when_strict_verification_required(
    db, admin_user, seed_distro
):
    """Fresh host (no verified SSHHostKey) with
    ``ssh_security_policy.require_host_key_verification=True`` must
    raise ``SSHConnectionError`` rather than fall through to
    ``HostKeyPromptPolicy`` (which would TOFU-capture the key and
    commit during the compliance evaluation transaction).
    """
    from app.db.models import Credential, Group, System
    from app.db.ssh_security_models import SSHSecurityPolicy

    policy = SSHSecurityPolicy(
        name="probe-strict",
        description="x",
        require_host_key_verification=True,
        created_by=admin_user.id,
    )
    db.add(policy)
    db.flush()

    group = Group(name="probe-strict-group", description="x")
    db.add(group)
    db.flush()
    cred = Credential(name="probe-strict-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    host = System(
        hostname="probe-strict.example.com",
        ip_address="10.0.0.71",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
        ssh_security_policy_id=policy.id,
    )
    db.add(host)
    db.flush()

    svc = compliance_probe_runner_service._ReadOnlyComplianceSSHService(db)
    from app.services.ssh_service import SSHConnectionError

    with pytest.raises(SSHConnectionError, match="TOFU"):
        svc._create_connection(host)


def test_ssh_execute_does_not_commit_during_probe(db, host_with_metadata, monkeypatch):
    """The probe runner's transport adapter must never call
    ``self.db.commit()``. Spy on the session's ``commit`` method and
    assert it is not invoked while a probe runs through the new
    subclass-backed ``_ssh_execute``.
    """
    host, _ = host_with_metadata

    commit_calls: List[str] = []
    original_commit = db.commit

    def _spy_commit(*args, **kwargs):
        commit_calls.append("commit")
        return original_commit(*args, **kwargs)

    monkeypatch.setattr(db, "commit", _spy_commit)

    fake = _FakeParamikoClient(exit_code=0, stdout=b"exists", stderr=b"")
    monkeypatch.setattr(
        compliance_probe_runner_service._ReadOnlyComplianceSSHService,
        "get_connection",
        lambda self, system_id, force_password_auth=False: (fake, False),
    )

    result = compliance_probe_runner_service._ssh_execute(
        db,
        system_id=host.id,
        remote_command="echo hi",
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    assert result["status"] == "success"
    assert commit_calls == []


def test_ssh_execute_does_not_grow_ssh_audit_tables(
    db, host_with_metadata, monkeypatch
):
    """Row-count regression: an entire probe run through
    ``_ssh_execute`` must not append ``SSHSecurityLog`` or
    ``SSHHostKey`` rows, even though it exercises ``get_connection``.
    """
    host, _ = host_with_metadata
    before = _count_ssh_audit_rows(db)

    fake = _FakeParamikoClient(exit_code=0, stdout=b"exists", stderr=b"")
    monkeypatch.setattr(
        compliance_probe_runner_service._ReadOnlyComplianceSSHService,
        "get_connection",
        lambda self, system_id, force_password_auth=False: (fake, False),
    )

    compliance_probe_runner_service._ssh_execute(
        db,
        system_id=host.id,
        remote_command="echo hi",
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    db.flush()
    after = _count_ssh_audit_rows(db)
    assert after == before


def test_ssh_execute_uses_readonly_subclass_not_base_sshservice(db, host, monkeypatch):
    """Belt + suspenders: the ``SSHService`` symbol imported by the
    probe runner must NOT be the class actually instantiated by
    ``_ssh_execute``. The subclass is the only acceptable instance
    type — anything else means a refactor regressed the read-only
    contract.
    """
    captured_classes: List[type] = []

    real_init = compliance_probe_runner_service._ReadOnlyComplianceSSHService.__init__

    def _spy_init(self, *args, **kwargs):
        captured_classes.append(type(self))
        return real_init(self, *args, **kwargs)

    monkeypatch.setattr(
        compliance_probe_runner_service._ReadOnlyComplianceSSHService,
        "__init__",
        _spy_init,
    )

    fake = _FakeParamikoClient(exit_code=0, stdout=b"exists", stderr=b"")
    monkeypatch.setattr(
        compliance_probe_runner_service._ReadOnlyComplianceSSHService,
        "get_connection",
        lambda self, system_id, force_password_auth=False: (fake, False),
    )

    compliance_probe_runner_service._ssh_execute(
        db,
        system_id=host.id,
        remote_command="echo hi",
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    assert captured_classes == [
        compliance_probe_runner_service._ReadOnlyComplianceSSHService
    ]
