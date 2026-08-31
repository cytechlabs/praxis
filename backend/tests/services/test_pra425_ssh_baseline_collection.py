"""PRA-425: the SSH baseline survives collection, ingestion, and evaluation.

Every test here drives the shipped collector script, the shipped SSH parser,
and ``FactsService.ingest`` in sequence. Nothing hand-builds a payload, because
the defect this covers lived in the collector's own resolution of the server
configuration: a hand-written payload would have skipped straight past it.

Three contracts are exercised end to end:

* a setting an administrator actually configured reaches the stored row, even
  when it lives in an included drop-in file and the collector cannot run the
  server's own configuration dump;
* a setting the collection could not establish is recorded as such rather than
  left as a bare NULL, so it evaluates as a coverage gap and never as a host
  that has yet to be scanned; and
* both transports and every administrator spelling land one canonical value.
"""

import base64
import os
import shutil
import subprocess

import pytest

from app.db.models import Credential, Group, HostFacts, System
from app.services import (
    compliance_evaluation_service,
    compliance_labels,
    facts_service,
    ssh_facts_collector_service,
)

COLLECTOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "app",
    "services",
    "_assets",
    "collect-facts.sh",
)

PERMIT_ROOT_LOGIN = "ssh.config.PermitRootLogin"
PASSWORD_AUTHENTICATION = "ssh.config.PasswordAuthentication"


def _server_dump_is_available() -> bool:
    """True when this machine's own sshd can print an effective configuration.

    The collector prefers that dump over any configuration file, so it would
    answer from the machine running the tests instead of from the fixture
    tree. The collector deliberately offers no override for which binary it
    runs, so the tests state the dependency and skip instead of pretending.
    """
    candidates = [shutil.which("sshd")]
    candidates += ["/usr/sbin/sshd", "/sbin/sshd", "/usr/local/sbin/sshd"]
    for candidate in candidates:
        if not candidate or not os.access(candidate, os.X_OK):
            continue
        try:
            proc = subprocess.run(
                [candidate, "-T"], capture_output=True, text=True, timeout=15
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            return True
    return False


needs_config_walk = pytest.mark.skipif(
    _server_dump_is_available(),
    reason="this machine's sshd answers -T, so the collector never reads the fixture",
)


@pytest.fixture
def system(db, seed_distro):
    group = Group(name="pra425-facts", description="x")
    db.add(group)
    db.flush()
    cred = Credential(name="cred-pra425", auth_method="ssh_key", username="praxisops")
    db.add(cred)
    db.flush()
    row = System(
        hostname="pra425-host.example.com",
        ip_address="192.0.2.125",
        distro_id=seed_distro.id,
        os_version="12",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(row)
    db.flush()
    db.commit()
    return row


# --------------------------------------------------------------- collection


def _run_collector(config_path, cwd=None) -> str:
    """Run the shipped collector against a fixture configuration root."""
    env = dict(os.environ)
    env["PRAXIS_SSHD_CONFIG"] = str(config_path)
    proc = subprocess.run(
        ["sh", COLLECTOR],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=60,
    )
    return proc.stdout


def _collect(config_path, cwd=None) -> dict:
    """Collector output through the shipped parser: the real ingest payload."""
    return ssh_facts_collector_service.parse_payload(_run_collector(config_path, cwd))


def _drop_in_tree(tmp_path, name, body, root_extra=""):
    """Write the layout every current distribution ships: a root file whose
    baseline directives are commented out, plus an included drop-in that
    carries the settings an administrator actually applied."""
    include_dir = tmp_path / "sshd_config.d"
    include_dir.mkdir(parents=True, exist_ok=True)
    (include_dir / name).write_text(body)
    root = tmp_path / "sshd_config"
    root.write_text(
        "Include sshd_config.d/*.conf\n"
        "#PermitRootLogin prohibit-password\n"
        "#PasswordAuthentication yes\n" + root_extra
    )
    return root


def _ingest(db, system_id, payload, *, transport="ssh", collected_at=None, force=False):
    """Persist a collected payload.

    ``collected_at`` is overridden only where a test needs two collections in
    a defined order; the collector stamps a real timestamp otherwise.
    """
    if collected_at is not None:
        payload = dict(payload, collected_at=collected_at)
    return facts_service.ingest(
        db,
        system_id=system_id,
        payload=payload,
        source_transport=transport,
        force=force,
    )


def _row(db, system_id) -> HostFacts:
    return db.query(HostFacts).filter(HostFacts.system_id == system_id).one()


def _evaluate(db, system_id, fact_key, expected="no"):
    return compliance_evaluation_service._evaluate_fact_equals(
        db, system_id, {"fact_key": fact_key, "expected": expected}
    )


def _status(verdict):
    return compliance_labels.evidence_status(verdict.verdict, verdict.reason)


def _errors_for(row, key):
    return {
        entry["error"] for entry in (row.partial_errors or []) if entry["key"] == key
    }


# ------------------------------------------- a configured value is not lost


@needs_config_walk
def test_hardened_drop_in_reaches_the_row_and_scores_a_pass(db, system, tmp_path):
    """The regression. Both settings live in an included drop-in file and the
    root file only comments out the defaults, which is the layout Debian- and
    EL-family hosts ship. An unprivileged collection could not run the
    server's dump and reported nothing at all, so a hardened host presented
    as one nobody had scanned."""
    config = _drop_in_tree(
        tmp_path,
        "50-hardening.conf",
        "PermitRootLogin no\nPasswordAuthentication no\n",
    )
    payload = _collect(config)

    assert payload["ssh_permit_root_login"] == "no"
    assert payload["ssh_password_authentication"] == "no"

    _ingest(db, system.id, payload)
    row = _row(db, system.id)
    assert row.ssh_permit_root_login == "no"
    assert row.ssh_password_authentication == "no"
    assert _errors_for(row, "ssh_permit_root_login") == set()

    for fact_key in (PERMIT_ROOT_LOGIN, PASSWORD_AUTHENTICATION):
        verdict = _evaluate(db, system.id, fact_key)
        assert verdict.verdict == compliance_evaluation_service.VERDICT_PASS
        assert verdict.observed_value == "no"


@needs_config_walk
def test_permissive_drop_in_reaches_the_row_and_scores_a_fail(db, system, tmp_path):
    """The same path must carry the value that fails the check, not only the
    one that passes it."""
    config = _drop_in_tree(
        tmp_path,
        "50-permissive.conf",
        "PermitRootLogin yes\nPasswordAuthentication yes\n",
    )
    _ingest(db, system.id, _collect(config))

    row = _row(db, system.id)
    assert row.ssh_permit_root_login == "yes"
    assert row.ssh_password_authentication == "yes"

    for fact_key in (PERMIT_ROOT_LOGIN, PASSWORD_AUTHENTICATION):
        verdict = _evaluate(db, system.id, fact_key)
        assert verdict.verdict == compliance_evaluation_service.VERDICT_FAIL
        assert verdict.observed_value == "yes"


@needs_config_walk
def test_the_first_occurrence_wins_exactly_as_the_server_resolves_it(
    db, system, tmp_path
):
    """The server keeps the first value it obtains for a keyword. Reporting a
    later line would tell an operator their host is hardened when the running
    server ignores that line."""
    config = tmp_path / "sshd_config"
    config.write_text(
        "PermitRootLogin no\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication no\n"
        "PasswordAuthentication yes\n"
    )
    payload = _collect(config)

    assert payload["ssh_permit_root_login"] == "no"
    assert payload["ssh_password_authentication"] == "no"


@needs_config_walk
def test_a_nested_include_is_followed(db, system, tmp_path):
    """EL-family hosts include a drop-in that includes a further file, so the
    walk has to recurse rather than read one level."""
    inner = tmp_path / "inner.conf"
    inner.write_text("PermitRootLogin no\n")
    config = _drop_in_tree(
        tmp_path,
        "50-distro.conf",
        f"Include {inner}\nPasswordAuthentication no\n",
    )
    payload = _collect(config)

    assert payload["ssh_permit_root_login"] == "no"
    assert payload["ssh_password_authentication"] == "no"


@needs_config_walk
def test_a_relative_include_resolves_against_the_configuration_directory(
    db, system, tmp_path
):
    """The server resolves a relative Include under its own configuration
    directory. The collector runs from whatever directory the managed
    account lands in, so resolving it there instead would read a file the
    server never consults."""
    config = _drop_in_tree(
        tmp_path / "real", "50-hardening.conf", "PermitRootLogin no\n"
    )
    decoy = tmp_path / "decoy" / "sshd_config.d"
    decoy.mkdir(parents=True)
    (decoy / "50-hardening.conf").write_text("PermitRootLogin yes\n")

    payload = _collect(config, cwd=str(tmp_path / "decoy"))

    assert payload["ssh_permit_root_login"] == "no"


@needs_config_walk
def test_a_directive_inside_a_match_block_is_not_reported_as_effective(
    db, system, tmp_path
):
    """Directives after the first Match apply only to matching connections.
    Reporting one as the server-wide setting would invent evidence."""
    config = tmp_path / "sshd_config"
    config.write_text(
        "PermitRootLogin no\nMatch User deploy\nPasswordAuthentication yes\n"
    )
    payload = _collect(config)

    assert payload["ssh_permit_root_login"] == "no"
    assert "ssh_password_authentication" not in payload

    _ingest(db, system.id, payload)
    assert _evaluate(db, system.id, PERMIT_ROOT_LOGIN).verdict == (
        compliance_evaluation_service.VERDICT_PASS
    )
    assert _status(_evaluate(db, system.id, PASSWORD_AUTHENTICATION)) == (
        compliance_labels.STATUS_COVERAGE_PENDING
    )


@needs_config_walk
@pytest.mark.skipif(
    os.geteuid() == 0, reason="root reads a mode-000 file, so nothing is unreadable"
)
def test_an_unreadable_earlier_file_stops_the_walk(db, system, tmp_path):
    """A file the collection cannot read may hold the occurrence that wins.
    Anything after it is therefore overridable and must not be reported."""
    include_dir = tmp_path / "sshd_config.d"
    include_dir.mkdir()
    blocked = include_dir / "10-blocked.conf"
    blocked.write_text("PermitRootLogin no\n")
    blocked.chmod(0o000)
    config = tmp_path / "sshd_config"
    config.write_text(
        "Include sshd_config.d/*.conf\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
    )
    payload = _collect(config)

    assert "ssh_permit_root_login" not in payload
    assert "ssh_password_authentication" not in payload


@needs_config_walk
def test_administrator_spelling_lands_in_the_canonical_form(db, system, tmp_path):
    """Configuration files carry whatever capitalization, quoting, and
    separator an administrator used. One host's evidence must not compare
    unequal to another's because of it."""
    config = _drop_in_tree(
        tmp_path,
        "50-style.conf",
        'permitROOTlogin  "Without-Password"\nPASSWORDauthentication=NO\n',
    )
    payload = _collect(config)

    assert payload["ssh_permit_root_login"] == "without-password"
    assert payload["ssh_password_authentication"] == "no"

    _ingest(db, system.id, payload)
    row = _row(db, system.id)
    assert row.ssh_permit_root_login == "without-password"
    assert row.ssh_password_authentication == "no"


# ---------------------------------------- a value that cannot be established


@needs_config_walk
def test_a_configuration_that_settles_nothing_reports_coverage_not_a_scan(
    db, system, tmp_path
):
    """The stock layout with nothing overridden: the collection ran, read the
    configuration, and could not establish either setting. Presenting that as
    a host awaiting its first scan sends an operator to re-run a collection
    that cannot help."""
    config = _drop_in_tree(tmp_path, "50-empty.conf", "# nothing set here\n")
    payload = _collect(config)

    assert "ssh_permit_root_login" not in payload
    assert "ssh_password_authentication" not in payload
    # The collection itself worked: other facts came back from the host.
    assert payload["kernel_version"]

    _ingest(db, system.id, payload)
    row = _row(db, system.id)
    assert row.ssh_permit_root_login is None
    for key in ("ssh_permit_root_login", "ssh_password_authentication"):
        assert _errors_for(row, key) == {
            facts_service.UNREPORTED_WITHOUT_EVIDENCE_REASON
        }

    for fact_key in (PERMIT_ROOT_LOGIN, PASSWORD_AUTHENTICATION):
        verdict = _evaluate(db, system.id, fact_key)
        assert verdict.reason == (
            compliance_evaluation_service.REASON_FACT_COLLECTION_UNAVAILABLE
        )
        assert _status(verdict) == compliance_labels.STATUS_COVERAGE_PENDING
        assert verdict.observed_value is None


@needs_config_walk
def test_a_missing_configuration_file_reports_coverage(db, system, tmp_path):
    """Nothing to read at all is still a collection that ran."""
    _ingest(db, system.id, _collect(tmp_path / "absent"))

    assert _status(_evaluate(db, system.id, PERMIT_ROOT_LOGIN)) == (
        compliance_labels.STATUS_COVERAGE_PENDING
    )


def test_a_collector_reported_parse_failure_is_not_doubled_up(db, system):
    """A transcript whose value cannot be decoded is a gap the parser itself
    reports. Ingestion must keep that reason rather than stack its own on
    top, and the fact must still evaluate as a coverage gap."""
    good = base64.b64encode(b"no").decode()
    raw = (
        f"schema_version={base64.b64encode(b'1').decode()}\n"
        "ssh_permit_root_login=not+valid+base64!!\n"
        f"ssh_password_authentication={good}\n"
    )
    payload = ssh_facts_collector_service.parse_payload(raw)
    assert {"key": "ssh_permit_root_login", "error": "undecodable_value"} in payload[
        "partial_errors"
    ]

    _ingest(db, system.id, payload)
    row = _row(db, system.id)
    assert _errors_for(row, "ssh_permit_root_login") == {"undecodable_value"}
    assert row.ssh_password_authentication == "no"

    assert _status(_evaluate(db, system.id, PERMIT_ROOT_LOGIN)) == (
        compliance_labels.STATUS_COVERAGE_PENDING
    )
    assert _evaluate(db, system.id, PASSWORD_AUTHENTICATION).verdict == (
        compliance_evaluation_service.VERDICT_PASS
    )


def test_a_blank_reported_value_is_not_treated_as_evidence(db, system):
    """A value that reduces to nothing would otherwise compare unequal to
    every expectation and fail the host on no evidence at all."""
    _ingest(
        db,
        system.id,
        {
            "schema_version": 1,
            "collected_at": "2026-08-24T10:00:00",
            "kernel_version": "6.8.0-generic",
            "ssh_permit_root_login": "   ",
        },
    )

    row = _row(db, system.id)
    assert row.ssh_permit_root_login is None
    assert _errors_for(row, "ssh_permit_root_login") == {
        facts_service.UNREPORTED_WITHOUT_EVIDENCE_REASON
    }
    assert _status(_evaluate(db, system.id, PERMIT_ROOT_LOGIN)) == (
        compliance_labels.STATUS_COVERAGE_PENDING
    )


# ------------------------------------------------ merge policy over the real
# ------------------------------------------------ collector's output


@needs_config_walk
def test_a_later_blind_collection_preserves_and_reports_the_earlier_value(
    db, system, tmp_path
):
    """Preservation keeps the evidence readable; the coverage entry keeps it
    from being re-scored under the new collection's timestamp."""
    hardened = _drop_in_tree(
        tmp_path / "a", "50-hardening.conf", "PermitRootLogin no\n"
    )
    blind = _drop_in_tree(tmp_path / "b", "50-empty.conf", "# nothing\n")

    _ingest(db, system.id, _collect(hardened), collected_at="2026-08-24T10:00:00")
    result = _ingest(db, system.id, _collect(blind), collected_at="2026-08-24T11:00:00")

    row = _row(db, system.id)
    assert result.preserved_keys == ["ssh_permit_root_login"]
    assert row.ssh_permit_root_login == "no"
    assert _errors_for(row, "ssh_permit_root_login") == {
        facts_service.PRESERVED_WITHOUT_COVERAGE_REASON
    }
    assert _status(_evaluate(db, system.id, PERMIT_ROOT_LOGIN)) == (
        compliance_labels.STATUS_COVERAGE_PENDING
    )


@needs_config_walk
def test_a_fresh_value_overrides_a_preserved_one(db, system, tmp_path):
    """A host that was hardened and then loosened must show the change."""
    hardened = _drop_in_tree(tmp_path / "a", "50-x.conf", "PermitRootLogin no\n")
    loosened = _drop_in_tree(tmp_path / "b", "50-x.conf", "PermitRootLogin yes\n")

    _ingest(db, system.id, _collect(hardened), collected_at="2026-08-24T10:00:00")
    result = _ingest(
        db, system.id, _collect(loosened), collected_at="2026-08-24T11:00:00"
    )

    assert result.preserved_keys == []
    assert _row(db, system.id).ssh_permit_root_login == "yes"
    verdict = _evaluate(db, system.id, PERMIT_ROOT_LOGIN)
    assert verdict.verdict == compliance_evaluation_service.VERDICT_FAIL


@needs_config_walk
def test_force_clears_the_retained_value_and_still_reports_the_gap(
    db, system, tmp_path
):
    """The out-of-band correction path drops the retained value. It does not
    make the collection able to report one, so the gap is still recorded."""
    hardened = _drop_in_tree(tmp_path / "a", "50-x.conf", "PermitRootLogin no\n")
    blind = _drop_in_tree(tmp_path / "b", "50-empty.conf", "# nothing\n")

    _ingest(db, system.id, _collect(hardened), collected_at="2026-08-24T10:00:00")
    result = _ingest(
        db,
        system.id,
        _collect(blind),
        collected_at="2026-08-24T11:00:00",
        force=True,
    )

    row = _row(db, system.id)
    assert result.preserved_keys == []
    assert row.ssh_permit_root_login is None
    assert _errors_for(row, "ssh_permit_root_login") == {
        facts_service.UNREPORTED_WITHOUT_EVIDENCE_REASON
    }
    assert _status(_evaluate(db, system.id, PERMIT_ROOT_LOGIN)) == (
        compliance_labels.STATUS_COVERAGE_PENDING
    )


@needs_config_walk
def test_a_stale_collection_cannot_replace_the_row(db, system, tmp_path):
    """Neither the value nor its coverage entry may be rewritten by a report
    older than the one on disk."""
    hardened = _drop_in_tree(tmp_path / "a", "50-x.conf", "PermitRootLogin no\n")
    loosened = _drop_in_tree(tmp_path / "b", "50-x.conf", "PermitRootLogin yes\n")

    _ingest(db, system.id, _collect(hardened), collected_at="2026-08-24T12:00:00")
    result = _ingest(
        db, system.id, _collect(loosened), collected_at="2026-08-24T09:00:00"
    )

    assert result.status == "rejected_stale"
    assert _row(db, system.id).ssh_permit_root_login == "no"


@needs_config_walk
def test_both_transports_agree_on_one_value_for_the_same_host(db, system, tmp_path):
    """The agent reports the token the server prints; an SSH collection reads
    the administrator's spelling out of the configuration. Neither transport
    may produce a row the other would not."""
    config = _drop_in_tree(
        tmp_path,
        "50-style.conf",
        'PermitRootLogin "No"\nPasswordAuthentication No\n',
    )
    _ingest(db, system.id, _collect(config), collected_at="2026-08-24T10:00:00")
    ssh_values = (
        _row(db, system.id).ssh_permit_root_login,
        _row(db, system.id).ssh_password_authentication,
    )

    _ingest(
        db,
        system.id,
        {
            "schema_version": 1,
            "ssh_permit_root_login": "no",
            "ssh_password_authentication": "no",
        },
        transport="agent",
        collected_at="2026-08-24T11:00:00",
    )
    row = _row(db, system.id)

    assert ssh_values == ("no", "no")
    assert (row.ssh_permit_root_login, row.ssh_password_authentication) == ssh_values
    assert row.source_transport == "agent"
    assert row.partial_errors is None


@needs_config_walk
def test_an_agent_collection_can_cover_what_an_ssh_collection_could_not(
    db, system, tmp_path
):
    """Mixed transports on one host: the SSH collection establishes nothing,
    a later agent collection reports both settings, and the coverage entries
    clear."""
    blind = _drop_in_tree(tmp_path, "50-empty.conf", "# nothing\n")
    _ingest(db, system.id, _collect(blind), collected_at="2026-08-24T10:00:00")
    assert _status(_evaluate(db, system.id, PERMIT_ROOT_LOGIN)) == (
        compliance_labels.STATUS_COVERAGE_PENDING
    )

    _ingest(
        db,
        system.id,
        {
            "schema_version": 1,
            "ssh_permit_root_login": "no",
            "ssh_password_authentication": "no",
        },
        transport="agent",
        collected_at="2026-08-24T11:00:00",
    )

    row = _row(db, system.id)
    assert row.partial_errors is None
    for fact_key in (PERMIT_ROOT_LOGIN, PASSWORD_AUTHENTICATION):
        assert _evaluate(db, system.id, fact_key).verdict == (
            compliance_evaluation_service.VERDICT_PASS
        )


@needs_config_walk
def test_the_collector_reports_no_configuration_content(
    db, system, tmp_path, monkeypatch
):
    """The collection reads privileged configuration. Only the two settings
    may leave the host: no file content, no paths, no other directives, on the
    wire, in the stored row, or in the audit context."""
    config = _drop_in_tree(
        tmp_path,
        "50-secrets.conf",
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "AllowUsers deploy@10.9.8.7\n"
        "HostKey /etc/ssh/ssh_host_ed25519_key\n"
        "TrustedUserCAKeys /etc/ssh/praxis_ca.pub\n",
    )
    stdout = _run_collector(config)
    decoded = "\n".join(
        base64.b64decode(line.split("=", 1)[1]).decode("utf-8", "replace")
        for line in stdout.splitlines()
        if "=" in line
    )

    emitted = []
    monkeypatch.setattr(facts_service, "safe_emit", lambda **kw: emitted.append(kw))
    _ingest(db, system.id, ssh_facts_collector_service.parse_payload(stdout))

    row = _row(db, system.id)
    # The whole file was read, so the sensitive directives were in front of
    # the collector and still did not travel.
    assert (row.ssh_permit_root_login, row.ssh_password_authentication) == ("no", "no")
    assert row.partial_errors is None

    audit = str(emitted[-1]["context"])
    for secret in (
        "deploy@10.9.8.7",
        "ssh_host_ed25519_key",
        "praxis_ca.pub",
        "AllowUsers",
        "/etc/ssh",
    ):
        assert secret not in stdout
        assert secret not in decoded
        assert secret not in audit
