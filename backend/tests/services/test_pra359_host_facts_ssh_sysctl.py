"""PRA-359 — broaden host-fact coverage for CIS starter-pack SSH/sysctl checks.

The 5 fact keys the SSH + kernel starter-pack baselines need are now collected,
parsed, ingested, mapped, and evaluated to real pass/fail:

- ssh.config.PermitRootLogin
- ssh.config.PasswordAuthentication
- sysctl.kernel.randomize_va_space
- sysctl.net.ipv4.ip_forward
- sysctl.net.ipv4.conf.all.rp_filter

Covers: collector-output parsing, FactsService ingest/persistence, and the
compliance evaluation matrix (pass / fail / null-value / no-facts-row /
re-evaluate) while PRESERVING PRA-346 behavior — a genuinely unmapped key still
reads as coverage_pending.
"""

from __future__ import annotations

import base64
import os
import subprocess

import pytest

from app.db.models import Credential, Group, HostFacts, System
from app.services import (
    compliance_evaluation_service,
    compliance_service,
    facts_service,
    ssh_facts_collector_service,
)
from app.services.compliance_evaluation_service import (
    REASON_FACT_VALUE_NULL,
    REASON_NO_HOST_FACTS,
    VERDICT_ERROR,
    VERDICT_FAIL,
    VERDICT_PASS,
)

_SSH_SYSCTL_KEYS = (
    "ssh_permit_root_login",
    "ssh_password_authentication",
    "sysctl_kernel_randomize_va_space",
    "sysctl_net_ipv4_ip_forward",
    "sysctl_net_ipv4_conf_all_rp_filter",
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def host(db, seed_distro):
    g = Group(name="pra359", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="pra359-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="pra359-host.example.com",
        ip_address="10.0.0.71",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    db.commit()
    return sys_row


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _line(key: str, value: str) -> str:
    return f"{key}={_b64(value)}"


def _make_check(db, admin_user, slug, fact_key, expected):
    policy = compliance_service.create_policy(
        db, actor_user_id=admin_user.id, slug=slug, name=slug.upper()
    )
    compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"{slug}-chk",
        title=slug,
        kind="fact_equals",
        definition={"fact_key": fact_key, "expected": expected},
    )
    return policy


def _evaluate_one(db, policy, host):
    compliance_evaluation_service.evaluate_policy_for_host(
        db, policy_id=policy.id, system_id=host.id
    )
    rows = (
        db.query(compliance_evaluation_service.CompliancePolicyEvidence)
        .filter(
            compliance_evaluation_service.CompliancePolicyEvidence.policy_id
            == policy.id,
            compliance_evaluation_service.CompliancePolicyEvidence.system_id == host.id,
        )
        .order_by(compliance_evaluation_service.CompliancePolicyEvidence.id.asc())
        .all()
    )
    return rows[-1]


def _set_facts(db, system_id, **fields):
    row = HostFacts(
        system_id=system_id,
        schema_version=1,
        collected_at=facts_service_now(),
        source_transport="ssh",
        **fields,
    )
    db.add(row)
    db.flush()
    return row


def facts_service_now():
    from datetime import datetime

    return datetime.utcnow()


# ---------------------------------------------------------------------------
# Collector parsing
# ---------------------------------------------------------------------------


def test_parse_payload_includes_ssh_and_sysctl_scalars():
    raw = "\n".join(
        [
            _line("schema_version", "1"),
            _line("collected_at", "2026-05-01T12:00:00Z"),
            _line("ssh_permit_root_login", "no"),
            _line("ssh_password_authentication", "no"),
            _line("sysctl_kernel_randomize_va_space", "2"),
            _line("sysctl_net_ipv4_ip_forward", "0"),
            _line("sysctl_net_ipv4_conf_all_rp_filter", "1"),
        ]
    )
    payload = ssh_facts_collector_service.parse_payload(raw)
    assert payload["ssh_permit_root_login"] == "no"
    assert payload["ssh_password_authentication"] == "no"
    assert payload["sysctl_kernel_randomize_va_space"] == "2"
    assert payload["sysctl_net_ipv4_ip_forward"] == "0"
    assert payload["sysctl_net_ipv4_conf_all_rp_filter"] == "1"


def test_parse_payload_omits_missing_scalars():
    raw = _line("schema_version", "1")
    payload = ssh_facts_collector_service.parse_payload(raw)
    for key in _SSH_SYSCTL_KEYS:
        assert key not in payload


# ---------------------------------------------------------------------------
# FactsService ingest / persistence
# ---------------------------------------------------------------------------


def test_ingest_persists_ssh_and_sysctl_scalars(db, host):
    payload = {
        "schema_version": 1,
        "collected_at": "2026-05-01T12:00:00",
        "ssh_permit_root_login": "no",
        "ssh_password_authentication": "no",
        "sysctl_kernel_randomize_va_space": "2",
        "sysctl_net_ipv4_ip_forward": "0",
        "sysctl_net_ipv4_conf_all_rp_filter": "1",
    }
    facts_service.ingest(db, system_id=host.id, payload=payload, source_transport="ssh")
    row = db.query(HostFacts).filter(HostFacts.system_id == host.id).first()
    assert row.ssh_permit_root_login == "no"
    assert row.ssh_password_authentication == "no"
    assert row.sysctl_kernel_randomize_va_space == "2"
    assert row.sysctl_net_ipv4_ip_forward == "0"
    assert row.sysctl_net_ipv4_conf_all_rp_filter == "1"
    # Additive nullable facts don't bump the schema version.
    assert row.schema_version == 1


# ---------------------------------------------------------------------------
# Compliance evaluation — the 5 representative pass/fail checks
# ---------------------------------------------------------------------------


def test_permit_root_login_disabled_pass(db, admin_user, host):
    _set_facts(db, host.id, ssh_permit_root_login="no")
    policy = _make_check(db, admin_user, "prl-pass", "ssh.config.PermitRootLogin", "no")
    row = _evaluate_one(db, policy, host)
    assert row.verdict == VERDICT_PASS


def test_permit_root_login_enabled_fail(db, admin_user, host):
    _set_facts(db, host.id, ssh_permit_root_login="yes")
    policy = _make_check(db, admin_user, "prl-fail", "ssh.config.PermitRootLogin", "no")
    row = _evaluate_one(db, policy, host)
    assert row.verdict == VERDICT_FAIL
    assert row.observed_value == "yes"


def test_password_authentication_disabled_pass(db, admin_user, host):
    _set_facts(db, host.id, ssh_password_authentication="no")
    policy = _make_check(
        db, admin_user, "pwauth-pass", "ssh.config.PasswordAuthentication", "no"
    )
    assert _evaluate_one(db, policy, host).verdict == VERDICT_PASS


def test_aslr_enabled_pass(db, admin_user, host):
    _set_facts(db, host.id, sysctl_kernel_randomize_va_space="2")
    policy = _make_check(
        db, admin_user, "aslr-pass", "sysctl.kernel.randomize_va_space", "2"
    )
    assert _evaluate_one(db, policy, host).verdict == VERDICT_PASS


def test_ip_forward_disabled_pass(db, admin_user, host):
    _set_facts(db, host.id, sysctl_net_ipv4_ip_forward="0")
    policy = _make_check(db, admin_user, "ipf-pass", "sysctl.net.ipv4.ip_forward", "0")
    assert _evaluate_one(db, policy, host).verdict == VERDICT_PASS


def test_rp_filter_enabled_pass(db, admin_user, host):
    _set_facts(db, host.id, sysctl_net_ipv4_conf_all_rp_filter="1")
    policy = _make_check(
        db, admin_user, "rpf-pass", "sysctl.net.ipv4.conf.all.rp_filter", "1"
    )
    assert _evaluate_one(db, policy, host).verdict == VERDICT_PASS


# ---------------------------------------------------------------------------
# PRA-346 behavior preserved
# ---------------------------------------------------------------------------


def test_facts_row_but_null_value_is_missing_not_pass_fail(db, admin_user, host):
    # A facts row exists (host scanned) but this specific value wasn't reported.
    _set_facts(db, host.id, kernel_version="6.0")  # ssh_permit_root_login is NULL
    policy = _make_check(db, admin_user, "prl-null", "ssh.config.PermitRootLogin", "no")
    row = _evaluate_one(db, policy, host)
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_FACT_VALUE_NULL


def test_no_facts_row_is_awaiting_scan(db, admin_user, host):
    # No HostFacts row at all -> awaiting host scan, not coverage pending.
    policy = _make_check(
        db, admin_user, "prl-noscan", "ssh.config.PermitRootLogin", "no"
    )
    row = _evaluate_one(db, policy, host)
    assert row.verdict == VERDICT_ERROR
    assert row.verdict_reason == REASON_NO_HOST_FACTS


def test_reevaluate_after_fact_change_flips_verdict(db, admin_user, host):
    _set_facts(db, host.id, sysctl_net_ipv4_ip_forward="1")  # enabled -> fail
    policy = _make_check(
        db, admin_user, "ipf-reeval", "sysctl.net.ipv4.ip_forward", "0"
    )
    assert _evaluate_one(db, policy, host).verdict == VERDICT_FAIL

    # Operator disables forwarding; a fresh scan overwrites the fact.
    fact_row = db.query(HostFacts).filter(HostFacts.system_id == host.id).first()
    fact_row.sysctl_net_ipv4_ip_forward = "0"
    db.add(fact_row)
    db.flush()
    assert _evaluate_one(db, policy, host).verdict == VERDICT_PASS


# ---------------------------------------------------------------------------
# Collector shell — sshd_config fallback must fire even without an sshd binary
# on PATH (send-back fix). Runs the real collect-facts.sh in a subprocess.
# ---------------------------------------------------------------------------

_COLLECTOR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "app",
    "services",
    "_assets",
    "collect-facts.sh",
)


def _run_collector(env_overrides):
    env = dict(os.environ)
    env.update(env_overrides)
    proc = subprocess.run(
        ["sh", _COLLECTOR],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    return proc.stdout


def _decoded(stdout, key):
    for line in stdout.splitlines():
        if line.startswith(key + "="):
            return base64.b64decode(line.split("=", 1)[1]).decode("utf-8")
    return None


def test_collector_sshd_config_fallback_without_sshd_on_path(tmp_path):
    # No sshd binary is resolvable in the test container, so `sshd -T` yields
    # nothing — the collector must still read the (readable) sshd_config
    # fallback rather than skipping SSH facts entirely.
    cfg = tmp_path / "sshd_config"
    cfg.write_text("# comment\nPermitRootLogin no\nPasswordAuthentication no\n")
    stdout = _run_collector({"PRAXIS_SSHD_CONFIG": str(cfg)})
    assert _decoded(stdout, "ssh_permit_root_login") == "no"
    assert _decoded(stdout, "ssh_password_authentication") == "no"


def test_collector_emits_no_ssh_facts_when_config_absent(tmp_path):
    # Neither sshd -T nor a readable config -> no emit -> NULL fact, never faked.
    stdout = _run_collector({"PRAXIS_SSHD_CONFIG": str(tmp_path / "does-not-exist")})
    assert _decoded(stdout, "ssh_permit_root_login") is None
    assert _decoded(stdout, "ssh_password_authentication") is None
