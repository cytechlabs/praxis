"""PRA-234 — native sshd account allow-list diagnostics.

Covers:
    * Deterministic parsing of ``sshd -T`` effective allow/deny directives.
    * ``evaluate_login_allowlist`` against sshd's own evaluation order, incl.
      globs, negation, and the critical false-positive guards (an ordinary
      allowed login must NOT be reported as blocked).
    * ``diagnose_login_allowlist`` over an injected command runner: blocked,
      allowed, and indeterminate (probe unavailable) outcomes.
    * ``SSHIdentityService.check_access_allowlist`` end-to-end with a fake
      bootstrap SSH client and a provisioned ``HostUserState`` row.
    * The reactive session-open helpers ``_looks_like_auth_failure`` and
      ``_diagnose_allowlist_denial``.
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

import paramiko
import pytest

from app.db.access_models import HostUserState
from app.db.models import Credential, Group, System
from app.services import session_service
from app.services import ssh_allowlist_diagnostics as diag
from app.services.ssh_identity_service import SSHIdentityService

# --------------------------------------------------------------- fakes


class _FakeStd:
    def __init__(self, out: str = "", code: int = 0):
        self._out = out.encode()
        self.channel = MagicMock()
        self.channel.recv_exit_status.return_value = code

    def read(self):
        return self._out


class FakeClient:
    """Minimal paramiko-shaped client whose exec_command returns canned data.

    ``responses`` is an ordered list of ``(substring, stdout, exit_code)``. The
    first substring found in the command wins; unmatched commands return a
    non-zero exit with empty stdout.
    """

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def exec_command(self, command, timeout=None):  # noqa: ARG002
        self.calls.append(command)
        for substr, out, code in self.responses:
            if substr in command:
                return (MagicMock(), _FakeStd(out, code), _FakeStd("", 0))
        return (MagicMock(), _FakeStd("", 1), _FakeStd("", 1))


def _runner(responses):
    return diag.runner_for_client(FakeClient(responses))


# ------------------------------------------------------------- parsing


def test_parse_extracts_all_four_directives():
    out = (
        "port 22\n"
        "permitrootlogin no\n"
        "allowusers praxis admin\n"
        "allowgroups sshusers wheel\n"
        "denyusers baduser\n"
        "denygroups nologin\n"
    )
    parsed = diag.parse_sshd_effective_allowlists(out)
    assert parsed["allow_users"] == ["praxis", "admin"]
    assert parsed["allow_groups"] == ["sshusers", "wheel"]
    assert parsed["deny_users"] == ["baduser"]
    assert parsed["deny_groups"] == ["nologin"]


def test_parse_absent_directive_is_none_not_empty():
    """sshd omits unconfigured allow/deny directives — None means 'unrestricted',
    which is semantically different from an empty allow-list (which blocks all)."""
    parsed = diag.parse_sshd_effective_allowlists("port 22\npermitrootlogin no\n")
    assert parsed["allow_users"] is None
    assert parsed["allow_groups"] is None
    assert parsed["deny_users"] is None
    assert parsed["deny_groups"] is None


def test_parse_is_case_insensitive_on_directive_name():
    parsed = diag.parse_sshd_effective_allowlists("AllowUsers praxis\n")
    assert parsed["allow_users"] == ["praxis"]


# ---------------------------------------------------------- evaluation


def test_allowusers_blocks_unlisted_login():
    denial = diag.evaluate_login_allowlist("operator", [], {"allow_users": ["praxis"]})
    assert denial is not None
    assert denial.kind == "allow_users"
    assert "operator" in denial.message("host1")
    assert "AllowUsers" in denial.message("host1")


def test_allowusers_allows_listed_login_no_false_positive():
    """Regression guard: an allowed login must never be flagged as blocked."""
    denial = diag.evaluate_login_allowlist(
        "praxis", [], {"allow_users": ["praxis", "admin"]}
    )
    assert denial is None


def test_no_directives_means_allowed():
    parsed = {
        "allow_users": None,
        "allow_groups": None,
        "deny_users": None,
        "deny_groups": None,
    }
    assert diag.evaluate_login_allowlist("operator", ["operator"], parsed) is None


def test_allowgroups_blocks_when_no_group_overlap():
    denial = diag.evaluate_login_allowlist(
        "operator", ["operator", "users"], {"allow_groups": ["sshusers"]}
    )
    assert denial is not None
    assert denial.kind == "allow_groups"


def test_allowgroups_allows_when_group_overlaps():
    denial = diag.evaluate_login_allowlist(
        "operator", ["operator", "sshusers"], {"allow_groups": ["sshusers"]}
    )
    assert denial is None


def test_denyusers_blocks():
    denial = diag.evaluate_login_allowlist("operator", [], {"deny_users": ["operator"]})
    assert denial is not None
    assert denial.kind == "deny_users"


def test_denygroups_blocks_and_names_group():
    denial = diag.evaluate_login_allowlist(
        "operator", ["operator", "nologin"], {"deny_groups": ["nologin"]}
    )
    assert denial is not None
    assert denial.kind == "deny_groups"
    assert denial.matched_group == "nologin"


def test_allowusers_glob_pattern_matches():
    assert (
        diag.evaluate_login_allowlist("dev-alice", [], {"allow_users": ["dev-*"]})
        is None
    )
    assert (
        diag.evaluate_login_allowlist("ops-bob", [], {"allow_users": ["dev-*"]})
        is not None
    )


def test_allowusers_negation_rejects():
    """A negated pattern is an immediate reject even if a later positive matches."""
    denial = diag.evaluate_login_allowlist(
        "operator", [], {"allow_users": ["!operator", "*"]}
    )
    assert denial is not None
    assert denial.kind == "allow_users"


def test_allowusers_user_at_host_matches_user_part():
    assert (
        diag.evaluate_login_allowlist(
            "praxis", [], {"allow_users": ["praxis@10.0.0.0/8"]}
        )
        is None
    )


def test_deny_takes_precedence_over_allow():
    denial = diag.evaluate_login_allowlist(
        "operator", [], {"allow_users": ["operator"], "deny_users": ["operator"]}
    )
    assert denial is not None
    assert denial.kind == "deny_users"


# --------------------------------------------------- diagnose (runner)


def test_diagnose_blocked_returns_actionable_result():
    run = _runner(
        [
            ("sshd -T", "allowusers praxis\n", 0),
            ("id -nG", "operator users\n", 0),
            ("grep", "/etc/ssh/sshd_config.d/90-hardening.conf\n", 0),
        ]
    )
    result = diag.diagnose_login_allowlist(run, "operator")
    assert result.checked is True
    assert result.blocked is True
    assert result.denial.kind == "allow_users"
    assert result.denial.source_file == "/etc/ssh/sshd_config.d/90-hardening.conf"
    assert result.remediation  # non-empty remediation guidance
    assert any("AllowUsers" in r for r in result.remediation)


def test_diagnose_allowed_login_not_blocked():
    run = _runner(
        [
            ("sshd -T", "allowusers praxis operator\n", 0),
            ("id -nG", "operator users\n", 0),
        ]
    )
    result = diag.diagnose_login_allowlist(run, "operator")
    assert result.checked is True
    assert result.blocked is False
    assert result.denial is None


def test_diagnose_indeterminate_when_sshd_t_unavailable():
    """No sshd -T output (old sshd, no sudo) → checked False, never a fake denial."""
    run = _runner([("id -nG", "operator\n", 0)])  # sshd -T falls through to exit 1
    result = diag.diagnose_login_allowlist(run, "operator")
    assert result.checked is False
    assert result.blocked is False
    assert result.indeterminate_reason


def test_diagnose_no_restrictions_configured_is_allowed():
    run = _runner(
        [
            ("sshd -T", "port 22\npermitrootlogin no\n", 0),
            ("id -nG", "operator users\n", 0),
        ]
    )
    result = diag.diagnose_login_allowlist(run, "operator")
    assert result.checked is True
    assert result.blocked is False


# ----------------------------------------- service: check_access_allowlist


@pytest.fixture
def _system(db, seed_distro):
    grp = db.query(Group).filter_by(name="Default").first()
    if not grp:
        grp = Group(name="Default")
        db.add(grp)
        db.flush()
    cred = Credential(
        name="pra234-cred",
        auth_method="password",
        username="praxis",
        vault_path="v/pra234",
    )
    db.add(cred)
    db.flush()
    s = System(
        hostname="pra234-host",
        ip_address="10.9.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


def test_check_access_allowlist_flags_blocked_provisioned_login(
    db, _system, monkeypatch
):
    db.add(
        HostUserState(
            system_id=_system.id, login="operator", mode="per_user", state="provisioned"
        )
    )
    db.add(
        HostUserState(
            system_id=_system.id, login="praxis", mode="per_user", state="provisioned"
        )
    )
    db.flush()

    fake = FakeClient(
        [
            ("sshd -T", "allowusers praxis\n", 0),
            ("id -nG", "users\n", 0),
            ("grep", "/etc/ssh/sshd_config.d/90-hardening.conf\n", 0),
        ]
    )
    svc = SSHIdentityService(db)
    monkeypatch.setattr(svc.ssh_service, "get_connection", lambda *a, **k: (fake, True))

    out = svc.check_access_allowlist(_system.id)
    assert out["checked"] is True
    assert "operator" in out["blocked_logins"]
    assert "praxis" not in out["blocked_logins"]
    blocked = next(r for r in out["results"] if r["login"] == "operator")
    assert blocked["blocked"] is True
    assert "AllowUsers" in blocked["reason"]
    assert blocked["remediation"]


def test_check_access_allowlist_connection_failure_is_unverified(
    db, _system, monkeypatch
):
    db.add(
        HostUserState(
            system_id=_system.id, login="operator", mode="per_user", state="provisioned"
        )
    )
    db.flush()

    from app.services.ssh_service import SSHConnectionError

    svc = SSHIdentityService(db)

    def _boom(*a, **k):
        raise SSHConnectionError("host down")

    monkeypatch.setattr(svc.ssh_service, "get_connection", _boom)
    out = svc.check_access_allowlist(_system.id)
    assert out["checked"] is False
    assert out["blocked_logins"] == []
    assert out["results"][0]["blocked"] is False


# ------------------------------------------- reactive session helpers


def test_looks_like_auth_failure_true_for_auth_exc():
    assert session_service._looks_like_auth_failure(
        paramiko.AuthenticationException("Authentication (publickey) failed")
    )


def test_looks_like_auth_failure_false_for_timeout():
    assert not session_service._looks_like_auth_failure(socket.timeout("timed out"))
    assert not session_service._looks_like_auth_failure(
        ConnectionRefusedError("refused")
    )


def test_diagnose_allowlist_denial_surfaces_message(db, _system, monkeypatch):
    denial = diag.AllowlistDenial(
        kind="allow_users",
        login="operator",
        directive_value="praxis",
        source_file="/etc/ssh/sshd_config.d/90-hardening.conf",
    )
    result = diag.AllowlistDiagnosis(
        login="operator",
        checked=True,
        blocked=True,
        denial=denial,
        remediation=diag.remediation_for(denial),
    )
    monkeypatch.setattr(
        SSHIdentityService,
        "diagnose_login_allowlist",
        lambda self, sid, login, client=None: result,
    )
    msg = session_service._diagnose_allowlist_denial(
        db, _system, "operator", paramiko.AuthenticationException("publickey failed")
    )
    assert msg is not None
    assert msg.startswith("allowlist_denied:")
    assert "AllowUsers" in msg
    assert "Remediation:" in msg


def test_diagnose_allowlist_denial_none_for_non_auth_error(db, _system):
    msg = session_service._diagnose_allowlist_denial(
        db, _system, "operator", socket.timeout("timed out")
    )
    assert msg is None


def test_diagnose_allowlist_denial_none_when_not_blocked(db, _system, monkeypatch):
    result = diag.AllowlistDiagnosis(login="operator", checked=True, blocked=False)
    monkeypatch.setattr(
        SSHIdentityService,
        "diagnose_login_allowlist",
        lambda self, sid, login, client=None: result,
    )
    msg = session_service._diagnose_allowlist_denial(
        db, _system, "operator", paramiko.AuthenticationException("publickey failed")
    )
    assert msg is None
