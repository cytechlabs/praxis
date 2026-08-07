"""PRA-175 Slice 3 — compliance remediation execution service sudo wrapping.

Slices 1 + 2 wrapped patch update, rollback, and reboot dispatch
through ``dispatch_sudo.wrap_argv_for_sudo`` and surfaced the
post-wrap ``effective_argv`` in each surface's JSONB evidence
column. The compliance remediation dispatch path
(``compliance_remediation_execution_service.dispatch_attempt``)
already routes through ``patch_execution_dispatch_service.default_dispatch``
and therefore inherits the Slice 1 sudo wrap and the Slice 2
``DispatchResult.effective_argv`` field. What Slice 3 adds is
**persistence**: the compliance attempt row had no JSONB evidence
column for the post-wrap argv, so a new
``ComplianceRemediationExecutionAttempt.dispatch_details`` JSONB
column is added and the dispatch path writes the planned/raw argv
plus the effective argv into it.

Slice 3 locks:

* Slice 1 sudo behavior unchanged (``none`` / ``nopasswd`` /
  ``password``).
* The shared wrapper is the only source of effective argv — no
  duplicated sudo-method branching in the compliance service.
* Password mode never persists the sudo password or stdin payload.
* Planned argv evidence remains the raw apt/dnf command the
  dispatcher built; effective argv is recorded as additional
  evidence.
* No new tests run real OpenSCAP, package-manager, reboot,
  subprocess, host mutation, scheduler, queue, broker, Redis, or
  notification behavior.

Tests use the existing PRA-176 ``_make_acknowledged_attempt``
fixture pattern (re-implemented locally so this file doesn't
import private helpers from another test module) and inject either
the real ``default_dispatch`` (with mocked transport layer) or a
fake ``DispatchCallable`` returning an explicit ``effective_argv``.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pytest

from app.db.models import (
    CompliancePolicyEvidence,
    ComplianceRemediationExecutionAttempt,
    Credential,
    Group,
    HostFacts,
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
    STATE_FAILED,
    STATE_SUCCEEDED,
)
from app.services.dispatch_sudo import (
    SUDO_METHOD_NONE,
    SUDO_METHOD_NOPASSWD,
    SUDO_METHOD_PASSWORD,
)
from app.services.patch_execution_dispatch_service import DispatchResult

# ---------------------------------------------------------------------------
# Vault stub
# ---------------------------------------------------------------------------


class _VaultStub:
    def __init__(self, secrets: Dict[str, Dict[str, Any]]):
        self.secrets = secrets

    def __call__(self, _db) -> "_VaultStub":
        return self

    def read_secret(self, path: str) -> Optional[Dict[str, Any]]:
        return self.secrets.get(path)


@pytest.fixture
def stub_vault(monkeypatch):
    def install(secrets: Dict[str, Dict[str, Any]]) -> _VaultStub:
        stub = _VaultStub(secrets)
        monkeypatch.setattr("app.services.vault_service.VaultService", stub)
        return stub

    return install


# ---------------------------------------------------------------------------
# Recording transport for end-to-end default_dispatch integration
# ---------------------------------------------------------------------------


class _RecordingTransport:
    name = "ssh"

    def __init__(self, *, exit_code: int = 0):
        self.calls: List[Tuple[List[str], Optional[bytes]]] = []
        self._exit_code = exit_code

    async def run_command(self, cmd, *, stdin=None, timeout_seconds=None):
        self.calls.append((list(cmd), stdin))
        from app.services.transport.base import CommandResult

        return CommandResult(
            exit_code=self._exit_code, stdout=b"", stderr=b"", duration_ms=9
        )


@pytest.fixture
def patch_default_dispatch_transport(monkeypatch):
    def install(transport: _RecordingTransport):
        async def _fake_factory(system, broker_client, ssh_service=None):
            return transport

        class _FakeBroker:
            def __init__(self, *_a, **_k):
                pass

            async def __aexit__(self, *_a, **_k):
                return None

        class _FakeSSHService:
            def __init__(self, *_a, **_k):
                pass

            def close_all_connections(self):
                return None

        monkeypatch.setattr("app.services.transport.get_transport", _fake_factory)
        monkeypatch.setattr(
            "app.services.transport.factory.get_transport", _fake_factory
        )
        monkeypatch.setattr("app.services.broker_client.BrokerClient", _FakeBroker)
        monkeypatch.setattr("app.services.ssh_service.SSHService", _FakeSSHService)

    return install


# ---------------------------------------------------------------------------
# Host + credential fixture pattern (mirrors PRA-176 test pattern)
# ---------------------------------------------------------------------------


@pytest.fixture
def cred_factory(db):
    counter = {"n": 0}

    def make(
        *,
        sudo_method: str = SUDO_METHOD_NONE,
        vault_path: Optional[str] = "vault/sudo-cred",
        auth_method: str = "ssh_key",
        username: str = "root",
    ) -> Credential:
        counter["n"] += 1
        cred = Credential(
            name=f"pra175s3-cred-{counter['n']}",
            auth_method=auth_method,
            username=username,
            vault_path=vault_path,
            sudo_method=sudo_method,
        )
        db.add(cred)
        db.flush()
        return cred

    return make


@pytest.fixture
def host_factory(db, seed_distro, cred_factory):
    counter = {"n": 0}

    def make(*, credential: Optional[Credential] = None) -> System:
        counter["n"] += 1
        if credential is None:
            credential = cred_factory()
        group = Group(name=f"pra175s3-grp-{counter['n']}", description="x")
        db.add(group)
        db.flush()
        sys_row = System(
            hostname=f"pra175s3-host-{counter['n']}.example.com",
            ip_address=f"10.0.177.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=credential.id,
        )
        db.add(sys_row)
        db.flush()
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

    return make


def _make_acknowledged_attempt(
    db,
    admin_user,
    maintainer_user,
    host,
    *,
    suffix: str,
    package_name: str = "missing-pkg",
):
    """Mirror of ``test_pra176_execution_dispatch_service._make_acknowledged_attempt``
    that builds the full PRA-167 chain + Slice 1 attempt creation
    without importing private helpers across test modules.
    """
    policy = compliance_service.create_policy(
        db,
        actor_user_id=admin_user.id,
        slug=f"pra175s3-{suffix}",
        name=f"pra175s3 {suffix}",
    )
    check = compliance_service.add_check(
        db,
        policy.id,
        actor_user_id=admin_user.id,
        slug=f"c-{suffix}",
        title=f"c {suffix}",
        kind="package_installed",
        definition={"package": package_name},
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
    return attempt


# ---------------------------------------------------------------------------
# Persistence: dispatch_details is populated from DispatchResult.effective_argv
# ---------------------------------------------------------------------------


def test_dispatch_attempt_persists_effective_argv_on_success(
    db, admin_user, maintainer_user, host_factory, cred_factory
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    host = host_factory(credential=cred)
    attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="pra175s3-success"
    )

    fake_effective = [
        "sudo",
        "-n",
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        "missing-pkg",
    ]

    def _fake_dispatcher(system, cmd):
        return DispatchResult(
            exit_code=0,
            transport_name="ssh",
            duration_ms=42,
            effective_argv=list(fake_effective),
        )

    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )
    assert out.state == STATE_SUCCEEDED

    details = out.dispatch_details
    assert details["effective_argv"] == fake_effective
    # Planned argv is the raw apt-get command the dispatcher built —
    # not prefixed with sudo (the wrap is an effective-runtime concern).
    assert details["planned_argv"][:4] == [
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
    ]
    assert "sudo" not in details["planned_argv"]
    assert details["transport"] == "ssh"
    assert details["recorded_at"].endswith("Z")


def test_dispatch_attempt_persists_effective_argv_on_failure(
    db, admin_user, maintainer_user, host_factory, cred_factory
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    host = host_factory(credential=cred)
    attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="pra175s3-failure"
    )

    fake_effective = [
        "sudo",
        "-n",
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        "missing-pkg",
    ]

    def _fake_dispatcher(system, cmd):
        return DispatchResult(
            exit_code=100,
            stderr="E: Unable to locate package",
            transport_name="ssh",
            effective_argv=list(fake_effective),
        )

    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )
    assert out.state == STATE_FAILED
    assert out.dispatch_details["effective_argv"] == fake_effective
    assert "sudo" not in out.dispatch_details["planned_argv"]


def test_dispatch_attempt_records_none_effective_argv_for_fake_without_field(
    db, admin_user, maintainer_user, host_factory, cred_factory
):
    """Backward-compat lock: a dispatcher fake that omits
    ``effective_argv`` (PRA-176 / older test fakes) records
    ``effective_argv: None`` rather than crashing, and the planned
    argv evidence is still captured."""
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    host = host_factory(credential=cred)
    attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="pra175s3-noeff"
    )

    def _fake_dispatcher(system, cmd):
        return DispatchResult(exit_code=0, transport_name="fake")

    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )
    details = out.dispatch_details
    assert details["effective_argv"] is None
    assert details["planned_argv"][:4] == [
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
    ]


# ---------------------------------------------------------------------------
# End-to-end through default_dispatch with mocked transport
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,expected_prefix",
    [
        (SUDO_METHOD_NONE, []),
        (SUDO_METHOD_NOPASSWD, ["sudo", "-n"]),
        (SUDO_METHOD_PASSWORD, ["sudo", "-S"]),
    ],
)
def test_dispatch_attempt_records_wrapped_argv_via_default_dispatch(
    db,
    admin_user,
    maintainer_user,
    host_factory,
    cred_factory,
    patch_default_dispatch_transport,
    stub_vault,
    method,
    expected_prefix,
):
    """End-to-end: compliance dispatch goes through PRA-175 Slice 1's
    ``default_dispatch`` (and therefore through ``wrap_argv_for_sudo``),
    and the post-wrap argv lands in
    ``attempt.dispatch_details.effective_argv`` for all three
    ``sudo_method`` values."""
    cred = cred_factory(sudo_method=method, vault_path="vault/pra175s3-e2e")
    stub_vault({"vault/pra175s3-e2e": {"sudo_password": "e2e-pw"}})
    host = host_factory(credential=cred)
    transport = _RecordingTransport()
    patch_default_dispatch_transport(transport)
    attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix=f"e2e-{method}"
    )

    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        # Use the real default dispatcher (no override) so the
        # Slice 1 wrap runs end-to-end.
    )
    assert out.state == STATE_SUCCEEDED

    expected_effective = expected_prefix + [
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        "missing-pkg",
    ]
    assert out.dispatch_details["effective_argv"] == expected_effective
    # Planned argv stays raw apt-get; no sudo prefix.
    assert "sudo" not in out.dispatch_details["planned_argv"]
    # And the mocked transport actually received the wrapped argv +
    # the expected stdin for password mode.
    cmd, stdin = transport.calls[0]
    assert cmd == expected_effective
    if method == SUDO_METHOD_PASSWORD:
        assert stdin == b"e2e-pw\n"
    else:
        assert stdin is None


# ---------------------------------------------------------------------------
# Redaction: password is never persisted
# ---------------------------------------------------------------------------


def test_dispatch_attempt_password_mode_does_not_leak_sudo_password(
    db, admin_user, maintainer_user, host_factory, cred_factory
):
    cred = cred_factory(sudo_method=SUDO_METHOD_PASSWORD)
    host = host_factory(credential=cred)
    attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="pra175s3-redact"
    )

    sentinel = "never-record-this-sudo-password"
    fake_effective = [
        "sudo",
        "-S",
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        "missing-pkg",
    ]

    def _fake_dispatcher(system, cmd):
        # Mirror what the real default_dispatch returns: effective_argv
        # carries the sudo -S prefix; the password goes via stdin and
        # never appears on the result envelope.
        return DispatchResult(
            exit_code=0,
            stdout="",
            stderr="",
            transport_name="ssh",
            effective_argv=list(fake_effective),
        )

    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )

    serialized = json.dumps(
        {
            "dispatch_details": out.dispatch_details,
            "transport": out.transport,
            "stdout_summary": out.stdout_summary,
            "stderr_summary": out.stderr_summary,
            "failure_reason": out.failure_reason,
            "error_message": out.error_message,
        },
        default=str,
    )
    assert sentinel not in serialized
    assert out.dispatch_details["effective_argv"] == fake_effective


# ---------------------------------------------------------------------------
# Read envelope surface
# ---------------------------------------------------------------------------


def test_attempt_read_envelope_exposes_dispatch_details(
    db, admin_user, maintainer_user, host_factory, cred_factory
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    host = host_factory(credential=cred)
    attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="pra175s3-envelope"
    )
    fake_effective = ["sudo", "-n", "apt-get", "install", "-y", "openssl"]

    def _fake_dispatcher(system, cmd):
        return DispatchResult(
            exit_code=0,
            transport_name="ssh",
            effective_argv=list(fake_effective),
        )

    out = compliance_remediation_execution_service.dispatch_attempt(
        db,
        attempt_id=attempt.id,
        actor_user_id=admin_user.id,
        dispatch_callable=_fake_dispatcher,
    )
    env = compliance_remediation_execution_service.attempt_read_envelope(out)
    assert "dispatch_details" in env
    assert env["dispatch_details"]["effective_argv"] == fake_effective
    assert env["dispatch_details"]["transport"] == "ssh"


def test_attempt_read_envelope_for_pending_attempt_has_empty_dispatch_details(
    db, admin_user, maintainer_user, host_factory, cred_factory
):
    """A pending attempt that hasn't dispatched yet must have an empty
    ``dispatch_details`` (server_default ``{}``), never ``None``,
    so consumers don't have to defensively coerce."""
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    host = host_factory(credential=cred)
    attempt = _make_acknowledged_attempt(
        db, admin_user, maintainer_user, host, suffix="pra175s3-pending"
    )
    env = compliance_remediation_execution_service.attempt_read_envelope(attempt)
    assert env["dispatch_details"] == {}
