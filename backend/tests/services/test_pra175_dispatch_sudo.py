"""PRA-175 Slice 1 — sudo-aware dispatch argv wrapping.

Covers the shared :mod:`app.services.dispatch_sudo` helper and the
two default-dispatch entry points that consume it
(``patch_execution_dispatch_service.default_dispatch`` for patch
update + rollback, ``patch_reboot_dispatch_service.default_reboot_dispatch``
for reboot).

The slice locks pin:

* ``none`` — argv preserved verbatim, no stdin.
* ``nopasswd`` — argv prefixed with ``sudo -n``.
* ``password`` — argv prefixed with ``sudo -S``, sudo password
  pulled from ``credential.vault_path`` via Vault and piped to
  stdin terminated with a newline.
* Patch update and rollback share the same wrap path (both go
  through ``default_dispatch``).
* Reboot dispatch is wrapped consistently — the legacy hardcoded
  ``["sudo", "systemctl", "reboot"]`` is gone; PR planned argv is
  ``["systemctl", "reboot"]`` and the wrap is applied per
  credential.

Tests use fake transports and a stubbed Vault so no real SSH,
package-manager, or reboot command is ever issued.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest

from app.db.models import Credential, Group, System
from app.services.dispatch_sudo import (
    SUDO_METHOD_MISSING,
    SUDO_METHOD_NONE,
    SUDO_METHOD_NOPASSWD,
    SUDO_METHOD_PASSWORD,
    SUDO_METHOD_UNKNOWN,
    SudoMethodError,
    resolve_system_credential,
    wrap_argv_for_sudo,
)
from app.services.patch_execution_dispatch_service import (
    DispatchResult,
    default_dispatch,
)
from app.services.patch_reboot_dispatch_service import (
    DEFAULT_REBOOT_COMMAND,
    EXIT_SIGNAL_EXIT_ZERO,
    EXIT_SIGNAL_SUDO_METHOD_INVALID,
    default_reboot_dispatch,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cred_factory(db):
    """Builds a Credential row with the requested sudo_method."""
    counter = {"n": 0}

    def make(
        *,
        sudo_method: str = SUDO_METHOD_NONE,
        vault_path: Optional[str] = "vault/sudo-cred",
        auth_method: str = "password",
        username: str = "root",
    ) -> Credential:
        counter["n"] += 1
        cred = Credential(
            name=f"pra175-cred-{counter['n']}",
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
    """Builds a System bound to a credential."""
    counter = {"n": 0}

    def make(*, credential: Optional[Credential] = None) -> System:
        counter["n"] += 1
        if credential is None:
            credential = cred_factory()
        group = Group(
            name=f"pra175-grp-{counter['n']}",
            description="pra175",
        )
        db.add(group)
        db.flush()
        sys_row = System(
            hostname=f"pra175-host-{counter['n']}.example.com",
            ip_address=f"10.0.175.{counter['n']}",
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=credential.id,
        )
        db.add(sys_row)
        db.flush()
        return sys_row

    return make


class _VaultStub:
    """In-memory Vault double scoped to ``wrap_argv_for_sudo``.

    Replaces ``app.services.vault_service.VaultService`` for tests that
    need the password-mode Vault read to return a known sudo password
    (or simulate read failure).
    """

    def __init__(self, secrets: Dict[str, Dict[str, Any]]):
        self.secrets = secrets

    def __call__(self, _db) -> "_VaultStub":
        # Constructed inside wrap_argv_for_sudo as VaultService(db).
        return self

    def read_secret(self, path: str) -> Optional[Dict[str, Any]]:
        return self.secrets.get(path)


@pytest.fixture
def stub_vault(monkeypatch):
    """Provide a Vault stub the password-mode helper will read from."""

    def install(secrets: Dict[str, Dict[str, Any]]) -> _VaultStub:
        stub = _VaultStub(secrets)
        monkeypatch.setattr("app.services.vault_service.VaultService", stub)
        return stub

    return install


# ---------------------------------------------------------------------------
# wrap_argv_for_sudo — unit
# ---------------------------------------------------------------------------


def test_wrap_argv_none_preserves_argv(db, cred_factory):
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    argv, stdin = wrap_argv_for_sudo(db, cred, ["apt-get", "install", "-y", "openssl"])
    assert argv == ["apt-get", "install", "-y", "openssl"]
    assert stdin is None


def test_wrap_argv_none_when_credential_is_none(db):
    argv, stdin = wrap_argv_for_sudo(db, None, ["systemctl", "reboot"])
    assert argv == ["systemctl", "reboot"]
    assert stdin is None


def test_wrap_argv_nopasswd_prepends_sudo_n(db, cred_factory):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    argv, stdin = wrap_argv_for_sudo(db, cred, ["dnf", "install", "-y", "nginx"])
    assert argv == ["sudo", "-n", "dnf", "install", "-y", "nginx"]
    assert stdin is None


def test_wrap_argv_password_reads_vault_and_pipes_stdin(db, cred_factory, stub_vault):
    cred = cred_factory(
        sudo_method=SUDO_METHOD_PASSWORD, vault_path="vault/pra175-sudo"
    )
    stub_vault({"vault/pra175-sudo": {"sudo_password": "s3cret"}})
    argv, stdin = wrap_argv_for_sudo(db, cred, ["apt-mark", "unhold", "openssl"])
    assert argv == ["sudo", "-S", "apt-mark", "unhold", "openssl"]
    # Trailing newline so sudo -S consumes one line from stdin.
    assert stdin == b"s3cret\n"


def test_wrap_argv_password_missing_vault_path_yields_empty_stdin(
    db, cred_factory, stub_vault
):
    cred = cred_factory(sudo_method=SUDO_METHOD_PASSWORD, vault_path=None)
    stub_vault({})
    argv, stdin = wrap_argv_for_sudo(db, cred, ["systemctl", "reboot"])
    assert argv == ["sudo", "-S", "systemctl", "reboot"]
    # Empty password still terminated by a newline so sudo -S consumes
    # one line and fails deterministically instead of hanging.
    assert stdin == b"\n"


def test_wrap_argv_password_vault_read_failure_yields_empty_stdin(
    db, cred_factory, monkeypatch
):
    cred = cred_factory(
        sudo_method=SUDO_METHOD_PASSWORD, vault_path="vault/pra175-broken"
    )

    class _Boom:
        def __init__(self, _db):
            pass

        def read_secret(self, _path):
            raise RuntimeError("vault unreachable")

    monkeypatch.setattr("app.services.vault_service.VaultService", _Boom)
    argv, stdin = wrap_argv_for_sudo(db, cred, ["apt-get", "remove", "-y", "x"])
    assert argv == ["sudo", "-S", "apt-get", "remove", "-y", "x"]
    assert stdin == b"\n"


def test_wrap_argv_unknown_sudo_method_raises_structured(db, cred_factory):
    """PRA-229 PATCH-03: an unrecognized sudo_method is a structured, actionable
    condition — not a silent raw-argv fallback that would fail opaquely."""
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    # Bypass the Credential CHECK by mutating after persistence.
    cred.sudo_method = "wat"
    with pytest.raises(SudoMethodError) as exc:
        wrap_argv_for_sudo(db, cred, ["echo", "hi"])
    assert exc.value.reason == SUDO_METHOD_UNKNOWN
    msg = exc.value.operator_message()
    assert "wat" in msg
    assert "nopasswd" in msg  # names the valid options


def test_wrap_argv_null_sudo_method_raises_structured(db, cred_factory):
    """PRA-229 PATCH-03: a null/blank sudo_method on a resolved credential is a
    structured missing-config condition, distinct from 'no credential at all'."""
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    cred.sudo_method = None
    with pytest.raises(SudoMethodError) as exc:
        wrap_argv_for_sudo(db, cred, ["echo", "hi"])
    assert exc.value.reason == SUDO_METHOD_MISSING
    assert "no sudo_method configured" in exc.value.operator_message()


def test_wrap_argv_empty_argv_is_returned_unchanged(db, cred_factory):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    argv, stdin = wrap_argv_for_sudo(db, cred, [])
    assert argv == []
    assert stdin is None


def test_resolve_system_credential_returns_none_when_unbound(db):
    """The systems table requires credentials_id NOT NULL, so the
    None-cred_id branch only triggers for non-ORM callers. Exercise
    it directly with a stub system object."""

    class _StubSystem:
        credentials_id = None

    assert resolve_system_credential(db, _StubSystem()) is None
    assert resolve_system_credential(db, None) is None


def test_resolve_system_credential_returns_none_for_missing_row(db):
    """If the stored cred_id points at a credential that no longer
    exists (e.g. a deleted credential surfaced through a stale
    object), the helper returns None rather than raising — the
    dispatcher then falls back to sudo_method=none semantics."""

    class _StubSystem:
        credentials_id = 99_999_999  # nothing here

    assert resolve_system_credential(db, _StubSystem()) is None


def test_resolve_system_credential_returns_credential_when_bound(
    db, host_factory, cred_factory
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    sys_row = host_factory(credential=cred)
    resolved = resolve_system_credential(db, sys_row)
    assert resolved is not None
    assert resolved.id == cred.id
    assert resolved.sudo_method == SUDO_METHOD_NOPASSWD


# ---------------------------------------------------------------------------
# default_dispatch — patch update + rollback path (shared)
# ---------------------------------------------------------------------------


class _RecordingTransport:
    """Records every ``run_command`` invocation and returns a scripted
    result tuple. Lets us assert on the effective argv + stdin that
    ``default_dispatch`` produced without standing up paramiko."""

    name = "ssh"

    def __init__(self, *, exit_code: int = 0, stdout: bytes = b"", stderr: bytes = b""):
        self.calls: List[Tuple[List[str], Optional[bytes]]] = []
        self._exit_code = exit_code
        self._stdout = stdout
        self._stderr = stderr

    async def run_command(self, cmd, *, stdin=None, timeout_seconds=None):
        self.calls.append((list(cmd), stdin))
        from app.services.transport.base import CommandResult

        return CommandResult(
            exit_code=self._exit_code,
            stdout=self._stdout,
            stderr=self._stderr,
            duration_ms=11,
        )


@pytest.fixture
def patch_default_dispatch_transport(monkeypatch):
    """Wire up the seam used by ``default_dispatch``: mock the
    transport factory + BrokerClient + SSHService so the test runs
    purely in-process and observes the effective argv + stdin that
    ``default_dispatch`` produced.
    """

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


def test_default_dispatch_none_passes_argv_untouched(
    db, host_factory, cred_factory, patch_default_dispatch_transport
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    sys_row = host_factory(credential=cred)
    transport = _RecordingTransport()
    patch_default_dispatch_transport(transport)

    result = default_dispatch(db, sys_row, ["apt-get", "install", "-y", "openssl"])
    assert isinstance(result, DispatchResult)
    assert result.exit_code == 0
    assert result.error is None
    assert len(transport.calls) == 1
    cmd, stdin = transport.calls[0]
    assert cmd == ["apt-get", "install", "-y", "openssl"]
    assert stdin is None


def test_default_dispatch_nopasswd_prepends_sudo_n(
    db, host_factory, cred_factory, patch_default_dispatch_transport
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    sys_row = host_factory(credential=cred)
    transport = _RecordingTransport()
    patch_default_dispatch_transport(transport)

    default_dispatch(db, sys_row, ["dnf", "install", "-y", "nginx"])
    assert len(transport.calls) == 1
    cmd, stdin = transport.calls[0]
    assert cmd == ["sudo", "-n", "dnf", "install", "-y", "nginx"]
    assert stdin is None


def test_default_dispatch_password_uses_vault_sudo_password(
    db, host_factory, cred_factory, patch_default_dispatch_transport, stub_vault
):
    cred = cred_factory(
        sudo_method=SUDO_METHOD_PASSWORD, vault_path="vault/pra175-dispatch"
    )
    stub_vault({"vault/pra175-dispatch": {"sudo_password": "abc!"}})
    sys_row = host_factory(credential=cred)
    transport = _RecordingTransport()
    patch_default_dispatch_transport(transport)

    default_dispatch(db, sys_row, ["apt-mark", "unhold", "openssl"])
    assert len(transport.calls) == 1
    cmd, stdin = transport.calls[0]
    assert cmd == ["sudo", "-S", "apt-mark", "unhold", "openssl"]
    assert stdin == b"abc!\n"


def test_default_dispatch_password_uses_credential_vault_path_not_hardcoded(
    db, host_factory, cred_factory, patch_default_dispatch_transport, stub_vault
):
    """PRA-175 acceptance: the sudo password lookup MUST come from the
    credential's own ``vault_path``, never a hardcoded path."""
    cred = cred_factory(
        sudo_method=SUDO_METHOD_PASSWORD, vault_path="vault/per-cred-path-XYZ"
    )
    stub_vault(
        {
            "vault/per-cred-path-XYZ": {"sudo_password": "from-credential-path"},
            "vault/sudo-password": {"sudo_password": "wrong-hardcoded"},
        }
    )
    sys_row = host_factory(credential=cred)
    transport = _RecordingTransport()
    patch_default_dispatch_transport(transport)

    default_dispatch(db, sys_row, ["apt-get", "remove", "-y", "x"])
    _, stdin = transport.calls[0]
    assert stdin == b"from-credential-path\n"


def test_default_dispatch_treats_missing_credential_as_none(
    db, host_factory, cred_factory, patch_default_dispatch_transport, monkeypatch
):
    """If ``resolve_system_credential`` returns None (deleted /
    missing credential row), ``default_dispatch`` must not crash —
    argv is passed through unchanged with sudo_method=none semantics.
    Patch the resolver to simulate the missing-row branch since the
    systems.credentials_id FK + NOT NULL constraint won't let us
    persist that state directly.
    """
    cred = cred_factory(sudo_method=SUDO_METHOD_PASSWORD)
    sys_row = host_factory(credential=cred)
    monkeypatch.setattr(
        "app.services.dispatch_sudo.resolve_system_credential",
        lambda _db, _sys: None,
    )
    transport = _RecordingTransport()
    patch_default_dispatch_transport(transport)

    default_dispatch(db, sys_row, ["apt-get", "install", "-y", "openssl"])
    cmd, stdin = transport.calls[0]
    assert cmd == ["apt-get", "install", "-y", "openssl"]
    assert stdin is None


# ---------------------------------------------------------------------------
# default_reboot_dispatch — reboot path
# ---------------------------------------------------------------------------


class _RecordingSSHService:
    def __init__(self, *_a, **_k):
        pass

    def get_connection(self, _system_id):
        return ("fake-client", False)

    def close_all_connections(self):
        return None


@pytest.fixture
def patch_default_reboot_dispatch(monkeypatch):
    """Mock SSHTransport.run_command + SSHService so default_reboot_dispatch
    runs in-process. Returns the list that records (cmd, stdin) per call.
    """
    calls: List[Tuple[List[str], Optional[bytes]]] = []

    async def _fake_run_command(self, cmd, *, stdin=None, timeout_seconds=None):
        calls.append((list(cmd), stdin))
        from app.services.transport.base import CommandResult

        return CommandResult(exit_code=0, stdout=b"", stderr=b"", duration_ms=12)

    monkeypatch.setattr(
        "app.services.transport.ssh.SSHTransport.run_command", _fake_run_command
    )
    monkeypatch.setattr("app.services.ssh_service.SSHService", _RecordingSSHService)
    return calls


def test_default_reboot_dispatch_none_keeps_planned_argv(
    db, host_factory, cred_factory, patch_default_reboot_dispatch
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    sys_row = host_factory(credential=cred)
    result = default_reboot_dispatch(db, sys_row, list(DEFAULT_REBOOT_COMMAND))
    assert result.exit_signal_kind == EXIT_SIGNAL_EXIT_ZERO
    assert len(patch_default_reboot_dispatch) == 1
    cmd, stdin = patch_default_reboot_dispatch[0]
    assert cmd == ["systemctl", "reboot"]
    assert stdin is None


def test_default_reboot_dispatch_nopasswd_prepends_sudo_n(
    db, host_factory, cred_factory, patch_default_reboot_dispatch
):
    cred = cred_factory(sudo_method=SUDO_METHOD_NOPASSWD)
    sys_row = host_factory(credential=cred)
    default_reboot_dispatch(db, sys_row, list(DEFAULT_REBOOT_COMMAND))
    cmd, stdin = patch_default_reboot_dispatch[0]
    assert cmd == ["sudo", "-n", "systemctl", "reboot"]
    assert stdin is None


def test_default_reboot_dispatch_password_pipes_vault_password(
    db, host_factory, cred_factory, patch_default_reboot_dispatch, stub_vault
):
    cred = cred_factory(
        sudo_method=SUDO_METHOD_PASSWORD, vault_path="vault/reboot-cred"
    )
    stub_vault({"vault/reboot-cred": {"sudo_password": "reboot-pw"}})
    sys_row = host_factory(credential=cred)
    default_reboot_dispatch(db, sys_row, list(DEFAULT_REBOOT_COMMAND))
    cmd, stdin = patch_default_reboot_dispatch[0]
    assert cmd == ["sudo", "-S", "systemctl", "reboot"]
    assert stdin == b"reboot-pw\n"


def test_default_reboot_command_no_longer_hardcodes_sudo():
    """Regression pin for PRA-175: the planned reboot argv must not
    embed ``sudo`` — privilege escalation belongs to the wrap helper."""
    assert "sudo" not in DEFAULT_REBOOT_COMMAND
    assert DEFAULT_REBOOT_COMMAND == ["systemctl", "reboot"]


# ---------------------------------------------------------------------------
# PRA-229 PATCH-03: structured sudo-method failure at the dispatcher boundary
# ---------------------------------------------------------------------------


def test_default_dispatch_sudo_method_error_is_structured_no_dispatch(
    db, host_factory, cred_factory, patch_default_dispatch_transport, monkeypatch
):
    """A null/unknown sudo_method surfaces as a structured DispatchResult
    (exit_code -1 + reason in error/stderr) and the transport is NEVER called,
    so patch/rollback never run an unescalated command. Covers rollback too,
    which dispatches through this same default_dispatch."""
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    sys_row = host_factory(credential=cred)
    transport = _RecordingTransport()
    patch_default_dispatch_transport(transport)

    def _raise(*_a, **_k):
        raise SudoMethodError(SUDO_METHOD_UNKNOWN, "wat", credential_id=cred.id)

    monkeypatch.setattr("app.services.dispatch_sudo.wrap_argv_for_sudo", _raise)

    result = default_dispatch(db, sys_row, ["apt-get", "install", "-y", "openssl"])
    assert isinstance(result, DispatchResult)
    assert result.exit_code == -1
    assert result.error == SUDO_METHOD_UNKNOWN
    assert "wat" in (result.stderr or "")
    assert result.effective_argv is None
    assert transport.calls == []  # no unescalated dispatch


def test_default_reboot_dispatch_sudo_method_error_is_structured_no_reboot(
    db, host_factory, cred_factory, patch_default_reboot_dispatch, monkeypatch
):
    """A null/unknown sudo_method fails the reboot row with a structured signal
    instead of attempting an unescalated reboot."""
    cred = cred_factory(sudo_method=SUDO_METHOD_NONE)
    sys_row = host_factory(credential=cred)

    def _raise(*_a, **_k):
        raise SudoMethodError(SUDO_METHOD_MISSING, None, credential_id=cred.id)

    monkeypatch.setattr("app.services.dispatch_sudo.wrap_argv_for_sudo", _raise)

    result = default_reboot_dispatch(db, sys_row, list(DEFAULT_REBOOT_COMMAND))
    assert result.exit_signal_kind == EXIT_SIGNAL_SUDO_METHOD_INVALID
    assert result.error == SUDO_METHOD_MISSING
    assert "no sudo_method configured" in (result.stderr or "")
    assert result.effective_argv is None
    assert patch_default_reboot_dispatch == []  # no unescalated reboot
