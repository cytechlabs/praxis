"""PRA-413: portable Access Broker enrollment across the supported host matrix.

Covers the deterministic half of the fix without a live host:

  * the generated privileged-install program never asks a privileged process to
    read ``/dev/stdin``, installs with the required mode and root ownership,
    swaps atomically, and cleans up its staging copies;
  * the generated reload program validates the configuration before it reloads,
    knows both the deb and EL service names, never signals a process it has not
    positively identified, and fails closed;
  * deploy, revoke, rollback and re-enrollment route every reload through that
    one helper and only record enrollment once the host has proved it.

Live behaviour on real deb and EL containers is covered by
``tests/integration/test_pra413_host_matrix.py``.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess

import paramiko
import pytest

from app.db.models import Credential, Group, System
from app.services import ssh_identity_service
from app.services.ssh_identity_service import (
    CA_KEY_PATH,
    MANAGED_STATE_PREFIX,
    PRINCIPALS_DIR,
    PRINCIPALS_SCRIPT_PATH,
    RELOAD_MECHANISM_PREFIX,
    SSHD_CONFIG_PATH,
    SSHD_PRINCIPALS_MARKER,
    SSHIdentityError,
    SSHIdentityService,
    build_managed_state_capture_command,
    build_managed_state_restore_command,
    build_privileged_install_command,
    build_sshd_reload_command,
    managed_file_backup_path,
    parse_managed_state,
    parse_reload_mechanism,
)
from app.services.ssh_service import (
    CertificateSSHClient,
    SSHConnectionError,
    SSHService,
)

CA_KEY_BODY = "ssh-ed25519 AAAATESTCAMATERIAL test@praxis"

# The reload program is one shell script carried in a heredoc; this is the only
# stable way for a test to recognise it among the recorded commands.
_RELOAD_SIGNATURE = "praxis_body=$(cat"

# The managed-file transaction runs fixed shell bodies with the paths passed as
# positional operands, so a test recognises an action by its body and reads the
# affected path out of the operands.
_RESTORE_EXISTING_BODY = 'cp -a "$2" "$1" && rm -f "$2"'
_DELETE_CREATED_BODY = 'rm -f "$1" "$2"'
_DISCARD_BACKUP_BODY = 'rm -f "$1"'
_REMOVE_DIRECTORY_BODY = 'rmdir "$1" 2>/dev/null || true'


def _is_reload(command: str) -> bool:
    return _RELOAD_SIGNATURE in command


def _operands(command: str) -> list:
    """Positional operands of a ``sh -c <body> _ a b`` privileged command."""
    tokens = shlex.split(command.splitlines()[-1])
    return tokens[tokens.index("_") + 1 :]


def _has_body(command: str, body: str) -> bool:
    return f"sh -c {shlex.quote(body)}" in command


# --------------------------------------------------------------- fake host


class _FakeStd:
    def __init__(self, payload: str, exit_code: int):
        self._payload = payload.encode()
        self.channel = _FakeChannel(exit_code)

    def read(self):
        return self._payload


class _FakeChannel:
    def __init__(self, exit_code: int):
        self._exit_code = exit_code

    def recv_exit_status(self):
        return self._exit_code


class _FakeHost:
    """Records every command and answers with a scripted or default result.

    ``failures`` maps a substring of the command to ``(exit_code, stdout,
    stderr)``. Anything unmatched succeeds, with the reload program and the two
    probes answering the way a healthy host would.
    """

    def __init__(self, failures=None, existing_paths=None):
        self.commands: list[str] = []
        self.failures = list((failures or {}).items())
        # Paths the host already has, so a capture reports "present" for them
        # and "absent" for everything else. A real host always has an
        # sshd_config, so that is the baseline a test overrides rather than
        # rebuilds.
        self.existing_paths = (
            {SSHD_CONFIG_PATH} if existing_paths is None else set(existing_paths)
        )
        self.closed = False

    def exec_command(self, command, timeout=None):  # noqa: ARG002
        self.commands.append(command)
        for substring, response in self.failures:
            if substring in command:
                exit_code, out, err = response
                return (None, _FakeStd(out, exit_code), _FakeStd(err, exit_code))
        return (None, _FakeStd(self._default_stdout(command), 0), _FakeStd("", 0))

    def close(self):
        self.closed = True

    def _default_stdout(self, command: str) -> str:
        if _is_reload(command):
            return f"{RELOAD_MECHANISM_PREFIX}sighup:pid-file:42\n"
        if MANAGED_STATE_PREFIX in command:
            path = _operands(command)[0]
            state = "present" if path in self.existing_paths else "absent"
            return f"{MANAGED_STATE_PREFIX}{state}\n"
        if "echo praxis_reload_ok" in command:
            return "praxis_reload_ok\n"
        if "echo praxis_selftest_ok" in command:
            return "praxis_selftest_ok\n"
        return ""

    # -- assertions helpers ------------------------------------------------

    def index_of(self, needle: str) -> int:
        for position, command in enumerate(self.commands):
            if needle in command:
                return position
        raise AssertionError(f"no recorded command contains {needle!r}")

    def reload_indexes(self) -> list:
        return [i for i, c in enumerate(self.commands) if _is_reload(c)]

    def _paths_for_body(self, body: str) -> list:
        return [_operands(c)[0] for c in self.commands if _has_body(c, body)]

    def captured_paths(self) -> list:
        return [_operands(c)[0] for c in self.commands if MANAGED_STATE_PREFIX in c]

    def restored_paths(self) -> list:
        """Paths put back from a rollback copy because they existed before."""
        return self._paths_for_body(_RESTORE_EXISTING_BODY)

    def deleted_paths(self) -> list:
        """Paths removed on rollback because this operation created them."""
        return self._paths_for_body(_DELETE_CREATED_BODY)

    def discarded_backups(self) -> list:
        """Rollback copies dropped after the operation proved itself."""
        return self._paths_for_body(_DISCARD_BACKUP_BODY)

    def removed_directories(self) -> list:
        return self._paths_for_body(_REMOVE_DIRECTORY_BODY)

    def index_of_body(self, body: str) -> int:
        for position, command in enumerate(self.commands):
            if _has_body(command, body):
                return position
        raise AssertionError(f"no recorded command runs body {body!r}")


def _make_system(db, seed_distro, hostname, **kwargs):
    group = db.query(Group).filter_by(name="Default").first()
    if group is None:
        group = Group(name="Default")
        db.add(group)
        db.flush()
    credential = Credential(
        name=f"{hostname}-cred",
        auth_method="password",
        username="praxis",
        vault_path=f"v/{hostname}",
    )
    db.add(credential)
    db.flush()
    system = System(
        hostname=hostname,
        ip_address="10.13.0.1",
        distro_id=seed_distro.id,
        os_version="26.04",
        status="Active",
        group_id=group.id,
        credentials_id=credential.id,
        **kwargs,
    )
    db.add(system)
    db.flush()
    return system


def _service(db, monkeypatch, host, *, connect_errors=(), cert_auth=True):
    """An SSHIdentityService whose every connection lands on ``host``.

    ``connect_errors`` is an iterable of ``None`` or ``SSHConnectionError``
    applied to successive ``get_connection`` calls, so a test can make only the
    post-reload connection fail. ``cert_auth`` drives the certificate-only entry
    point the self-test uses: True for a host that accepts the certificate,
    False for one that rejects it.
    """
    service = SSHIdentityService(db)
    monkeypatch.setattr(
        service.vault_service,
        "get_ssh_ca_public_key",
        lambda: CA_KEY_BODY,
    )
    pending = list(connect_errors)

    def _connect(*args, **kwargs):  # noqa: ARG001
        # The last entry repeats, so a test can model either a one-off refusal
        # or a host that stays unreachable.
        if pending:
            error = pending.pop(0) if len(pending) > 1 else pending[0]
            if error is not None:
                raise error
        return host, True

    monkeypatch.setattr(service.ssh_service, "get_connection", _connect)

    # The self-test goes through the SSH service's public certificate-only
    # entry point, so that one method is the whole seam.
    def _certificate_connection(system_id):  # noqa: ARG001
        if cert_auth:
            return host
        raise SSHConnectionError(
            "Certificate authentication failed for host: Authentication failed."
        )

    monkeypatch.setattr(
        service.ssh_service, "connect_with_certificate", _certificate_connection
    )
    return service


@pytest.fixture(autouse=True)
def _no_probe_backoff(monkeypatch):
    """Keep the post-reload retry window instant for unit tests."""
    monkeypatch.setattr(
        ssh_identity_service, "POST_RELOAD_PROBE_DELAY_SECONDS", 0, raising=True
    )


def _shell_syntax_ok(tmp_path, program: str, shell: str = "sh") -> None:
    script = tmp_path / "program.sh"
    script.write_text(program)
    result = subprocess.run(
        [shell, "-n", str(script)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


# ------------------------------------------------- privileged file install


def test_install_command_never_asks_a_privileged_process_for_dev_stdin():
    """The original defect: minimal hosts do not expose /dev/stdin to sudo."""
    program = build_privileged_install_command(CA_KEY_BODY, CA_KEY_PATH, "0644")
    assert "/dev/stdin" not in program


def test_install_command_is_valid_posix_shell(tmp_path):
    program = build_privileged_install_command(CA_KEY_BODY, CA_KEY_PATH, "0644")
    _shell_syntax_ok(tmp_path, program)


def test_install_command_sets_mode_ownership_and_renames_atomically():
    program = build_privileged_install_command(CA_KEY_BODY, CA_KEY_PATH, "0644")
    staged = f"{CA_KEY_PATH}.praxis-tmp"
    assert "install -m 0644 -o root -g root" in program
    assert staged in program
    assert f"mv -f {staged} {CA_KEY_PATH}" in program
    # The staging copy is installed first and only then swapped in, so a failed
    # write never truncates the live file.
    assert program.index(staged) < program.index(f"mv -f {staged}")


def test_install_command_verifies_the_staged_byte_count():
    body = f"{CA_KEY_BODY}\n"
    program = build_privileged_install_command(body, CA_KEY_PATH, "0644")
    assert f'!= "{len(body.encode())}"' in program


def test_install_command_removes_both_temporary_files_on_failure():
    program = build_privileged_install_command(CA_KEY_BODY, CA_KEY_PATH, "0644")
    staged = f"{CA_KEY_PATH}.praxis-tmp"
    # The private staging file is trapped, so it goes on any exit path.
    assert "trap 'rm -f \"$praxis_tmp\"' EXIT INT TERM HUP" in program
    # The privileged copy beside the destination is cleaned on both of its own
    # failure branches rather than left behind in /etc.
    assert program.count(f"rm -f {staged}") == 2


def _record_privileged_argv(tmp_path, program):
    """Run an install program with stubbed privileged tools and return their argv.

    ``install`` and ``mv`` are replaced by recorders and ``sudo`` by a
    pass-through, so the real quoting behaviour of the generated program is
    observed without needing root or touching the filesystem outside tmp_path.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "argv.log"
    for name in ("install", "mv"):
        stub = bin_dir / name
        stub.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "{name}" >> "$PRAXIS_ARGV_LOG"\n'
            'for arg in "$@"; do printf "\\t%s\\n" "$arg" >> "$PRAXIS_ARGV_LOG"; done\n'
            "exit 0\n"
        )
        stub.chmod(0o755)
    sudo = bin_dir / "sudo"
    sudo.write_text('#!/bin/sh\nif [ "$1" = "-n" ]; then shift; fi\nexec "$@"\n')
    sudo.chmod(0o755)

    script = tmp_path / "install.sh"
    script.write_text(program)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["PRAXIS_ARGV_LOG"] = str(log)
    result = subprocess.run(
        ["sh", str(script)], capture_output=True, text=True, env=env, check=False
    )
    assert result.returncode == 0, result.stderr

    calls = []
    for line in log.read_text().splitlines():
        if line.startswith("\t"):
            calls[-1].append(line[1:])
        else:
            calls.append([line])
    return calls


def test_install_command_passes_mode_owner_and_paths_as_single_arguments(tmp_path):
    program = build_privileged_install_command(CA_KEY_BODY, CA_KEY_PATH, "0644")
    calls = _record_privileged_argv(tmp_path, program)
    assert len(calls) == 2, f"expected one install and one mv call, got {calls}"
    install_call, mv_call = calls
    assert install_call[:6] == [
        "install",
        "-m",
        "0644",
        "-o",
        "root",
        "-g",
    ]
    assert install_call[-1] == f"{CA_KEY_PATH}.praxis-tmp"
    assert mv_call == ["mv", "-f", f"{CA_KEY_PATH}.praxis-tmp", CA_KEY_PATH]


def test_install_command_quotes_a_destination_with_shell_metacharacters(tmp_path):
    """A login is operator data; it must never reach the host as shell syntax."""
    login = "odd; touch /tmp/praxis-pra413-pwned"
    dest = f"{PRINCIPALS_DIR}/{login}"
    program = build_privileged_install_command(f"{login}\n", dest, "0644")
    calls = _record_privileged_argv(tmp_path, program)
    assert len(calls) == 2, f"expected one install and one mv call, got {calls}"
    install_call, mv_call = calls
    # The whole path arrives as one argument rather than being split at the ';'.
    assert install_call[-1] == f"{dest}.praxis-tmp"
    assert mv_call[-1] == dest
    assert not os.path.exists("/tmp/praxis-pra413-pwned")


@pytest.mark.parametrize("mode", ["", "8", "0o644", "rwx", "06440"])
def test_install_command_rejects_an_unusable_mode(mode):
    with pytest.raises(SSHIdentityError, match="invalid file mode"):
        build_privileged_install_command(CA_KEY_BODY, CA_KEY_PATH, mode)


def test_install_command_rejects_empty_content():
    with pytest.raises(SSHIdentityError, match="empty content"):
        build_privileged_install_command("", CA_KEY_PATH, "0644")


def test_install_command_rejects_content_that_would_truncate_the_transfer():
    with pytest.raises(SSHIdentityError, match="transfer marker"):
        build_privileged_install_command(
            "line\nPRAXIS_CONTENT_EOF\nmore\n", CA_KEY_PATH, "0644"
        )


def test_install_command_rejects_binary_content():
    with pytest.raises(SSHIdentityError, match="binary content"):
        build_privileged_install_command("key\x00blob", CA_KEY_PATH, "0644")


# ------------------------------------------------------- init-agnostic reload


@pytest.mark.parametrize("shell", ["sh", "bash"])
def test_reload_command_is_valid_posix_shell(tmp_path, shell):
    _shell_syntax_ok(tmp_path, build_sshd_reload_command(), shell)


def test_reload_command_validates_before_attempting_any_reload():
    program = build_sshd_reload_command()
    validation = program.index(f"-t -f {SSHD_CONFIG_PATH}")
    for attempt in ("systemctl reload", "service ", "kill -HUP"):
        assert validation < program.index(attempt), attempt


def test_reload_command_knows_both_deb_and_el_names():
    program = build_sshd_reload_command()
    assert "for praxis_unit in sshd.service ssh.service" in program
    assert "for praxis_service in sshd ssh" in program
    assert "/etc/init.d/sshd /etc/init.d/ssh" in program


def test_reload_command_handles_socket_activated_sshd():
    """A socket-activated listener re-reads the configuration per connection."""
    program = build_sshd_reload_command()
    assert "for praxis_socket in sshd.socket ssh.socket" in program
    assert f"{RELOAD_MECHANISM_PREFIX}systemd-socket:" in program


def test_reload_command_never_broadcasts_a_signal():
    program = build_sshd_reload_command()
    for forbidden in ("pkill", "killall", "pgrep", "kill -HUP -1", "kill -1"):
        assert forbidden not in program
    # The single signalling site targets the one pid the program resolved.
    assert program.count("kill -HUP") == 1
    assert 'kill -HUP "$praxis_master"' in program


def test_reload_command_only_signals_a_process_running_the_located_sshd():
    program = build_sshd_reload_command()
    assert '[ "$praxis_exe" = "$praxis_sshd" ] || continue' in program
    # A per-connection child (parent is another sshd) is never a candidate.
    assert '*" $praxis_ppid "*) ;;' in program


def test_reload_command_fails_closed_when_nothing_safe_is_available():
    program = build_sshd_reload_command()
    assert "no safe sshd reload mechanism available" in program
    assert "exit 93" in program
    assert "sshd master process is ambiguous" in program
    assert "no running sshd master process" in program


def test_reload_command_honours_a_custom_config_path():
    program = build_sshd_reload_command("/etc/ssh/sshd_config.d/other conf")
    assert "'/etc/ssh/sshd_config.d/other conf'" in program


def test_parse_reload_mechanism():
    assert (
        parse_reload_mechanism(f"noise\n{RELOAD_MECHANISM_PREFIX}service:ssh\n")
        == "service:ssh"
    )
    assert parse_reload_mechanism("nothing useful\n") is None
    assert parse_reload_mechanism(RELOAD_MECHANISM_PREFIX) is None


# ---------------------------------------------------------------- CA trust


def test_deploy_ca_trust_backs_up_installs_reloads_then_proves_a_new_login(
    db, seed_distro, monkeypatch
):
    system = _make_system(db, seed_distro, "pra413-ca-deploy")
    host = _FakeHost()
    service = _service(db, monkeypatch, host)

    result = service.deploy_ca_trust(system.id)

    order = [
        host.index_of("install -m 0644 -o root -g root"),
        host.index_of("grep -qF 'TrustedUserCAKeys"),
        host.reload_indexes()[0],
        host.index_of("echo praxis_reload_ok"),
    ]
    assert order == sorted(order)
    # Both managed paths are captured before the first write.
    assert host.captured_paths() == [SSHD_CONFIG_PATH, CA_KEY_PATH]
    assert max(host.index_of(p) for p in (SSHD_CONFIG_PATH, CA_KEY_PATH)) >= 0
    assert host.index_of_body(_DISCARD_BACKUP_BODY) > order[-1]
    assert result["reload_mechanism"] == "sighup:pid-file:42"
    assert system.ca_trust_deployed is True
    assert system.ca_trust_deployed_at is not None
    # The rollback copies are not left behind in /etc once they are spent.
    assert sorted(host.discarded_backups()) == sorted(
        [
            managed_file_backup_path(SSHD_CONFIG_PATH, "ca"),
            managed_file_backup_path(CA_KEY_PATH, "ca"),
        ]
    )


def test_deploy_ca_trust_retires_the_legacy_reload_chain(db, seed_distro, monkeypatch):
    system = _make_system(db, seed_distro, "pra413-ca-legacy")
    host = _FakeHost()
    _service(db, monkeypatch, host).deploy_ca_trust(system.id)

    for command in host.commands:
        assert "systemctl reload sshd || sudo service ssh reload" not in command
        assert "/dev/stdin" not in command
    assert host.reload_indexes(), "no reload went through the shared helper"


def test_deploy_ca_trust_rolls_back_and_records_nothing_when_reload_fails(
    db, seed_distro, monkeypatch
):
    system = _make_system(db, seed_distro, "pra413-ca-reload-fail")
    host = _FakeHost(
        failures={
            _RELOAD_SIGNATURE: (
                91,
                "",
                "praxis-reload: sshd rejected the configuration",
            )
        }
    )
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError, match="reload sshd"):
        service.deploy_ca_trust(system.id)

    db.refresh(system)
    assert system.ca_trust_deployed is False
    assert system.ca_trust_deployed_at is None
    # sshd_config existed, so it is restored; the CA key did not, so it goes.
    assert host.restored_paths() == [SSHD_CONFIG_PATH]
    assert host.deleted_paths() == [CA_KEY_PATH]


def test_deploy_ca_trust_rolls_back_when_the_host_stops_accepting_logins(
    db, seed_distro, monkeypatch
):
    """The session that applied the change survives a reload; a new one may not."""
    system = _make_system(db, seed_distro, "pra413-ca-lockout")
    host = _FakeHost()
    service = _service(
        db,
        monkeypatch,
        host,
        connect_errors=[None, SSHConnectionError("connection refused")],
    )

    with pytest.raises(SSHIdentityError, match="refused a new connection"):
        service.deploy_ca_trust(system.id)

    db.refresh(system)
    assert system.ca_trust_deployed is False
    assert host.restored_paths() == [SSHD_CONFIG_PATH]
    assert host.deleted_paths() == [CA_KEY_PATH]
    # The restored configuration is reloaded too, not just written back.
    assert len(host.reload_indexes()) == 2


def test_deploy_ca_trust_rides_out_the_reexec_window(db, seed_distro, monkeypatch):
    """A reloading daemon is briefly not listening; that is not a lockout."""
    system = _make_system(db, seed_distro, "pra413-ca-reexec")
    host = _FakeHost()
    service = _service(
        db,
        monkeypatch,
        host,
        connect_errors=[None, SSHConnectionError("connection reset"), None],
    )

    assert service.deploy_ca_trust(system.id)["status"] == "deployed"
    assert system.ca_trust_deployed is True


def test_deploy_ca_trust_recovers_cleanly_on_a_rerun(db, seed_distro, monkeypatch):
    system = _make_system(db, seed_distro, "pra413-ca-rerun")
    failing = _FakeHost(failures={_RELOAD_SIGNATURE: (93, "", "no mechanism")})
    with pytest.raises(SSHIdentityError):
        _service(db, monkeypatch, failing).deploy_ca_trust(system.id)
    db.refresh(system)
    assert system.ca_trust_deployed is False

    healthy = _FakeHost()
    result = _service(db, monkeypatch, healthy).deploy_ca_trust(system.id)
    assert result["status"] == "deployed"
    db.refresh(system)
    assert system.ca_trust_deployed is True


def test_deploy_ca_trust_failure_never_surfaces_key_material(
    db, seed_distro, monkeypatch, caplog
):
    system = _make_system(db, seed_distro, "pra413-ca-quiet")
    host = _FakeHost(
        failures={
            "install -m 0644": (92, "", "praxis-install: privileged staging failed")
        }
    )
    service = _service(db, monkeypatch, host)

    with caplog.at_level(logging.DEBUG), pytest.raises(SSHIdentityError) as excinfo:
        service.deploy_ca_trust(system.id)

    assert CA_KEY_BODY not in str(excinfo.value)
    assert CA_KEY_BODY not in caplog.text


def test_revoke_ca_trust_reloads_before_deleting_the_key_file(
    db, seed_distro, monkeypatch
):
    """sshd must never run against a config naming a file that is already gone."""
    system = _make_system(db, seed_distro, "pra413-ca-revoke", ca_trust_deployed=True)
    host = _FakeHost()
    service = _service(db, monkeypatch, host)

    service.revoke_ca_trust(system.id)

    assert host.reload_indexes()[0] < host.index_of(f"rm -f {CA_KEY_PATH}")
    assert system.ca_trust_deployed is False
    assert system.ca_trust_deployed_at is None


def test_revoke_ca_trust_keeps_state_when_the_reload_fails(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db, seed_distro, "pra413-ca-revoke-fail", ca_trust_deployed=True
    )
    host = _FakeHost(failures={_RELOAD_SIGNATURE: (93, "", "no mechanism")})
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError):
        service.revoke_ca_trust(system.id)

    db.refresh(system)
    assert system.ca_trust_deployed is True
    # The key file survives, so the restored configuration stays coherent.
    assert not any(f"rm -f {shlex.quote(CA_KEY_PATH)}" in c for c in host.commands)
    assert host.restored_paths() == [SSHD_CONFIG_PATH]


# --------------------------------------------------------- principals hook


def test_deploy_principals_hook_installs_every_file_with_its_required_mode(
    db, seed_distro, monkeypatch
):
    system = _make_system(db, seed_distro, "pra413-hook-deploy", ca_trust_deployed=True)
    host = _FakeHost()
    service = _service(db, monkeypatch, host)

    result = service.deploy_principals_hook(system.id)

    script_install = host.commands[
        host.index_of(f"{PRINCIPALS_SCRIPT_PATH}.praxis-tmp")
    ]
    assert "install -m 0755 -o root -g root" in script_install
    seed_install = host.commands[host.index_of(f"{PRINCIPALS_DIR}/praxis.praxis-tmp")]
    assert "install -m 0644 -o root -g root" in seed_install
    assert host.index_of(f"install -d -m 0755 -o root -g root {PRINCIPALS_DIR}") > 0
    assert host.index_of(SSHD_PRINCIPALS_MARKER) < host.reload_indexes()[0]
    assert host.index_of("echo praxis_selftest_ok") > host.reload_indexes()[0]
    assert result["reload_mechanism"] == "sighup:pid-file:42"
    assert system.principals_hook_deployed is True


def test_deploy_principals_hook_rolls_back_when_the_self_test_fails(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db, seed_distro, "pra413-hook-selftest", ca_trust_deployed=True
    )
    host = _FakeHost(failures={"echo praxis_selftest_ok": (1, "", "denied")})
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError, match="self-test"):
        service.deploy_principals_hook(system.id)

    db.refresh(system)
    assert system.principals_hook_deployed is False
    assert system.principals_hook_deployed_at is None
    assert SSHD_CONFIG_PATH in host.restored_paths()
    assert len(host.reload_indexes()) == 2


def test_deploy_principals_hook_rolls_back_when_sshd_rejects_the_config(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db, seed_distro, "pra413-hook-badconf", ca_trust_deployed=True
    )
    host = _FakeHost(
        failures={
            _RELOAD_SIGNATURE: (
                91,
                "",
                "praxis-reload: sshd rejected the configuration",
            )
        }
    )
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError, match="sshd rejected the configuration"):
        service.deploy_principals_hook(system.id)

    db.refresh(system)
    assert system.principals_hook_deployed is False
    assert not any("echo praxis_selftest_ok" in c for c in host.commands)
    assert SSHD_CONFIG_PATH in host.restored_paths()


def test_revoke_principals_hook_reloads_before_removing_the_helper(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db,
        seed_distro,
        "pra413-hook-revoke",
        ca_trust_deployed=True,
        principals_hook_deployed=True,
    )
    host = _FakeHost()
    service = _service(db, monkeypatch, host)

    service.revoke_principals_hook(system.id)

    assert host.reload_indexes()[0] < host.index_of(f"rm -f {PRINCIPALS_SCRIPT_PATH}")
    assert system.principals_hook_deployed is False


def test_enroll_access_broker_resumes_after_a_partial_failure(
    db, seed_distro, monkeypatch
):
    system = _make_system(db, seed_distro, "pra413-enroll")
    failing = _FakeHost(failures={_RELOAD_SIGNATURE: (93, "", "no mechanism")})
    with pytest.raises(SSHIdentityError):
        _service(db, monkeypatch, failing).enroll_access_broker(system.id)
    db.refresh(system)
    assert system.ca_trust_deployed is False
    assert system.principals_hook_deployed is False

    healthy = _FakeHost()
    result = _service(db, monkeypatch, healthy).enroll_access_broker(system.id)
    assert result["ca_trust_deployed"] is True
    assert result["principals_hook_deployed"] is True


# ------------------------------------------ rollback covers every managed file


def test_deploy_ca_trust_captures_every_managed_path_before_writing_any(
    db, seed_distro, monkeypatch
):
    system = _make_system(db, seed_distro, "pra413-capture-order")
    host = _FakeHost()
    _service(db, monkeypatch, host).deploy_ca_trust(system.id)

    first_write = host.index_of("install -m 0644 -o root -g root")
    last_capture = max(
        position
        for position, command in enumerate(host.commands)
        if MANAGED_STATE_PREFIX in command
    )
    assert last_capture < first_write


def test_deploy_ca_trust_refuses_to_start_without_a_rollback_point(
    db, seed_distro, monkeypatch
):
    """A capture that fails must abort before anything is overwritten."""
    system = _make_system(db, seed_distro, "pra413-capture-fail")
    host = _FakeHost(failures={MANAGED_STATE_PREFIX: (90, "", "cp: permission denied")})
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError, match="capture prior state"):
        service.deploy_ca_trust(system.id)

    assert not any("install -m 0644" in command for command in host.commands)
    db.refresh(system)
    assert system.ca_trust_deployed is False


def test_deploy_ca_trust_restores_the_previous_ca_key_on_a_failed_redeploy(
    db, seed_distro, monkeypatch
):
    """CA rotation must not leave the old directive pointing at the new key."""
    system = _make_system(db, seed_distro, "pra413-ca-rotate", ca_trust_deployed=True)
    host = _FakeHost(
        existing_paths=(SSHD_CONFIG_PATH, CA_KEY_PATH),
        failures={_RELOAD_SIGNATURE: (91, "", "sshd rejected the configuration")},
    )
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError):
        service.deploy_ca_trust(system.id)

    # The key that was already there is put back, not deleted.
    assert sorted(host.restored_paths()) == sorted([SSHD_CONFIG_PATH, CA_KEY_PATH])
    assert host.deleted_paths() == []
    # Restoration happens before the rollback reload, so the daemon reloads the
    # configuration that matches the key file on disk.
    assert host.index_of_body(_RESTORE_EXISTING_BODY) < host.reload_indexes()[-1]


def test_deploy_ca_trust_rollback_leaves_nothing_behind_on_a_first_deploy(
    db, seed_distro, monkeypatch
):
    system = _make_system(db, seed_distro, "pra413-ca-first")
    host = _FakeHost(failures={_RELOAD_SIGNATURE: (93, "", "no mechanism")})
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError):
        service.deploy_ca_trust(system.id)

    assert host.deleted_paths() == [CA_KEY_PATH]
    assert host.restored_paths() == [SSHD_CONFIG_PATH]


def test_deploy_principals_hook_rolls_back_every_managed_path(
    db, seed_distro, monkeypatch
):
    """Helper, bootstrap principal, and directory all revert, not just the config."""
    system = _make_system(
        db, seed_distro, "pra413-hook-rollback-all", ca_trust_deployed=True
    )
    seed_path = f"{PRINCIPALS_DIR}/praxis"
    host = _FakeHost(failures={"echo praxis_selftest_ok": (1, "", "denied")})
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError):
        service.deploy_principals_hook(system.id)

    assert host.captured_paths() == [
        SSHD_CONFIG_PATH,
        PRINCIPALS_SCRIPT_PATH,
        PRINCIPALS_DIR,
        seed_path,
    ]
    assert host.restored_paths() == [SSHD_CONFIG_PATH]
    assert sorted(host.deleted_paths()) == sorted([PRINCIPALS_SCRIPT_PATH, seed_path])
    assert host.removed_directories() == [PRINCIPALS_DIR]
    db.refresh(system)
    assert system.principals_hook_deployed is False


def test_deploy_principals_hook_restores_a_previous_helper_and_principal(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db, seed_distro, "pra413-hook-reinstall", ca_trust_deployed=True
    )
    seed_path = f"{PRINCIPALS_DIR}/praxis"
    host = _FakeHost(
        existing_paths=(
            SSHD_CONFIG_PATH,
            PRINCIPALS_SCRIPT_PATH,
            PRINCIPALS_DIR,
            seed_path,
        ),
        failures={"echo praxis_selftest_ok": (1, "", "denied")},
    )
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError):
        service.deploy_principals_hook(system.id)

    assert sorted(host.restored_paths()) == sorted(
        [SSHD_CONFIG_PATH, PRINCIPALS_SCRIPT_PATH, seed_path]
    )
    assert host.deleted_paths() == []
    # A directory that was already there is never removed.
    assert host.removed_directories() == []


def test_rollback_copies_carry_bytes_mode_and_ownership():
    """`cp -a` is what preserves mode and ownership across the rollback."""
    backup = managed_file_backup_path(CA_KEY_PATH, "ca")
    capture = build_managed_state_capture_command(CA_KEY_PATH, backup)
    restore = build_managed_state_restore_command(CA_KEY_PATH, backup, True)
    assert 'cp -a "$1" "$2"' in capture
    assert 'cp -a "$2" "$1"' in restore
    # Paths reach the host as operands, never interpolated into the body.
    assert _operands(capture) == [CA_KEY_PATH, backup]


def test_capture_command_reports_both_prior_states():
    command = build_managed_state_capture_command("/etc/x", "/etc/x.bak")
    assert f"{MANAGED_STATE_PREFIX}present" in command
    assert f"{MANAGED_STATE_PREFIX}absent" in command
    assert parse_managed_state(f"{MANAGED_STATE_PREFIX}present\n") is True
    assert parse_managed_state(f"{MANAGED_STATE_PREFIX}absent\n") is False
    assert parse_managed_state("nothing\n") is None


def test_capture_command_quotes_an_operator_supplied_login(tmp_path):
    login = "odd; touch /tmp/praxis-pra413-capture"
    path = f"{PRINCIPALS_DIR}/{login}"
    command = build_managed_state_capture_command(
        path, managed_file_backup_path(path, "principals")
    )
    _shell_syntax_ok(tmp_path, command)
    assert _operands(command)[0] == path


# ------------------------------- revocation holds its rollback point to the end


def test_revoke_ca_trust_restores_the_directive_when_key_deletion_fails(
    db, seed_distro, monkeypatch
):
    """DB and host must not disagree because only the delete step failed."""
    system = _make_system(
        db, seed_distro, "pra413-ca-revoke-delete", ca_trust_deployed=True
    )
    host = _FakeHost(
        existing_paths=(SSHD_CONFIG_PATH, CA_KEY_PATH),
        failures={
            f"rm -f {shlex.quote(CA_KEY_PATH)}": (1, "", "read-only file system")
        },
    )
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError, match="remove CA key file"):
        service.revoke_ca_trust(system.id)

    db.refresh(system)
    assert system.ca_trust_deployed is True
    # The rollback copies were still available when deletion failed, and the key
    # is captured too so a later failure can put it back.
    assert sorted(host.restored_paths()) == sorted([SSHD_CONFIG_PATH, CA_KEY_PATH])
    assert host.index_of_body(_RESTORE_EXISTING_BODY) > host.index_of(
        f"rm -f {shlex.quote(CA_KEY_PATH)}"
    )
    # And the restored directive is reloaded, so the daemon trusts the CA again.
    assert len(host.reload_indexes()) == 2


def test_revoke_ca_trust_does_not_discard_its_rollback_copy_early(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db, seed_distro, "pra413-ca-revoke-order", ca_trust_deployed=True
    )
    host = _FakeHost(existing_paths=(SSHD_CONFIG_PATH, CA_KEY_PATH))
    _service(db, monkeypatch, host).revoke_ca_trust(system.id)

    assert host.index_of_body(_DISCARD_BACKUP_BODY) > host.index_of(
        f"rm -f {shlex.quote(CA_KEY_PATH)}"
    )


def test_revoke_principals_hook_restores_the_config_when_helper_deletion_fails(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db,
        seed_distro,
        "pra413-hook-revoke-delete",
        ca_trust_deployed=True,
        principals_hook_deployed=True,
    )
    host = _FakeHost(
        existing_paths=(SSHD_CONFIG_PATH, PRINCIPALS_SCRIPT_PATH),
        failures={
            f"rm -f {shlex.quote(PRINCIPALS_SCRIPT_PATH)}": (1, "", "device busy")
        },
    )
    service = _service(db, monkeypatch, host)

    with pytest.raises(SSHIdentityError, match="remove praxis-principals script"):
        service.revoke_principals_hook(system.id)

    db.refresh(system)
    assert system.principals_hook_deployed is True
    assert sorted(host.restored_paths()) == sorted(
        [SSHD_CONFIG_PATH, PRINCIPALS_SCRIPT_PATH]
    )
    assert len(host.reload_indexes()) == 2


def test_revoke_principals_hook_does_not_discard_its_rollback_copy_early(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db,
        seed_distro,
        "pra413-hook-revoke-order",
        ca_trust_deployed=True,
        principals_hook_deployed=True,
    )
    host = _FakeHost(existing_paths=(SSHD_CONFIG_PATH, PRINCIPALS_SCRIPT_PATH))
    _service(db, monkeypatch, host).revoke_principals_hook(system.id)

    assert host.index_of_body(_DISCARD_BACKUP_BODY) > host.index_of(
        f"rm -f {shlex.quote(PRINCIPALS_SCRIPT_PATH)}"
    )


# ------------------------------------------- the self-test proves certificates


def test_self_test_never_uses_the_falling_back_connection_helper(
    db, seed_distro, monkeypatch
):
    """The pooled helper accepts credential auth, so it cannot prove anything."""
    system = _make_system(
        db, seed_distro, "pra413-selftest-strict", ca_trust_deployed=True
    )
    host = _FakeHost()
    service = _service(db, monkeypatch, host)

    def _forbidden(*args, **kwargs):  # noqa: ARG001
        raise AssertionError("self-test used the credential-fallback connection")

    monkeypatch.setattr(service.ssh_service, "get_connection", _forbidden)

    result = service.self_test_cert_auth(system.id)
    assert result["authentication"] == "certificate"


def test_self_test_fails_when_the_certificate_is_rejected(db, seed_distro, monkeypatch):
    """The exact false success reproduced on Ubuntu 26.04 must now be a failure."""
    system = _make_system(
        db, seed_distro, "pra413-selftest-reject", ca_trust_deployed=True
    )
    host = _FakeHost()
    service = _service(db, monkeypatch, host, cert_auth=False)

    with pytest.raises(SSHIdentityError, match="certificate authentication failed"):
        service.self_test_cert_auth(system.id)

    # No command ran, so nothing can have been mistaken for a healthy result.
    assert not any("praxis_selftest_ok" in command for command in host.commands)


def test_principals_hook_is_not_marked_deployed_when_cert_auth_fails(
    db, seed_distro, monkeypatch
):
    """A host that cannot use the broker must not read as enrolled."""
    system = _make_system(
        db, seed_distro, "pra413-hook-cert-reject", ca_trust_deployed=True
    )
    host = _FakeHost()
    service = _service(db, monkeypatch, host, cert_auth=False)

    with pytest.raises(SSHIdentityError, match="certificate authentication failed"):
        service.deploy_principals_hook(system.id)

    db.refresh(system)
    assert system.principals_hook_deployed is False
    assert system.principals_hook_deployed_at is None
    assert SSHD_CONFIG_PATH in host.restored_paths()


def test_enroll_access_broker_is_not_enrolled_when_cert_auth_fails(
    db, seed_distro, monkeypatch
):
    system = _make_system(db, seed_distro, "pra413-enroll-cert-reject")
    host = _FakeHost()
    service = _service(db, monkeypatch, host, cert_auth=False)

    with pytest.raises(SSHIdentityError, match="certificate authentication failed"):
        service.enroll_access_broker(system.id)

    db.refresh(system)
    # CA trust legitimately landed; the broker half did not, and says so.
    assert system.ca_trust_deployed is True
    assert system.principals_hook_deployed is False


# ------------------------------ host rollback survives a database commit failure


class _CommitFailure(Exception):
    """Stand-in for whatever PostgreSQL raises when the commit cannot land."""


def _fail_the_commit(db, monkeypatch):
    """Make the next ``db.commit()`` raise, and record that a rollback followed.

    Only the enrollment commit is failed. The SSH service commits its own
    security-log rows through the same session earlier in the flow, and failing
    those would abort before the code under test is reached.
    """
    state = {"rolled_back": False, "armed": True}
    real_rollback = db.rollback

    def _commit():
        if state["armed"]:
            state["armed"] = False
            raise _CommitFailure("could not serialize access")

    def _rollback():
        state["rolled_back"] = True
        real_rollback()

    monkeypatch.setattr(db, "commit", _commit)
    monkeypatch.setattr(db, "rollback", _rollback)
    return state


def test_ca_deploy_restores_the_host_when_the_database_commit_fails(
    db, seed_distro, monkeypatch
):
    """Host changed, flags did not land: the host must go back."""
    system = _make_system(db, seed_distro, "pra413-ca-commit-fail")
    host = _FakeHost()
    service = _service(db, monkeypatch, host)
    state = _fail_the_commit(db, monkeypatch)

    with pytest.raises(SSHIdentityError, match="could not be recorded"):
        service.deploy_ca_trust(system.id)

    assert state["rolled_back"] is True
    # The rollback copies were still there to restore from.
    assert host.restored_paths() == [SSHD_CONFIG_PATH]
    assert host.deleted_paths() == [CA_KEY_PATH]
    # Restoring without reloading would leave the daemon on the failed config.
    assert len(host.reload_indexes()) == 2
    # Nothing was discarded before the commit was known to have succeeded.
    assert host.discarded_backups() == []


def test_ca_revoke_restores_the_host_when_the_database_commit_fails(
    db, seed_distro, monkeypatch
):
    """The deleted CA key comes back, because revocation captured it."""
    system = _make_system(
        db, seed_distro, "pra413-ca-revoke-commit-fail", ca_trust_deployed=True
    )
    host = _FakeHost(existing_paths=(SSHD_CONFIG_PATH, CA_KEY_PATH))
    service = _service(db, monkeypatch, host)
    state = _fail_the_commit(db, monkeypatch)

    with pytest.raises(SSHIdentityError, match="could not be recorded"):
        service.revoke_ca_trust(system.id)

    assert state["rolled_back"] is True
    assert sorted(host.restored_paths()) == sorted([SSHD_CONFIG_PATH, CA_KEY_PATH])
    assert len(host.reload_indexes()) == 2
    assert host.discarded_backups() == []


def test_principals_deploy_restores_the_host_when_the_database_commit_fails(
    db, seed_distro, monkeypatch
):
    system = _make_system(
        db, seed_distro, "pra413-hook-commit-fail", ca_trust_deployed=True
    )
    seed_path = f"{PRINCIPALS_DIR}/praxis"
    host = _FakeHost()
    service = _service(db, monkeypatch, host)
    state = _fail_the_commit(db, monkeypatch)

    with pytest.raises(SSHIdentityError, match="could not be recorded"):
        service.deploy_principals_hook(system.id)

    assert state["rolled_back"] is True
    assert host.restored_paths() == [SSHD_CONFIG_PATH]
    assert sorted(host.deleted_paths()) == sorted([PRINCIPALS_SCRIPT_PATH, seed_path])
    assert host.removed_directories() == [PRINCIPALS_DIR]
    assert host.discarded_backups() == []


def test_principals_revoke_restores_the_host_when_the_database_commit_fails(
    db, seed_distro, monkeypatch
):
    """The deleted helper comes back, because revocation captured it."""
    system = _make_system(
        db,
        seed_distro,
        "pra413-hook-revoke-commit-fail",
        ca_trust_deployed=True,
        principals_hook_deployed=True,
    )
    host = _FakeHost(existing_paths=(SSHD_CONFIG_PATH, PRINCIPALS_SCRIPT_PATH))
    service = _service(db, monkeypatch, host)
    state = _fail_the_commit(db, monkeypatch)

    with pytest.raises(SSHIdentityError, match="could not be recorded"):
        service.revoke_principals_hook(system.id)

    assert state["rolled_back"] is True
    assert sorted(host.restored_paths()) == sorted(
        [SSHD_CONFIG_PATH, PRINCIPALS_SCRIPT_PATH]
    )
    assert len(host.reload_indexes()) == 2
    assert host.discarded_backups() == []


def test_rollback_copies_are_discarded_only_after_the_commit_lands(
    db, seed_distro, monkeypatch
):
    system = _make_system(db, seed_distro, "pra413-commit-order")
    host = _FakeHost()
    commits = []
    service = _service(db, monkeypatch, host)
    real_commit = db.commit

    def _commit():
        commits.append(len(host.commands))
        real_commit()

    monkeypatch.setattr(db, "commit", _commit)
    service.deploy_ca_trust(system.id)

    assert host.discarded_backups(), "rollback copies were never released"
    # Every discard happens after the last commit recorded during the operation.
    assert host.index_of_body(_DISCARD_BACKUP_BODY) >= commits[-1]


# ------------------------------------- RSA-SHA2 certificate algorithm agreement
#
# Enrollment proves the broker works by authenticating with an RSA certificate.
# The signature algorithm that certificate is signed under has to be RSA-SHA2:
# supported servers dropped SHA-1 from their default PubkeyAcceptedAlgorithms,
# and Praxis retired it outright.


def _connect_kwargs(monkeypatch):
    """Capture what the shared client hands paramiko's own ``connect``."""
    seen = {}

    def _super_connect(self, *args, **kwargs):  # noqa: ARG001
        seen.update(kwargs)

    monkeypatch.setattr(paramiko.SSHClient, "connect", _super_connect)
    return seen


def test_certificate_client_cannot_negotiate_a_sha1_rsa_signature(monkeypatch):
    """The retired algorithms are refused even when the caller names none."""
    seen = _connect_kwargs(monkeypatch)
    CertificateSSHClient().connect(hostname="host", username="praxis")

    disabled = seen["disabled_algorithms"]
    assert "ssh-rsa" in disabled["pubkeys"]
    assert "ssh-rsa" in disabled["keys"]
    assert "ssh-dss" in disabled["pubkeys"]
    assert "diffie-hellman-group14-sha1" in disabled["kex"]
    assert "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==" in disabled["kex"]


def test_certificate_client_extends_a_callers_own_policy(monkeypatch):
    """A policy narrows negotiation further; it never replaces the floor."""
    seen = _connect_kwargs(monkeypatch)
    CertificateSSHClient().connect(
        hostname="host",
        username="praxis",
        disabled_algorithms={
            "kex": ["diffie-hellman-group16-sha512"],
            "ciphers": ["3des-cbc"],
        },
    )

    disabled = seen["disabled_algorithms"]
    assert disabled["ciphers"] == ["3des-cbc"]
    assert "diffie-hellman-group16-sha512" in disabled["kex"]
    assert "diffie-hellman-group14-sha1" in disabled["kex"]
    assert "ssh-rsa" in disabled["pubkeys"]


def test_rsa_certificate_key_material_is_still_named_ssh_rsa():
    """An RSA key serializes as ``ssh-rsa``; that is material, not a signature.

    Enrollment hands this exact line to the secrets service for signing, so
    refusing it would break certificate auth outright.
    """
    key = paramiko.RSAKey.generate(2048)
    assert key.get_name() == "ssh-rsa"
    assert f"{key.get_name()} {key.get_base64()}".startswith("ssh-rsa AAAA")
    # The same name cannot be used as a signature algorithm.
    assert "ssh-rsa" not in paramiko.RSAKey.HASHES


# --------------------------------- the certificate-only connection never falls back


def _ssh_service(db, seed_distro, hostname, **kwargs):
    system = _make_system(db, seed_distro, hostname, **kwargs)
    db.commit()
    return SSHService(db), system


def test_connect_with_certificate_returns_the_authenticated_client(
    db, seed_distro, monkeypatch
):
    service, system = _ssh_service(db, seed_distro, "pra413-cert-ok")
    host = _FakeHost()
    monkeypatch.setattr(
        "app.services.ssh_service.configure_host_key_policy", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "app.services.ssh_service.CertificateSSHClient", lambda *a, **k: host
    )
    monkeypatch.setattr(service, "_try_ca_cert_auth", lambda *a, **k: True)

    assert service.connect_with_certificate(system.id) is host


def test_connect_with_certificate_never_falls_back_to_the_credential(
    db, seed_distro, monkeypatch
):
    """A rejected certificate must not quietly become a password login."""
    service, system = _ssh_service(db, seed_distro, "pra413-cert-reject")
    host = _FakeHost()
    monkeypatch.setattr(
        "app.services.ssh_service.configure_host_key_policy", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "app.services.ssh_service.CertificateSSHClient", lambda *a, **k: host
    )

    def _reject(*args, **kwargs):  # noqa: ARG001
        raise paramiko.AuthenticationException("Authentication failed.")

    monkeypatch.setattr(service, "_try_ca_cert_auth", _reject)

    def _forbidden(*args, **kwargs):  # noqa: ARG001
        raise AssertionError("certificate-only connect fell back to the credential")

    monkeypatch.setattr(service, "_create_connection", _forbidden)

    with pytest.raises(SSHConnectionError, match="Certificate authentication failed"):
        service.connect_with_certificate(system.id)
    assert host.closed is True


def test_connect_with_certificate_fails_when_auth_does_not_complete(
    db, seed_distro, monkeypatch
):
    service, system = _ssh_service(db, seed_distro, "pra413-cert-incomplete")
    host = _FakeHost()
    monkeypatch.setattr(
        "app.services.ssh_service.configure_host_key_policy", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "app.services.ssh_service.CertificateSSHClient", lambda *a, **k: host
    )
    monkeypatch.setattr(service, "_try_ca_cert_auth", lambda *a, **k: False)

    with pytest.raises(SSHConnectionError, match="did not complete"):
        service.connect_with_certificate(system.id)
    assert host.closed is True


def test_connect_with_certificate_applies_host_key_policy_and_port(
    db, seed_distro, monkeypatch
):
    """Host-key verification and the disabled-algorithm policy still apply."""
    service, system = _ssh_service(db, seed_distro, "pra413-cert-policy")
    host = _FakeHost()
    applied = {}

    def _policy(client, database, target, ssh_port=None):  # noqa: ARG001
        applied["policy_for"] = target.hostname
        applied["policy_port"] = ssh_port

    monkeypatch.setattr("app.services.ssh_service.configure_host_key_policy", _policy)
    monkeypatch.setattr(
        "app.services.ssh_service.CertificateSSHClient", lambda *a, **k: host
    )
    monkeypatch.setattr(
        service, "_build_disabled_algorithms", lambda target: {"kex": ["weak"]}
    )

    def _capture(client, target, credential, ssh_port, disabled):  # noqa: ARG001
        applied["port"] = ssh_port
        applied["disabled"] = disabled
        return True

    monkeypatch.setattr(service, "_try_ca_cert_auth", _capture)
    service.connect_with_certificate(system.id)

    assert applied["policy_for"] == system.hostname
    assert applied["port"] == service._default_ssh_port
    # The port the pin is preloaded under is the port the connection dials.
    assert applied["policy_port"] == applied["port"]
    assert applied["disabled"] == {"kex": ["weak"]}


def test_connect_with_certificate_is_not_pooled(db, seed_distro, monkeypatch):
    """A proof-of-life connection must not occupy or evict a pool slot."""
    service, system = _ssh_service(db, seed_distro, "pra413-cert-pool")
    host = _FakeHost()
    monkeypatch.setattr(
        "app.services.ssh_service.configure_host_key_policy", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "app.services.ssh_service.CertificateSSHClient", lambda *a, **k: host
    )
    monkeypatch.setattr(service, "_try_ca_cert_auth", lambda *a, **k: True)

    service.connect_with_certificate(system.id)
    assert system.hostname not in service._connection_pool
