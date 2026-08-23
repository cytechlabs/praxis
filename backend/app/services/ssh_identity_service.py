"""
SSH identity service: deploy and revoke Vault CA trust on remote systems.

Zero-trust model: once the Vault SSH CA public key is installed at
/etc/ssh/trusted_user_ca_keys and referenced from sshd_config, all
future SSH connections from Praxis use short-lived Vault-signed user
certs. Username/password stays functional as a fallback.

The principals hook adds:
  * ``/usr/local/bin/praxis-principals`` - shell wrapper that sshd invokes via
    ``AuthorizedPrincipalsCommand`` to resolve per-login authorised cert
    principals from ``/etc/praxis/principals.d/<login>``.
  * ``AuthorizedPrincipalsCommand`` + ``AuthorizedPrincipalsCommandUser``
    directives appended to sshd_config with their own marker.
  * Self-test that mints a short-lived cert for the bootstrap credential's
    username and attempts a cert-auth login after reload. On failure, the
    sshd_config backup is restored and sshd reloaded again.

Host portability
----------------

A managed host is not required to run systemd, to ship ``sudo``, or to expose a
usable ``/dev/stdin`` to a privileged process. Every privileged write and every
sshd reload here therefore goes through one of two generated POSIX shell
programs:

  * ``build_privileged_install_command`` stages the content in a private
    temporary file, checks the staged byte count, installs that staging copy
    beside its destination with the required mode and root ownership, and swaps
    it in with an atomic rename. Both temporary files are cleaned up on success
    and on failure.
  * ``build_sshd_reload_command`` locates the sshd binary, validates the
    configuration that is about to be loaded with ``sshd -t``, then reloads
    through the first mechanism that actually works on the host: an active
    systemd unit, a socket-activated listener, a service-manager command, an
    init script, or a SIGHUP to a single unambiguously identified daemon. It
    never signals a process it has not positively identified as the sshd
    master, and it fails closed when no safe mechanism exists.

Transaction boundaries
----------------------

An operation captures the prior state of every managed path it is about to
replace before it writes any of them (``HostFileTransaction``), and only drops
those rollback copies once the host has proved the result: the configuration
validated, the daemon reloaded, a brand-new login succeeded, and, for the
principals hook, a strict certificate login succeeded. Any failure restores each
captured path exactly -- bytes, mode, and ownership for a file that already
existed, deletion for one the operation created -- and reloads the restored
configuration.

Revocation holds its rollback point until the managed file is actually gone, not
just until the directive is withdrawn, so a deletion failure puts the directive
back rather than leaving the database and the host disagreeing.

Enrollment state is recorded only after every one of those proofs succeeds, so a
partial failure never leaves the database claiming a host is enrolled.
"""

import logging
import shlex
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..db.access_models import HostUserState
from ..db.models import System
from . import ssh_allowlist_diagnostics as allowlist_diag
from .ssh_service import SSHConnectionError, SSHService
from .vault_service import VaultConnectionError, VaultSecretError, VaultService

logger = logging.getLogger(__name__)

CA_KEY_PATH = "/etc/ssh/trusted_user_ca_keys"
CA_KEY_MODE = "0644"
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
SSHD_CONFIG_MARKER = "# Praxis zero-trust CA (PRA-44)"
SSHD_CONFIG_DIRECTIVE = f"TrustedUserCAKeys {CA_KEY_PATH}"

# PRA-138: AuthorizedPrincipalsCommand wiring
PRINCIPALS_SCRIPT_PATH = "/usr/local/bin/praxis-principals"
PRINCIPALS_SCRIPT_MODE = "0755"
PRINCIPALS_DIR = "/etc/praxis/principals.d"
PRINCIPALS_FILE_MODE = "0644"
SSHD_PRINCIPALS_MARKER = "# Praxis principals hook (PRA-138)"
SSHD_PRINCIPALS_DIRECTIVES = (
    f"AuthorizedPrincipalsCommand {PRINCIPALS_SCRIPT_PATH} %u\n"
    "AuthorizedPrincipalsCommandUser nobody"
)

# Idempotent wrapper script. Prints the contents of
# /etc/praxis/principals.d/<login> (one cert principal per line) or nothing
# if the file is missing. Never errors — sshd treats non-zero exit as deny.
PRINCIPALS_SCRIPT_BODY = """\
#!/bin/sh
# praxis-principals <login> — emits authorised SSH cert principals for a login.
# Consumed by sshd's AuthorizedPrincipalsCommand directive (PRA-138).
set -eu
login="$1"
file="/etc/praxis/principals.d/$login"
if [ -r "$file" ]; then
  cat "$file"
fi
"""

# Where the sshd binary lives across the supported host matrix. Probed in order;
# the first executable match is the daemon the reload helper validates against
# and, when it has to fall back to a signal, the only binary it will signal.
SSHD_BINARY_CANDIDATES = (
    "/usr/sbin/sshd",
    "/usr/local/sbin/sshd",
    "/sbin/sshd",
    "/usr/libexec/openssh/sshd",
)

# Systemd calls the unit ``sshd`` on EL-family hosts and ``ssh`` on deb-family
# hosts. Recent deb releases additionally socket-activate the listener, in which
# case there is no long-lived daemon and the configuration is read per
# connection, so a reload has nothing to signal.
SSHD_SYSTEMD_UNITS = ("sshd.service", "ssh.service")
SSHD_SYSTEMD_SOCKETS = ("sshd.socket", "ssh.socket")

# Traditional service managers use the same two names.
SSHD_SERVICE_NAMES = ("sshd", "ssh")
SSHD_INIT_SCRIPTS = ("/etc/init.d/sshd", "/etc/init.d/ssh")

# Pid files a directly launched daemon writes. Only used when the recorded pid
# still resolves to the sshd binary located above.
SSHD_PID_FILE_CANDIDATES = (
    "/run/sshd.pid",
    "/var/run/sshd.pid",
    "/run/ssh.pid",
    "/var/run/ssh.pid",
)

# Marker the reload program prints on success so the caller can report which
# mechanism actually applied the configuration.
RELOAD_MECHANISM_PREFIX = "PRAXIS_RELOAD_MECHANISM="

# Marker the managed-file capture program prints so the caller knows whether a
# path has to be restored on rollback or deleted.
MANAGED_STATE_PREFIX = "PRAXIS_MANAGED_STATE="

# Suffix for the same-directory staging copy an install swaps into place.
_STAGING_SUFFIX = ".praxis-tmp"

# Heredoc delimiters. Content that contains either as a whole line is rejected
# before a command is built rather than silently truncated on the host.
_CONTENT_DELIMITER = "PRAXIS_CONTENT_EOF"
_RELOAD_BODY_DELIMITER = "PRAXIS_RELOAD_BODY_EOF"

# Resolves the privilege prefix on the host instead of assuming it. A root
# credential on a minimal image may have no sudo at all, and ``sudo -n`` never
# prompts, so a sudoers policy that demands a password fails fast with a clear
# diagnostic instead of hanging the session or consuming the command's stdin.
_PRIVILEGE_PRELUDE = (
    'if [ "$(id -u)" -eq 0 ]; then praxis_priv=""; else praxis_priv="sudo -n"; fi'
)

# Backup tags keep the CA-trust and principals-hook rollback points distinct.
_CA_BACKUP_TAG = "ca"
_PRINCIPALS_BACKUP_TAG = "principals"

# A reloaded daemon re-execs itself, so its listening socket is briefly closed
# and a connection attempted in that window is refused. The post-reload proof
# retries across that window rather than rolling back a healthy deployment.
POST_RELOAD_PROBE_ATTEMPTS = 4
POST_RELOAD_PROBE_DELAY_SECONDS = 1.5


class SSHIdentityError(Exception):
    """Exception raised for SSH identity deployment errors."""


def managed_file_backup_path(path: str, tag: str) -> str:
    """Path of the rollback copy taken for one managed file."""
    return f"{path}.praxis-{tag}.bak"


def privileged_command(command: str) -> str:
    """Wrap a single shell command so it runs as root on any supported host."""
    return "\n".join(("set -u", _PRIVILEGE_PRELUDE, f"$praxis_priv {command}"))


def privileged_shell(body: str, *arguments: str) -> str:
    """Run one shell body as root with its operands passed positionally.

    The body never interpolates a path, so an operator-supplied login can only
    ever arrive as ``$1``, ``$2``, ... and never as shell syntax.
    """
    operands = " ".join(shlex.quote(argument) for argument in arguments)
    return "\n".join(
        (
            "set -u",
            _PRIVILEGE_PRELUDE,
            f"$praxis_priv sh -c {shlex.quote(body)} _ {operands}".rstrip(),
        )
    )


def build_managed_state_capture_command(path: str, backup_path: str) -> str:
    """Build a program that records a managed file's prior state and copies it aside.

    Prints ``PRAXIS_MANAGED_STATE=present`` when the file was already on the host
    and a rollback copy now holds its exact bytes, mode, and ownership, or
    ``PRAXIS_MANAGED_STATE=absent`` when the operation is about to create it. A
    stale copy left by an interrupted run is cleared first, so whatever remains
    afterwards belongs to this operation alone.
    """
    body = (
        'if [ -e "$1" ]; then '
        'rm -f "$2" && cp -a "$1" "$2" || exit 90; '
        f"echo {MANAGED_STATE_PREFIX}present; "
        "else "
        'rm -f "$2" || exit 90; '
        f"echo {MANAGED_STATE_PREFIX}absent; "
        "fi"
    )
    return privileged_shell(body, path, backup_path)


def build_managed_state_restore_command(
    path: str, backup_path: str, existed: bool
) -> str:
    """Build a program that puts one managed file back the way it was found.

    A file that existed is restored from its rollback copy with mode and
    ownership intact; a file the operation created is removed, so a failed
    deployment leaves nothing behind.
    """
    if existed:
        body = 'cp -a "$2" "$1" && rm -f "$2"'
    else:
        body = 'rm -f "$1" "$2"'
    return privileged_shell(body, path, backup_path)


def build_managed_state_discard_command(backup_path: str) -> str:
    """Build a program that drops a rollback copy the operation no longer needs."""
    return privileged_shell('rm -f "$1"', backup_path)


def build_managed_directory_capture_command(path: str) -> str:
    """Build a program that reports whether a managed directory already exists.

    Only existence is recorded. Copying the directory aside would capture
    unrelated files that other subsystems own.
    """
    body = (
        'if [ -d "$1" ]; then '
        f"echo {MANAGED_STATE_PREFIX}present; "
        "else "
        f"echo {MANAGED_STATE_PREFIX}absent; "
        "fi"
    )
    return privileged_shell(body, path)


def build_managed_directory_remove_command(path: str) -> str:
    """Build a program that removes a directory this operation created.

    ``rmdir`` refuses a non-empty directory, so one that has gained content from
    another source is left alone.
    """
    return privileged_shell('rmdir "$1" 2>/dev/null || true', path)


def parse_managed_state(stdout: str) -> Optional[bool]:
    """True when the captured path already existed, False when it did not.

    ``None`` when the host reported no state at all, which callers must treat as
    a missing rollback point rather than as "absent".
    """
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(MANAGED_STATE_PREFIX):
            value = stripped[len(MANAGED_STATE_PREFIX) :]
            if value == "present":
                return True
            if value == "absent":
                return False
    return None


def build_privileged_install_command(content: str, dest: str, mode: str) -> str:
    """Build a POSIX shell program that installs ``content`` at ``dest``.

    The program stages the bytes in a private temporary file, checks the staged
    byte count, installs the staging copy beside ``dest`` with ``mode`` and root
    ownership, then swaps it in with an atomic rename. It never asks a
    privileged process to read ``/dev/stdin``, which minimal hosts do not
    reliably expose, and it removes both temporary files whether it succeeds or
    fails. Re-running it on an already-correct host is a no-op in effect.
    """
    if not 2 <= len(mode) <= 4 or any(
        character not in "01234567" for character in mode
    ):
        raise SSHIdentityError(f"invalid file mode '{mode}'")
    if not content:
        raise SSHIdentityError(f"refusing to install empty content at {dest}")
    if "\x00" in content:
        raise SSHIdentityError(f"refusing to install binary content at {dest}")
    body = content if content.endswith("\n") else content + "\n"
    if any(line == _CONTENT_DELIMITER for line in body.splitlines()):
        raise SSHIdentityError(f"content for {dest} collides with the transfer marker")

    size = len(body.encode("utf-8"))
    quoted_dest = shlex.quote(dest)
    quoted_staged = shlex.quote(f"{dest}{_STAGING_SUFFIX}")
    return "\n".join(
        (
            "set -u",
            "umask 077",
            _PRIVILEGE_PRELUDE,
            "praxis_tmp=$(mktemp 2>/dev/null) || praxis_tmp=''",
            'if [ -z "$praxis_tmp" ]; then',
            '  echo "praxis-install: could not create a staging file" >&2',
            "  exit 90",
            "fi",
            "trap 'rm -f \"$praxis_tmp\"' EXIT INT TERM HUP",
            f"cat > \"$praxis_tmp\" <<'{_CONTENT_DELIMITER}'",
            body + _CONTENT_DELIMITER,
            "praxis_size=$(wc -c < \"$praxis_tmp\" | tr -d ' \\t\\r\\n')",
            f'if [ "$praxis_size" != "{size}" ]; then',
            '  echo "praxis-install: staged content is incomplete" >&2',
            "  exit 91",
            "fi",
            f"if ! $praxis_priv install -m {mode} -o root -g root"
            f' "$praxis_tmp" {quoted_staged}; then',
            f"  $praxis_priv rm -f {quoted_staged} >/dev/null 2>&1 || true",
            '  echo "praxis-install: privileged staging failed" >&2',
            "  exit 92",
            "fi",
            f"if ! $praxis_priv mv -f {quoted_staged} {quoted_dest}; then",
            f"  $praxis_priv rm -f {quoted_staged} >/dev/null 2>&1 || true",
            '  echo "praxis-install: atomic rename failed" >&2',
            "  exit 93",
            "fi",
        )
    )


def _reload_program_body(config_path: str) -> str:
    """The privileged half of the reload helper, run as root on the host."""
    quoted_config = shlex.quote(config_path)
    binaries = " ".join(shlex.quote(path) for path in SSHD_BINARY_CANDIDATES)
    units = " ".join(SSHD_SYSTEMD_UNITS)
    sockets = " ".join(SSHD_SYSTEMD_SOCKETS)
    services = " ".join(SSHD_SERVICE_NAMES)
    init_scripts = " ".join(shlex.quote(path) for path in SSHD_INIT_SCRIPTS)
    pid_files = " ".join(shlex.quote(path) for path in SSHD_PID_FILE_CANDIDATES)
    return "\n".join(
        (
            "set -u",
            'praxis_diag=""',
            # 1. Locate the daemon binary. Everything below is validated
            #    against this one path.
            'praxis_sshd=""',
            f"for praxis_candidate in {binaries}; do",
            '  if [ -x "$praxis_candidate" ]; then',
            '    praxis_sshd="$praxis_candidate"',
            "    break",
            "  fi",
            "done",
            'if [ -z "$praxis_sshd" ]; then',
            '  praxis_sshd=$(command -v sshd 2>/dev/null) || praxis_sshd=""',
            "fi",
            'if [ -z "$praxis_sshd" ] || [ ! -x "$praxis_sshd" ]; then',
            '  echo "praxis-reload: no sshd binary found on this host" >&2',
            "  exit 90",
            "fi",
            # 2. Refuse to reload a configuration the daemon would reject.
            f'if ! praxis_check=$("$praxis_sshd" -t -f {quoted_config} 2>&1); then',
            '  echo "praxis-reload: sshd rejected the configuration:'
            ' $praxis_check" >&2',
            "  exit 91",
            "fi",
            # 3. A functioning systemd unit is the preferred mechanism. A
            #    socket-activated listener has no daemon to signal because each
            #    connection reads the configuration afresh.
            "if [ -d /run/systemd/system ] && command -v systemctl"
            " >/dev/null 2>&1; then",
            f"  for praxis_unit in {units}; do",
            '    if systemctl is-active --quiet "$praxis_unit" 2>/dev/null; then',
            '      if praxis_out=$(systemctl reload "$praxis_unit" 2>&1); then',
            f'        echo "{RELOAD_MECHANISM_PREFIX}systemd-unit:$praxis_unit"',
            "        exit 0",
            "      fi",
            '      praxis_diag="$praxis_diag; systemctl reload $praxis_unit'
            ' failed: $praxis_out"',
            "    fi",
            "  done",
            f"  for praxis_socket in {sockets}; do",
            '    if systemctl is-active --quiet "$praxis_socket" 2>/dev/null; then',
            f'      echo "{RELOAD_MECHANISM_PREFIX}systemd-socket:$praxis_socket"',
            "      exit 0",
            "    fi",
            "  done",
            '  praxis_diag="$praxis_diag; no active systemd sshd unit or socket"',
            "else",
            '  praxis_diag="$praxis_diag; systemd is not supervising this host"',
            "fi",
            # 4. Traditional service managers, under both service names.
            "if command -v service >/dev/null 2>&1; then",
            f"  for praxis_service in {services}; do",
            '    if praxis_out=$(service "$praxis_service" reload 2>&1); then',
            f'      echo "{RELOAD_MECHANISM_PREFIX}service:$praxis_service"',
            "      exit 0",
            "    fi",
            '    praxis_diag="$praxis_diag; service $praxis_service reload failed"',
            "  done",
            "else",
            '  praxis_diag="$praxis_diag; no service command"',
            "fi",
            f"for praxis_init in {init_scripts}; do",
            '  [ -x "$praxis_init" ] || continue',
            '  if praxis_out=$("$praxis_init" reload 2>&1); then',
            f'    echo "{RELOAD_MECHANISM_PREFIX}init-script:$praxis_init"',
            "    exit 0",
            "  fi",
            '  praxis_diag="$praxis_diag; $praxis_init reload failed"',
            "done",
            # 5. Directly launched daemon. A pid file is trusted only when the
            #    pid it names still runs the located sshd binary.
            'praxis_master=""',
            'praxis_source=""',
            f"for praxis_pidfile in {pid_files}; do",
            '  [ -f "$praxis_pidfile" ] || continue',
            '  praxis_pid=$(head -n 1 "$praxis_pidfile" 2>/dev/null'
            " | tr -d ' \\t\\r')",
            '  case "$praxis_pid" in',
            '    "" | *[!0-9]*)',
            '      praxis_diag="$praxis_diag; $praxis_pidfile holds no single pid"',
            "      continue",
            "      ;;",
            "  esac",
            '  praxis_exe=$(readlink "/proc/$praxis_pid/exe" 2>/dev/null)'
            ' || praxis_exe=""',
            '  praxis_exe=${praxis_exe%" (deleted)"}',
            '  if [ "$praxis_exe" = "$praxis_sshd" ]; then',
            '    praxis_master="$praxis_pid"',
            '    praxis_source="pid-file"',
            "    break",
            "  fi",
            '  praxis_diag="$praxis_diag; $praxis_pidfile does not name the'
            ' running sshd"',
            "done",
            # 6. No usable pid file: derive the master from the process table.
            #    Every sshd process is collected, then any whose parent is
            #    itself an sshd is dropped as a per-connection child. Exactly
            #    one survivor is the master; zero or several fail closed rather
            #    than guess, and no other process is ever signalled.
            'if [ -z "$praxis_master" ]; then',
            '  praxis_pids=""',
            "  for praxis_entry in /proc/[0-9]*; do",
            '    [ -d "$praxis_entry" ] || continue',
            '    praxis_exe=$(readlink "$praxis_entry/exe" 2>/dev/null) || continue',
            '    praxis_exe=${praxis_exe%" (deleted)"}',
            '    [ "$praxis_exe" = "$praxis_sshd" ] || continue',
            '    praxis_pids="$praxis_pids ${praxis_entry#/proc/}"',
            "  done",
            '  praxis_roots=""',
            "  for praxis_pid in $praxis_pids; do",
            '    praxis_ppid=""',
            "    while IFS= read -r praxis_line; do",
            '      case "$praxis_line" in',
            "        PPid:*)",
            "          praxis_ppid=$(echo ${praxis_line#PPid:})",
            "          break",
            "          ;;",
            "      esac",
            '    done < "/proc/$praxis_pid/status" 2>/dev/null',
            # An unreadable parent must not read as "child of an sshd", which
            # would silently promote a per-connection process to master.
            '    [ -n "$praxis_ppid" ] || praxis_ppid="unknown"',
            '    case " $praxis_pids " in',
            '      *" $praxis_ppid "*) ;;',
            '      *) praxis_roots="$praxis_roots $praxis_pid" ;;',
            "    esac",
            "  done",
            "  set -- $praxis_roots",
            '  if [ "$#" -eq 1 ]; then',
            '    praxis_master="$1"',
            '    praxis_source="process-table"',
            '  elif [ "$#" -eq 0 ]; then',
            '    praxis_diag="$praxis_diag; no running sshd master process"',
            "  else",
            '    praxis_diag="$praxis_diag; sshd master process is ambiguous,'
            ' candidates:$praxis_roots"',
            "  fi",
            "fi",
            'if [ -n "$praxis_master" ]; then',
            '  if kill -HUP "$praxis_master" 2>/dev/null; then',
            f'    echo "{RELOAD_MECHANISM_PREFIX}sighup:$praxis_source:$praxis_master"',
            "    exit 0",
            "  fi",
            '  praxis_diag="$praxis_diag; SIGHUP to sshd master'
            ' $praxis_master failed"',
            "fi",
            'echo "praxis-reload: no safe sshd reload mechanism'
            ' available$praxis_diag" >&2',
            "exit 93",
        )
    )


def build_sshd_reload_command(config_path: str = SSHD_CONFIG_PATH) -> str:
    """Build the init-agnostic, validate-then-reload program for sshd.

    Every deploy, revoke, rollback, and redeployment path uses this one helper,
    so a host that needs a SIGHUP rather than a service manager behaves the same
    everywhere. The program prints ``PRAXIS_RELOAD_MECHANISM=<mechanism>`` on
    success and fails closed with a precise diagnostic otherwise.

    Reading ``/proc/<pid>/exe`` for a root-owned daemon requires root, so the
    whole program runs behind the privilege prefix in one shot rather than
    elevating command by command.
    """
    body = _reload_program_body(config_path)
    return "\n".join(
        (
            "set -u",
            _PRIVILEGE_PRELUDE,
            f"praxis_body=$(cat <<'{_RELOAD_BODY_DELIMITER}'",
            body,
            _RELOAD_BODY_DELIMITER,
            ")",
            '$praxis_priv sh -c "$praxis_body"',
        )
    )


def parse_reload_mechanism(stdout: str) -> Optional[str]:
    """Extract the reload mechanism the host reported, if it reported one."""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(RELOAD_MECHANISM_PREFIX):
            return stripped[len(RELOAD_MECHANISM_PREFIX) :] or None
    return None


@dataclass
class _CapturedPath:
    """One host path an operation is about to replace, and how to undo that."""

    path: str
    backup_path: Optional[str]
    existed: bool
    is_directory: bool = False


class HostFileTransaction:
    """The prior state of every host path one enrollment operation replaces.

    Enrollment writes several managed files before it can prove the result is
    good, and the proof lives at the end: validation, reload, a fresh login, and
    the certificate self-test. Restoring only ``sshd_config`` when one of those
    fails leaves the host mismatched -- most dangerously during CA
    redeployment, where the restored directive would point at a key file that
    was already overwritten with new bytes.

    So every managed path is captured before the first write. ``rollback`` then
    puts each one back exactly as it was found, deleting the ones this operation
    created, and ``commit`` drops the rollback copies once the host has proved
    itself.
    """

    def __init__(self, service: "SSHIdentityService", client, tag: str):
        self._service = service
        self._client = client
        self._tag = tag
        self._captured: List[_CapturedPath] = []

    @property
    def captured_paths(self) -> List[str]:
        """Paths captured so far, in the order they were captured."""
        return [entry.path for entry in self._captured]

    def capture_file(self, path: str) -> None:
        """Record a managed file's prior state before the operation writes it.

        Raises when the rollback point cannot be taken. Refusing to start is the
        only safe response: without it a later failure could not undo the write.
        """
        backup_path = managed_file_backup_path(path, self._tag)
        result = self._service.run_step(
            self._client,
            build_managed_state_capture_command(path, backup_path),
            f"capture prior state of {path}",
        )
        existed = parse_managed_state(result["stdout"])
        if existed is None:
            raise SSHIdentityError(
                f"Step 'capture prior state of {path}' reported no state"
            )
        self._captured.append(
            _CapturedPath(path=path, backup_path=backup_path, existed=existed)
        )

    def capture_directory(self, path: str) -> None:
        """Record whether a managed directory already existed."""
        result = self._service.run_step(
            self._client,
            build_managed_directory_capture_command(path),
            f"capture prior state of {path}",
        )
        existed = parse_managed_state(result["stdout"])
        if existed is None:
            raise SSHIdentityError(
                f"Step 'capture prior state of {path}' reported no state"
            )
        self._captured.append(
            _CapturedPath(
                path=path, backup_path=None, existed=existed, is_directory=True
            )
        )

    def rollback(self) -> None:
        """Undo every captured write, newest first. Never raises.

        A rollback runs while an operation is already failing, so a problem here
        is logged rather than raised: replacing the original error would hide
        why the host is being rolled back at all.
        """
        for entry in reversed(self._captured):
            if entry.is_directory:
                if not entry.existed:
                    self._service.run_step(
                        self._client,
                        build_managed_directory_remove_command(entry.path),
                        f"remove {entry.path}",
                        raise_on_fail=False,
                    )
                continue
            result = self._service.run_step(
                self._client,
                build_managed_state_restore_command(
                    entry.path, entry.backup_path, entry.existed
                ),
                f"restore {entry.path}",
                raise_on_fail=False,
            )
            if result["exit_code"] != 0:
                logger.error(
                    "could not restore %s from its rollback copy (exit %s)",
                    entry.path,
                    result["exit_code"],
                )

    def commit(self) -> None:
        """Drop the rollback copies. Best effort; never raises."""
        for entry in self._captured:
            if entry.backup_path is None:
                continue
            self._service.run_step(
                self._client,
                build_managed_state_discard_command(entry.backup_path),
                f"remove rollback copy of {entry.path}",
                raise_on_fail=False,
            )
        self._captured = []


class SSHIdentityService:
    """Deploy / revoke Vault SSH CA trust on remote systems."""

    def __init__(self, db: Session):
        self.db = db
        self.ssh_service = SSHService(db)
        self.vault_service = VaultService(db)

    def deploy_ca_trust(self, system_id: int) -> Dict[str, Any]:
        """Push the Vault SSH CA public key to a system and enable TrustedUserCAKeys.

        Uses the system's existing credential (username/password) to open the
        onboarding SSH session. Idempotent — safe to call on already-deployed
        systems. The system is not marked as trusting the CA until the new
        configuration validates, reloads, and still accepts a fresh login.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        try:
            ca_pubkey = self.vault_service.get_ssh_ca_public_key()
        except (VaultConnectionError, VaultSecretError) as e:
            raise SSHIdentityError(f"Vault SSH CA not available: {e}") from e

        if not ca_pubkey:
            raise SSHIdentityError("Vault returned no CA public key")

        ca_pubkey = ca_pubkey.strip()

        # Use onboarding SSH session (password or existing key — not cert auth)
        try:
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=True
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"Cannot connect to system: {e}") from e

        # Capture every path this operation replaces before it writes any of
        # them. On a redeployment the key file already holds the previous CA, so
        # a failure after the write has to put those exact bytes back or the
        # restored directive would point at a key the fleet never trusted.
        transaction = HostFileTransaction(self, client, _CA_BACKUP_TAG)
        transaction.capture_file(SSHD_CONFIG_PATH)
        transaction.capture_file(CA_KEY_PATH)

        try:
            self._install_file(
                client,
                content=f"{ca_pubkey}\n",
                dest=CA_KEY_PATH,
                mode=CA_KEY_MODE,
                description=f"write {CA_KEY_PATH}",
            )
            self._ensure_sshd_block(
                client,
                guard=SSHD_CONFIG_DIRECTIVE,
                marker=SSHD_CONFIG_MARKER,
                directives=SSHD_CONFIG_DIRECTIVE,
                description="update sshd_config",
            )
            mechanism = self._reload_sshd(client, "reload sshd")
            self._verify_bootstrap_login(system_id, "CA trust deployment")
        except SSHIdentityError:
            self._roll_back_host(client, transaction)
            raise

        system.ca_trust_deployed = True
        system.ca_trust_deployed_at = datetime.utcnow()
        self._commit_enrollment_state(client, transaction, "CA trust deployment")

        logger.info("CA trust deployed to system %s (%s)", system.hostname, system_id)
        return {
            "status": "deployed",
            "system_id": system_id,
            "hostname": system.hostname,
            "deployed_at": system.ca_trust_deployed_at.isoformat() + "Z",
            "reload_mechanism": mechanism,
        }

    def revoke_ca_trust(self, system_id: int) -> Dict[str, Any]:
        """Remove the CA public key and TrustedUserCAKeys directive from a system.

        The directive is withdrawn and reloaded before the key file is deleted,
        so the daemon never runs against a configuration that points at a file
        which is no longer there.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        try:
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=True
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"Cannot connect to system: {e}") from e

        # The rollback point covers the whole revocation, not just the edit.
        # Deleting the key file can still fail after the directive is gone, and
        # so can recording the result, and the database must never record "not
        # deployed" for a host that is in some third state. Capturing the key
        # file as well means even a successful delete can be undone.
        transaction = HostFileTransaction(self, client, _CA_BACKUP_TAG)
        transaction.capture_file(SSHD_CONFIG_PATH)
        transaction.capture_file(CA_KEY_PATH)

        try:
            # Remove the directive and marker from sshd_config (single sed call)
            cmd_sshd = (
                f"sed -i '/{SSHD_CONFIG_MARKER}/d; "
                f"\\|{SSHD_CONFIG_DIRECTIVE}|d' {SSHD_CONFIG_PATH}"
            )
            self.run_step(client, privileged_command(cmd_sshd), "clean sshd_config")

            mechanism = self._reload_sshd(client, "reload sshd")
            self._verify_bootstrap_login(system_id, "CA trust revocation")

            # Safe now that no loaded configuration references the file. If this
            # fails the directive goes back and is reloaded, so the host returns
            # to trusting the CA that its key file still holds.
            self.run_step(
                client,
                privileged_command(f"rm -f {shlex.quote(CA_KEY_PATH)}"),
                "remove CA key file",
            )
        except SSHIdentityError:
            self._roll_back_host(client, transaction)
            raise

        system.ca_trust_deployed = False
        system.ca_trust_deployed_at = None
        self._commit_enrollment_state(client, transaction, "CA trust revocation")

        logger.info("CA trust revoked from system %s (%s)", system.hostname, system_id)
        return {
            "status": "revoked",
            "system_id": system_id,
            "hostname": system.hostname,
            "reload_mechanism": mechanism,
        }

    def run_step(
        self, client, command: str, description: str, raise_on_fail: bool = True
    ) -> Dict[str, Any]:
        """Run one enrollment step over SSH.

        Returns ``{"exit_code", "stdout", "stderr"}``. Raises SSHIdentityError
        when ``raise_on_fail`` and exit code is non-zero.
        """
        _, stdout, stderr = client.exec_command(command, timeout=30)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if exit_code != 0 and raise_on_fail:
            raise SSHIdentityError(
                f"Step '{description}' failed (exit {exit_code}): {err}"
            )
        return {"exit_code": exit_code, "stdout": out, "stderr": err}

    # ------------------------------------------------------- host primitives

    def _install_file(
        self, client, *, content: str, dest: str, mode: str, description: str
    ) -> None:
        """Install ``content`` at ``dest`` with ``mode`` and root ownership."""
        self.run_step(
            client, build_privileged_install_command(content, dest, mode), description
        )

    def _ensure_sshd_block(
        self, client, *, guard: str, marker: str, directives: str, description: str
    ) -> None:
        """Append a marked directive block to sshd_config unless already present.

        ``guard`` is the literal line whose presence means the block is already
        installed, so re-running never duplicates directives.
        """
        command = "\n".join(
            (
                "set -u",
                _PRIVILEGE_PRELUDE,
                f"if ! grep -qF {shlex.quote(guard)} "
                f"{shlex.quote(SSHD_CONFIG_PATH)}; then",
                f"  printf '\\n%s\\n%s\\n' {shlex.quote(marker)} "
                f"{shlex.quote(directives)} | $praxis_priv tee -a "
                f"{shlex.quote(SSHD_CONFIG_PATH)} > /dev/null",
                "fi",
            )
        )
        self.run_step(client, command, description)

    def _reload_sshd(
        self, client, description: str, raise_on_fail: bool = True
    ) -> Optional[str]:
        """Validate the sshd configuration and reload it, however this host runs.

        Returns the mechanism the host used, or ``None`` when the reload failed
        and ``raise_on_fail`` is False.
        """
        result = self.run_step(
            client,
            build_sshd_reload_command(),
            description,
            raise_on_fail=raise_on_fail,
        )
        if result["exit_code"] != 0:
            logger.error(
                "sshd reload step '%s' failed (exit %s)",
                description,
                result["exit_code"],
            )
            return None
        mechanism = parse_reload_mechanism(result["stdout"])
        if not mechanism and raise_on_fail:
            raise SSHIdentityError(
                f"Step '{description}' did not confirm a reload mechanism"
            )
        return mechanism

    def _verify_bootstrap_login(self, system_id: int, context: str) -> None:
        """Prove sshd still accepts a brand-new login after a configuration change.

        The session that applied the change survives a reload by design, so it
        cannot detect a configuration that locks the host out. Opening a fresh
        connection can, while the rollback point is still in place. Attempts are
        retried over the short window in which a re-execing daemon is not yet
        listening again.
        """
        client = None
        last_error: Optional[SSHConnectionError] = None
        for attempt in range(POST_RELOAD_PROBE_ATTEMPTS):
            try:
                client, _ = self.ssh_service.get_connection(
                    system_id, force_password_auth=True, bypass_cooldown=True
                )
                break
            except SSHConnectionError as e:
                last_error = e
                if attempt + 1 < POST_RELOAD_PROBE_ATTEMPTS:
                    time.sleep(POST_RELOAD_PROBE_DELAY_SECONDS)
        if client is None:
            raise SSHIdentityError(
                f"{context}: sshd refused a new connection after reload: {last_error}"
            ) from last_error
        try:
            result = self.run_step(
                client,
                "echo praxis_reload_ok",
                f"{context} post-reload probe",
                raise_on_fail=False,
            )
        finally:
            try:
                client.close()
            except Exception:  # pylint: disable=broad-except
                pass
        if result["exit_code"] != 0 or "praxis_reload_ok" not in result["stdout"]:
            raise SSHIdentityError(
                f"{context}: a new connection did not survive the sshd reload"
            )

    def _commit_enrollment_state(
        self, client, transaction: "HostFileTransaction", context: str
    ) -> None:
        """Persist the flags, then release the host rollback material.

        The database commit is the last thing that can fail, and until it
        succeeds the host has changed while PostgreSQL still holds the previous
        flags. Discarding the rollback copies before it would leave nothing to
        undo with, so they are released only afterwards. A failed commit rolls
        the session back, restores the host, reloads the restored
        configuration, and raises.
        """
        try:
            self.db.commit()
        except Exception as e:  # pylint: disable=broad-except
            logger.error("%s: recording enrollment state failed: %s", context, e)
            self.db.rollback()
            self._roll_back_host(client, transaction)
            raise SSHIdentityError(
                f"{context}: host changes were rolled back because enrollment "
                f"state could not be recorded: {e}"
            ) from e
        transaction.commit()

    def _roll_back_host(self, client, transaction: "HostFileTransaction") -> None:
        """Put every managed path back, then reload the restored configuration.

        Restoring the files without reloading would leave the running daemon on
        the failed configuration, so the reload is part of the rollback rather
        than a separate concern. It runs non-fatally: the caller is already
        raising the error that explains why the host is being rolled back.
        """
        transaction.rollback()
        self._reload_sshd(client, "reload sshd (rollback)", raise_on_fail=False)

    # ------------------------------------------------------------------ PRA-138
    # AuthorizedPrincipalsCommand hook + praxis-principals wrapper script.

    def deploy_principals_hook(self, system_id: int) -> Dict[str, Any]:
        """Install the praxis-principals script and wire sshd to consult it.

        Pre-reqs:
          - system.ca_trust_deployed must be True (CA pubkey already on host).

        Steps (idempotent):
          1. Write /usr/local/bin/praxis-principals + mode 0755.
          2. Seed /etc/praxis/principals.d/<bootstrap_login> with the
             bootstrap username so cert-auth works for the control plane
             itself and the self-test has a valid principal.
          3. Back up sshd_config, append marker + directives.
          4. Validate and reload through the init-agnostic helper. Restore the
             backup and abort if the daemon rejects the configuration.
          5. Prove a fresh bootstrap login still works.
          6. Self-test: mint a cert for the bootstrap user and attempt cert
             auth. On failure, restore backup + reload and raise.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")
        if not system.ca_trust_deployed:
            raise SSHIdentityError(
                "CA trust not deployed; deploy_ca_trust must run first"
            )

        credential = system.credentials
        bootstrap_login = (credential.username or "").strip() if credential else ""
        if not bootstrap_login:
            raise SSHIdentityError(
                "System credential has no username; cannot seed principals"
            )

        try:
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=True
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"Cannot connect to system: {e}") from e

        seed_path = f"{PRINCIPALS_DIR}/{bootstrap_login}"

        # 1. Capture every path this operation replaces, before it writes any of
        # them. A re-run over an existing deployment overwrites the helper and
        # the bootstrap principal file, so both have to be restorable.
        transaction = HostFileTransaction(self, client, _PRINCIPALS_BACKUP_TAG)
        transaction.capture_file(SSHD_CONFIG_PATH)
        transaction.capture_file(PRINCIPALS_SCRIPT_PATH)
        transaction.capture_directory(PRINCIPALS_DIR)
        transaction.capture_file(seed_path)

        try:
            # 2. Write the principals wrapper script
            self._install_file(
                client,
                content=PRINCIPALS_SCRIPT_BODY,
                dest=PRINCIPALS_SCRIPT_PATH,
                mode=PRINCIPALS_SCRIPT_MODE,
                description="install praxis-principals",
            )

            # 3. Seed bootstrap user's principals file (directory must exist first)
            self.run_step(
                client,
                privileged_command(
                    f"install -d -m 0755 -o root -g root {shlex.quote(PRINCIPALS_DIR)}"
                ),
                "create /etc/praxis/principals.d",
            )
            self._install_file(
                client,
                content=f"{bootstrap_login}\n",
                dest=seed_path,
                mode=PRINCIPALS_FILE_MODE,
                description="seed bootstrap principals",
            )

            # 4. Append the directives
            self._ensure_sshd_block(
                client,
                guard=SSHD_PRINCIPALS_MARKER,
                marker=SSHD_PRINCIPALS_MARKER,
                directives=SSHD_PRINCIPALS_DIRECTIVES,
                description="append AuthorizedPrincipalsCommand",
            )

            # 5/6/7. Validate, reload, prove the host is still reachable, then
            # prove certificate auth itself works. Any failure rolls every
            # managed path back and leaves the system unmarked.
            mechanism = self._reload_sshd(client, "reload sshd")
            self._verify_bootstrap_login(system_id, "principals hook deployment")
            self.self_test_cert_auth(system_id)
        except SSHIdentityError as e:
            logger.error(
                "principals hook deployment failed on %s: %s; rolling back",
                system.hostname,
                e,
            )
            self._roll_back_host(client, transaction)
            raise

        system.principals_hook_deployed = True
        system.principals_hook_deployed_at = datetime.utcnow()
        self._commit_enrollment_state(client, transaction, "principals hook deployment")

        logger.info(
            "principals hook deployed to %s (system %s)", system.hostname, system_id
        )
        return {
            "status": "deployed",
            "system_id": system_id,
            "hostname": system.hostname,
            "deployed_at": system.principals_hook_deployed_at.isoformat() + "Z",
            "reload_mechanism": mechanism,
        }

    def revoke_principals_hook(self, system_id: int) -> Dict[str, Any]:
        """Remove the principals sshd directives + praxis-principals script.

        The directives go first and are reloaded before the script is deleted,
        so sshd never runs with an AuthorizedPrincipalsCommand that is missing.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        try:
            client, _ = self.ssh_service.get_connection(
                system_id, force_password_auth=True
            )
        except SSHConnectionError as e:
            raise SSHIdentityError(f"Cannot connect to system: {e}") from e

        # The rollback point covers the whole revocation. Deleting the helper
        # can still fail after the directives are gone, and so can recording the
        # result, and the database must never record "not deployed" for a host
        # that is in some third state. Capturing the helper as well means even a
        # successful delete can be undone.
        transaction = HostFileTransaction(self, client, _PRINCIPALS_BACKUP_TAG)
        transaction.capture_file(SSHD_CONFIG_PATH)
        transaction.capture_file(PRINCIPALS_SCRIPT_PATH)

        try:
            # Strip the marker + the two directives that follow it
            cmd_sshd = f"sed -i '/{SSHD_PRINCIPALS_MARKER}/,+2d' {SSHD_CONFIG_PATH}"
            self.run_step(client, privileged_command(cmd_sshd), "clean sshd_config")

            mechanism = self._reload_sshd(client, "reload sshd")
            self._verify_bootstrap_login(system_id, "principals hook revocation")

            # If this fails the directives go back and are reloaded, so the host
            # returns to a configuration whose helper is still present.
            self.run_step(
                client,
                privileged_command(f"rm -f {shlex.quote(PRINCIPALS_SCRIPT_PATH)}"),
                "remove praxis-principals script",
            )
        except SSHIdentityError:
            self._roll_back_host(client, transaction)
            raise

        system.principals_hook_deployed = False
        system.principals_hook_deployed_at = None
        self._commit_enrollment_state(client, transaction, "principals hook revocation")

        logger.info(
            "principals hook revoked from %s (system %s)", system.hostname, system_id
        )
        return {
            "status": "revoked",
            "system_id": system_id,
            "hostname": system.hostname,
            "reload_mechanism": mechanism,
        }

    def enroll_access_broker(self, system_id: int) -> Dict[str, Any]:
        """One-shot enrollment: CA trust + principals hook + self-test.

        Convenience wrapper for the operator-facing "Enroll" button. Safe to
        re-run; each step is idempotent, and because a step only marks the
        system once it has fully succeeded, a re-run after a partial failure
        resumes at the step that failed.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        if not system.ca_trust_deployed:
            self.deploy_ca_trust(system_id)
        if not system.principals_hook_deployed:
            self.deploy_principals_hook(system_id)

        # PRA-234: CA trust + principals hook succeeding does NOT prove the
        # broker is usable. Native sshd AllowUsers/AllowGroups policy can still
        # reject provisioned logins at the account gate. Surface that here as a
        # non-fatal warning so the enrollment banner cannot over-claim. Failure
        # to run the check must never fail enrollment itself.
        allowlist: Dict[str, Any]
        try:
            allowlist = self.check_access_allowlist(system_id)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning(
                "allow-list check failed during enrollment of %s: %s",
                system.hostname,
                e,
            )
            allowlist = {"checked": False, "blocked_logins": [], "results": []}

        return {
            "status": "enrolled",
            "system_id": system_id,
            "hostname": system.hostname,
            "ca_trust_deployed": system.ca_trust_deployed,
            "principals_hook_deployed": system.principals_hook_deployed,
            "allowlist": allowlist,
            "allowlist_blocked_logins": allowlist.get("blocked_logins", []),
        }

    def self_test_cert_auth(self, system_id: int) -> Dict[str, Any]:
        """Prove certificate authentication works end to end.

        Uses the SSH service's certificate-only entry point, which never falls
        back to the stored credential, and runs ``echo praxis_selftest_ok`` over
        it. The pooled connection helper does fall back, which would let a host
        that cannot actually use the broker report a healthy self-test. Raises
        SSHIdentityError on any failure.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        try:
            client = self.ssh_service.connect_with_certificate(system_id)
        except SSHConnectionError as e:
            raise SSHIdentityError(f"certificate authentication failed: {e}") from e
        try:
            result = self.run_step(
                client, "echo praxis_selftest_ok", "self-test exec", raise_on_fail=False
            )
        finally:
            try:
                client.close()
            except Exception:  # pylint: disable=broad-except
                pass
        if result["exit_code"] != 0 or "praxis_selftest_ok" not in result["stdout"]:
            raise SSHIdentityError("self-test command did not return expected output")

        return {
            "status": "ok",
            "system_id": system_id,
            "authentication": "certificate",
        }

    # --------------------------------------------------------------- PRA-234
    # Native sshd account allow-list (AllowUsers/AllowGroups/DenyUsers/
    # DenyGroups) compatibility detection. Enrollment and the bootstrap
    # self-test both pass on a host hardened with e.g. ``AllowUsers praxis``,
    # yet a provisioned login such as ``operator`` is rejected at the allow-list
    # gate before the CA cert is evaluated. These helpers surface that instead
    # of letting Connect collapse into a generic publickey failure.

    def diagnose_login_allowlist(
        self, system_id: int, login: str, client=None
    ) -> allowlist_diag.AllowlistDiagnosis:
        """Diagnose whether native sshd allow-lists would reject ``login``.

        Uses a bootstrap (password/existing-credential) SSH session — which
        still works because the bootstrap login is what the operator hardened
        the host around — to read effective sshd policy via ``sshd -T`` and the
        login's group membership. Never edits host policy. Returns an
        ``AllowlistDiagnosis``; ``checked=False`` when the probe could not run,
        so callers must not fabricate a denial.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        if client is None:
            try:
                client, _ = self.ssh_service.get_connection(
                    system_id, force_password_auth=True
                )
            except SSHConnectionError as e:
                return allowlist_diag.AllowlistDiagnosis(
                    login=login,
                    checked=False,
                    blocked=False,
                    indeterminate_reason=f"bootstrap SSH connection failed: {e}",
                )

        run = allowlist_diag.runner_for_client(client)
        try:
            return allowlist_diag.diagnose_login_allowlist(run, login)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning(
                "allow-list diagnosis errored on %s for %s: %s",
                system.hostname,
                login,
                e,
            )
            return allowlist_diag.AllowlistDiagnosis(
                login=login,
                checked=False,
                blocked=False,
                indeterminate_reason=f"allow-list probe error: {e}",
            )

    def check_access_allowlist(
        self, system_id: int, logins: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Check allow-list compatibility for provisioned logins on a host.

        When ``logins`` is omitted, every provisioned ``HostUserState`` login on
        the system is checked. Reuses a single bootstrap connection. Returns a
        summary the enrollment flow, a dedicated endpoint, and the UI banner can
        all consume, so a healthy CA/principals deployment does not imply the
        broker is usable when eligible logins are blocked by host policy.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHIdentityError(f"System {system_id} not found")

        if logins is None:
            rows = (
                self.db.query(HostUserState)
                .filter(
                    HostUserState.system_id == system_id,
                    HostUserState.state == "provisioned",
                )
                .all()
            )
            logins = sorted({r.login for r in rows})

        results: List[Dict[str, Any]] = []
        client = None
        if logins:
            try:
                client, _ = self.ssh_service.get_connection(
                    system_id, force_password_auth=True
                )
            except SSHConnectionError as e:
                # No connection at all — report every login as unverified rather
                # than claiming a denial we could not observe.
                for login in logins:
                    results.append(
                        allowlist_diag.AllowlistDiagnosis(
                            login=login,
                            checked=False,
                            blocked=False,
                            indeterminate_reason=(
                                f"bootstrap SSH connection failed: {e}"
                            ),
                        ).to_dict(system.hostname)
                    )
                return {
                    "system_id": system_id,
                    "hostname": system.hostname,
                    "checked": False,
                    "blocked_logins": [],
                    "results": results,
                }

        for login in logins:
            diag = self.diagnose_login_allowlist(system_id, login, client=client)
            results.append(diag.to_dict(system.hostname))

        blocked = [r["login"] for r in results if r["blocked"]]
        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "checked": any(r["checked"] for r in results) if results else True,
            "blocked_logins": blocked,
            "results": results,
        }
