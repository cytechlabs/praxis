"""Preflight SSH verification and discovery for guided onboarding.

Every other SSH path in Praxis starts from a managed ``System`` row: the
connection pool, the host-key store, the facts collector and the distribution
detector are all keyed on ``system_id``. Guided onboarding cannot be, because
the whole point is to find out whether a host is usable *before* it becomes a
managed host. A draft that never finishes must leave nothing behind and consume
no license capacity.

So this module connects from explicit parameters instead of a row, and reuses
the authoritative pieces rather than reimplementing them: the credential key
loader, the secrets service, the SSH policy allow-lists, and the shared host-key
fingerprint definition. What it deliberately does not do is persist anything.
No system, no metadata, no host-key row, no security log. The only durable
result is what the caller chooses to write into the draft.

Checks run as an ordered sequence over one connection, but they are reported
independently, so an operator sees that the host answered and the handshake
succeeded and the password was wrong, rather than one flat failure. Reaching
the transport in stages is what makes that possible: a raw socket answers the
reachability question, ``start_client()`` answers the handshake and host
identity question, and authentication is a separate call after both.

Nothing here returns transport or exception text. Failures are mapped to the
reason codes in ``app/api/schemas/onboarding.py`` and the operator-facing
wording is derived from the code, so a library message cannot leak a path, a
key, or an internal hostname into the UI, the draft, or an audit row.
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import paramiko
from sqlalchemy.orm import Session

from ..api.schemas import onboarding as schemas
from ..db.models import Credential
from ..db.ssh_security_models import SSHSecurityPolicy
from .ssh_service import SSHKeyError, host_key_fingerprint, load_credential_private_key
from .vault_service import VaultService

logger = logging.getLogger(__name__)

# Bounds for a preflight connection. Deliberately short: this runs while an
# operator watches a spinner, and a host that needs longer than this to answer a
# trivial command is not ready to be managed.
CONNECT_TIMEOUT_SECONDS = 10
HANDSHAKE_TIMEOUT_SECONDS = 15
COMMAND_TIMEOUT_SECONDS = 20

# Command output is read into memory, so it is capped. Discovery needs a few
# hundred bytes; anything beyond this is a misbehaving host, not data we want.
MAX_OUTPUT_BYTES = 64 * 1024

# Read-only identity probe. Single command, no shell metacharacters beyond the
# separators, nothing written to the host.
_IDENTITY_COMMAND = (
    "echo PRAXIS_HOSTNAME=$(hostname 2>/dev/null); "
    "echo PRAXIS_FQDN=$(hostname -f 2>/dev/null); "
    "echo PRAXIS_ARCH=$(uname -m 2>/dev/null); "
    "echo PRAXIS_KERNEL=$(uname -r 2>/dev/null); "
    "cat /etc/os-release 2>/dev/null"
)

_ECHO_COMMAND = "echo praxis-preflight-ok"
_ECHO_EXPECTED = "praxis-preflight-ok"

# Package family by os-release ID / ID_LIKE. Mirrors the vocabulary the mirror
# and patch surfaces already use (``deb`` / ``rpm``).
_DEB_IDS = {"debian", "ubuntu", "raspbian", "linuxmint", "pop"}
_RPM_IDS = {
    "rhel",
    "centos",
    "rocky",
    "almalinux",
    "fedora",
    "ol",
    "oracle",
    "amzn",
    "sles",
    "opensuse",
    "opensuse-leap",
}

_PACKAGE_MANAGER = {"deb": "apt", "rpm": "dnf"}

# sudo probe wording, matched case-insensitively against the host's own stderr.
# The stderr itself is never surfaced; only the code it maps to.
_SUDO_PASSWORD_PATTERNS = (
    "password is required",
    "a password is required",
    "no tty present",
    "sudo: a terminal is required",
)
_SUDO_DENIED_PATTERNS = (
    "not allowed to run sudo",
    "is not in the sudoers file",
    "not allowed to execute",
    "sorry, user",
)
_SUDO_UNAVAILABLE_PATTERNS = (
    "command not found",
    "no such file or directory",
)


class PreflightError(Exception):
    """A preflight step failed with a structured reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass
class OfferedHostKey:
    """The public host key a target presented during preflight."""

    key_type: str
    public_key: str
    fingerprint: str


@dataclass
class PreflightTarget:
    """Everything a preflight connection needs, taken from a draft."""

    address: str
    ssh_port: int
    credential: Credential
    policy: Optional[SSHSecurityPolicy] = None
    pinned_public_key: Optional[str] = None
    require_host_key_verification: bool = True


@dataclass
class PreflightResult:
    """Independent per-check outcomes plus whatever the host told us."""

    checks: List[Dict[str, Any]] = field(default_factory=list)
    offered_host_key: Optional[OfferedHostKey] = None
    identity: Dict[str, Any] = field(default_factory=dict)
    os_release: Dict[str, str] = field(default_factory=dict)
    resolved_ip: Optional[str] = None

    @property
    def verified(self) -> bool:
        """True only when no check failed and authentication actually ran.

        A run that never reached authentication is not verified, however many
        earlier checks passed.
        """
        if any(c["status"] == schemas.STATUS_FAIL for c in self.checks):
            return False
        return any(
            c["check"] == schemas.CHECK_AUTHENTICATION
            and c["status"] == schemas.STATUS_PASS
            for c in self.checks
        )

    def reason_code(self) -> str:
        """The first failing reason code, or ``verified``."""
        for check in self.checks:
            if check["status"] == schemas.STATUS_FAIL:
                return check["reason_code"]
        return schemas.REASON_VERIFIED


def policy_requires_host_key_verification(policy: Optional[SSHSecurityPolicy]) -> bool:
    """Whether ``policy`` demands host-key verification.

    A missing policy is absent security configuration, not an opt-out, so it
    verifies. Only a stored policy that explicitly clears the flag waives it.
    This mirrors ``ssh_service.configure_host_key_policy`` so guided onboarding
    and ordinary connections read a policy the same way.
    """
    return not (policy is not None and policy.require_host_key_verification is False)


def build_disabled_algorithms(
    policy: Optional[SSHSecurityPolicy],
) -> Optional[Dict[str, List[str]]]:
    """Translate a policy's allow-lists into paramiko's pre-handshake dict.

    Same translation ``SSHService`` applies to a managed host, expressed against
    a policy rather than a system, so preflight negotiates exactly what the
    host will negotiate once it is managed.
    """
    if policy is None:
        return None

    def _diff(allowed_csv: Optional[str], supported: List[str]) -> List[str]:
        if not allowed_csv:
            return []
        allowed = {a.strip() for a in allowed_csv.split(",") if a.strip()}
        return [s for s in supported if s not in allowed]

    probe = paramiko.Transport(socket.socket())
    try:
        sec_opts = probe.get_security_options()
        disabled: Dict[str, List[str]] = {}
        ciphers = _diff(policy.allowed_ciphers, list(sec_opts.ciphers))
        macs = _diff(policy.allowed_macs, list(sec_opts.digests))
        kex = _diff(policy.allowed_kex, list(sec_opts.kex))
    finally:
        try:
            probe.close()
        except Exception:  # pylint: disable=broad-except
            pass

    if ciphers:
        disabled["ciphers"] = ciphers
    if macs:
        disabled["macs"] = macs
    if kex:
        disabled["kex"] = kex
    return disabled or None


def _resolve(address: str, port: int) -> List[Tuple[Any, ...]]:
    """Resolve an address to connectable socket parameters, v4 or v6."""
    try:
        return socket.getaddrinfo(address, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise PreflightError(schemas.REASON_ADDRESS_INVALID) from exc


def _open_socket(address: str, port: int) -> Tuple[socket.socket, Optional[str]]:
    """Open a TCP socket and report the address actually reached.

    Registration needs a concrete address, and a named host may resolve
    differently later, so what the connection landed on is captured here rather
    than resolved again at the end.
    """
    infos = _resolve(address, port)
    last_timeout = False
    for family, socktype, proto, _canon, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            sock.connect(sockaddr)
            try:
                peer = sock.getpeername()[0]
            except OSError:
                peer = sockaddr[0] if sockaddr else None
            return sock, peer
        except socket.timeout:
            last_timeout = True
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
    raise PreflightError(
        schemas.REASON_CONNECTION_TIMEOUT
        if last_timeout
        else schemas.REASON_NETWORK_UNREACHABLE
    )


def _read_bounded(channel_file) -> str:
    """Read at most ``MAX_OUTPUT_BYTES`` and decode leniently."""
    data = channel_file.read(MAX_OUTPUT_BYTES)
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def _run_command(
    transport: paramiko.Transport, command: str, stdin_payload: Optional[str] = None
) -> Tuple[int, str, str]:
    """Run one bounded command on its own channel."""
    channel = transport.open_session(timeout=COMMAND_TIMEOUT_SECONDS)
    try:
        channel.settimeout(COMMAND_TIMEOUT_SECONDS)
        channel.exec_command(command)
        if stdin_payload is not None:
            stdin = channel.makefile("wb")
            try:
                stdin.write(stdin_payload.encode("utf-8"))
                stdin.flush()
            finally:
                stdin.close()
            channel.shutdown_write()
        stdout = _read_bounded(channel.makefile("rb"))
        stderr = _read_bounded(channel.makefile_stderr("rb"))
        exit_status = channel.recv_exit_status()
        return exit_status, stdout, stderr
    finally:
        try:
            channel.close()
        except Exception:  # pylint: disable=broad-except
            pass


def _resolve_username(credential: Credential, secret: Dict[str, Any]) -> str:
    """The login to authenticate as, or a structured failure.

    A CA principal is not a substitute here: preflight authenticates with the
    stored credential, so the credential itself must name the account.
    """
    username = credential.username or secret.get("username")
    if not username or not str(username).strip():
        raise PreflightError(schemas.REASON_USERNAME_MISSING)
    return str(username).strip()


def _authenticate(
    transport: paramiko.Transport,
    credential: Credential,
    secret: Dict[str, Any],
    policy: Optional[SSHSecurityPolicy],
) -> None:
    """Authenticate the transport with the stored credential."""
    username = _resolve_username(credential, secret)

    if credential.auth_method == "ssh_key":
        minimum_rsa_bits = policy.minimum_key_size if policy else None
        try:
            pkey = load_credential_private_key(
                secret.get("ssh_key"),
                passphrase=secret.get("ssh_passphrase"),
                minimum_rsa_bits=minimum_rsa_bits,
            )
        except SSHKeyError as exc:
            raise PreflightError(schemas.REASON_KEY_TYPE_UNSUPPORTED) from exc
        try:
            transport.auth_publickey(username, pkey)
        except paramiko.AuthenticationException as exc:
            raise PreflightError(schemas.REASON_AUTHENTICATION_FAILED) from exc
        except paramiko.SSHException as exc:
            raise PreflightError(schemas.REASON_AUTHENTICATION_FAILED) from exc
        return

    password = secret.get("password")
    if not password:
        raise PreflightError(schemas.REASON_AUTHENTICATION_FAILED)
    try:
        transport.auth_password(username, password)
    except paramiko.AuthenticationException as exc:
        raise PreflightError(schemas.REASON_AUTHENTICATION_FAILED) from exc
    except paramiko.SSHException as exc:
        raise PreflightError(schemas.REASON_AUTHENTICATION_FAILED) from exc


def _classify_sudo_failure(stderr: str) -> str:
    """Map a sudo probe's own stderr to a reason code, never surfacing it."""
    lowered = stderr.lower()
    for pattern in _SUDO_UNAVAILABLE_PATTERNS:
        if pattern in lowered:
            return schemas.REASON_SUDO_UNAVAILABLE
    for pattern in _SUDO_PASSWORD_PATTERNS:
        if pattern in lowered:
            return schemas.REASON_SUDO_PASSWORD_REQUIRED
    for pattern in _SUDO_DENIED_PATTERNS:
        if pattern in lowered:
            return schemas.REASON_SUDO_DENIED
    return schemas.REASON_SUDO_DENIED


def _probe_sudo(
    transport: paramiko.Transport, credential: Credential, secret: Dict[str, Any]
) -> Dict[str, Any]:
    """Probe elevation according to the credential's declared sudo method."""
    method = (credential.sudo_method or "none").strip().lower()

    if method == "none":
        return schemas.serialize_check(
            schemas.CHECK_SUDO, schemas.STATUS_SKIPPED, schemas.REASON_VERIFIED
        )

    if method == "password":
        sudo_password = secret.get("sudo_password")
        if not sudo_password:
            return schemas.serialize_check(
                schemas.CHECK_SUDO,
                schemas.STATUS_FAIL,
                schemas.REASON_SUDO_PASSWORD_REQUIRED,
            )
        exit_status, _out, err = _run_command(
            transport, "sudo -S -p '' -- true", stdin_payload=f"{sudo_password}\n"
        )
    else:
        exit_status, _out, err = _run_command(transport, "sudo -n -- true")

    if exit_status == 0:
        return schemas.serialize_check(
            schemas.CHECK_SUDO, schemas.STATUS_PASS, schemas.REASON_VERIFIED
        )
    return schemas.serialize_check(
        schemas.CHECK_SUDO, schemas.STATUS_FAIL, _classify_sudo_failure(err)
    )


def _parse_os_release(text: str) -> Dict[str, str]:
    """Parse the ``KEY=value`` lines of /etc/os-release."""
    parsed: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        parsed[key.strip().upper()] = value
    return parsed


def _parse_identity(stdout: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Split the identity probe's output into scalars and os-release."""
    identity: Dict[str, Any] = {}
    os_release_lines: List[str] = []
    for line in stdout.splitlines():
        matched = re.match(r"^PRAXIS_([A-Z]+)=(.*)$", line.strip())
        if matched:
            identity[matched.group(1).lower()] = matched.group(2).strip() or None
        else:
            os_release_lines.append(line)
    return identity, _parse_os_release("\n".join(os_release_lines))


def package_family_for(os_release: Dict[str, str]) -> Optional[str]:
    """Resolve ``deb`` / ``rpm`` from os-release ID and ID_LIKE."""
    candidates: List[str] = []
    if os_release.get("ID"):
        candidates.append(os_release["ID"].strip().lower())
    for like in (os_release.get("ID_LIKE") or "").split():
        candidates.append(like.strip().lower())
    for candidate in candidates:
        if candidate in _DEB_IDS:
            return "deb"
        if candidate in _RPM_IDS:
            return "rpm"
    return None


def package_manager_for(package_family: Optional[str]) -> Optional[str]:
    """The package manager a family implies."""
    if package_family is None:
        return None
    return _PACKAGE_MANAGER.get(package_family)


def _check_address(result: PreflightResult, target: PreflightTarget) -> bool:
    """Re-validate the address. True when the sequence may continue.

    Already schema-validated, re-checked here because a draft may have been
    created before a DNS change.
    """
    try:
        schemas.validate_address(target.address)
    except ValueError:
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_ADDRESS,
                schemas.STATUS_FAIL,
                schemas.REASON_ADDRESS_INVALID,
            )
        )
        return False
    result.checks.append(
        schemas.serialize_check(
            schemas.CHECK_ADDRESS, schemas.STATUS_PASS, schemas.REASON_VERIFIED
        )
    )
    return True


def _check_network(
    result: PreflightResult, target: PreflightTarget
) -> Optional[socket.socket]:
    """Open the raw socket, so an unreachable host is distinguishable from one
    that never answers. Returns the socket, or ``None`` when the check failed.
    """
    try:
        sock, resolved_ip = _open_socket(target.address, target.ssh_port)
        result.resolved_ip = resolved_ip
    except PreflightError as exc:
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_NETWORK, schemas.STATUS_FAIL, exc.reason_code
            )
        )
        return None
    result.checks.append(
        schemas.serialize_check(
            schemas.CHECK_NETWORK, schemas.STATUS_PASS, schemas.REASON_VERIFIED
        )
    )
    return sock


def _start_transport(
    result: PreflightResult, target: PreflightTarget, sock: socket.socket
) -> Tuple[Optional[paramiko.Transport], bool]:
    """Complete the key exchange without authenticating, so the host key is
    available for the operator to review before any secret is offered.

    Returns ``(transport, started)``. The transport is returned even when the
    handshake fails so the caller's cleanup still closes it; it is ``None`` only
    when the transport could not be constructed at all.
    """
    transport: Optional[paramiko.Transport] = None
    try:
        disabled_algorithms = build_disabled_algorithms(target.policy)
        transport = paramiko.Transport(sock, disabled_algorithms=disabled_algorithms)
        transport.banner_timeout = HANDSHAKE_TIMEOUT_SECONDS
        transport.handshake_timeout = HANDSHAKE_TIMEOUT_SECONDS
        transport.start_client(timeout=HANDSHAKE_TIMEOUT_SECONDS)
    except paramiko.SSHException as exc:
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_HOST_IDENTITY,
                schemas.STATUS_FAIL,
                schemas.REASON_SSH_POLICY_REJECTED,
            )
        )
        logger.info("preflight handshake rejected: %s", type(exc).__name__)
        return transport, False
    except OSError:
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_HOST_IDENTITY,
                schemas.STATUS_FAIL,
                schemas.REASON_NETWORK_UNREACHABLE,
            )
        )
        return transport, False
    return transport, True


def _check_host_identity(
    result: PreflightResult,
    target: PreflightTarget,
    transport: paramiko.Transport,
) -> bool:
    """Record the offered key and decide whether it may be continued with."""
    server_key = transport.get_remote_server_key()
    offered = OfferedHostKey(
        key_type=server_key.get_name(),
        public_key=server_key.get_base64(),
        fingerprint=host_key_fingerprint(server_key),
    )
    result.offered_host_key = offered

    if target.require_host_key_verification:
        if target.pinned_public_key is None:
            # Nothing approved yet. The key is reported for an explicit
            # decision; the draft advances no further on this run.
            result.checks.append(
                schemas.serialize_check(
                    schemas.CHECK_HOST_IDENTITY,
                    schemas.STATUS_FAIL,
                    schemas.REASON_HOST_KEY_UNKNOWN,
                )
            )
            return False
        if target.pinned_public_key != offered.public_key:
            # Fail closed. The approved key is the only key this draft may
            # continue with.
            result.checks.append(
                schemas.serialize_check(
                    schemas.CHECK_HOST_IDENTITY,
                    schemas.STATUS_FAIL,
                    schemas.REASON_HOST_KEY_MISMATCH,
                )
            )
            return False

    result.checks.append(
        schemas.serialize_check(
            schemas.CHECK_HOST_IDENTITY,
            schemas.STATUS_PASS,
            schemas.REASON_VERIFIED,
        )
    )
    return True


def _check_authentication(
    db: Session,
    result: PreflightResult,
    target: PreflightTarget,
    transport: paramiko.Transport,
) -> Optional[Dict[str, Any]]:
    """Authenticate with the stored credential.

    Returns the credential secret so later stages can reuse it, or ``None``
    when the check failed.
    """
    try:
        secret = VaultService(db).read_secret(target.credential.vault_path) or {}
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "preflight could not read credential secret: %s", type(exc).__name__
        )
        secret = {}
    if not secret:
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_AUTHENTICATION,
                schemas.STATUS_FAIL,
                schemas.REASON_AUTHENTICATION_FAILED,
            )
        )
        return None

    try:
        _authenticate(transport, target.credential, secret, target.policy)
    except PreflightError as exc:
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_AUTHENTICATION, schemas.STATUS_FAIL, exc.reason_code
            )
        )
        return None
    if not transport.is_authenticated():
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_AUTHENTICATION,
                schemas.STATUS_FAIL,
                schemas.REASON_AUTHENTICATION_FAILED,
            )
        )
        return None
    result.checks.append(
        schemas.serialize_check(
            schemas.CHECK_AUTHENTICATION,
            schemas.STATUS_PASS,
            schemas.REASON_VERIFIED,
        )
    )
    return secret


def _check_command(result: PreflightResult, transport: paramiko.Transport) -> bool:
    """Run a bounded, non-privileged command.

    Authenticating proves the account exists; this proves it can actually do
    anything.
    """
    try:
        exit_status, stdout, _stderr = _run_command(transport, _ECHO_COMMAND)
    except (paramiko.SSHException, OSError):
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_COMMAND,
                schemas.STATUS_FAIL,
                schemas.REASON_COMMAND_FAILED,
            )
        )
        return False
    if exit_status != 0 or _ECHO_EXPECTED not in stdout:
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_COMMAND,
                schemas.STATUS_FAIL,
                schemas.REASON_COMMAND_FAILED,
            )
        )
        return False
    result.checks.append(
        schemas.serialize_check(
            schemas.CHECK_COMMAND, schemas.STATUS_PASS, schemas.REASON_VERIFIED
        )
    )
    return True


def _check_sudo(
    result: PreflightResult,
    target: PreflightTarget,
    transport: paramiko.Transport,
    secret: Dict[str, Any],
) -> None:
    """Elevation, reported on its own so a host that is fine except for sudo
    reads that way instead of failing wholesale.
    """
    try:
        result.checks.append(_probe_sudo(transport, target.credential, secret))
    except (paramiko.SSHException, OSError):
        result.checks.append(
            schemas.serialize_check(
                schemas.CHECK_SUDO,
                schemas.STATUS_FAIL,
                schemas.REASON_SUDO_UNAVAILABLE,
            )
        )


def _collect_identity(result: PreflightResult, transport: paramiko.Transport) -> None:
    """Read identity on the same authenticated transport, so discovery does not
    pay for a second connection.
    """
    try:
        _status, stdout, _err = _run_command(transport, _IDENTITY_COMMAND)
        identity, os_release = _parse_identity(stdout)
        result.identity = identity
        result.os_release = os_release
    except (paramiko.SSHException, OSError):
        logger.info("preflight identity probe did not complete")


def _close_quietly(
    transport: Optional[paramiko.Transport], sock: socket.socket
) -> None:
    """Release the transport and socket whatever the outcome was."""
    if transport is not None:
        try:
            transport.close()
        except Exception:  # pylint: disable=broad-except
            pass
    try:
        sock.close()
    except OSError:
        pass


def run_preflight(
    db: Session, target: PreflightTarget, *, collect_identity: bool = True
) -> PreflightResult:
    """Connect, verify, and optionally read identity, persisting nothing.

    Returns a result whose checks are always populated up to the point of
    failure. A failure stops the sequence: there is no useful sudo answer for a
    host that refused the password. The stages run in a fixed order on one
    connection, and the transport and socket are released whatever happens.
    """
    result = PreflightResult()

    if not _check_address(result, target):
        return result

    sock = _check_network(result, target)
    if sock is None:
        return result

    transport: Optional[paramiko.Transport] = None
    try:
        transport, started = _start_transport(result, target, sock)
        if not started:
            return result

        if not _check_host_identity(result, target, transport):
            return result

        secret = _check_authentication(db, result, target, transport)
        if secret is None:
            return result

        if not _check_command(result, transport):
            return result

        _check_sudo(result, target, transport, secret)

        if collect_identity:
            _collect_identity(result, transport)

        return result
    finally:
        _close_quietly(transport, sock)


def utcnow_iso() -> str:
    """Timestamp for stored verification and discovery blocks."""
    return datetime.utcnow().isoformat()
