"""
SSH service for managing SSH connections to remote systems.
"""

import base64
import hashlib
import io
import logging
import re
import select
import socket
import struct
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import paramiko
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from ..db.command_execution_models import CommandExecutionResult
from ..db.models import Credential, GlobalConnectionSettings, System, SystemMetadata
from ..db.ssh_security_models import SSHHostKey, SSHSecurityLog
from .vault_service import VaultService

logger = logging.getLogger(__name__)


class SSHConnectionError(Exception):
    """Exception raised for SSH connection errors."""


class SSHCommandTimeout(SSHConnectionError):
    """Raised when a command exceeds its hard wall-clock timeout (PRA-322).

    Subclasses SSHConnectionError so existing callers that catch that keep
    working, but callers can special-case a command TIMEOUT — which means the
    host was reachable (we connected + ran the command) but the command took too
    long — separately from a transport failure. A command timeout must NOT mark a
    host Unreachable.
    """


# PRA-322: hard bounds for internal SSH command execution so one slow/noisy host
# cannot deadlock the backend or exhaust its memory.
# - Captured stdout/stderr are each capped; excess is drained (so the remote SSH
#   window never fills and the command can't wedge) but not retained.
# - A hard wall-clock deadline forcibly closes the channel on expiry.
_MAX_INTERNAL_OUTPUT_BYTES = 16 * 1024 * 1024  # 16 MiB per stream
_DEFAULT_COMMAND_WALL_TIMEOUT = 120  # seconds


# --------------------------------------------------------------------------- #
# PRA-313: per-host transport circuit breaker                                 #
#                                                                             #
# One bad/half-open SSH host must not make unrelated pages, dashboard/status  #
# requests, or scheduler work wait on that host's SSH timeout. After a        #
# configured number of consecutive banner/connect/socket failures a host      #
# enters a short cooldown; during it, NORMAL ops fast-fail without opening a  #
# new socket. Explicit operator rechecks pass ``bypass=True`` to retry and    #
# clear the cooldown on success. Auth failures do NOT trip the breaker — they #
# mean the transport reached the host (and are fast), so they reset it.       #
#                                                                             #
# These are module-level so both SSHService and the direct-paramiko SFTP path #
# in file_transfer_service share one implementation.                          #
# --------------------------------------------------------------------------- #

_DEFAULT_TRANSPORT_FAILURE_THRESHOLD = 3
_DEFAULT_TRANSPORT_COOLDOWN_SECONDS = 60
_DEFAULT_CONNECTION_TIMEOUT = 10
_MAX_TRANSPORT_ERROR_LEN = 500


class HostCoolingDownError(SSHConnectionError):
    """Raised when a host's transport breaker is open and the caller did not
    request an explicit bypass. Fast-fail: no socket is opened."""

    def __init__(
        self, system: System, remaining_s: float, last_error: Optional[str] = None
    ):
        self.remaining_s = remaining_s
        self.last_error = last_error
        msg = (
            f"Host {system.hostname} is temporarily unreachable "
            f"(cooling down, retry in ~{int(remaining_s)}s)"
        )
        if last_error:
            msg = f"{msg}: {last_error}"
        super().__init__(msg)


def is_transport_failure(exc: BaseException) -> bool:
    """True for banner/connect/socket-level failures that should trip the
    breaker. Auth failures and host-key mismatches mean the host is reachable
    (and are fast), so they are excluded."""
    if isinstance(
        exc, (paramiko.AuthenticationException, paramiko.BadHostKeyException)
    ):
        return False
    return isinstance(exc, (socket.timeout, OSError, paramiko.SSHException))


def _transport_breaker_settings(db: Session) -> Tuple[int, int]:
    """(failure_threshold, cooldown_seconds) from global settings, with defaults."""
    settings = db.query(GlobalConnectionSettings).first()
    threshold = (
        settings.transport_failure_threshold
        if settings and settings.transport_failure_threshold
        else _DEFAULT_TRANSPORT_FAILURE_THRESHOLD
    )
    cooldown = (
        settings.transport_cooldown_seconds
        if settings and settings.transport_cooldown_seconds
        else _DEFAULT_TRANSPORT_COOLDOWN_SECONDS
    )
    return threshold, cooldown


def connection_timeout_for(db: Session) -> int:
    """Configured SSH connection timeout (seconds), falling back to the default.
    Shared so the SFTP path honors the same tunable instead of a hardcoded value."""
    settings = db.query(GlobalConnectionSettings).first()
    return (
        settings.connection_timeout
        if settings and settings.connection_timeout
        else _DEFAULT_CONNECTION_TIMEOUT
    )


def _ensure_metadata(db: Session, system: System) -> SystemMetadata:
    md = system.system_metadata
    if md is None:
        md = SystemMetadata(system_id=system.id)
        db.add(md)
        system.system_metadata = md
    return md


def is_host_cooling_down(
    db: Session, system: System, *, now: Optional[datetime] = None
) -> Optional[float]:
    """Seconds remaining in an active cooldown, or ``None`` if the host is not
    cooling down (never tripped, or the window elapsed)."""
    now = now or datetime.utcnow()
    md = system.system_metadata
    if md is None or md.transport_cooldown_until is None:
        return None
    if md.transport_cooldown_until <= now:
        return None
    return (md.transport_cooldown_until - now).total_seconds()


def raise_if_cooling_down(
    db: Session,
    system: System,
    *,
    bypass: bool = False,
    now: Optional[datetime] = None,
) -> None:
    """Fast-fail with :class:`HostCoolingDownError` if the host is cooling down.
    ``bypass=True`` (explicit operator recheck) skips the gate entirely."""
    if bypass:
        return
    remaining = is_host_cooling_down(db, system, now=now)
    if remaining is not None:
        md = system.system_metadata
        raise HostCoolingDownError(
            system, remaining, md.last_transport_error if md else None
        )


def record_transport_failure(
    db: Session, system: System, error: str, *, now: Optional[datetime] = None
) -> None:
    """Count one transport failure; open the cooldown once the threshold is hit.
    Commits so concurrent/subsequent callers (and other sessions) observe it."""
    now = now or datetime.utcnow()
    threshold, cooldown = _transport_breaker_settings(db)
    md = _ensure_metadata(db, system)
    md.transport_failures = (md.transport_failures or 0) + 1
    md.last_transport_error = (str(error) or "")[:_MAX_TRANSPORT_ERROR_LEN] or None
    if md.transport_failures >= threshold:
        md.transport_cooldown_until = now + timedelta(seconds=cooldown)
        logger.warning(
            "Host %s entered transport cooldown after %d consecutive failures "
            "(until %s): %s",
            system.hostname,
            md.transport_failures,
            md.transport_cooldown_until,
            md.last_transport_error,
        )
    db.commit()


def record_transport_success(db: Session, system: System) -> None:
    """Clear the breaker after a successful connect (or a reachable-but-auth-failed
    connect). No-op/commit-free when there is nothing to clear."""
    md = system.system_metadata
    if md is None:
        return
    if md.transport_failures or md.transport_cooldown_until or md.last_transport_error:
        md.transport_failures = 0
        md.transport_cooldown_until = None
        md.last_transport_error = None
        db.commit()


# Auth failures / host-key mismatches reach the host, so they reset the breaker
# the same way a success does.
record_transport_reachable = record_transport_success


class HostKeyPromptPolicy(paramiko.MissingHostKeyPolicy):
    """TOFU (trust-on-first-use) host key policy (PRA-119).

    If we've never seen a host key for this system, accept and persist it
    as verified. On subsequent connections the key is pre-loaded from the
    DB as a trusted host key; this policy is only consulted when no key
    is known yet. A key *change* is detected in _store_host_key() after
    the connection completes, because paramiko's RejectPolicy rejects
    changed keys before we even get here.
    """

    def __init__(self, db: Session, system: System):
        self.db = db
        self.system = system

    def missing_host_key(self, client, hostname, key):
        key_type = key.get_name()
        public_key = key.get_base64()
        fingerprint = hashlib.sha256(key.asbytes()).hexdigest()

        existing_key = (
            self.db.query(SSHHostKey)
            .filter(SSHHostKey.system_id == self.system.id)
            .first()
        )

        if existing_key:
            # Should be rare — normally the known key is pre-loaded before
            # connect(). If we end up here, the key changed; reject for safety.
            if existing_key.public_key != public_key:
                raise SSHConnectionError(
                    f"Host key MISMATCH for {hostname}. "
                    f"Stored fingerprint: {existing_key.fingerprint[:16]}… "
                    f"Server offered: {fingerprint[:16]}… "
                    "Review and delete the stored key in SSH Security > Host Keys to re-trust."
                )
            existing_key.last_seen = datetime.utcnow()
            self.db.commit()
            client.get_host_keys().add(hostname, key_type, key)
            return

        # TOFU — capture and trust on first use
        host_key = SSHHostKey(
            system_id=self.system.id,
            hostname=self.system.hostname,
            key_type=key_type,
            public_key=public_key,
            fingerprint=fingerprint,
            verified=True,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        self.db.add(host_key)
        self.db.commit()
        logger.info(
            "TOFU: captured host key for %s (fingerprint=%s)",
            self.system.hostname,
            fingerprint[:16],
        )
        # Register with client so paramiko completes the handshake
        client.get_host_keys().add(hostname, key_type, key)


def configure_host_key_policy(
    client: paramiko.SSHClient, db: Session, system: System
) -> None:
    """Install the correct Paramiko missing-host-key policy for ``system`` and
    preload any verified host key (PRA-245).

    This is the single host-key verification path shared by :class:`SSHService`,
    browser sessions (``session_service``), and SFTP file transfers
    (``file_transfer_service``) so none of them can silently accept an
    attacker-controlled host key:

    - verification required + a verified key is stored -> ``RejectPolicy`` and
      preload the key for both hostname and IP (paramiko then rejects any
      mismatch/unknown key); an unsupported stored key type fails closed with
      :class:`SSHConnectionError`.
    - verification required + no verified key -> :class:`HostKeyPromptPolicy`
      (trust-on-first-use, capturing and verifying the first key).
    - verification explicitly disabled on a *persisted* policy -> ``AutoAddPolicy``
      (the administrator opt-out; unchanged permissive behavior).
    - **no policy at all** -> verification required. A missing policy
      relationship is absent security configuration, not an opt-out, so it fails
      closed through the same verified-key / first-use-capture path above and can
      never reach ``AutoAddPolicy``.
    """
    security_policy = system.ssh_security_policy

    # Only a persisted policy row that *explicitly* clears the flag may waive
    # host-key verification. A ``None`` relationship (e.g. a system created
    # before its default policy was attached) is absent security configuration,
    # not an administrator opt-out, so it must not be conflated with one; an
    # unset/NULL flag is likewise not an opt-out. Both fall through to the
    # verifying path below.
    if (
        security_policy is not None
        and security_policy.require_host_key_verification is False
    ):
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return

    known_host = db.query(SSHHostKey).filter(SSHHostKey.system_id == system.id).first()
    if known_host and known_host.verified:
        # Reject anything that doesn't match the preloaded verified key.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            key_data = base64.b64decode(known_host.public_key)
            if known_host.key_type == "ssh-rsa":
                key = paramiko.RSAKey(data=key_data)
            elif known_host.key_type == "ssh-ed25519":
                key = paramiko.Ed25519Key(data=key_data)
            elif known_host.key_type == "ssh-dss":
                key = paramiko.DSSKey(data=key_data)
            else:
                logger.warning("Unsupported key type: %s", known_host.key_type)
                raise SSHConnectionError(
                    f"Unsupported host key type: {known_host.key_type}"
                )

            client.get_host_keys().add(system.hostname, known_host.key_type, key)
            client.get_host_keys().add(system.ip_address, known_host.key_type, key)
            logger.info("Added verified host key for %s", system.hostname)
        except Exception as e:
            logger.error("Error loading host key for %s: %s", system.hostname, str(e))
            raise SSHConnectionError(
                f"Error loading host key for {system.hostname}: {str(e)}"
            ) from e
    else:
        # No verified host key yet -> TOFU capture on first use.
        client.set_missing_host_key_policy(HostKeyPromptPolicy(db, system))


# --------------------------------------------------------------------------- #
# Stored credential private keys                                              #
#                                                                             #
# One loader for every path that authenticates with a credential's stored     #
# private key, so command execution, browser sessions, SFTP and lifecycle     #
# work accept the same formats and fail the same way. Modern OpenSSH installs #
# default to Ed25519, so an RSA-only reader rejects the key most operators    #
# generate.                                                                   #
#                                                                             #
# Failures carry fixed, sanitized text. Neither the key body, the passphrase, #
# nor the underlying parser message is propagated or logged: a parser message #
# can quote the bytes it failed on, and these strings reach audit rows and    #
# operator-facing errors.                                                     #
# --------------------------------------------------------------------------- #

# Tried in order. Ed25519 and ECDSA reject a key of the wrong algorithm and RSA
# is last, so the first parser that succeeds owns the key. DSA is deliberately
# absent: it is obsolete, OpenSSH refuses it by default, and paramiko's DSSKey
# accepts an RSA key without checking the embedded algorithm name, so including
# it would let it claim keys it does not own.
_CREDENTIAL_KEY_CLASSES = (
    paramiko.Ed25519Key,
    paramiko.ECDSAKey,
    paramiko.RSAKey,
)

_SUPPORTED_KEY_SUMMARY = "an Ed25519, ECDSA (nistp256/384/521) or RSA private key"

# Algorithm-appropriate strength floors. RSA security scales with modulus size,
# so it carries a bit floor. An ECDSA curve and Ed25519 carry their strength in
# the algorithm itself and must not be measured against the RSA rule.
_MIN_RSA_KEY_BITS = 2048
_MIN_ECDSA_KEY_BITS = 256

_OPENSSH_KEY_MAGIC = b"openssh-key-v1\x00"

_PEM_BEGIN = re.compile(r"^-{5}BEGIN ?(?P<tag>[A-Z0-9 ]*?) ?PRIVATE KEY-{5}$")
_PEM_END = re.compile(r"^-{5}END ?[A-Z0-9 ]*? ?PRIVATE KEY-{5}$")

# PEM envelopes that cannot carry a usable key, mapped to the name to report.
# An empty tag is a bare PKCS#8 container, which paramiko cannot read.
_UNUSABLE_PEM_TAGS = {"DSA": "DSA", "": "PKCS#8", "ENCRYPTED": "PKCS#8"}


class SSHKeyError(SSHConnectionError):
    """A stored credential private key cannot be used.

    Subclasses :class:`SSHConnectionError` so existing callers keep working,
    while callers that care can tell an unusable key from a transport problem.
    """


def _read_ssh_string(blob: bytes, offset: int) -> Tuple[bytes, int]:
    """Read one length-prefixed field of an OpenSSH key blob."""
    if offset + 4 > len(blob):
        raise ValueError("truncated field")
    (length,) = struct.unpack(">I", blob[offset : offset + 4])
    end = offset + 4 + length
    if end > len(blob):
        raise ValueError("truncated field")
    return blob[offset + 4 : end], end


def _openssh_container(body: str) -> Optional[Tuple[str, bool]]:
    """``(algorithm name, encrypted)`` from an ``OPENSSH PRIVATE KEY`` body.

    The container's header and first public key are never encrypted, so both
    facts are readable even when the private half is not. Returns ``None`` when
    the container cannot be parsed; the caller then treats the key as
    unreadable rather than guessing.
    """
    try:
        blob = base64.b64decode("".join(body.split()), validate=True)
    except ValueError:
        return None
    if not blob.startswith(_OPENSSH_KEY_MAGIC):
        return None
    try:
        cipher, offset = _read_ssh_string(blob, len(_OPENSSH_KEY_MAGIC))
        for _ in range(2):  # kdfname, kdfoptions
            _, offset = _read_ssh_string(blob, offset)
        # Skip the 4-byte key count; the first public key follows it, and its
        # own first field is the algorithm name.
        public_key, _ = _read_ssh_string(blob, offset + 4)
        algorithm, _ = _read_ssh_string(public_key, 0)
        return algorithm.decode("ascii"), cipher != b"none"
    except (ValueError, struct.error):
        return None


def _describe_private_key(key_text: str) -> Tuple[Optional[str], bool, bool]:
    """``(unusable format name, encrypted, traditional PEM)`` from the envelope.

    The format name is ``None`` for anything worth handing to the parsers,
    either because it is supported or because only a parser can tell that it is
    broken. Knowing up front that a key is encrypted is what lets a wrong
    passphrase be reported as such instead of as an unreadable key, and the
    traditional-PEM flag is what keeps the compatibility path in
    :func:`load_credential_private_key` to the one envelope that needs it.
    """
    lines = key_text.splitlines()
    for index, line in enumerate(lines):
        match = _PEM_BEGIN.match(line.strip())
        if not match:
            continue
        tag = match.group("tag").strip()
        if tag != "OPENSSH":
            # A classic PEM body declares its encryption in the header line
            # directly after the BEGIN marker.
            encrypted = tag == "ENCRYPTED" or any(
                header.strip().startswith("Proc-Type:") and "ENCRYPTED" in header
                for header in lines[index + 1 : index + 3]
            )
            unusable = _UNUSABLE_PEM_TAGS.get(tag)
            return unusable, encrypted, unusable is None
        body = []
        for following in lines[index + 1 :]:
            if _PEM_END.match(following.strip()):
                break
            body.append(following.strip())
        container = _openssh_container("".join(body))
        if container is None:
            return None, False, False
        algorithm, encrypted = container
        return ("DSA" if algorithm == "ssh-dss" else None), encrypted, False
    if key_text.lstrip().startswith("PuTTY-User-Key-File"):
        return "PuTTY PPK", False, False
    return None, False, False


def _enforce_key_strength(key: paramiko.PKey, minimum_rsa_bits: Optional[int]) -> None:
    """Apply the strength rule that belongs to this key's algorithm.

    ``minimum_rsa_bits`` is the operator-configured floor. It can only raise the
    built-in RSA floor; a configured value below it is not an opt-out.
    """
    name = key.get_name()
    bits = key.get_bits()
    if name.startswith(("ssh-rsa", "rsa-sha2")):
        floor = max(minimum_rsa_bits or 0, _MIN_RSA_KEY_BITS)
        if bits < floor:
            raise SSHKeyError(
                f"The stored RSA private key is {bits} bits, below the "
                f"required minimum of {floor} bits."
            )
    elif name.startswith("ecdsa-") and bits < _MIN_ECDSA_KEY_BITS:
        raise SSHKeyError(
            f"The stored ECDSA private key uses a {bits}-bit curve, below the "
            f"required minimum of {_MIN_ECDSA_KEY_BITS} bits."
        )


def _parse_private_key(
    key_text: str, passphrase: Optional[str]
) -> Tuple[Optional[paramiko.PKey], bool]:
    """``(key, encrypted)`` from the first supported parser that accepts the key.

    ``key`` is ``None`` when none of them did; ``encrypted`` reports whether a
    parser refused because the key needs a passphrase it was not given.
    """
    encrypted = False
    for key_class in _CREDENTIAL_KEY_CLASSES:
        try:
            return (
                key_class.from_private_key(
                    io.StringIO(key_text), password=passphrase or None
                ),
                encrypted,
            )
        except paramiko.PasswordRequiredException:
            encrypted = True
        except Exception:  # pylint: disable=broad-except
            # Each parser rejects the algorithms it does not own, and a
            # malformed key can surface as almost any exception type from the
            # crypto library underneath. Neither is fatal until all have tried.
            continue
    return None, encrypted


def _unwrap_traditional_pem(key_text: str, passphrase: str) -> Optional[str]:
    """Re-encode an encrypted traditional PEM with its envelope removed.

    Paramiko decrypts a ``Proc-Type: 4,ENCRYPTED`` body but hands the result on
    with its block padding still attached, which a strict DER parser rejects.
    The passphrase is correct in that case and only the envelope handling is
    at fault, so the key is decrypted here instead and Paramiko is given the
    same key with no envelope encryption. Returns ``None`` when the passphrase
    does not open it or the body is not a key.

    The plaintext lives only as long as the load. It is never logged,
    persisted, or placed in an error, and the caller holds the parsed key
    rather than this text.
    """
    try:
        unwrapped = serialization.load_pem_private_key(
            key_text.encode(), password=passphrase.encode()
        )
        return unwrapped.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
    except Exception:  # pylint: disable=broad-except
        # A wrong passphrase, an unsupported algorithm and a corrupt body all
        # end here, and all of them mean the caller reports its own failure.
        return None


def load_credential_private_key(
    key_text: Optional[str],
    *,
    passphrase: Optional[str] = None,
    minimum_rsa_bits: Optional[int] = None,
) -> paramiko.PKey:
    """Load a stored credential private key, or raise :class:`SSHKeyError`.

    Accepts the Ed25519, ECDSA and RSA private keys OpenSSH writes, in both the
    ``OPENSSH PRIVATE KEY`` container and the older PEM envelopes. An encrypted
    key loads only when ``passphrase`` unlocks it.
    """
    if not key_text or not key_text.strip():
        raise SSHKeyError("No SSH private key is stored for this credential.")

    unusable, encrypted, traditional_pem = _describe_private_key(key_text)
    if unusable:
        raise SSHKeyError(
            f"The stored SSH private key is in {unusable} format, which is not "
            f"supported. Use {_SUPPORTED_KEY_SUMMARY}."
        )

    key, needs_passphrase = _parse_private_key(key_text, passphrase)
    encrypted = encrypted or needs_passphrase

    if key is None and encrypted and passphrase and traditional_pem:
        unwrapped = _unwrap_traditional_pem(key_text, passphrase)
        if unwrapped is not None:
            key, _ = _parse_private_key(unwrapped, None)

    if key is not None:
        _enforce_key_strength(key, minimum_rsa_bits)
        return key

    if encrypted and passphrase:
        raise SSHKeyError(
            "The stored SSH private key could not be decrypted with the stored "
            "passphrase."
        )
    if encrypted:
        raise SSHKeyError(
            "The stored SSH private key is encrypted. Store its passphrase "
            "alongside the key as 'ssh_passphrase' in the secrets service."
        )
    raise SSHKeyError(
        f"The stored SSH private key could not be read. Use {_SUPPORTED_KEY_SUMMARY}."
    )


class SSHService:  # pylint: disable=too-many-instance-attributes
    """Service for managing SSH connections to remote systems."""

    def __init__(self, db: Session):
        """Initialize the SSH service."""
        self.db = db
        self._connection_pool = {}  # hostname -> (client, last_used_time)
        self._connection_lock = threading.RLock()

        # Load tunables from DB (PRA-62), fall back to defaults
        settings = db.query(GlobalConnectionSettings).first()
        self._pool_cleanup_interval = (
            settings.pool_cleanup_interval if settings else 300
        )
        self._connection_timeout = settings.connection_timeout if settings else 10
        self._max_pool_size = settings.max_pool_size if settings else 50
        self._max_connection_idle_time = settings.max_idle_time if settings else 600
        self._default_ssh_port = settings.default_ssh_port if settings else 22
        self._unreachable_threshold = settings.unreachable_threshold if settings else 2
        self._last_pool_cleanup_at = time.time()

    def _maybe_cleanup_idle_connections(self):
        """Opportunistically clean up this instance's pool.

        ``SSHService`` is request/service scoped in most call paths. Starting one
        daemon cleanup thread per instance leaks threads under reconcile-heavy
        workloads, eventually starving Paramiko with ``can't start new thread``.
        """
        now = time.time()
        if now - self._last_pool_cleanup_at < self._pool_cleanup_interval:
            return
        self._last_pool_cleanup_at = now
        try:
            self._remove_idle_connections()
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error cleaning up idle connections: %s", str(e))

    def _remove_idle_connections(self):
        """Remove idle connections from the pool."""
        current_time = time.time()
        with self._connection_lock:
            hostnames_to_remove = []
            for hostname, (client, last_used_time) in self._connection_pool.items():
                if current_time - last_used_time > self._max_connection_idle_time:
                    try:
                        client.close()
                        logger.info("Closed idle connection to %s", hostname)
                    except Exception as e:  # pylint: disable=broad-except
                        logger.error(
                            "Error closing connection to %s: %s", hostname, str(e)
                        )
                    hostnames_to_remove.append(hostname)

            for hostname in hostnames_to_remove:
                del self._connection_pool[hostname]

            logger.info(
                "Cleaned up %d idle connections. Pool size: %d",
                len(hostnames_to_remove),
                len(self._connection_pool),
            )

    # PRA-342: deterministic client teardown so failed connects/commands and
    # ephemeral (reconcile/provisioning) SSHService instances never orphan a
    # Paramiko client — which showed up as long-lived `sshd: praxis@notty`
    # sessions piling up on managed hosts.
    def _close_client_quietly(
        self, client: paramiko.SSHClient, hostname: str, *, reason: str
    ) -> None:
        """Close a Paramiko client (transport + socket), swallowing errors."""
        try:
            client.close()
            logger.info("Discarded SSH client to %s (%s)", hostname, reason)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning(
                "Error discarding SSH client to %s (%s): %s", hostname, reason, e
            )

    def __enter__(self) -> "SSHService":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Ephemeral SSHService instances (reconcile, host provisioning) MUST close
        # their pool here; remote lifecycle correctness cannot depend on idle
        # cleanup that only runs on a still-referenced instance.
        try:
            self.close_all_connections()
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Error closing SSH connection pool on exit: %s", e)

    def _try_ca_cert_auth(
        self,
        client: paramiko.SSHClient,
        system: System,
        credential: Credential,
        ssh_port: int,
        disabled_algorithms: Optional[Dict[str, List[str]]] = None,
    ) -> bool:
        """PRA-44: Attempt Vault-signed SSH user cert auth.

        Generates a throwaway RSA keypair, has Vault sign the public key as
        a short-lived user certificate for the target principal, then uses
        paramiko's connect(pkey=..., ) where pkey carries the signed cert
        via the .load_certificate() helper. Returns True on success.
        """
        from ..db.models import SSHIdentitySettings

        settings = self.db.query(SSHIdentitySettings).first()
        ttl = settings.user_cert_ttl_seconds if settings else 300

        # Resolve the target username. Prefer the global default principal,
        # then the credential's own username, then fall back to the username
        # stored inside the Vault secret for vault-type credentials.
        principal = (settings.default_principal if settings else None) or (
            credential.username or None
        )
        if not principal and credential.type == "vault" and credential.vault_kv_path:
            try:
                secret = VaultService(self.db).read_secret(credential.vault_kv_path)
                if secret:
                    principal = secret.get("username")
            except Exception:  # pylint: disable=broad-except
                pass
        if not principal:
            raise SSHConnectionError("No principal available for CA cert signing")

        key_id = f"praxis-{system.hostname}-{int(time.time())}"

        # Generate ephemeral RSA keypair (in-memory only)
        pkey = paramiko.RSAKey.generate(2048)
        public_key_openssh = f"{pkey.get_name()} {pkey.get_base64()}"

        vault_service = VaultService(self.db)
        signed_cert = vault_service.sign_ssh_user_cert(
            public_key=public_key_openssh,
            principal=principal,
            ttl_seconds=ttl,
            key_id=key_id,
        )

        # Attach the signed cert to the private key
        pkey.load_certificate(signed_cert)

        connect_kwargs: Dict[str, Any] = {
            "hostname": system.ip_address,
            "port": ssh_port,
            "username": principal,
            "pkey": pkey,
            "timeout": self._connection_timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if disabled_algorithms:
            connect_kwargs["disabled_algorithms"] = disabled_algorithms
        client.connect(**connect_kwargs)
        logger.info("CA cert auth succeeded for %s as %s", system.hostname, principal)
        self._on_connected(system, client, principal)
        return True

    def validate_ssh_key(self, ssh_key: str, passphrase: Optional[str] = None) -> bool:
        """True when ``ssh_key`` is a usable credential private key.

        Applies the same format and algorithm-appropriate strength rules as the
        connection path, at the built-in floors.
        """
        try:
            load_credential_private_key(ssh_key, passphrase=passphrase)
            return True
        except SSHConnectionError as exc:
            # The message is already sanitized; it carries no key material.
            logger.warning("Rejected stored SSH private key: %s", exc)
            return False

    def _get_known_hosts_for_system(self, system_id: int) -> Optional[SSHHostKey]:
        """Get known host keys for a system from the database."""
        return (
            self.db.query(SSHHostKey).filter(SSHHostKey.system_id == system_id).first()
        )

    def _store_host_key(self, system: System, transport: paramiko.Transport) -> None:
        """Store or update host key for a system (PRA-119 TOFU).

        On first sight: capture and mark verified (trust on first use).
        On subsequent sights: if the key changed, flip verified=False and
        fire a host_key_changed notification so an admin can review. The
        next connect attempt will be rejected by `RejectPolicy` until the
        admin either deletes the stored key (to re-TOFU) or re-verifies.
        """
        try:
            server_key = transport.get_server_key()
            if server_key is None:
                # Some paramiko code paths don't expose the server key on the
                # transport (e.g. when auth completed via a pre-loaded host key
                # already in the client). Nothing to capture — return quietly.
                return
            key_type = server_key.get_name()
            public_key = server_key.get_base64()
            fingerprint = hashlib.sha256(server_key.asbytes()).hexdigest()

            existing_key = self._get_known_hosts_for_system(system.id)

            if existing_key:
                existing_key.last_seen = datetime.utcnow()
                if existing_key.public_key != public_key:
                    old_fingerprint = existing_key.fingerprint
                    logger.warning(
                        "Host key changed for %s (was %s, now %s)",
                        system.hostname,
                        old_fingerprint[:16],
                        fingerprint[:16],
                    )
                    existing_key.public_key = public_key
                    existing_key.fingerprint = fingerprint
                    existing_key.verified = False
                    self._notify_host_key_changed(system, old_fingerprint, fingerprint)
            else:
                # TOFU: trust the key on first sight
                host_key = SSHHostKey(
                    system_id=system.id,
                    hostname=system.hostname,
                    key_type=key_type,
                    public_key=public_key,
                    fingerprint=fingerprint,
                    verified=True,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                )
                self.db.add(host_key)
                logger.info(
                    "Captured host key for %s (TOFU, fingerprint=%s)",
                    system.hostname,
                    fingerprint[:16],
                )

            self.db.commit()
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Error storing host key for %s: %s", system.hostname, str(e))

    def _notify_host_key_changed(
        self, system: System, old_fp: str, new_fp: str
    ) -> None:
        """Fire a host_key_changed notification for admin review (PRA-119)."""
        try:
            from .notification_service import create_notification

            create_notification(
                self.db,
                type="host_key_changed",
                title=f"Host key changed: {system.hostname}",
                message=(
                    f"The SSH host key for {system.hostname} has changed. "
                    f"Old fingerprint: {old_fp[:32]}… New fingerprint: {new_fp[:32]}… "
                    "This may indicate a legitimate OS reinstall or a MITM attempt. "
                    "Review and re-verify in SSH Security > Host Keys."
                ),
                severity="warning",
            )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Failed to fire host_key_changed notification: %s", e)

    def _build_disabled_algorithms(
        self, system: System
    ) -> Optional[Dict[str, List[str]]]:
        """Translate the system's SSH policy allow-lists into paramiko's
        `disabled_algorithms` dict, which must be set pre-handshake via
        `client.connect(disabled_algorithms=...)`.

        Paramiko supports disabling by three keys: ciphers, macs, kex.
        For each policy allow-list, we disable every supported algorithm
        not present in the allow-list.
        """
        if not system.ssh_security_policy:
            return None

        policy = system.ssh_security_policy
        disabled: Dict[str, List[str]] = {}

        def _diff(allowed_csv: Optional[str], supported: List[str]) -> List[str]:
            if not allowed_csv:
                return []
            allowed = {a.strip() for a in allowed_csv.split(",") if a.strip()}
            return [s for s in supported if s not in allowed]

        sec_opts = paramiko.Transport(socket.socket()).get_security_options()
        try:
            ciphers_disabled = _diff(policy.allowed_ciphers, list(sec_opts.ciphers))
            macs_disabled = _diff(policy.allowed_macs, list(sec_opts.digests))
            kex_disabled = _diff(policy.allowed_kex, list(sec_opts.kex))
        finally:
            # Transport built on a fresh socket just to enumerate options;
            # no handshake happened, but close defensively.
            pass

        if ciphers_disabled:
            disabled["ciphers"] = ciphers_disabled
        if macs_disabled:
            disabled["macs"] = macs_disabled
        if kex_disabled:
            disabled["kex"] = kex_disabled
        return disabled or None

    def _on_connected(
        self, system: System, client: paramiko.SSHClient, username: str
    ) -> None:
        """Shared post-connect bookkeeping: host key TOFU capture + success log.

        Called from both the CA cert path and the credential fallback path
        so neither silently skips the audit trail.
        """
        # PRA-313: a successful connect clears any transport cooldown for this host.
        record_transport_success(self.db, system)

        transport = client.get_transport()
        if transport:
            try:
                transport.set_keepalive(self._connection_timeout)
            except Exception:  # pylint: disable=broad-except
                pass
            self._store_host_key(system, transport)

        self._log_security_event(
            system,
            "connection_success",
            {
                "username": username,
                "source_ip": "localhost",
                "success": True,
            },
        )
        logger.info("Successfully connected to %s as %s", system.hostname, username)

    def _log_security_event(
        self, system: System, event_type: str, details: Dict[str, Any]
    ) -> None:
        """Log a security-related event."""
        security_log = SSHSecurityLog(
            system_id=system.id,
            event_type=event_type,
            source_ip=details.get("source_ip"),
            username=details.get("username"),
            success=details.get("success", False),
            timestamp=datetime.utcnow(),
        )
        security_log.set_event_details(details)
        self.db.add(security_log)
        self.db.commit()

        # Also log to application logger
        if details.get("success", False):
            logger.info(
                "SSH Security Event: %s - System: %s - Success: %s",
                event_type,
                system.hostname,
                details.get("success", False),
            )
        else:
            logger.warning(
                "SSH Security Event: %s - System: %s - Success: %s",
                event_type,
                system.hostname,
                details.get("success", False),
            )

    def get_connection(
        self,
        system_id: int,
        force_password_auth: bool = False,
        *,
        bypass_cooldown: bool = False,
    ) -> Tuple[paramiko.SSHClient, bool]:
        """
        Get an SSH connection for the specified system.

        Args:
            system_id: target system
            force_password_auth: bypass CA cert auth and use the stored
                credential directly (used by SSH identity onboarding so it
                can deploy the CA even when ca_trust_deployed is True).
            bypass_cooldown: PRA-313 — skip the transport circuit breaker for an
                explicit operator recheck. Normal callers leave this False so a
                cooling-down host fast-fails without opening a new SSH socket.

        Returns a tuple of (ssh_client, is_new_connection)
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHConnectionError(f"System with ID {system_id} not found")

        # PRA-313: fast-fail a cooling-down host BEFORE touching the pool or
        # opening a socket. Explicit rechecks pass bypass_cooldown=True.
        raise_if_cooling_down(self.db, system, bypass=bypass_cooldown)

        hostname = system.hostname
        self._maybe_cleanup_idle_connections()

        # Onboarding path needs a fresh, non-pooled connection using
        # the stored credential only — skip the pool entirely.
        if force_password_auth:
            client = self._create_connection(system, force_password_auth=True)
            return client, True

        # Check if we have a connection in the pool
        with self._connection_lock:
            if hostname in self._connection_pool:
                client, _ = self._connection_pool[hostname]
                try:
                    # Test if the connection is still valid
                    transport = client.get_transport()
                    if transport and transport.is_active():
                        # Update the last used time
                        self._connection_pool[hostname] = (client, time.time())
                        return client, False

                    # Connection is no longer valid, remove it from the pool
                    try:
                        client.close()
                    except Exception:  # pylint: disable=broad-except
                        pass
                    del self._connection_pool[hostname]
                except Exception:  # pylint: disable=broad-except
                    # Connection is no longer valid, remove it from the pool
                    try:
                        client.close()
                    except Exception:  # pylint: disable=broad-except
                        pass
                    del self._connection_pool[hostname]

        # Create a new connection
        client = self._create_connection(system)

        # Add the connection to the pool
        with self._connection_lock:
            # Check if we need to remove connections to stay within the pool size limit
            if len(self._connection_pool) >= self._max_pool_size:
                self._remove_oldest_connection()

            self._connection_pool[hostname] = (client, time.time())

        return client, True

    def _remove_oldest_connection(self):
        """Remove the oldest connection from the pool."""
        oldest_hostname = None
        oldest_time = float("inf")

        for hostname, (client, last_used_time) in self._connection_pool.items():
            if last_used_time < oldest_time:
                oldest_time = last_used_time
                oldest_hostname = hostname

        if oldest_hostname:
            client, _ = self._connection_pool[oldest_hostname]
            try:
                client.close()
            except Exception:  # pylint: disable=broad-except
                pass
            del self._connection_pool[oldest_hostname]
            logger.info(
                "Removed oldest connection to %s to stay within pool size limit",
                oldest_hostname,
            )

    def _create_connection(  # pylint: disable=too-many-branches,too-many-statements
        self, system: System, force_password_auth: bool = False
    ) -> paramiko.SSHClient:  # pylint: disable=too-many-branches,too-many-statements
        """Create a new SSH connection to the specified system.

        If system.ca_trust_deployed is True and force_password_auth is False,
        attempts Vault CA-signed cert auth first, falling back to the stored
        credential on any failure (PRA-44).
        """
        client = paramiko.SSHClient()

        # Configure host key policy based on security settings (shared with
        # browser sessions and SFTP file transfers — PRA-245).
        configure_host_key_policy(client, self.db, system)

        # Get the credentials for the system
        credential = (
            self.db.query(Credential)
            .filter(Credential.id == system.credentials_id)
            .first()
        )
        if not credential:
            raise SSHConnectionError(
                f"Credentials not found for system {system.hostname}"
            )

        # Get the SSH port from system metadata, falling back to global default
        ssh_port = self._default_ssh_port
        if system.system_metadata and system.system_metadata.ssh_port:
            ssh_port = system.system_metadata.ssh_port

        # Translate the SSH policy allow-lists into paramiko's pre-handshake
        # disabled_algorithms dict so ciphers/MACs/KEX are actually enforced.
        disabled_algorithms = self._build_disabled_algorithms(system)

        # PRA-44: Try Vault CA-signed cert auth if the system has CA trust deployed.
        # On any failure we fall through to the existing credential-based auth.
        # PRA-234: keep the CA-cert failure detail so a later credential-auth
        # failure does not flatten both causes into a bare "Authentication
        # failed" — the CA-cert reject is often the actionable one (e.g. sshd
        # AllowUsers/AllowGroups rejecting the cert principal).
        ca_auth_error: Optional[str] = None
        if system.ca_trust_deployed and not force_password_auth:
            try:
                if self._try_ca_cert_auth(
                    client, system, credential, ssh_port, disabled_algorithms
                ):
                    return client
            except Exception as e:  # pylint: disable=broad-except
                ca_auth_error = str(e)
                logger.warning(
                    "CA cert auth failed for %s, falling back to credential auth: %s",
                    system.hostname,
                    e,
                )
                # PRA-342: the failed cert connect can leave a live transport/socket
                # on this client; close it before the credential-auth path opens a
                # new one, or the CA-cert transport orphans an sshd session. close()
                # clears the transport but keeps host-key config, so reconnect is OK.
                self._close_client_quietly(
                    client, system.hostname, reason="ca_cert_fallback"
                )

        try:
            # All credentials are Vault-backed — fetch secret at connection time
            if not credential.vault_path:
                raise SSHConnectionError("Credential has no Vault path configured")

            vault_service = VaultService(self.db)
            secret_data = vault_service.read_secret(credential.vault_path)

            if not secret_data:
                raise SSHConnectionError(
                    f"Failed to retrieve credentials from Vault at {credential.vault_path}"
                )

            username = credential.username or secret_data.get("username")

            if credential.auth_method == "ssh_key":
                ssh_key_data = secret_data.get("ssh_key")
                if not ssh_key_data:
                    raise SSHConnectionError("SSH key not found in Vault secret")

                # A configured policy raises the RSA floor; without one the
                # loader still applies its own built-in minimum.
                minimum_rsa_bits = (
                    system.ssh_security_policy.minimum_key_size
                    if system.ssh_security_policy
                    else None
                )
                pkey = load_credential_private_key(
                    ssh_key_data,
                    passphrase=secret_data.get("ssh_passphrase"),
                    minimum_rsa_bits=minimum_rsa_bits,
                )
                connect_kwargs: Dict[str, Any] = {
                    "hostname": system.ip_address,
                    "port": ssh_port,
                    "username": username,
                    "pkey": pkey,
                    "timeout": self._connection_timeout,
                }
                if disabled_algorithms:
                    connect_kwargs["disabled_algorithms"] = disabled_algorithms
                client.connect(**connect_kwargs)
            elif credential.auth_method == "password":
                password = secret_data.get("password")
                if not password:
                    raise SSHConnectionError("Password not found in Vault secret")

                connect_kwargs = {
                    "hostname": system.ip_address,
                    "port": ssh_port,
                    "username": username,
                    "password": password,
                    "timeout": self._connection_timeout,
                }
                if disabled_algorithms:
                    connect_kwargs["disabled_algorithms"] = disabled_algorithms
                client.connect(**connect_kwargs)
            else:
                raise SSHConnectionError(
                    f"Unsupported auth method: {credential.auth_method}"
                )

            self._on_connected(system, client, username)
            return client
        except paramiko.AuthenticationException as exc:
            # PRA-313: an auth failure means the transport REACHED the host (and is
            # fast) — reset the breaker rather than trip it.
            record_transport_reachable(self.db, system)
            self._log_security_event(
                system,
                "auth_failure",
                {
                    "username": credential.username,
                    "source_ip": "localhost",
                    "success": False,
                    "error": str(exc),
                    "ca_cert_auth_error": ca_auth_error,
                },
            )
            # Preserve the CA-cert auth cause when present; it is usually the
            # actionable one and would otherwise be silently dropped (PRA-234).
            msg = f"Authentication failed for {system.hostname}"
            if ca_auth_error:
                msg = f"{msg} (CA cert auth also failed: {ca_auth_error})"
            self._close_client_quietly(client, system.hostname, reason="auth_failed")
            raise SSHConnectionError(msg) from exc
        except paramiko.SSHException as e:
            # PRA-313: banner/protocol failures trip the breaker; a host-key
            # mismatch (BadHostKeyException) means the host is reachable, so reset.
            if is_transport_failure(e):
                record_transport_failure(self.db, system, str(e))
            else:
                record_transport_reachable(self.db, system)
            self._log_security_event(
                system,
                "connection_error",
                {
                    "username": credential.username,
                    "source_ip": "localhost",
                    "success": False,
                    "error": str(e),
                },
            )
            self._close_client_quietly(client, system.hostname, reason="ssh_error")
            raise SSHConnectionError(
                f"SSH error for {system.hostname}: {str(e)}"
            ) from e
        except socket.timeout as exc:
            record_transport_failure(self.db, system, str(exc) or "connection timeout")
            self._log_security_event(
                system,
                "connection_timeout",
                {
                    "username": credential.username,
                    "source_ip": "localhost",
                    "success": False,
                    "error": str(exc),
                },
            )
            self._close_client_quietly(client, system.hostname, reason="conn_timeout")
            raise SSHConnectionError(
                f"Connection timeout for {system.hostname}"
            ) from exc
        except socket.error as e:
            record_transport_failure(self.db, system, str(e))
            self._log_security_event(
                system,
                "connection_error",
                {
                    "username": credential.username,
                    "source_ip": "localhost",
                    "success": False,
                    "error": str(e),
                },
            )
            self._close_client_quietly(client, system.hostname, reason="socket_error")
            raise SSHConnectionError(
                f"Socket error for {system.hostname}: {str(e)}"
            ) from e
        except Exception as e:  # pylint: disable=broad-except
            # PRA-313: only genuine transport failures trip the breaker — a
            # manually-raised SSHConnectionError (no Vault path, no credential,
            # etc.) never contacted the host and must not open a cooldown.
            if is_transport_failure(e):
                record_transport_failure(self.db, system, str(e))
            self._log_security_event(
                system,
                "connection_error",
                {
                    "username": credential.username,
                    "source_ip": "localhost",
                    "success": False,
                    "error": str(e),
                },
            )
            self._close_client_quietly(client, system.hostname, reason="connect_error")
            raise SSHConnectionError(
                f"Error connecting to {system.hostname}: {str(e)}"
            ) from e

    def close_connection(self, system_id: int) -> bool:
        """Close the SSH connection for the specified system."""
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHConnectionError(f"System with ID {system_id} not found")

        hostname = system.hostname

        with self._connection_lock:
            if hostname in self._connection_pool:
                client, _ = self._connection_pool[hostname]
                try:
                    client.close()
                    logger.info("Closed connection to %s", hostname)
                except Exception as e:  # pylint: disable=broad-except
                    logger.error("Error closing connection to %s: %s", hostname, str(e))

                del self._connection_pool[hostname]
                return True

        return False

    def close_all_connections(self, scope_system_ids=None) -> int:
        """Close all SSH connections in the pool.

        PRA-281: ``scope_system_ids`` (``None`` = tenant-wide admin) restricts the
        close to connections for in-scope systems, so a scoped caller never tears
        down an out-of-scope host's pooled connection. The pool is keyed by
        hostname, so scope is resolved to the in-scope hostnames first.
        """
        allowed_hostnames = None
        if scope_system_ids is not None:
            if not scope_system_ids:
                return 0
            allowed_hostnames = {
                row[0]
                for row in self.db.query(System.hostname)
                .filter(System.id.in_(scope_system_ids))
                .all()
            }

        closed_count = 0
        with self._connection_lock:
            for hostname in list(self._connection_pool.keys()):
                if allowed_hostnames is not None and hostname not in allowed_hostnames:
                    continue
                client, _ = self._connection_pool[hostname]
                try:
                    client.close()
                    logger.info("Closed connection to %s", hostname)
                    closed_count += 1
                except Exception as e:  # pylint: disable=broad-except
                    logger.error("Error closing connection to %s: %s", hostname, str(e))
                del self._connection_pool[hostname]

        return closed_count

    def test_connection(
        self, system_id: int, *, bypass_cooldown: bool = False
    ) -> Dict[str, Any]:
        """
        Test the SSH connection to the specified system.

        ``bypass_cooldown`` (PRA-313): an explicit operator recheck ignores the
        transport circuit breaker so a cooling-down host can be retried and, on
        success, have its cooldown cleared.

        Returns a dictionary with connection status information.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHConnectionError(f"System with ID {system_id} not found")

        start_time = time.time()
        result = {
            "system_id": system_id,
            "hostname": system.hostname,
            "ip_address": system.ip_address,
            "status": "failed",
            "message": "",
            "response_time_ms": 0,
            "tested_at": datetime.utcnow().isoformat(),
        }

        try:
            # Get a connection from the pool or create a new one
            client, _ = self.get_connection(system_id, bypass_cooldown=bypass_cooldown)
        except SSHConnectionError as e:
            # PRA-322: keep auth (reachable) distinct from transport (offline).
            self._record_connect_failure(system, e)
            if isinstance(e, HostCoolingDownError):
                result["status"] = "failed"
                result["message"] = str(e)
            elif "Authentication failed" in str(e):
                result["status"] = "warning"
                result["message"] = str(e)
            else:
                result["status"] = "failed"
                result["message"] = str(e)
            end_time = time.time()
            result["response_time_ms"] = int((end_time - start_time) * 1000)
            return result

        # Connected => reachable.
        self._update_system_connection_status(system, "connected")
        try:
            # Bounded test command so a wedged host can't hang the health check.
            exit_code, output, error, _ = self._run_bounded_command(
                client,
                "echo 'Connection test successful'",
                wall_timeout=self._connection_timeout,
            )
            if exit_code != 0 or error.strip():
                result["status"] = "warning"
                result["message"] = (
                    "Connection established but command returned error: {}".format(  # pylint:disable=consider-using-f-string
                        error.strip() or f"exit {exit_code}"
                    )
                )
            else:
                result["status"] = "success"
                result["message"] = output.strip()
        except SSHCommandTimeout as e:
            # Reachable but the trivial test command wedged — drop the client, do
            # NOT mark the host Unreachable.
            self.close_connection(system_id)
            result["status"] = "warning"
            result["message"] = str(e)
        except Exception as e:  # pylint: disable=broad-except
            result["status"] = "warning"
            result["message"] = f"Command error: {str(e)}"

        # Calculate response time
        end_time = time.time()
        result["response_time_ms"] = int((end_time - start_time) * 1000)

        return result

    def _update_system_connection_status(self, system: System, status: str) -> None:
        """
        Update the connection status in the system metadata and update system status.

        If connection status is 'warning' or 'disconnected', system status is set to 'Inactive'.
        After UNREACHABLE_THRESHOLD consecutive failures, status becomes 'Unreachable' (PRA-112).
        If connection status is 'connected', system status is set to 'Active' and counter resets.
        """
        # PRA-112 / PRA-62: Threshold from global settings
        UNREACHABLE_THRESHOLD = self._unreachable_threshold

        # Get or create system metadata
        metadata = system.system_metadata
        if not metadata:
            metadata = SystemMetadata(system_id=system.id)
            self.db.add(metadata)
            system.system_metadata = metadata

        # PRA-344: remember the pre-update connection state. If THIS SSH path is
        # the first to move the host back online (offline -> connected), we emit
        # the recovery alert below — previously only the health-check path did, so
        # a package scan / command / file transfer could silently consume the
        # transition and no recovery alert ever fired.
        previous_status = metadata.connection_status

        # Update connection status and last connection time
        metadata.connection_status = status
        metadata.last_connection = datetime.utcnow()

        # Update system status based on connection status
        if status == "connected":
            metadata.consecutive_failures = 0
            system.status = "Active"
            logger.info(
                "System %s set to Active status due to successful connection",
                system.hostname,
            )
        elif status == "auth_failed":
            # PRA-322: transport reached the host but authentication was rejected
            # (wrong credentials/cert). The host is REACHABLE, so this must be kept
            # distinct from "offline": clear any stale unreachable state and do NOT
            # count toward the Unreachable threshold. Status reflects that Praxis
            # cannot currently manage it, without falsely claiming it is down.
            metadata.consecutive_failures = 0
            metadata.connection_status = "auth_failed"
            if system.status == "Unreachable":
                system.status = "Inactive"
            logger.info(
                "System %s authentication failed (reachable; not marking Unreachable)",
                system.hostname,
            )
        elif status in ["warning", "disconnected", "error"]:
            metadata.consecutive_failures = (metadata.consecutive_failures or 0) + 1
            if metadata.consecutive_failures >= UNREACHABLE_THRESHOLD:
                system.status = "Unreachable"
                metadata.connection_status = "unreachable"
                logger.warning(
                    "System %s marked Unreachable after %d consecutive failures",
                    system.hostname,
                    metadata.consecutive_failures,
                )
            else:
                system.status = "Inactive"
                logger.info(
                    "System %s set to Inactive (failure %d/%d)",
                    system.hostname,
                    metadata.consecutive_failures,
                    UNREACHABLE_THRESHOLD,
                )

        self.db.commit()

        # PRA-344: after host state is committed, emit a recovery alert if this
        # update brought the host back online. Centralized in notification_service
        # and shared with HealthService so recovery fires regardless of which path
        # reconnects first. The helper is idempotent (no-op unless offline ->
        # connected) and isolates alert failures from this host-state update.
        # Lazy import mirrors the existing create_notification usage in this file.
        from .notification_service import notify_host_recovered

        notify_host_recovered(
            self.db, system, previous_status, metadata.connection_status
        )

    def test_all_connections(self, scope_system_ids=None) -> List[Dict[str, Any]]:
        """
        Test connections to all systems (both Active and Inactive).

        Returns a list of dictionaries with connection status information.
        System status will be updated based on connection results:
        - If connection is successful, system status will be set to Active
        - If connection fails, system status will be set to Inactive

        PRA-281: ``scope_system_ids`` (``None`` = tenant-wide admin) restricts the
        sweep to in-scope systems, so a scoped caller never opens connections to,
        or learns hostnames/status of, out-of-scope hosts. Empty scope tests none.
        """
        query = self.db.query(System)
        if scope_system_ids is not None:
            if not scope_system_ids:
                return []
            query = query.filter(System.id.in_(scope_system_ids))
        systems = query.all()
        results = []

        for system in systems:
            try:
                result = self.test_connection(system.id)
                results.append(result)
            except Exception as e:  # pylint: disable=broad-except
                logger.error(
                    "Error testing connection to %s: %s", system.hostname, str(e)
                )
                results.append(
                    {
                        "system_id": system.id,
                        "hostname": system.hostname,
                        "ip_address": system.ip_address,
                        "status": "error",
                        "message": "Error testing connection: {}".format(  # pylint:disable=consider-using-f-string
                            str(e)
                        ),  # pylint:disable=consider-using-f-string
                        "response_time_ms": 0,
                        "tested_at": datetime.utcnow().isoformat(),
                    }
                )

        return results

    def _run_bounded_command(
        self,
        client: paramiko.SSHClient,
        command: str,
        *,
        wall_timeout: float,
        max_bytes: int = _MAX_INTERNAL_OUTPUT_BYTES,
        stdin_data: Optional[str] = None,
    ) -> Tuple[int, str, str, bool]:
        """PRA-322: run ``command`` draining stdout/stderr CONTINUOUSLY so a large
        output can never fill the SSH window and deadlock (the classic
        recv_exit_status-before-read hang). A hard wall-clock ``wall_timeout``
        forcibly closes the channel on expiry (raising :class:`SSHCommandTimeout`),
        and each captured stream is capped at ``max_bytes`` — excess is still
        drained (so the remote never blocks on a full window) but discarded.

        ``stdin_data`` (e.g. a sudo password) is written, then stdin is closed.

        Returns ``(exit_code, stdout, stderr, truncated)``.
        """
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise SSHConnectionError("SSH transport is not active")
        chan = transport.open_session()
        try:
            chan.settimeout(0.0)  # non-blocking recv; we drive the deadline
            chan.exec_command(command)
            if stdin_data is not None:
                try:
                    chan.sendall(stdin_data.encode())
                    chan.shutdown_write()
                except OSError:
                    pass

            deadline = time.monotonic() + wall_timeout
            out = bytearray()
            err = bytearray()
            truncated = False

            def _absorb(buf: bytearray, data: bytes) -> None:
                nonlocal truncated
                room = max_bytes - len(buf)
                if room > 0:
                    buf += data[:room]
                if len(data) > max(room, 0):
                    truncated = True

            while True:
                if time.monotonic() >= deadline:
                    try:
                        chan.close()
                    finally:
                        raise SSHCommandTimeout(
                            f"command exceeded {wall_timeout:.0f}s wall-clock timeout"
                        )
                slice_s = min(1.0, max(0.0, deadline - time.monotonic()))
                try:
                    select.select([chan], [], [], slice_s)
                except (OSError, ValueError):
                    break
                drained = False
                while chan.recv_ready():
                    data = chan.recv(65536)
                    if not data:
                        break
                    drained = True
                    _absorb(out, data)
                while chan.recv_stderr_ready():
                    data = chan.recv_stderr(65536)
                    if not data:
                        break
                    drained = True
                    _absorb(err, data)
                if (
                    chan.exit_status_ready()
                    and not chan.recv_ready()
                    and not chan.recv_stderr_ready()
                    and not drained
                ):
                    break

            exit_code = chan.recv_exit_status()
            return (
                exit_code,
                out.decode(errors="replace"),
                err.decode(errors="replace"),
                truncated,
            )
        finally:
            try:
                chan.close()
            except Exception:  # pylint: disable=broad-except
                pass

    def execute_command(
        self,
        system_id: int,
        command: str,
        timeout: int = None,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command on the specified system.

        If `user_id` is provided, persists a `CommandExecutionResult` so the
        execution appears in Command History. Internal callers (health checks,
        pollers) pass user_id=None and remain out of the user audit trail.

        PRA-322: reachability is decided by the CONNECT, not the command. Once
        get_connection succeeds the host is reachable, so we clear any stale
        unreachable state up front; a later command failure/timeout is a command
        outcome, NOT a reason to mark the host offline. Output is drained + bounded
        and the command is bounded by a hard wall-clock timeout that closes the
        (possibly wedged) pooled connection.

        Returns a dictionary with command execution results.
        """
        if timeout is None:
            timeout = self._connection_timeout

        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHConnectionError(f"System with ID {system_id} not found")

        started_at = datetime.utcnow()
        result = {
            "system_id": system_id,
            "hostname": system.hostname,
            "command": command,
            "status": "failed",
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "execution_time_ms": 0,
            "executed_at": started_at.isoformat(),
        }

        start_time = time.time()

        # ---- connect (decides reachability) ----
        try:
            client, _ = self.get_connection(system_id)
        except SSHConnectionError as e:
            self._record_connect_failure(system, e)
            result["stderr"] = str(e)
            result["outcome"] = self._connect_outcome(e)
            self._finish_command(
                system_id, user_id, command, result, started_at, start_time
            )
            return result

        # Connected => reachable. Clear stale unreachable/failure state now so a
        # later command failure/timeout can't mark the host offline (PRA-322).
        self._update_system_connection_status(system, "connected")

        # ---- run the command (bounded; does not affect reachability) ----
        try:
            exit_code, stdout, stderr, truncated = self._run_bounded_command(
                client, command, wall_timeout=timeout or _DEFAULT_COMMAND_WALL_TIMEOUT
            )
            result["stdout"] = stdout
            result["stderr"] = stderr
            result["exit_code"] = exit_code
            result["truncated"] = truncated
            result["status"] = "success" if exit_code == 0 else "warning"
            result["outcome"] = "success" if exit_code == 0 else "command_failed"

            if system.ssh_security_policy and system.ssh_security_policy.log_commands:
                cred = system.credentials
                self._log_security_event(
                    system,
                    "command_execution",
                    {
                        "command": command,
                        "source_ip": "localhost",
                        "username": cred.username if cred else None,
                        "success": exit_code == 0,
                        "exit_code": exit_code,
                    },
                )
        except SSHCommandTimeout as e:
            # The host is reachable (we connected + ran it), but the command
            # exceeded its wall-clock budget. Drop the possibly-wedged pooled
            # client; do NOT mark the host Unreachable.
            self.close_connection(system_id)
            result["status"] = "failed"
            result["outcome"] = "command_timeout"
            result["timed_out"] = True
            result["stderr"] = str(e)
            logger.warning("command timed out on %s: %s", system.hostname, e)
        except Exception as e:  # pylint: disable=broad-except
            # Command-level error on a reachable host — not an offline signal.
            result["status"] = "failed"
            result["outcome"] = "command_failed"
            result["stderr"] = f"Command error: {str(e)}"
            logger.warning("command error on %s: %s", system.hostname, e)

        self._finish_command(
            system_id, user_id, command, result, started_at, start_time
        )
        return result

    def _connect_outcome(self, err: Exception) -> str:
        """Operator-readable outcome for a failed CONNECT."""
        if isinstance(err, HostCoolingDownError):
            return "cooldown"
        msg = str(err)
        if "Authentication failed" in msg:
            return "auth_failure"
        return "transport_failure"

    def _record_connect_failure(self, system: System, err: Exception) -> None:
        """Update reachability for a failed CONNECT, keeping auth/transport
        distinct (PRA-322). A cooling-down host is left in its cooldown state; an
        auth failure means the host is REACHABLE (wrong creds) and must not count
        toward Unreachable; only a transport failure escalates toward Unreachable.
        """
        if isinstance(err, HostCoolingDownError):
            return  # breaker already owns this state; don't double-count
        if "Authentication failed" in str(err):
            self._update_system_connection_status(system, "auth_failed")
        else:
            self._update_system_connection_status(system, "disconnected")

    def _finish_command(
        self,
        system_id: int,
        user_id: Optional[int],
        command: str,
        result: Dict[str, Any],
        started_at: datetime,
        start_time: float,
    ) -> None:
        result["execution_time_ms"] = int((time.time() - start_time) * 1000)
        if user_id is not None:
            self._persist_execution_result(
                system_id, user_id, command, result, started_at
            )

    def _persist_execution_result(
        self,
        system_id: int,
        user_id: int,
        command: str,
        result: Dict[str, Any],
        started_at: datetime,
    ) -> None:
        """Persist a user-initiated command execution to command_execution_results
        so it appears in the Command History UI. Errors are swallowed to avoid
        failing the execute call over an audit-write problem."""
        try:
            status_map = {
                "success": "success",
                "warning": "failed",
                "failed": "failed",
            }
            record = CommandExecutionResult(
                system_id=system_id,
                user_id=user_id,
                command=command,
                normalized_command=command.strip(),
                command_hash=hashlib.sha256(command.encode()).hexdigest(),
                execution_status=status_map.get(result.get("status", ""), "failed"),
                exit_code=result.get("exit_code"),
                stdout=result.get("stdout") or None,
                stderr=result.get("stderr") or None,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                execution_time_ms=result.get("execution_time_ms"),
                timeout_seconds=self._connection_timeout,
                validation_status="bypassed",
                risk_level="low",
                requires_sudo=command.strip().startswith("sudo"),
            )
            self.db.add(record)
            self.db.commit()
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Failed to persist CommandExecutionResult: %s", e)
            try:
                self.db.rollback()
            except Exception:  # pylint: disable=broad-except
                pass

    def execute_privileged_command(
        self,
        system_id: int,
        command: str,
        timeout: int = None,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command with appropriate privilege escalation based on
        the system's credential sudo_method.
        """
        if timeout is None:
            timeout = self._connection_timeout

        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise SSHConnectionError(f"System with ID {system_id} not found")

        started_at = datetime.utcnow()
        credential = system.credentials
        sudo_method = credential.sudo_method if credential else "none"

        if sudo_method == "none":
            return self.execute_command(
                system_id, command, timeout=timeout, user_id=user_id
            )

        if sudo_method == "nopasswd":
            return self.execute_command(
                system_id, f"sudo -n {command}", timeout=timeout, user_id=user_id
            )

        # sudo_method == "password"
        result = {
            "system_id": system_id,
            "hostname": system.hostname,
            "command": f"sudo -S {command}",
            "status": "failed",
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "execution_time_ms": 0,
            "executed_at": datetime.utcnow().isoformat(),
        }

        start_time = time.time()

        # ---- connect (decides reachability) ----
        try:
            client, _ = self.get_connection(system_id)
        except SSHConnectionError as e:
            self._record_connect_failure(system, e)
            result["stderr"] = str(e)
            result["outcome"] = self._connect_outcome(e)
            self._finish_command(
                system_id, user_id, f"sudo -S {command}", result, started_at, start_time
            )
            return result

        # Connected => reachable (PRA-322).
        self._update_system_connection_status(system, "connected")

        # Fetch sudo_password from Vault before running (kept off the wire log).
        sudo_password = ""
        if credential.vault_path:
            vault_svc = VaultService(self.db)
            sudo_secret = vault_svc.read_secret(credential.vault_path)
            if sudo_secret:
                sudo_password = sudo_secret.get("sudo_password", "")

        # ---- run the command (bounded; does not affect reachability) ----
        try:
            exit_code, stdout, stderr, truncated = self._run_bounded_command(
                client,
                f"sudo -S {command}",
                wall_timeout=timeout or _DEFAULT_COMMAND_WALL_TIMEOUT,
                stdin_data=sudo_password + "\n",
            )
            result["stdout"] = stdout
            result["stderr"] = stderr
            result["exit_code"] = exit_code
            result["truncated"] = truncated
            result["status"] = "success" if exit_code == 0 else "warning"
            result["outcome"] = "success" if exit_code == 0 else "command_failed"

            if system.ssh_security_policy and system.ssh_security_policy.log_commands:
                self._log_security_event(
                    system,
                    "command_execution",
                    {
                        "command": f"sudo -S {command}",
                        "source_ip": "localhost",
                        "username": credential.username if credential else None,
                        "success": exit_code == 0,
                        "exit_code": exit_code,
                    },
                )
        except SSHCommandTimeout as e:
            self.close_connection(system_id)
            result["status"] = "failed"
            result["outcome"] = "command_timeout"
            result["timed_out"] = True
            result["stderr"] = str(e)
            logger.warning("privileged command timed out on %s: %s", system.hostname, e)
        except Exception as e:  # pylint: disable=broad-except
            result["status"] = "failed"
            result["outcome"] = "command_failed"
            result["stderr"] = f"Command error: {str(e)}"
            logger.warning("privileged command error on %s: %s", system.hostname, e)

        self._finish_command(
            system_id, user_id, f"sudo -S {command}", result, started_at, start_time
        )
        return result
