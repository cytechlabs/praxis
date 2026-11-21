"""SFTP-based file transfer service (PRA-142).

Every operation:

    1. passes the PRA-139 authorization gate (action = "file_transfer")
    2. opens a short-lived paramiko connection using a Vault-signed user
       cert bound to the grant's login
    3. performs the SFTP op via paramiko's SFTPClient
    4. records a FileTransferAudit row capturing direction, path, bytes,
       sha256 (for upload/download), status, and client IP

The SFTP subsystem runs as the mapped Linux account on the remote host, so
the kernel enforces per-user filesystem permissions — Praxis doesn't try to
reimplement unix perms in userspace.

Naming: the PRA title says "SCP/SFTP" because that's how ops folks refer to
it. The implementation is SFTP only. OpenSSH 8+ uses SFTP under the hood for
``scp`` anyway, so there's no user-visible gap. Users running ``scp`` from
their own terminal against a Praxis-managed host still work as always —
they're using their cert directly, not going through this service.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import errno
import hashlib
import logging
import os
import posixpath
import re
import stat as stat_module
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Awaitable, Dict, Iterator, List, Optional, Tuple

import paramiko
from sqlalchemy.orm import Session as DbSession

from ..core.redaction import redact_text
from ..db.access_models import FileTransferAudit
from ..db.models import System, SystemMetadata, User
from .access_authorization_service import (
    PermissionDenied,
    authorize_action,
    cert_principal_for_user,
    has_fresh_totp,
)
from .broker_client import BrokerClient
from .ssh_service import (
    CertificateSSHClient,
    SSHConnectionError,
    SSHService,
    configure_host_key_policy,
    connection_timeout_for,
    is_transport_failure,
    raise_if_cooling_down,
    record_transport_failure,
    record_transport_reachable,
    record_transport_success,
)
from .transport import (
    TransportError,
    TransportUnavailable,
    TransportUnsupported,
    get_transport,
)
from .vault_service import VaultService

logger = logging.getLogger(__name__)

# 5 GiB per-transfer cap. Sized to cover DB dumps / log archives while keeping
# a blast radius. Applies to the SSH path, which streams chunk-by-chunk and
# never holds the whole body in backend memory.
MAX_TRANSFER_BYTES = int(5 * 1024 * 1024 * 1024)

# PRA-180 TRANSPORT-02: the agent-backed transfer bridge currently buffers the
# WHOLE body in backend memory (the broker side streams; the sync->async bridge
# in _download_via_agent / _upload_via_agent does not yet). Until end-to-end
# streaming lands, bound the agent path to a memory-safe ceiling that is
# separate from — and never larger than — the SSH streaming cap, so one
# authorized agent transfer can't allocate multi-GiB of backend RAM. Operators
# with headroom can raise it via PRAXIS_AGENT_TRANSFER_MAX_BYTES.
_DEFAULT_AGENT_TRANSFER_MAX_BYTES = 1 * 1024 * 1024 * 1024  # 1 GiB


def _resolve_agent_transfer_cap() -> int:
    raw = os.getenv("PRAXIS_AGENT_TRANSFER_MAX_BYTES")
    try:
        configured = int(raw) if raw else _DEFAULT_AGENT_TRANSFER_MAX_BYTES
    except ValueError:
        logger.warning(
            "invalid PRAXIS_AGENT_TRANSFER_MAX_BYTES=%r; using default %d",
            raw,
            _DEFAULT_AGENT_TRANSFER_MAX_BYTES,
        )
        configured = _DEFAULT_AGENT_TRANSFER_MAX_BYTES
    if configured <= 0:
        configured = _DEFAULT_AGENT_TRANSFER_MAX_BYTES
    # Never exceed the global per-transfer ceiling.
    return min(configured, MAX_TRANSFER_BYTES)


AGENT_TRANSFER_MAX_BYTES = _resolve_agent_transfer_cap()
CHUNK = 64 * 1024
# How far past the client's position an SSH download may ask the host to read.
# paramiko's prefetch() queues a request for every remaining byte of the file,
# so reading ahead is done one window at a time, re-armed as the client
# consumes the previous one.
SSH_READ_AHEAD_BYTES = 2 * 1024 * 1024


class FileTransferError(RuntimeError):
    """Transfer failed (permission, SSH, quota, etc.)."""


# ------------------------------------------------------------------ paths
# Allow absolute POSIX paths. Reject anything with NUL, CR, LF, or that tries
# to climb above root. We keep this lenient — sshd enforces real access.
_PATH_RE = re.compile(r"^/[^\x00\r\n]{0,4095}$")


def validate_remote_path(path: str) -> None:
    if not isinstance(path, str) or not _PATH_RE.match(path):
        raise FileTransferError(f"invalid remote path: {path!r}")


# -------------------------------------------------------------- auth + cert


def _mint_cert_for(user: User, login: str, ttl: int = 300) -> paramiko.PKey:
    """Generate an ephemeral keypair and get Vault to sign it for ``login``."""
    pkey = paramiko.RSAKey.generate(2048)
    pub = f"{pkey.get_name()} {pkey.get_base64()}"
    key_id = f"praxis-xfer-{user.id}-{int(time.time())}"
    from ..db.session import SessionLocal

    db = SessionLocal()
    try:
        vault = VaultService(db)
        # PRA-288: sign with the IMMUTABLE Praxis user principal (same mapping the
        # session path uses), not the shared Linux login. The SFTP connection still
        # uses ``login`` as the username.
        signed = vault.sign_ssh_user_cert(
            public_key=pub,
            principal=cert_principal_for_user(user),
            ttl_seconds=ttl,
            key_id=key_id,
        )
        # PRA-219: audit the user-cert issuance for the file-transfer path.
        from .audit_event_service import emit_user_cert_sign

        emit_user_cert_sign(
            db,
            actor_user_id=user.id,
            actor_username=user.username,
            login=login,
            ttl_s=ttl,
            key_id=key_id,
            purpose="file_transfer",
        )
    finally:
        db.close()
    pkey.load_certificate(signed)
    return pkey


def _ssh_port(db: DbSession, system: System) -> int:
    md = db.query(SystemMetadata).filter(SystemMetadata.system_id == system.id).first()
    return (md.ssh_port or 22) if md else 22


@contextmanager
def _open_sftp(
    db: DbSession, user: User, system: System, login: str
) -> Iterator[paramiko.SFTPClient]:
    """Open an SSH connection + SFTP subsystem. Closed on context exit.

    Paramiko raises ``AuthenticationException`` when the host doesn't accept
    the cert principal — typically because the access broker hook isn't
    enrolled on the host, or the mapped Linux account hasn't been
    provisioned yet. We translate that into a FileTransferError with an
    actionable hint so the route can return 400 JSON instead of a 500.

    PRA-313: shares the SSH path's per-host transport circuit breaker — a
    cooling-down host fast-fails here BEFORE minting a cert / hitting Vault or
    opening a socket, and transport failures/successes update the same breaker so
    one bad host can't make file-transfer requests hang on the SSH timeout.
    """
    # Fast-fail a cooling-down host before any Vault round-trip or socket open.
    try:
        raise_if_cooling_down(db, system)
    except SSHConnectionError as e:
        raise FileTransferError(f"host_cooling_down: {e}") from e
    pkey = _mint_cert_for(user, login)
    port = _ssh_port(db, system)
    # PRA-313: honor the configured SSH connection timeout instead of a hardcoded
    # value so operators tune one knob and the SFTP path can't wait longer than
    # command execution / health checks.
    timeout = connection_timeout_for(db)
    # This path only ever authenticates with the Vault-signed certificate minted
    # above, so it needs the client that lets a modern OpenSSH negotiate an
    # RSA-SHA2 certificate algorithm instead of the SHA-1 one those servers no
    # longer accept. It behaves exactly like paramiko's client otherwise.
    client = CertificateSSHClient()
    try:
        # Enforce the system's host-key verification policy (PRA-245) — the same
        # path SSH sessions use. A mismatch/unknown key fails the connect below
        # (translated to ssh_connect_failed); an unsupported stored key fails
        # closed here. The port dialled below is passed in so the key is pinned
        # under the endpoint name paramiko will look it up by on this very
        # connection.
        try:
            configure_host_key_policy(client, db, system, ssh_port=port)
        except SSHConnectionError as e:
            raise FileTransferError(f"ssh_host_key_error: {e}") from e
        try:
            client.connect(
                hostname=str(system.ip_address),
                port=port,
                username=login,
                pkey=pkey,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.AuthenticationException as e:
            # Reachable host, rejected cert — reset the breaker (not a timeout).
            record_transport_reachable(db, system)
            raise FileTransferError(
                f"ssh_auth_failed: host rejected cert for login {login!r}. "
                "Confirm the access broker is enrolled on this host and that "
                "reconcile has created the Linux account for this user."
            ) from e
        except (paramiko.SSHException, OSError) as e:
            # Banner/connect/socket failure trips the breaker; a host-key mismatch
            # (reachable) resets it. Either way the connect itself failed.
            if is_transport_failure(e):
                record_transport_failure(db, system, str(e))
            else:
                record_transport_reachable(db, system)
            raise FileTransferError(f"ssh_connect_failed: {e}") from e
        # Connected — clear any transport cooldown for this host.
        record_transport_success(db, system)
        try:
            sftp = client.open_sftp()
        except paramiko.SSHException as e:
            raise FileTransferError(f"sftp_open_failed: {e}") from e
        try:
            yield sftp
        finally:
            try:
                sftp.close()
            except Exception:  # pylint: disable=broad-except
                pass
    finally:
        try:
            client.close()
        except Exception:  # pylint: disable=broad-except
            pass


# ----------------------------------------------------------------- gate


def _pref(system: System) -> str:
    """Lowercased transport preference with the same default as the
    factory. Used by directory-op routing that doesn't need to call
    the broker (force-agent → unsupported, anything else → SSH).
    """
    return (system.transport_preference or "auto").lower()


def _reject_force_agent_directory_op(
    db: DbSession,
    *,
    user: User,
    system: System,
    login: str,
    direction: str,
    remote_path: str,
    client_ip: Optional[str],
) -> None:
    """Per the PRA-153 #3 lock: when an operator forces transport=agent
    and the agent doesn't support a directory op (list/stat/mkdir/
    unlink), we MUST open the audit row with transport="agent" +
    status="error" + reason="transport_unsupported" BEFORE raising
    so the failed attempt is visible in the ledger. Force means
    force; never silently fall back to SSH.

    No-op when pref is anything other than "agent".
    """
    if _pref(system) != "agent":
        return
    audit = _open_audit(
        db,
        user=user,
        system=system,
        login=login,
        direction=direction,
        remote_path=remote_path,
        client_ip=client_ip,
        transport="agent",
    )
    _finish_audit(
        db,
        audit,
        status="error",
        error_message="transport_unsupported",
    )
    raise TransportUnsupported(f"agent transport does not support {direction!r} ops")


def _run_async_from_sync(coro: Awaitable) -> Any:
    """Run an awaitable from sync code, even if a parent event loop
    is already running. Mirrors the helper in command_execution_service:
    asyncio.run() raises if a loop is already in this thread, so the
    fallback runs the coroutine in a fresh worker thread that owns
    its own event loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


async def _resolve_file_transport(system: System, db: DbSession):
    """Return (transport_name, transport_obj) for upload/download.

    A fresh BrokerClient is built INSIDE the coroutine so its
    httpx.AsyncClient is bound to the active event loop and torn
    down before the loop closes (same lesson learned in #3d).
    SSHService instances are cheap to construct and rebuild a fresh
    one bound to the caller's DB session.
    """
    broker = BrokerClient()
    try:
        transport = await get_transport(system, broker, ssh_service=SSHService(db))
        return transport.name, transport
    finally:
        await broker.__aexit__(None, None, None)


def _gate(db: DbSession, user: User, system_id: int) -> Tuple[System, str]:
    """Resolve system + enforce file_transfer grant. Returns (system, login)."""
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise FileTransferError(f"system {system_id} not found")
    try:
        result = authorize_action(db, user, system, "file_transfer")
    except PermissionDenied as e:
        raise FileTransferError(f"{e.code}: {e.reason}") from e
    if result.requires_approval:
        raise FileTransferError(
            "approval_required: fleet role requires session approval"
        )
    if result.requires_totp and not has_fresh_totp(db, user.id):
        raise FileTransferError("totp_required: step up via Security settings")
    return system, result.login


# -------------------------------------------------------------- audit


def _open_audit(
    db: DbSession,
    *,
    user: User,
    system: System,
    login: str,
    direction: str,
    remote_path: str,
    local_filename: Optional[str] = None,
    client_ip: Optional[str] = None,
    transport: Optional[str] = None,
) -> FileTransferAudit:
    row = FileTransferAudit(
        user_id=user.id,
        system_id=system.id,
        login=login,
        direction=direction,
        remote_path=remote_path,
        local_filename=local_filename,
        size_bytes=0,
        status="in_progress",
        client_ip=client_ip,
        started_at=datetime.utcnow(),
        transport=transport,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _finish_audit(
    db: DbSession,
    row: FileTransferAudit,
    *,
    status: str,
    size_bytes: int = 0,
    sha256: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    row.status = status
    row.size_bytes = size_bytes
    row.sha256 = sha256
    row.error_message = error_message
    row.ended_at = datetime.utcnow()
    db.commit()

    # PRA-143: emit a structured audit event mirroring the transfer audit
    # row so external sinks see file ops alongside everything else.
    try:
        from .audit_event_service import safe_emit

        outcome = (
            "success"
            if status == "success"
            else ("failure" if status == "error" else "success")
        )
        safe_emit(
            db=db,
            action=f"file.{row.direction}",
            outcome=outcome,
            actor_user_id=row.user_id,
            actor_ip=row.client_ip,
            target_system_id=row.system_id,
            target_kind="path",
            target_id=row.remote_path,
            context={
                "login": row.login,
                "size_bytes": size_bytes,
                "sha256": sha256,
                "error": error_message,
                "local_filename": row.local_filename,
                # PRA-153 #3 audit lock: every file.* event must
                # carry transport=ssh|agent so external SIEM sinks
                # can filter / correlate without a separate join
                # against file_transfer_audits.
                "transport": row.transport,
            },
        )
    except Exception:  # pylint: disable=broad-except
        pass


# -------------------------------------------------------------- operations


def listdir(
    db: DbSession,
    user: User,
    system_id: int,
    path: str,
    *,
    client_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    validate_remote_path(path)
    system, login = _gate(db, user, system_id)
    # PRA-153 #3e: directory ops are SSH-only. force-agent fails
    # loud with an audit row recording the rejected attempt.
    _reject_force_agent_directory_op(
        db,
        user=user,
        system=system,
        login=login,
        direction="listdir",
        remote_path=path,
        client_ip=client_ip,
    )
    with _open_sftp(db, user, system, login) as sftp:
        try:
            entries = sftp.listdir_attr(path)
        except IOError as e:
            raise FileTransferError(f"listdir failed: {e}") from e
    results = []
    for a in entries:
        results.append(
            {
                "name": a.filename,
                "size": int(a.st_size or 0),
                "mtime": int(a.st_mtime or 0),
                "mode": int(a.st_mode or 0),
                "is_dir": bool((a.st_mode or 0) & 0o040000),
                "is_link": bool((a.st_mode or 0) & 0o120000 == 0o120000),
            }
        )
    # Directories first, then files, both alphabetical.
    results.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return results


def stat(
    db: DbSession,
    user: User,
    system_id: int,
    path: str,
    *,
    client_ip: Optional[str] = None,
) -> Dict[str, Any]:
    validate_remote_path(path)
    system, login = _gate(db, user, system_id)
    _reject_force_agent_directory_op(
        db,
        user=user,
        system=system,
        login=login,
        direction="stat",
        remote_path=path,
        client_ip=client_ip,
    )
    with _open_sftp(db, user, system, login) as sftp:
        try:
            a = sftp.stat(path)
        except IOError as e:
            raise FileTransferError(f"stat failed: {e}") from e
    return {
        "size": int(a.st_size or 0),
        "mtime": int(a.st_mtime or 0),
        "mode": int(a.st_mode or 0),
        "is_dir": bool((a.st_mode or 0) & 0o040000),
    }


class DownloadStream:
    """A download whose setup has already succeeded.

    ``download_stream`` returns one only after authorization, the host
    connection, the file checks and (agent transport) the whole transfer have
    succeeded, so the caller can commit success headers. ``size`` is the exact
    body length when the host reported one (the caller declares it as
    Content-Length so a body that ends early is detectable) and ``None`` when
    the host cannot say. ``close`` releases the host connection or spool file
    and records an abandoned transfer as a failure.
    """

    def __init__(
        self, chunks: Iterator[bytes], first: Optional[bytes], size: Optional[int]
    ) -> None:
        self._chunks = chunks
        self._pending = first
        self.size = size

    def __iter__(self) -> "DownloadStream":
        return self

    def __next__(self) -> bytes:
        if self._pending is not None:
            chunk, self._pending = self._pending, None
            return chunk
        return next(self._chunks)

    def close(self) -> None:
        self._pending = None
        close = getattr(self._chunks, "close", None)
        if close is not None:
            close()


class _DownloadInfo:  # pylint: disable=too-few-public-methods
    """Body length published by a download generator before its first chunk."""

    size: Optional[int] = None


def _prime_download(chunks: Iterator[bytes], info: _DownloadInfo) -> DownloadStream:
    """Run a download generator up to its first chunk.

    Every failure that can happen before the first byte therefore raises here,
    inside the request, where it can still become an HTTP error status. The
    generator has already recorded the failure in the audit row by then.
    """
    try:
        first: Optional[bytes] = next(chunks)
    except StopIteration:
        first = None
    return DownloadStream(chunks, first, info.size)


def _failure_text(exc: BaseException) -> str:
    """Sanitized, never-empty text for a failed transfer.

    Some exceptions (``TimeoutError()``, ``EOFError()``) stringify to nothing;
    the failure must not depend on there being text to record.
    """
    return redact_text(str(exc)) or type(exc).__name__


def _finalize_download_audit(
    audit_id: int,
    *,
    failed: bool,
    error: Optional[str],
    size_bytes: int,
    sha256: Optional[str],
) -> None:
    """Persist the outcome of a download on its own session.

    The request session may be gone by the time a stream ends, so this opens a
    fresh one. ``failed`` decides the outcome, not the error text. A failed or
    abandoned transfer never carries a digest.
    """
    from ..db.session import SessionLocal

    fdb = SessionLocal()
    try:
        row = (
            fdb.query(FileTransferAudit)
            .filter(FileTransferAudit.id == audit_id)
            .first()
        )
        if row is not None:
            _finish_audit(
                fdb,
                row,
                status="error" if failed else "success",
                size_bytes=size_bytes,
                sha256=None if failed else sha256,
                error_message=error if failed else None,
            )
    finally:
        fdb.close()


def _remote_file_error(path: str, exc: OSError) -> FileTransferError:
    """Translate a remote open/stat failure into a sanitized, typed error."""
    if exc.errno == errno.ENOENT:
        return FileTransferError(f"file not found: {path}")
    if exc.errno in (errno.EACCES, errno.EPERM):
        return FileTransferError("forbidden: permission denied reading remote file")
    return FileTransferError("download failed: remote file could not be read")


def _stage_error(exc: OSError) -> FileTransferError:
    """Sanitized error for a local spool failure (full disk, unwritable dir)."""
    logger.warning("download spool failed: %s", _failure_text(exc))
    error = FileTransferError(
        "download failed: the backend could not stage the transfer"
    )
    error.__cause__ = exc
    return error


def _agent_transfer_error(path: str, exc: TransportError) -> FileTransferError:
    """Translate an agent file_get refusal into a sanitized, typed error."""
    reason = getattr(exc, "reason", None)
    if reason == "not_found":
        return FileTransferError(f"file not found: {path}")
    if reason == "denied":
        return FileTransferError("forbidden: permission denied reading remote file")
    if reason in ("is_directory", "not_regular"):
        return FileTransferError(f"not a regular file: {path}")
    if reason == "too_large":
        return FileTransferError("file too large: exceeds the transfer limit")
    return FileTransferError(f"download failed: {exc}")


def download_stream(
    db: DbSession,
    user: User,
    system_id: int,
    path: str,
    *,
    client_ip: Optional[str] = None,
) -> DownloadStream:
    """Prepare a download and return it ready to stream.

    Everything that can be known before the first byte is resolved here, so
    the route can still answer with a real HTTP status: authorization, the
    host connection, whether the path is a readable regular file, the size
    cap, and the first chunk of data. For the agent transport the whole body is
    received (into a bounded spool file) first, so a transfer that fails
    part-way is an ordinary error response, never a partial success.

    Routing is per-host transport_preference: ssh, or auto with the tunnel
    down, uses SFTP; auto with a healthy tunnel, or agent, uses the agent.
    For SSH the body is streamed from the host as the client consumes it, and
    a failure after streaming has begun raises out of the iterator so the
    connection is aborted instead of finishing as a short success.

    The audit row is opened before any host work and finalized when the
    transfer ends, fails, or is abandoned, so attribution survives caller
    disconnect. The transport column reflects what was actually attempted.
    """
    validate_remote_path(path)
    system, login = _gate(db, user, system_id)

    # Resolve routing up front so the audit row records the right
    # transport. For force-agent + tunnel down this raises
    # TransportUnavailable BEFORE we open the audit row — the lock
    # only requires audit-first-then-raise for forced-agent
    # UNSUPPORTED ops; UNAVAILABLE ops are full-on transport
    # failures that the caller surfaces themselves.
    try:
        transport_name, transport = _run_async_from_sync(
            _resolve_file_transport(system, db)
        )
    except TransportUnavailable:
        # Operator intent for the audit row attribution.
        audit = _open_audit(
            db,
            user=user,
            system=system,
            login=login,
            direction="download",
            remote_path=path,
            client_ip=client_ip,
            transport="agent",
        )
        _finish_audit(
            db,
            audit,
            status="error",
            error_message="transport_unavailable",
        )
        raise

    audit = _open_audit(
        db,
        user=user,
        system=system,
        login=login,
        direction="download",
        remote_path=path,
        local_filename=path.rsplit("/", 1)[-1] or path,
        client_ip=client_ip,
        transport=transport_name,
    )
    audit_id = audit.id

    if transport_name == "ssh":
        return _download_via_ssh(db, user, system, login, path, audit_id)
    return _download_via_agent(db, system, path, audit_id)


def _download_via_ssh(
    db: DbSession,
    user: User,
    system: System,
    login: str,
    path: str,
    audit_id: int,
) -> DownloadStream:
    """SSH-backed download, streamed from the host as the client reads."""
    info = _DownloadInfo()
    chunks = _ssh_download_chunks(db, user, system, login, path, audit_id, info)
    return _prime_download(chunks, info)


def _open_ssh_download(sftp: Any, path: str) -> Tuple[Any, int]:
    """Check that ``path`` is a readable regular file within the size cap and
    open it. Returns the open remote file and the size the host reports."""
    try:
        st = sftp.stat(path)
    except OSError as e:
        raise _remote_file_error(path, e) from e
    if st.st_mode is not None and not stat_module.S_ISREG(st.st_mode):
        raise FileTransferError(f"not a regular file: {path}")
    expected = int(st.st_size or 0)
    if expected > MAX_TRANSFER_BYTES:
        raise FileTransferError(f"file too large: {expected} > {MAX_TRANSFER_BYTES}")
    try:
        return sftp.open(path, "rb"), expected
    except OSError as e:
        raise _remote_file_error(path, e) from e


def _download_failure(exc: Exception, started: bool, detail: str) -> Exception:
    """The exception to raise for a failed download.

    Before the first byte an unexpected local or host error becomes a typed,
    sanitized FileTransferError so the route can answer with a real status;
    after streaming has begun it passes through and aborts the response.
    """
    if started or isinstance(exc, FileTransferError):
        return exc
    logger.warning("download failed: %s", _failure_text(exc))
    wrapped = FileTransferError(f"download failed: {detail}")
    wrapped.__cause__ = exc
    return wrapped


class _TransferState:  # pylint: disable=too-few-public-methods
    """Running outcome of one transfer, finalized into the audit row.

    The transfer failed unless it was marked ``completed``: neither an empty
    exception message nor an exit path nobody anticipated can finalize it as a
    success.
    """

    def __init__(self) -> None:
        self.sha = hashlib.sha256()
        self.total = 0
        self.digest: Optional[str] = None
        self.error: Optional[str] = None
        self.completed = False
        self.started = False

    def add(self, chunk: bytes) -> None:
        self.total += len(chunk)
        self.sha.update(chunk)

    def fail(self, exc: BaseException) -> None:
        self.error = _failure_text(exc)

    def finalize(self, audit_id: int) -> None:
        failed = not self.completed
        error = None
        if failed:
            error = self.error or "interrupted"
        _finalize_download_audit(
            audit_id,
            failed=failed,
            error=error,
            size_bytes=self.total,
            sha256=self.digest or self.sha.hexdigest(),
        )


def _read_next(
    remote: Any, state: "_TransferState", expected: int, window_end: int
) -> Tuple[bytes, int]:
    """Read the next chunk of an SSH download; returns (chunk, window_end).

    With a known size the host is asked for one ``SSH_READ_AHEAD_BYTES`` window
    at a time, re-armed only once the client has consumed the previous window,
    so a slow client holds back the host instead of queueing the whole file.
    """
    left = CHUNK if expected == 0 else expected - state.total
    if expected and left > 0 and state.total >= window_end:
        window_end = min(expected, state.total + SSH_READ_AHEAD_BYTES)
        remote.prefetch(file_size=window_end)
    want = min(CHUNK, left)
    if expected:
        want = min(want, window_end - state.total)
    return (remote.read(want) if want > 0 else b""), window_end


def _ssh_download_chunks(
    db: DbSession,
    user: User,
    system: System,
    login: str,
    path: str,
    audit_id: int,
    info: _DownloadInfo,
) -> Iterator[bytes]:
    state = _TransferState()
    try:
        with _open_sftp(db, user, system, login) as sftp:
            remote, expected = _open_ssh_download(sftp, path)
            with remote:
                # A host that reports size 0 may still have content (procfs
                # style); then read to EOF with no read-ahead and let the
                # response go without a declared length. Otherwise read exactly
                # the reported size, asking the host for one bounded window at
                # a time.
                info.size = expected
                window_end = 0
                while True:
                    chunk, window_end = _read_next(remote, state, expected, window_end)
                    if not chunk:
                        break
                    state.add(chunk)
                    if expected == 0 and state.total > MAX_TRANSFER_BYTES:
                        raise FileTransferError("transfer exceeded max size")
                    if expected == 0:
                        info.size = None
                    state.started = True
                    yield chunk
                if state.total < expected:
                    raise FileTransferError(
                        f"transfer incomplete: received {state.total} of "
                        f"{expected} bytes"
                    )
        state.completed = True
    except GeneratorExit:
        state.error = "client_disconnected"
        raise
    except Exception as e:  # pylint: disable=broad-except
        state.fail(e)
        failure = _download_failure(e, state.started, "could not read from the host")
        if failure is e:
            raise
        raise failure from e
    finally:
        state.finalize(audit_id)


async def _spool_agent_download(
    system: System, path: str, tmp_path: str
) -> Tuple[int, str]:
    """Receive an agent file_get body into ``tmp_path``; returns (bytes, sha256).

    Skips the transport factory: the caller already resolved this op to the
    agent path and the audit row says transport="agent". Re-running
    get_transport here could fall back to SSH if the tunnel just went
    unhealthy, leaving the audit row and the actual transport disagreeing.
    One chunk is in memory at a time; the byte cap bounds spool disk usage.
    """
    from .transport.agent import AgentTransport

    broker = BrokerClient()
    try:
        transport = AgentTransport(system, broker)
        stream = await transport.open_file_get(path)
        try:
            # Reject a declared oversize BEFORE consuming the body when the
            # stream advertises a size (broker X-Praxis-File-Size header).
            declared = getattr(stream, "size", None)
            if isinstance(declared, int) and declared > AGENT_TRANSFER_MAX_BYTES:
                raise FileTransferError("transfer exceeded max size")

            sha = hashlib.sha256()
            total = 0
            # tmp_path was created 0600 by mkstemp; "wb" truncates without
            # widening the mode.
            try:
                fh = open(tmp_path, "wb")  # pylint: disable=consider-using-with
            except OSError as e:
                raise _stage_error(e) from e
            with fh:
                async for chunk in stream.chunks:
                    total += len(chunk)
                    # Enforce the tighter agent ceiling while consuming, not
                    # the SSH cap.
                    if total > AGENT_TRANSFER_MAX_BYTES:
                        raise FileTransferError("transfer exceeded max size")
                    sha.update(chunk)
                    try:
                        fh.write(chunk)
                    except OSError as e:
                        raise _stage_error(e) from e
            if isinstance(declared, int) and declared > 0 and total < declared:
                raise FileTransferError(
                    f"transfer incomplete: received {total} of {declared} bytes"
                )
            return total, sha.hexdigest()
        finally:
            await stream.close()
    finally:
        await broker.__aexit__(None, None, None)


def _download_via_agent(
    _db: DbSession, system: System, path: str, audit_id: int
) -> DownloadStream:
    """Agent-backed download.

    The agent stream is spooled to a bounded, 0600 temp file (chunk by chunk,
    hashing and counting) before anything is returned, then served from that
    file in fixed-size chunks. Backend memory stays at one ``CHUNK`` however
    large the file is, and because the whole transfer has succeeded before the
    response starts, an agent failure can never surface as a half-sent 200.
    The temp file is always deleted (success, over-cap, error, or client
    disconnect). ``_db`` is unused; it keeps the call shape of the SSH path.
    """
    info = _DownloadInfo()
    chunks = _agent_download_chunks(system, path, audit_id, info)
    return _prime_download(chunks, info)


def _agent_download_chunks(
    system: System, path: str, audit_id: int, info: _DownloadInfo
) -> Iterator[bytes]:
    state = _TransferState()
    tmp_path: Optional[str] = None
    try:
        try:
            # 0600 spool file; deleted in finally. Allocation is inside the
            # protected block so a full or unwritable spool area is audited.
            try:
                fd, tmp_path = tempfile.mkstemp(
                    prefix="praxis-agent-dl-", suffix=".bin"
                )
                os.close(fd)
            except OSError as e:
                raise _stage_error(e) from e
            state.total, state.digest = _run_async_from_sync(
                _spool_agent_download(system, path, tmp_path)
            )
        except TransportUnavailable:
            raise
        except TransportError as e:
            raise _agent_transfer_error(path, e) from e
        info.size = state.total
        with open(tmp_path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                state.started = True
                yield chunk
        state.completed = True
    except GeneratorExit:
        state.error = "client_disconnected"
        raise
    except Exception as e:  # pylint: disable=broad-except
        # Fail closed like the SSH path: a broker truncation, short read, or
        # any other unexpected error marks the audit as an error, never as a
        # success on partial or absent data.
        state.fail(e)
        raise
    finally:
        try:
            if tmp_path is not None:
                os.remove(tmp_path)
        except OSError:
            pass
        state.finalize(audit_id)


def upload_stream(
    db: DbSession,
    user: User,
    system_id: int,
    remote_path: str,
    iterator: Iterator[bytes],
    *,
    local_filename: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> Dict[str, Any]:
    validate_remote_path(remote_path)
    system, login = _gate(db, user, system_id)

    # Resolve routing first so the audit row records the right
    # transport. force-agent + tunnel down → TransportUnavailable
    # bubbles after writing the rejection row.
    try:
        transport_name, transport = _run_async_from_sync(
            _resolve_file_transport(system, db)
        )
    except TransportUnavailable:
        audit = _open_audit(
            db,
            user=user,
            system=system,
            login=login,
            direction="upload",
            remote_path=remote_path,
            local_filename=local_filename,
            client_ip=client_ip,
            transport="agent",
        )
        _finish_audit(
            db,
            audit,
            status="error",
            error_message="transport_unavailable",
        )
        raise

    audit = _open_audit(
        db,
        user=user,
        system=system,
        login=login,
        direction="upload",
        remote_path=remote_path,
        local_filename=local_filename,
        client_ip=client_ip,
        transport=transport_name,
    )

    if transport_name == "ssh":
        return _upload_via_ssh(db, user, system, login, remote_path, iterator, audit)
    return _upload_via_agent(db, system, remote_path, iterator, audit)


def _sibling_tmp_path(remote_path: str) -> str:
    """PRA-254: a unique, hidden sibling temp path in the SAME directory as
    ``remote_path`` so the final atomic rename stays within one filesystem.

    ``remote_path`` is a validated absolute POSIX path. The random suffix makes
    concurrent uploads to the same destination collision-free.
    """
    remote_dir = posixpath.dirname(remote_path) or "/"
    base = posixpath.basename(remote_path) or "upload"
    return posixpath.join(
        remote_dir, f".praxis-upload-{base}-{os.urandom(8).hex()}.tmp"
    )


def _sftp_atomic_publish(sftp: Any, tmp_path: str, remote_path: str) -> None:
    """Publish the finished temp file over ``remote_path`` atomically.

    Prefer the OpenSSH ``posix-rename`` extension (``sftp.posix_rename``), which
    atomically REPLACES an existing destination in one operation — the existing
    file is never truncated or removed first. Fall back to plain ``sftp.rename``
    only when the extension is unavailable; note that classic SFTP ``rename`` may
    fail if the destination already exists, in which case we surface the error and
    leave the existing file intact (the caller then cleans up the temp file).
    """
    posix_rename = getattr(sftp, "posix_rename", None)
    if callable(posix_rename):
        posix_rename(tmp_path, remote_path)
    else:
        sftp.rename(tmp_path, remote_path)


def _sftp_best_effort_remove(sftp: Any, tmp_path: str) -> None:
    """Remove a temp upload artifact, swallowing errors — best effort so cleanup
    failures never mask the original error or leave the caller in a bad state."""
    try:
        sftp.remove(tmp_path)
    except Exception:  # pylint: disable=broad-except
        logger.warning("failed to remove temp upload artifact %s", tmp_path)


def _upload_via_ssh(
    db: DbSession,
    user: User,
    system: System,
    login: str,
    remote_path: str,
    iterator: Iterator[bytes],
    audit: FileTransferAudit,
) -> Dict[str, Any]:
    """PRA-254: failure-atomic SSH upload.

    Stream into a unique sibling temp file, enforce the size cap while writing,
    close/flush the temp handle, then publish over ``remote_path`` with an atomic
    rename ONLY after the whole upload succeeded. The final destination is never
    opened ``"wb"`` (which would truncate it before the upload is proven), so an
    oversize, an iterator/client error, a write/close failure, or a rename failure
    all leave any existing destination untouched. The temp file is removed on every
    failure path.
    """
    sha = hashlib.sha256()
    total = 0
    tmp_path = _sibling_tmp_path(remote_path)
    try:
        with _open_sftp(db, user, system, login) as sftp:
            published = False
            try:
                # Write ONLY the temp path. The final destination is left alone
                # until the atomic publish below.
                with sftp.open(tmp_path, "wb") as remote:
                    for chunk in iterator:
                        if not chunk:
                            continue
                        sha.update(chunk)
                        total += len(chunk)
                        if total > MAX_TRANSFER_BYTES:
                            raise FileTransferError("upload exceeded max size")
                        remote.write(chunk)
                # The temp handle is flushed + closed by the with-block above
                # before we publish.
                _sftp_atomic_publish(sftp, tmp_path, remote_path)
                published = True
            finally:
                # Any failure before a successful publish (cap, iterator, write,
                # close, or rename) leaves an orphan temp file — remove it while
                # the SFTP session is still open.
                if not published:
                    _sftp_best_effort_remove(sftp, tmp_path)
    except Exception as e:  # pylint: disable=broad-except
        _finish_audit(
            db,
            audit,
            status="error",
            size_bytes=total,
            error_message=str(e),
        )
        raise FileTransferError(f"upload failed: {e}") from e
    _finish_audit(
        db,
        audit,
        status="success",
        size_bytes=total,
        sha256=sha.hexdigest(),
    )
    return {
        "remote_path": remote_path,
        "size": total,
        "sha256": sha.hexdigest(),
    }


def _upload_via_agent(
    db: DbSession,
    system: System,
    remote_path: str,
    iterator: Iterator[bytes],
    audit: FileTransferAudit,
) -> Dict[str, Any]:
    """Agent-backed upload — buffers the body via the sync bridge then
    POSTs to the broker. Caller's sync iterator is fully consumed
    before the dispatch (true streaming through asyncio.run is a
    follow-up; the broker side already supports it).
    """
    sha = hashlib.sha256()
    body = bytearray()
    for chunk in iterator:
        if not chunk:
            continue
        sha.update(chunk)
        body.extend(chunk)
        # PRA-180 TRANSPORT-02: the agent bridge buffers the whole body in
        # memory, so enforce the tighter agent ceiling, not the 5 GiB SSH cap.
        if len(body) > AGENT_TRANSFER_MAX_BYTES:
            _finish_audit(
                db,
                audit,
                status="error",
                size_bytes=len(body),
                error_message="upload exceeded max size",
            )
            raise FileTransferError("upload exceeded max size")
    body_bytes = bytes(body)
    total = len(body_bytes)

    async def _send():
        # Skip the factory — same reasoning as _download_via_agent:
        # the audit row already says transport="agent", so a re-run
        # of get_transport that fell back to SSH on an in-flight
        # tunnel transition would lie about what happened.
        from .transport.agent import AgentTransport

        broker = BrokerClient()
        try:
            transport = AgentTransport(system, broker)
            stream = await transport.open_file_put(
                remote_path,
                size=total,
                overwrite=True,
            )

            async def _aiter():
                # One-shot — body already in memory.
                yield body_bytes

            agen = _aiter()
            async for chunk in agen:
                await stream.write(chunk)
            await stream.finish()
        finally:
            await broker.__aexit__(None, None, None)

    try:
        _run_async_from_sync(_send())
    except TransportError as e:
        _finish_audit(
            db,
            audit,
            status="error",
            size_bytes=total,
            error_message=str(e),
        )
        raise FileTransferError(f"upload failed: {e}") from e

    _finish_audit(
        db,
        audit,
        status="success",
        size_bytes=total,
        sha256=sha.hexdigest(),
    )
    return {
        "remote_path": remote_path,
        "size": total,
        "sha256": sha.hexdigest(),
    }


def mkdir(
    db: DbSession,
    user: User,
    system_id: int,
    path: str,
    *,
    client_ip: Optional[str] = None,
) -> None:
    validate_remote_path(path)
    system, login = _gate(db, user, system_id)
    _reject_force_agent_directory_op(
        db,
        user=user,
        system=system,
        login=login,
        direction="mkdir",
        remote_path=path,
        client_ip=client_ip,
    )
    audit = _open_audit(
        db,
        user=user,
        system=system,
        login=login,
        direction="mkdir",
        remote_path=path,
        client_ip=client_ip,
        transport="ssh",
    )
    try:
        with _open_sftp(db, user, system, login) as sftp:
            sftp.mkdir(path, mode=0o755)
    except Exception as e:  # pylint: disable=broad-except
        _finish_audit(db, audit, status="error", error_message=str(e))
        raise FileTransferError(f"mkdir failed: {e}") from e
    _finish_audit(db, audit, status="success")


def unlink(
    db: DbSession,
    user: User,
    system_id: int,
    path: str,
    *,
    client_ip: Optional[str] = None,
) -> None:
    validate_remote_path(path)
    system, login = _gate(db, user, system_id)
    _reject_force_agent_directory_op(
        db,
        user=user,
        system=system,
        login=login,
        direction="unlink",
        remote_path=path,
        client_ip=client_ip,
    )
    audit = _open_audit(
        db,
        user=user,
        system=system,
        login=login,
        direction="unlink",
        remote_path=path,
        client_ip=client_ip,
        transport="ssh",
    )
    try:
        with _open_sftp(db, user, system, login) as sftp:
            # Try rmdir first (succeeds for empty dirs); fall back to unlink.
            try:
                sftp.rmdir(path)
            except IOError:
                sftp.remove(path)
    except Exception as e:  # pylint: disable=broad-except
        _finish_audit(db, audit, status="error", error_message=str(e))
        raise FileTransferError(f"unlink failed: {e}") from e
    _finish_audit(db, audit, status="success")


# ------------------------------------------------------------------ query


def list_audits(
    db: DbSession,
    *,
    user_id: Optional[int] = None,
    system_id: Optional[int] = None,
    system_ids: Optional[set] = None,
    limit: int = 200,
) -> List[FileTransferAudit]:
    q = db.query(FileTransferAudit)
    if user_id is not None:
        q = q.filter(FileTransferAudit.user_id == user_id)
    if system_id is not None:
        q = q.filter(FileTransferAudit.system_id == system_id)
    # PRA-281: ``system_ids`` is the caller's fleet scope (None = tenant-wide
    # admin, unchanged). An empty set returns nothing; otherwise rows are
    # restricted to in-scope systems so out-of-scope transfers never leak.
    if system_ids is not None:
        if not system_ids:
            return []
        q = q.filter(FileTransferAudit.system_id.in_(system_ids))
    return q.order_by(FileTransferAudit.id.desc()).limit(limit).all()
