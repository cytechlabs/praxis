"""Interactive session service (PRA-140).

Opens and closes browser-to-host SSH terminal sessions. Uses the PRA-139
authorization gate to resolve who can do what, mints a short-lived
Vault-signed user cert with the chosen principal, opens a paramiko PTY
channel with ``invoke_shell``, and registers a ``SessionRuntime`` for the
WebSocket handler to plug into.

Responsibilities:
    * ``open_session(user, system_id, login=None)`` -> (Session row, runtime)
    * ``close_session(session_id, reason)`` -> close paramiko + update ledger
    * ``sweep_idle()`` / ``sweep_max_duration()`` -> background trimmers

Session approvals (fleet_role.session_requires_approval=True) are detected
but NOT yet handled in this effort — callers receive a ``approval_required``
PermissionDenied and should surface that clearly. Future work: a dedicated
SessionApproval workflow that mints an approval-backed binding and lets the
user retry once granted.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple

import paramiko
from sqlalchemy.orm import Session as DbSession

from ..db.access_models import FleetRole, HostUserState
from ..db.access_models import Session as SessionRow
from ..db.models import System, User
from . import session_runtime as runtime_registry
from .access_authorization_service import (
    PermissionDenied,
    authorize_action,
    cert_principal_for_user,
    has_fresh_totp,
)
from .session_runtime import SessionRuntime
from .ssh_service import configure_host_key_policy
from .vault_service import VaultService

logger = logging.getLogger(__name__)

DEFAULT_TERM = "xterm-256color"
DEFAULT_COLS = 120
DEFAULT_ROWS = 32


class SessionError(RuntimeError):
    """Generic session-open / close failure."""


class ApprovalRequired(SessionError):
    """Raised when ``open_session`` created (or reused) a pending approval.

    The attached ``approval_id`` lets the API layer return the row to the
    requester so the UI can poll until it's granted (PRA-147).
    """

    def __init__(self, approval_id: int, message: str = "approval pending"):
        super().__init__(message)
        self.approval_id = approval_id


def _resolve_ssh_port(db: DbSession, system: System) -> int:
    from ..db.models import SystemMetadata

    md = db.query(SystemMetadata).filter(SystemMetadata.system_id == system.id).first()
    return (md.ssh_port or 22) if md else 22


def _looks_like_auth_failure(exc: Exception) -> bool:
    """True when ``exc`` from ``client.connect`` looks like an sshd auth reject.

    Native sshd allow-list denials surface as authentication failures, so we
    only run the (bootstrap-connection) allow-list probe for these — never for
    timeouts, connection-refused, or host-key errors, which have their own
    honest messages and must be preserved.
    """
    if isinstance(exc, paramiko.AuthenticationException):
        return True
    text = str(exc).lower()
    return "authentication" in text or "publickey" in text


def _diagnose_allowlist_denial(
    db: DbSession, system: System, login: str, exc: Exception
) -> Optional[str]:
    """Return an actionable allow-list denial message, or ``None``.

    ``None`` means either the failure was not auth-shaped, the probe could not
    run, or the login is not actually blocked by an allow-list — in every one of
    those cases the caller keeps the original error rather than guessing.
    """
    if not _looks_like_auth_failure(exc):
        return None
    try:
        from .ssh_identity_service import SSHIdentityService

        diag = SSHIdentityService(db).diagnose_login_allowlist(system.id, login)
    except Exception as probe_err:  # pylint: disable=broad-except
        logger.warning(
            "allow-list diagnosis failed for %s on %s: %s",
            login,
            system.hostname,
            probe_err,
        )
        return None
    if not diag.checked or not diag.blocked or diag.denial is None:
        return None
    remediation = "; ".join(diag.remediation) if diag.remediation else ""
    msg = f"allowlist_denied: {diag.denial.message(system.hostname)}"
    if remediation:
        msg = f"{msg} Remediation: {remediation}"
    return msg


def open_session(
    db: DbSession,
    user: User,
    system_id: int,
    login: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> Tuple[SessionRow, SessionRuntime]:
    """Authorize, mint a cert, open the PTY, register the runtime."""
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise SessionError(f"system {system_id} not found")

    # --- authorization -----------------------------------------------------
    try:
        result = authorize_action(db, user, system, "session_open", login=login)
    except PermissionDenied as e:
        raise SessionError(f"{e.code}: {e.reason}") from e

    fleet_role: FleetRole = result.fleet_role
    effective_login = result.login

    # --- provisioning pre-flight -------------------------------------------
    # The login must be a Praxis-managed account that actually landed on the
    # host, else the Vault-signed cert authenticates against a user/principal
    # that sshd has never heard of and the connect fails with an opaque
    # "Authentication failed". Check the host_user_states ledger first and
    # raise an actionable error instead. (A granted login that was never
    # provisioned on the host would otherwise error opaquely on every session.)
    #
    # This runs BEFORE approval consumption/creation so a missing account
    # never burns a granted approval or spawns an approval request for a
    # session that can't open (PRA-147 ordering).
    host_user = (
        db.query(HostUserState)
        .filter(
            HostUserState.system_id == system.id,
            HostUserState.login == effective_login,
        )
        .first()
    )
    if host_user is None or host_user.state != "provisioned":
        state_desc = "not provisioned" if host_user is None else host_user.state
        raise SessionError(
            f"not_provisioned: account '{effective_login}' is {state_desc} on "
            f"{system.hostname}. Provision it on this host before opening a "
            f"session (Fleet → host → Provision)."
        )

    if result.requires_approval:
        # PRA-147: try to consume an existing granted approval matching
        # the (requester, system, fleet role, login) tuple. If none, fall
        # through to creating a fresh pending row and bouncing the caller.
        from . import session_approval_service

        usable = session_approval_service.find_usable_grant(
            db,
            requester_id=user.id,
            system_id=system.id,
            fleet_role_id=result.fleet_role.id,
            login=result.login,
        )
        if usable is not None:
            session_approval_service.consume(db, approval=usable)
        else:
            # If a pending request already exists for the same tuple, reuse
            # its id rather than spamming the approver queue with dupes.
            from ..db.access_models import SessionApproval

            existing = (
                db.query(SessionApproval)
                .filter(
                    SessionApproval.requester_id == user.id,
                    SessionApproval.system_id == system.id,
                    SessionApproval.fleet_role_id == result.fleet_role.id,
                    SessionApproval.login == result.login,
                    SessionApproval.state == "pending",
                )
                .order_by(SessionApproval.id.desc())
                .first()
            )
            if existing is not None:
                raise ApprovalRequired(existing.id)
            new_row = session_approval_service.request_approval(
                db,
                requester=user,
                system_id=system.id,
                fleet_role_id=result.fleet_role.id,
                login=result.login,
                actor_ip=client_ip,
            )
            raise ApprovalRequired(new_row.id)
    if result.requires_totp and not has_fresh_totp(db, user.id):
        raise SessionError("totp_required: step up via Security settings")

    # --- cert mint ---------------------------------------------------------
    # PRA-287: use the conservative (strictest/shortest) session ceiling across all
    # allowing roles for this login, not just the representative role's value, so a
    # looser role sharing the login cannot lengthen the session.
    ttl = int(result.max_session_s or 3600)
    key_id = f"praxis-session-{user.id}-{system.id}-{int(time.time())}"
    pkey = paramiko.RSAKey.generate(2048)
    pub_openssh = f"{pkey.get_name()} {pkey.get_base64()}"
    # PRA-288: sign with the IMMUTABLE Praxis user principal (not the shared Linux
    # login) so the host principals file authorizes this specific user; the SSH
    # connection below still uses the Linux login as the username.
    cert_principal = cert_principal_for_user(user)
    vault = VaultService(db)
    try:
        signed = vault.sign_ssh_user_cert(
            public_key=pub_openssh,
            principal=cert_principal,
            ttl_seconds=ttl,
            key_id=key_id,
        )
    except Exception as e:  # pylint: disable=broad-except
        raise SessionError(f"cert_mint_failed: {e}") from e
    # PRA-219: audit the user-cert issuance at mint time (before the SSH
    # connect, so a later connection failure still leaves the PKI record).
    from .audit_event_service import emit_user_cert_sign

    emit_user_cert_sign(
        db,
        actor_user_id=user.id,
        actor_username=user.username,
        actor_ip=client_ip,
        system_id=system.id,
        login=effective_login,
        ttl_s=ttl,
        key_id=key_id,
        purpose="session",
    )
    pkey.load_certificate(signed)

    # --- persistent row (status=opening) ----------------------------------
    max_expires = datetime.utcnow() + timedelta(seconds=ttl)
    row = SessionRow(
        user_id=user.id,
        system_id=system.id,
        fleet_role_id=fleet_role.id,
        login=effective_login,
        cert_serial=key_id,
        client_ip=client_ip,
        status="opening",
        started_at=datetime.utcnow(),
        max_expires_at=max_expires,
        # PRA-287: persist the conservative (longest) recording retention across all
        # allowing roles so recording_service enforces it, not the representative
        # role's value.
        recording_retention_days=result.recording_retention_days,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # --- paramiko transport + PTY -----------------------------------------
    port = _resolve_ssh_port(db, system)
    client = paramiko.SSHClient()
    try:
        # Enforce the system's host-key verification policy (PRA-245); a
        # mismatch/unknown key (or unsupported stored key) fails the connect,
        # handled by the except below as a session error.
        configure_host_key_policy(client, db, system)
        client.connect(
            hostname=str(system.ip_address),
            port=port,
            username=effective_login,
            pkey=pkey,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
    except Exception as e:  # pylint: disable=broad-except
        # PRA-234: a Vault-signed cert that authenticates fine can still be
        # rejected by native sshd account allow-lists (AllowUsers/AllowGroups)
        # *before* the cert is evaluated — paramiko only sees a generic
        # "Authentication (publickey) failed". If this looks like an auth
        # failure, run a bounded, read-only allow-list probe and surface the
        # real cause + remediation instead of the opaque message. The probe
        # must never mask the original error if it can't run.
        diag_msg = _diagnose_allowlist_denial(db, system, effective_login, e)
        detail = diag_msg or f"ssh_connect_failed: {e}"
        row.status = "errored"
        row.close_reason = f"ssh_connect: {e}"[:2000]
        row.ended_at = datetime.utcnow()
        db.commit()
        raise SessionError(detail) from e

    transport = client.get_transport()
    try:
        channel = client.invoke_shell(
            term=DEFAULT_TERM, width=DEFAULT_COLS, height=DEFAULT_ROWS
        )
    except Exception as e:  # pylint: disable=broad-except
        row.status = "errored"
        row.close_reason = f"invoke_shell: {e}"
        row.ended_at = datetime.utcnow()
        db.commit()
        try:
            client.close()
        except Exception:  # pylint: disable=broad-except
            pass
        raise SessionError(f"invoke_shell_failed: {e}") from e

    runtime = SessionRuntime(
        session_id=row.id,
        transport=transport,
        channel=channel,
        max_expires_at=max_expires,
    )
    runtime.set_on_close(_on_runtime_close)
    runtime_registry.register(runtime)

    # PRA-141: attach a recording writer to the runtime. Idempotent failure —
    # a broken writer must not block the user getting into their shell, but
    # we log at ERROR (not WARNING) with exc_info so silent misconfigurations
    # like a non-writable RECORDINGS_DIR actually surface in ops logs.
    try:
        from .recording_service import start_recording

        start_recording(db, runtime, width=DEFAULT_COLS, height=DEFAULT_ROWS)
    except Exception as e:  # pylint: disable=broad-except
        logger.error(
            "recording attach failed for session %d: %s", row.id, e, exc_info=True
        )

    row.status = "active"
    row.last_activity_at = datetime.utcnow()
    db.commit()
    db.refresh(row)

    logger.info(
        "session %d opened: user=%d system=%s login=%s ttl=%ds",
        row.id,
        user.id,
        system.hostname,
        effective_login,
        ttl,
    )
    try:
        from .audit_event_service import safe_emit

        safe_emit(
            db=db,
            action="session.open",
            actor_user_id=user.id,
            actor_username=user.username,
            actor_ip=client_ip,
            target_system_id=system.id,
            target_kind="session",
            target_id=str(row.id),
            context={
                "login": effective_login,
                "fleet_role": fleet_role.name,
                "cert_serial": key_id,
                "ttl_s": ttl,
            },
        )
    except Exception:  # pylint: disable=broad-except
        pass
    return row, runtime


def close_session(
    db: DbSession, session_id: int, reason: str = "client_close"
) -> Optional[SessionRow]:
    """Close an active session and update the DB row."""
    row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
    if row is None:
        return None
    rt = runtime_registry.get(session_id)
    if rt is not None:
        rt.close(reason=reason)
        runtime_registry.drop(session_id)
    if row.status in ("opening", "active"):
        row.status = "closed"
        row.close_reason = reason
        row.ended_at = datetime.utcnow()
        db.commit()
        db.refresh(row)
    # Finalize the recording writer even if the runtime was already torn
    # down by the remote side — idempotent.
    try:
        from .recording_service import stop_recording

        stop_recording(db, session_id)
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("stop_recording failed: %s", e)
    return row


def _on_runtime_close(session_id: int, reason: str) -> None:
    """Callback from the runtime when the remote side hangs up."""
    from ..db.session import SessionLocal
    from .audit_event_service import safe_emit
    from .recording_service import stop_recording

    db = SessionLocal()
    try:
        row = db.query(SessionRow).filter(SessionRow.id == session_id).first()
        if row is not None and row.status in ("opening", "active"):
            row.status = "closed" if reason == "client_close" else reason
            row.close_reason = reason
            row.ended_at = datetime.utcnow()
            db.commit()
            # Map close reasons to distinct audit actions so SIEM rules can
            # filter forced-close events from normal termination.
            # admin_force is emitted at the API layer with the operator as
            # actor, so we suppress the runtime-level event to avoid dupes.
            if reason != "admin_force":
                action = {
                    "idle_kill": "session.idle_kill",
                    "max_duration": "session.max_duration",
                }.get(reason, "session.close")
                try:
                    safe_emit(
                        db=db,
                        action=action,
                        actor_user_id=row.user_id,
                        target_system_id=row.system_id,
                        target_kind="session",
                        target_id=str(row.id),
                        context={"reason": reason, "login": row.login},
                    )
                except Exception:  # pylint: disable=broad-except
                    pass
        try:
            stop_recording(db, session_id)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("stop_recording failed: %s", e)
    except Exception as e:  # pylint: disable=broad-except
        logger.warning("on_close db update failed: %s", e)
    finally:
        db.close()
    runtime_registry.drop(session_id)


# ---------------------------------------------------------------- sweepers


def sweep_idle(db: Optional[DbSession] = None, idle_seconds: int = 900) -> int:
    """Close sessions with no input in the last ``idle_seconds``.

    Uses each runtime's ``last_activity`` monotonic timestamp (PTY-level),
    not the DB column, so keypress freshness is reflected immediately.
    """
    now = time.monotonic()
    closed = 0
    for rt in runtime_registry.list_active():
        if rt.closed.is_set():
            continue
        if now - rt.last_activity > idle_seconds:
            rt.close(reason="idle_kill")
            closed += 1
    return closed


def sweep_max_duration(db: Optional[DbSession] = None) -> int:
    """Close sessions past their ``max_expires_at``."""
    now = datetime.utcnow()
    closed = 0
    for rt in runtime_registry.list_active():
        if rt.closed.is_set():
            continue
        if rt.max_expires_at <= now:
            rt.close(reason="max_duration")
            closed += 1
    return closed
