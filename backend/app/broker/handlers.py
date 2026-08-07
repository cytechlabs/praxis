"""WebSocket handlers for the agent broker.

Two handlers, one shared listener (path-dispatched in
``app.broker.main``):

  ``tunnel_handler``  /agent/tunnel — long-lived control WSS. mTLS
                       identity extraction, hello/welcome handshake,
                       AgentRegistry registration, heartbeat lifecycle,
                       routing of agent op_complete messages to the
                       OperationManager.
  ``op_handler``       /agent/op — short-lived per-op WSS. mTLS extract
                       + nonce redemption + op_attach + frame bridge to
                       the Operation's inbound/outbound queues.

Audit-event emission for tunnel + op lifecycle is still future work
(PRA-151 task #20).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import websockets
from websockets.exceptions import ConnectionClosed
from websockets.legacy.server import WebSocketServerProtocol

from .audit import (
    OP_ATTACHED,
    OP_REJECTED,
    TUNNEL_CERT_EXPIRED,
    TUNNEL_CONNECTED,
    TUNNEL_DISCONNECTED,
    TUNNEL_HEARTBEAT_DEAD,
    TUNNEL_REJECTED,
    TUNNEL_REPLACED,
    AuditEmit,
    default_audit_emit,
    emit_op_event,
    emit_tunnel_event,
)
from .ops import NonceExpired, NonceInvalid, OperationManager, OperationState
from .protocol import (
    CONTROL_WSS_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
    HEARTBEAT_DEAD_SECONDS,
    HEARTBEAT_INTERVAL_SECONDS,
    Frame,
    FrameError,
    HandshakeError,
    decode_frame,
    encode_frame,
    negotiate_capabilities,
    parse_hello,
)
from .registry import AgentRegistry, TunnelEntry, default_registry
from .tls import (
    PeerCertError,
    PeerIdentity,
    extract_peer_identity,
    format_fingerprint_for_wire,
    normalize_serial,
)

logger = logging.getLogger(__name__)


# Reason codes carried in close frames + audit events.
REJECT_NO_CERT = "no_peer_cert"
REJECT_BAD_CERT = "bad_peer_cert"
REJECT_NOT_ACTIVE = "system_not_active"
REJECT_FINGERPRINT_MISMATCH = "fingerprint_mismatch"
REJECT_SERIAL_MISMATCH = "serial_mismatch"

# Throttle DB writes for ``System.agent_last_seen_at`` so a chatty
# heartbeat loop doesn't generate one UPDATE per peer per 30s.
LAST_SEEN_DB_WRITE_THROTTLE_SECONDS = 60.0


class BrokerRejection(Exception):
    """Raised by handler internals to short-circuit with a reason code."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


async def tunnel_handler(
    ws: WebSocketServerProtocol,
    *,
    identity_validator,
    registry: Optional[AgentRegistry] = None,
    manager: Optional[OperationManager] = None,
    last_seen_writer=None,
    facts_writer=None,
    audit_emit: Optional[AuditEmit] = None,
    heartbeat_interval_seconds: float = HEARTBEAT_INTERVAL_SECONDS,
    heartbeat_dead_seconds: float = HEARTBEAT_DEAD_SECONDS,
    last_seen_throttle_seconds: float = LAST_SEEN_DB_WRITE_THROTTLE_SECONDS,
) -> None:
    """Handle a /agent/tunnel WSS connection through to disconnect.

    Pipeline:
        1. Extract peer cert from the underlying SSLObject.
        2. Parse URI SAN -> system_id, serial, fingerprint, NotAfter.
        3. ``identity_validator`` confirms System.agent_status='active',
           cert serial + fingerprint match, etc.
        4. Read the agent's first message and validate as a ``hello``.
        5. Send the spec-defined ``welcome``.
        6. Register in ``AgentRegistry`` (newest valid tunnel for a
           system_id wins; predecessor gets ``bye:replaced``).
        7. Run four concurrent loops until any completes:
             - recv_loop: bumps last_recv on any inbound frame
             - send_heartbeat_loop: every ``heartbeat_interval_seconds``
             - liveness_watchdog: closes after ``heartbeat_dead_seconds``
               of receive silence
             - cert_expiry_timer: closes at PeerIdentity.not_after
        8. Unregister + close cleanly.

    Injectable knobs (kept in the signature, not ad-hoc env reads, so
    tests can drive sub-second cadences):
      ``registry``                  defaults to the module-level singleton
      ``last_seen_writer``          callable(system_id, agent_version) for
                                    the throttled DB update of
                                    agent_last_seen_at + agent_version;
                                    defaults to a no-op so tests don't need
                                    a DB
      ``heartbeat_interval_seconds`` / ``heartbeat_dead_seconds`` /
      ``last_seen_throttle_seconds``
    """
    if registry is None:
        registry = default_registry
    if last_seen_writer is None:
        last_seen_writer = _noop_last_seen_writer
    if facts_writer is None:
        facts_writer = _noop_facts_writer
    if audit_emit is None:
        audit_emit = default_audit_emit
    if ws.path != "/agent/tunnel":
        await ws.close(code=4404, reason="unknown path")
        return

    # ---------- mTLS identity ----------
    identity: Optional[PeerIdentity] = None
    try:
        identity = _extract(ws)
        accepted = identity_validator(identity)
        if accepted is None:
            raise BrokerRejection(REJECT_NOT_ACTIVE, "identity not accepted")
    except BrokerRejection as rej:
        await _reject(ws, rej.code, rej.detail)
        emit_tunnel_event(
            audit_emit,
            TUNNEL_REJECTED,
            system_id=identity.system_id if identity else None,
            tunnel_session_id=None,
            outcome="denied",
            reason=rej.code,
        )
        return
    except PeerCertError as e:
        logger.warning("tunnel rejected: bad peer cert: %s", e)
        await ws.close(code=4001, reason=REJECT_BAD_CERT)
        emit_tunnel_event(
            audit_emit,
            TUNNEL_REJECTED,
            system_id=None,
            tunnel_session_id=None,
            outcome="denied",
            reason=REJECT_BAD_CERT,
            extra={"detail": str(e)},
        )
        return
    except Exception:  # pylint: disable=broad-except
        logger.exception("tunnel handler crashed during validation")
        await ws.close(code=1011, reason="internal error")
        emit_tunnel_event(
            audit_emit,
            TUNNEL_REJECTED,
            system_id=identity.system_id if identity else None,
            tunnel_session_id=None,
            outcome="failure",
            reason="internal_error",
        )
        return

    # ---------- protocol handshake ----------
    try:
        raw = await ws.recv()
    except ConnectionClosed:
        logger.info("tunnel closed before hello (system_id=%s)", identity.system_id)
        return

    try:
        hello = parse_hello(raw, expected_fingerprint=identity.fingerprint_sha256)
    except HandshakeError as e:
        logger.warning(
            "handshake rejected: code=%s detail=%s system_id=%s",
            e.code,
            e.detail,
            identity.system_id,
        )
        await ws.close(code=4001, reason=e.code)
        emit_tunnel_event(
            audit_emit,
            TUNNEL_REJECTED,
            system_id=identity.system_id,
            tunnel_session_id=None,
            outcome="denied",
            reason=e.code,
        )
        return

    accepted_caps = negotiate_capabilities(hello["capabilities"])

    welcome = {
        "type": "welcome",
        "system_id": accepted["system_id"],
        "tunnel_session_id": str(uuid.uuid4()),
        "cert_fingerprint": format_fingerprint_for_wire(identity.fingerprint_sha256),
        "cert_expires_at": identity.not_after.isoformat() + "Z",
        "accepted_capabilities": accepted_caps,
        "server_time": datetime.utcnow().isoformat() + "Z",
        "heartbeat_interval_seconds": HEARTBEAT_INTERVAL_SECONDS,
        "heartbeat_dead_seconds": HEARTBEAT_DEAD_SECONDS,
    }
    try:
        await ws.send(json.dumps(welcome))
    except ConnectionClosed:
        return

    # ---------- registration + lifecycle loops ----------
    entry = TunnelEntry(
        system_id=accepted["system_id"],
        tunnel_session_id=welcome["tunnel_session_id"],
        ws=ws,
        identity=identity,
        capabilities=accepted_caps,
        agent_version=hello["agent_version"],
    )
    displaced = await registry.register(entry)

    # Persist agent_last_seen_at + agent_version immediately on connect so
    # the status API reflects the fresh tunnel without waiting for the first
    # throttled heartbeat write (entry.last_db_write_monotonic starts at 0.0,
    # so this first call always fires). Subsequent writes are throttled.
    _maybe_write_last_seen(
        entry, last_seen_writer, last_seen_throttle_seconds, time.monotonic()
    )

    logger.info(
        "tunnel accepted: system_id=%s session=%s agent_version=%s caps=%s%s",
        identity.system_id,
        entry.tunnel_session_id,
        hello["agent_version"],
        accepted_caps,
        f" (replaced session={displaced.tunnel_session_id})" if displaced else "",
    )

    if displaced is not None:
        asyncio.create_task(_close_displaced(displaced))
        if manager is not None:
            asyncio.create_task(
                manager.terminalize_for_session(
                    displaced.tunnel_session_id, reason="tunnel_replaced"
                ),
                name=f"orphan_ops:{displaced.tunnel_session_id}",
            )
        emit_tunnel_event(
            audit_emit,
            TUNNEL_REPLACED,
            system_id=displaced.system_id,
            tunnel_session_id=displaced.tunnel_session_id,
            reason="replaced",
            extra={"replaced_by_session": entry.tunnel_session_id},
        )

    emit_tunnel_event(
        audit_emit,
        TUNNEL_CONNECTED,
        system_id=entry.system_id,
        tunnel_session_id=entry.tunnel_session_id,
        extra={"agent_version": hello["agent_version"]},
    )

    try:
        await _run_lifecycle(
            entry,
            heartbeat_interval_seconds=heartbeat_interval_seconds,
            heartbeat_dead_seconds=heartbeat_dead_seconds,
            last_seen_writer=last_seen_writer,
            last_seen_throttle_seconds=last_seen_throttle_seconds,
            manager=manager,
            audit_emit=audit_emit,
            facts_writer=facts_writer,
        )
    finally:
        # Cleanup is scoped to OUR tunnel_session_id, never the
        # system_id — that's the only way to avoid nuking ops belonging
        # to a tunnel that replaced us. Safe to call even when we were
        # already displaced; ops on the new session won't match.
        await registry.unregister(entry.system_id, entry.tunnel_session_id)
        if manager is not None:
            await manager.terminalize_for_session(
                entry.tunnel_session_id, reason="tunnel_closed"
            )
        if not ws.closed:
            with contextlib.suppress(ConnectionClosed):
                await ws.close(code=1000, reason="tunnel_done")
        duration_ms = int((time.monotonic() - entry.connected_at_monotonic) * 1000)
        emit_tunnel_event(
            audit_emit,
            TUNNEL_DISCONNECTED,
            system_id=entry.system_id,
            tunnel_session_id=entry.tunnel_session_id,
            duration_ms=duration_ms,
        )
        logger.info(
            "tunnel closed: system_id=%s session=%s",
            entry.system_id,
            entry.tunnel_session_id,
        )


async def _reject(ws: WebSocketServerProtocol, code: str, detail: str) -> None:
    """Log a rejection with full context and close the WSS uniformly."""
    logger.warning(
        "tunnel rejected: code=%s detail=%s remote=%s",
        code,
        detail,
        ws.remote_address,
    )
    # 4000-4999 are app-defined close codes per RFC 6455 §7.4.2.
    await ws.close(code=4001, reason=code)


# ----------------------------------------------------------------------
# Lifecycle (PRA-151 task #15)
# ----------------------------------------------------------------------


def _noop_last_seen_writer(
    system_id: int, agent_version: Optional[str] = None
) -> None:  # noqa: ARG001
    """Default last-seen writer: do nothing. Production wiring
    (``main._build_last_seen_writer``) supplies a SessionLocal-backed writer
    that stamps ``agent_last_seen_at`` + ``agent_version``; tests inject their
    own to assert call cadence."""


def _noop_facts_writer(system_id: int, payload: dict) -> None:  # noqa: ARG001
    """Default facts writer: do nothing. Production wiring in
    PRA-155 #2a supplies a SessionLocal-backed writer that funnels
    into ``FactsService.ingest`` with ``source_transport='agent'``.
    Tests inject their own to assert call shape."""


async def _run_lifecycle(
    entry: TunnelEntry,
    *,
    heartbeat_interval_seconds: float,
    heartbeat_dead_seconds: float,
    last_seen_writer,
    last_seen_throttle_seconds: float,
    manager: Optional[OperationManager] = None,
    audit_emit: AuditEmit = default_audit_emit,
    facts_writer=None,
) -> None:
    """Run all four loops concurrently until any one finishes; cancel the
    rest. Exceptions inside loops are logged and treated as terminating
    events so the handler always exits cleanly through the finally
    block."""
    if facts_writer is None:
        facts_writer = _noop_facts_writer
    loops = [
        asyncio.create_task(
            _recv_loop(
                entry,
                last_seen_writer,
                last_seen_throttle_seconds,
                manager,
                facts_writer,
            ),
            name=f"recv:{entry.system_id}",
        ),
        asyncio.create_task(
            _heartbeat_send_loop(entry, heartbeat_interval_seconds),
            name=f"hb_send:{entry.system_id}",
        ),
        asyncio.create_task(
            _liveness_watchdog(entry, heartbeat_dead_seconds, audit_emit),
            name=f"watchdog:{entry.system_id}",
        ),
    ]

    expiry_task = _maybe_schedule_cert_expiry(entry, audit_emit)
    if expiry_task is not None:
        loops.append(expiry_task)

    try:
        done, pending = await asyncio.wait(loops, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            exc = task.exception()
            if exc and not isinstance(exc, (ConnectionClosed, asyncio.CancelledError)):
                logger.warning("lifecycle loop %s raised: %r", task.get_name(), exc)
        for task in pending:
            task.cancel()
        # Drain cancellations so we don't leak warnings.
        await asyncio.gather(*pending, return_exceptions=True)
    except Exception:  # pylint: disable=broad-except
        logger.exception("tunnel lifecycle crashed system_id=%s", entry.system_id)


async def _recv_loop(
    entry: TunnelEntry,
    last_seen_writer,
    last_seen_throttle_seconds: float,
    manager: Optional[OperationManager],
    facts_writer=None,
) -> None:
    """Read inbound frames forever; bump ``last_recv_monotonic`` on any
    valid received frame.

    Routes:
      ``heartbeat``    no-op (liveness already covered by the bump)
      ``op_complete``  forward to the OperationManager — agent reports
                       op outcome (success / cancelled / error)
      ``facts_report`` PRA-155 #2a: forward the facts payload to
                       ``facts_writer`` keyed on ``entry.system_id``
                       (mTLS-validated). The agent CANNOT spoof
                       system_id via the message body — we ignore any
                       ``system_id`` field on the message.
      anything else    log + ignore (forward-compat; the spec reserves
                       the right to add new control types)

    Note: agent-originated ``op_cancel`` is NOT a thing in this spec.
    Agents abort by sending ``op_complete(outcome=cancelled|error)``.
    """
    if facts_writer is None:
        facts_writer = _noop_facts_writer
    while True:
        raw = await entry.ws.recv()  # raises ConnectionClosed on close
        now = time.monotonic()
        entry.last_recv_monotonic = now
        _maybe_write_last_seen(entry, last_seen_writer, last_seen_throttle_seconds, now)
        if not isinstance(raw, (str, bytes, bytearray)):
            continue
        # Tighter cap than the listener's max_size: control WSS only
        # carries small JSON. Listener is sized for per-op frames.
        if len(raw) > CONTROL_WSS_MAX_MESSAGE_BYTES:
            logger.warning(
                "control msg %d bytes exceeds %d cap on system_id=%s; closing",
                len(raw),
                CONTROL_WSS_MAX_MESSAGE_BYTES,
                entry.system_id,
            )
            with contextlib.suppress(ConnectionClosed):
                await entry.ws.close(code=1009, reason="control_msg_too_large")
            return
        try:
            msg = json.loads(raw)
        except (ValueError, TypeError):
            logger.debug(
                "non-JSON control frame on system_id=%s (len=%d)",
                entry.system_id,
                len(raw) if hasattr(raw, "__len__") else -1,
            )
            continue
        if not isinstance(msg, dict):
            continue
        msg_type = msg.get("type")
        if msg_type == "heartbeat":
            continue
        if msg_type == "op_complete" and manager is not None:
            await _route_op_complete(manager, entry.system_id, msg)
            continue
        if msg_type == "facts_report":
            _route_facts_report(facts_writer, entry.system_id, msg)
            continue
        logger.debug(
            "unhandled control msg type=%r system_id=%s", msg_type, entry.system_id
        )


def _route_facts_report(facts_writer, system_id: int, msg: dict) -> None:
    """Forward a facts_report control message to the writer.

    ``system_id`` is the mTLS-validated identity from the tunnel entry
    — anything in ``msg`` that looks like a ``system_id`` field is
    deliberately ignored. The writer receives only the facts payload
    portion (``msg`` minus the wire-protocol envelope keys).

    Writer exceptions are caught + logged so a malformed ingest can't
    take down the control tunnel. Inventory is best-effort; the next
    collection attempt will retry.
    """
    payload = {k: v for k, v in msg.items() if k not in {"type", "system_id"}}
    try:
        facts_writer(system_id, payload)
    except Exception:  # pylint: disable=broad-except
        logger.exception(
            "facts_report writer failed for system_id=%s; tunnel continues",
            system_id,
        )


async def _route_op_complete(
    manager: OperationManager, system_id: int, msg: dict
) -> None:
    op_id = msg.get("operation_id")
    if not isinstance(op_id, int):
        logger.warning(
            "op_complete missing/invalid operation_id from system_id=%s", system_id
        )
        return
    op = manager.get(op_id)
    if op is None or op.system_id != system_id:
        logger.warning(
            "op_complete for unknown op=%s from system_id=%s", op_id, system_id
        )
        return
    outcome = str(msg.get("outcome") or "completed")
    error = msg.get("error") if isinstance(msg.get("error"), dict) else None
    # Capture top-level op_complete fields (exit_code, duration_ms,
    # any future agent extras). Without this, AgentTransport can't
    # honour command-ledger semantics like nonzero-exit -> failed
    # because exit_code is dropped.
    result_metadata = {
        k: v
        for k, v in msg.items()
        if k not in {"type", "operation_id", "outcome", "error"}
    } or None
    try:
        await manager.complete(
            op_id,
            outcome=outcome,
            error=error,
            result_metadata=result_metadata,
        )
    except Exception:  # pylint: disable=broad-except
        logger.exception("manager.complete failed for op=%s", op_id)


async def _heartbeat_send_loop(
    entry: TunnelEntry, heartbeat_interval_seconds: float
) -> None:
    """Send ``{"type":"heartbeat","ts":...}`` every interval. Returns
    when the connection drops."""
    while True:
        await asyncio.sleep(heartbeat_interval_seconds)
        ts = datetime.utcnow().isoformat() + "Z"
        await entry.ws.send(json.dumps({"type": "heartbeat", "ts": ts}))
        entry.last_heartbeat_sent_monotonic = time.monotonic()


async def _liveness_watchdog(
    entry: TunnelEntry,
    heartbeat_dead_seconds: float,
    audit_emit: AuditEmit,
) -> None:
    """Close the tunnel after ``heartbeat_dead_seconds`` of receive
    silence. Polls every 1/5 of the dead window so detection latency
    stays predictable but doesn't burn CPU."""
    poll = max(1.0, heartbeat_dead_seconds / 5.0)
    while True:
        await asyncio.sleep(poll)
        idle = time.monotonic() - entry.last_recv_monotonic
        if idle >= heartbeat_dead_seconds:
            logger.warning(
                "tunnel dead by silence: system_id=%s idle=%.1fs",
                entry.system_id,
                idle,
            )
            with contextlib.suppress(ConnectionClosed):
                await entry.ws.send(
                    json.dumps({"type": "bye", "reason": "heartbeat_dead"})
                )
                await entry.ws.close(code=1011, reason="heartbeat_dead")
            emit_tunnel_event(
                audit_emit,
                TUNNEL_HEARTBEAT_DEAD,
                system_id=entry.system_id,
                tunnel_session_id=entry.tunnel_session_id,
                outcome="failure",
                reason="heartbeat_dead",
                extra={"idle_seconds": round(idle, 1)},
            )
            return


def _maybe_schedule_cert_expiry(
    entry: TunnelEntry, audit_emit: AuditEmit
) -> Optional[asyncio.Task]:
    """Schedule a one-shot close at ``identity.not_after``.

    The validator already rejected expired certs at connect, so under
    normal flow this fires near the cert TTL boundary (default 1h).
    Returns None when the cert is somehow already past expiry — in that
    case the watchdog will tear the tunnel down on its own pass.
    """
    not_after = entry.identity.not_after
    delay = (not_after - datetime.utcnow()).total_seconds()
    if delay <= 0:
        return None

    async def _close_at_expiry() -> None:
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            raise
        logger.info(
            "tunnel closing on cert expiry: system_id=%s session=%s not_after=%s",
            entry.system_id,
            entry.tunnel_session_id,
            not_after.isoformat(),
        )
        with contextlib.suppress(ConnectionClosed):
            await entry.ws.send(json.dumps({"type": "bye", "reason": "cert_expired"}))
            await entry.ws.close(code=1000, reason="cert_expired")
        emit_tunnel_event(
            audit_emit,
            TUNNEL_CERT_EXPIRED,
            system_id=entry.system_id,
            tunnel_session_id=entry.tunnel_session_id,
            outcome="failure",
            reason="cert_expired",
            extra={"not_after": not_after.isoformat() + "Z"},
        )

    return asyncio.create_task(
        _close_at_expiry(), name=f"cert_expiry:{entry.system_id}"
    )


# ----------------------------------------------------------------------
# /agent/op handler (PRA-151 task #16)
# ----------------------------------------------------------------------


REJECT_NO_TUNNEL = "no_active_tunnel"
REJECT_MISSING_NONCE = "missing_nonce"
REJECT_NONCE_INVALID = "nonce_invalid"
REJECT_NONCE_EXPIRED = "nonce_expired"
REJECT_ATTACH_MISMATCH = "attach_mismatch"
REJECT_ATTACH_NOT_JSON = "attach_not_json"


async def op_handler(
    ws: WebSocketServerProtocol,
    *,
    identity_validator,
    registry: Optional[AgentRegistry] = None,
    manager: Optional[OperationManager] = None,
    audit_emit: Optional[AuditEmit] = None,
    max_frame_payload: int = DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
) -> None:
    """Handle a /agent/op WSS connection — the per-operation stream.

    Pipeline:
        1. Path check + mTLS identity extraction (same as /agent/tunnel).
        2. Identity validator (DB lookup; same shape as tunnel).
        3. Confirm the system has an active control tunnel (defense in
           depth — orphan op WSS without a tunnel is suspect).
        4. Read X-Praxis-Op-Nonce header; ``manager.redeem_nonce`` does
           constant-time hash compare + system_id binding + TTL.
        5. First inbound frame must be JSON ``op_attach`` with the
           matching ``operation_id``.
        6. Bridge the WSS to the Operation's inbound/outbound queues
           until either side closes.
        7. On WSS close, ``manager.complete`` resolves the op (outcome
           defaults to "completed" if no op_complete already arrived
           via the control WSS).
    """
    if registry is None:
        registry = default_registry
    if audit_emit is None:
        audit_emit = default_audit_emit
    if manager is None:
        # Op handler must have a manager; misconfiguration not a runtime
        # condition.
        await ws.close(code=1011, reason="no_manager")
        return
    if ws.path != "/agent/op":
        await ws.close(code=4404, reason="unknown_path")
        return

    def _audit_op_reject(sys_id: Optional[int], code: str) -> None:
        # Op rejections happen before we redeem an op, so operation_id
        # is None — the system_id is still the best correlation we have.
        if sys_id is None:
            return
        emit_op_event(
            audit_emit,
            OP_REJECTED,
            system_id=sys_id,
            operation_id=None,
            outcome="denied",
            reason=code,
        )

    # ---------- mTLS identity ----------
    identity: Optional[PeerIdentity] = None
    try:
        identity = _extract(ws)
        accepted = identity_validator(identity)
        if accepted is None:
            raise BrokerRejection(REJECT_NOT_ACTIVE, "identity not accepted")
    except BrokerRejection as rej:
        await _reject(ws, rej.code, rej.detail)
        _audit_op_reject(identity.system_id if identity else None, rej.code)
        return
    except PeerCertError as e:
        logger.warning("op rejected: bad peer cert: %s", e)
        await ws.close(code=4001, reason=REJECT_BAD_CERT)
        _audit_op_reject(None, REJECT_BAD_CERT)
        return

    # ---------- defence-in-depth: agent must have a live control tunnel ----------
    if registry.get(identity.system_id) is None:
        await _reject(ws, REJECT_NO_TUNNEL, "no control tunnel for system")
        _audit_op_reject(identity.system_id, REJECT_NO_TUNNEL)
        return

    # ---------- nonce ----------
    nonce = ws.request_headers.get("X-Praxis-Op-Nonce")
    if not nonce:
        await _reject(ws, REJECT_MISSING_NONCE, "header missing")
        _audit_op_reject(identity.system_id, REJECT_MISSING_NONCE)
        return
    try:
        op = await manager.redeem_nonce(nonce, system_id=identity.system_id)
    except NonceExpired as e:
        await _reject(ws, REJECT_NONCE_EXPIRED, str(e))
        _audit_op_reject(identity.system_id, REJECT_NONCE_EXPIRED)
        return
    except NonceInvalid as e:
        await _reject(ws, REJECT_NONCE_INVALID, str(e))
        _audit_op_reject(identity.system_id, REJECT_NONCE_INVALID)
        return

    # ---------- op_attach ----------
    try:
        first = await ws.recv()
    except ConnectionClosed:
        await manager.complete(
            op.operation_id, outcome="error", error={"reason": "closed_before_attach"}
        )
        return
    try:
        attach = (
            json.loads(first) if isinstance(first, (str, bytes, bytearray)) else None
        )
    except (ValueError, TypeError):
        attach = None
    if (
        not isinstance(attach, dict)
        or attach.get("type") != "op_attach"
        or attach.get("operation_id") != op.operation_id
    ):
        await _reject(ws, REJECT_ATTACH_MISMATCH, "first message must be op_attach")
        emit_op_event(
            audit_emit,
            OP_REJECTED,
            system_id=identity.system_id,
            operation_id=op.operation_id,
            op_type=op.op_type,
            outcome="denied",
            reason=REJECT_ATTACH_MISMATCH,
        )
        await manager.complete(
            op.operation_id, outcome="error", error={"reason": "attach_mismatch"}
        )
        return

    # ---------- bridge ----------
    op.attached_ws = ws
    logger.info(
        "op attached: op=%s system=%s op_type=%s",
        op.operation_id,
        op.system_id,
        op.op_type,
    )
    emit_op_event(
        audit_emit,
        OP_ATTACHED,
        system_id=op.system_id,
        operation_id=op.operation_id,
        op_type=op.op_type,
        tunnel_session_id=op.tunnel_session_id,
    )
    bridge_error: Optional[Dict[str, Any]] = None
    try:
        bridge_error = await _run_op_bridge(ws, op, max_frame_payload=max_frame_payload)
    finally:
        # If we exited the bridge for any reason and the op isn't
        # already terminal, terminalise. Protocol violations
        # (bad_frame) become ERRORED so callers and audit don't see
        # them as success; clean exits become COMPLETED. The control
        # WSS may have already supplied a richer outcome via
        # op_complete.
        if op.state not in {
            OperationState.COMPLETED,
            OperationState.ERRORED,
            OperationState.CANCELLED,
            OperationState.EXPIRED,
        }:
            if bridge_error:
                await manager.complete(
                    op.operation_id, outcome="error", error=bridge_error
                )
            else:
                await manager.complete(op.operation_id, outcome="completed")


async def _run_op_bridge(
    ws: WebSocketServerProtocol, op, *, max_frame_payload: int
) -> Optional[Dict[str, Any]]:
    """Pump WS <-> queues until one side ends. Two child tasks; first
    one to finish cancels the other and we return.

    Returns a ``{"reason": ...}`` dict if the bridge exited because of
    a protocol violation (e.g. malformed inbound frame). Caller uses
    this to terminalise the op as ERRORED instead of COMPLETED. Returns
    ``None`` for clean exits (peer closed, sentinel, etc).
    """
    bad_frame_error: Dict[str, Any] = {}

    async def _pump_inbound() -> None:
        async for raw in ws:
            if not isinstance(raw, (bytes, bytearray, memoryview)):
                # Spec: per-op WSS frames are binary. Tolerate but
                # don't try to decode text frames.
                logger.debug(
                    "op=%s: ignoring text frame on per-op WSS", op.operation_id
                )
                continue
            try:
                frame = decode_frame(bytes(raw), max_payload=max_frame_payload)
            except FrameError as e:
                logger.warning(
                    "op=%s: bad frame %s; closing per-op WSS", op.operation_id, e
                )
                bad_frame_error["reason"] = "bad_frame"
                bad_frame_error["detail"] = str(e)
                with contextlib.suppress(ConnectionClosed):
                    await ws.close(code=1003, reason="bad_frame")
                return
            await op.inbound.put(frame)

    async def _pump_outbound() -> None:
        while True:
            frame = await op.outbound.get()
            if frame is None:  # sentinel: caller signals end
                return
            try:
                wire = encode_frame(frame, max_payload=max_frame_payload)
            except FrameError as e:
                logger.error(
                    "op=%s: refusing oversize/invalid outbound frame: %s",
                    op.operation_id,
                    e,
                )
                continue
            try:
                await ws.send(wire)
            except ConnectionClosed:
                return

    inbound_task = asyncio.create_task(_pump_inbound(), name=f"op_in:{op.operation_id}")
    outbound_task = asyncio.create_task(
        _pump_outbound(), name=f"op_out:{op.operation_id}"
    )
    done, pending = await asyncio.wait(
        [inbound_task, outbound_task], return_when=asyncio.FIRST_COMPLETED
    )
    for task in done:
        exc = task.exception()
        if exc and not isinstance(exc, (ConnectionClosed, asyncio.CancelledError)):
            logger.warning("op=%s: bridge task raised: %r", op.operation_id, exc)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)

    return bad_frame_error or None


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


async def _close_displaced(displaced: TunnelEntry) -> None:
    """Send ``bye:replaced`` to a tunnel that just lost the system_id
    slot to a newer connection, then close it. Errors are swallowed —
    the displaced socket may already be gone."""
    logger.info(
        "closing displaced tunnel: system_id=%s session=%s",
        displaced.system_id,
        displaced.tunnel_session_id,
    )
    with contextlib.suppress(ConnectionClosed, OSError):
        await displaced.ws.send(json.dumps({"type": "bye", "reason": "replaced"}))
        await displaced.ws.close(code=1000, reason="replaced")


def _maybe_write_last_seen(
    entry: TunnelEntry,
    last_seen_writer,
    throttle_seconds: float,
    now_monotonic: float,
) -> None:
    """Throttled wrapper around the DB writer. We don't want one UPDATE
    per heartbeat per agent — once a minute is plenty for ops UX."""
    if now_monotonic - entry.last_db_write_monotonic < throttle_seconds:
        return
    entry.last_db_write_monotonic = now_monotonic
    try:
        last_seen_writer(entry.system_id, entry.agent_version)
    except Exception:  # pylint: disable=broad-except
        logger.exception("last_seen_at writer failed system_id=%s", entry.system_id)


def _extract(ws: WebSocketServerProtocol) -> PeerIdentity:
    transport = ws.transport
    if transport is None:
        raise BrokerRejection(REJECT_NO_CERT, "no transport")
    ssl_object = transport.get_extra_info("ssl_object")
    if ssl_object is None:
        raise BrokerRejection(REJECT_NO_CERT, "not a TLS connection")
    return extract_peer_identity(ssl_object)


def make_db_validator(SessionLocal):
    """Build an ``identity_validator`` that consults the live DB.

    Returns a callable suitable for passing to ``tunnel_handler``. Each
    call opens its own short-lived SessionLocal to avoid sharing sessions
    across concurrent handlers.
    """

    def _validator(identity: PeerIdentity) -> Dict[str, Any]:
        from app.db.models import System  # pylint: disable=import-outside-toplevel

        db = SessionLocal()
        try:
            system = db.query(System).filter(System.id == identity.system_id).first()
            if system is None:
                raise BrokerRejection(
                    REJECT_NOT_ACTIVE, f"system {identity.system_id} not found"
                )
            if system.agent_status != "active":
                raise BrokerRejection(
                    REJECT_NOT_ACTIVE, f"agent_status={system.agent_status}"
                )
            db_serial = normalize_serial(system.agent_cert_serial)
            if db_serial != identity.serial_hex:
                # Vault returns serials in aa:bb:cc form; PRA-150 may have
                # written either form depending on path. Normalize before
                # comparing so real Vault-issued certs aren't falsely
                # rejected.
                raise BrokerRejection(
                    REJECT_SERIAL_MISMATCH,
                    f"db={db_serial!r} cert={identity.serial_hex!r}",
                )
            if system.agent_cert_fingerprint != identity.fingerprint_sha256:
                raise BrokerRejection(REJECT_FINGERPRINT_MISMATCH, "fp mismatch")
            return {"system_id": system.id, "hostname": system.hostname}
        finally:
            db.close()

    return _validator
