"""PRA-151 task #20: broker audit event vocabulary + emitter wiring.

Wraps ``audit_event_service.safe_emit`` so audit failures never break
broker control or op traffic. Tests inject their own ``audit_emit``
callable; the broker process uses ``default_audit_emit`` which
delegates to safe_emit.

Event vocabulary (lifecycle edges only — heartbeats and per-frame
traffic are intentionally not audited):

  Tunnel
    agent.tunnel.connected         welcome sent + registered
    agent.tunnel.disconnected      clean close (carries duration_ms)
    agent.tunnel.replaced          old session displaced by newer
    agent.tunnel.rejected          identity validation or handshake failed
    agent.tunnel.heartbeat_dead    tunnel torn down for receive silence
    agent.tunnel.cert_expired      cert NotAfter timer fired

  Op
    agent.op.requested             backend created an op + issued nonce
    agent.op.attached              agent dialed /agent/op + op_attach matched
    agent.op.rejected              attach/nonce/auth failed before stream
    agent.op.cancel_requested      backend sent op_cancel
    agent.op.completed             terminal — outcome carries
                                   success / cancelled / error / errored / expired

Stable correlation fields per event (where available):
    system_id, tunnel_session_id, operation_id, op_type, reason,
    outcome, duration_ms

Never logged in audit context: raw nonce, private key bytes, full cert
PEMs, request headers.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


# ---------- tunnel actions ----------
TUNNEL_CONNECTED = "agent.tunnel.connected"
TUNNEL_DISCONNECTED = "agent.tunnel.disconnected"
TUNNEL_REPLACED = "agent.tunnel.replaced"
TUNNEL_REJECTED = "agent.tunnel.rejected"
TUNNEL_HEARTBEAT_DEAD = "agent.tunnel.heartbeat_dead"
TUNNEL_CERT_EXPIRED = "agent.tunnel.cert_expired"

# ---------- op actions ----------
OP_REQUESTED = "agent.op.requested"
OP_ATTACHED = "agent.op.attached"
OP_REJECTED = "agent.op.rejected"
OP_CANCEL_REQUESTED = "agent.op.cancel_requested"
OP_COMPLETED = "agent.op.completed"


# Type alias: kwargs go through safe_emit so we accept its signature
# verbatim. Action + outcome + target_kind + target_system_id +
# target_id + context dict.
AuditEmit = Callable[..., None]


def default_audit_emit(**kwargs: Any) -> None:
    """Default emitter — delegates to ``audit_event_service.safe_emit``.

    Lazy import: keeps the broker package importable without dragging
    in the full app.services tree at module load (matters for unit
    tests that monkey-patch around the audit path).
    """
    try:
        from app.services.audit_event_service import safe_emit  # noqa: PLC0415

        safe_emit(**kwargs)
    except Exception:  # pylint: disable=broad-except
        # safe_emit already swallows internally; this outer guard is
        # belt-and-suspenders for the import path.
        logger.exception("audit emit failed; continuing")


def emit_tunnel_event(
    audit_emit: AuditEmit,
    action: str,
    *,
    system_id: Optional[int],
    tunnel_session_id: Optional[str],
    outcome: str = "success",
    reason: Optional[str] = None,
    duration_ms: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit a tunnel.* event with the standard correlation fields."""
    context: Dict[str, Any] = {}
    if tunnel_session_id is not None:
        context["tunnel_session_id"] = tunnel_session_id
    if reason is not None:
        context["reason"] = reason
    if duration_ms is not None:
        context["duration_ms"] = duration_ms
    if extra:
        context.update(extra)
    try:
        audit_emit(
            action=action,
            outcome=outcome,
            target_kind="system" if system_id is not None else None,
            target_system_id=system_id,
            target_id=str(system_id) if system_id is not None else None,
            context=context,
        )
    except Exception:  # pylint: disable=broad-except
        logger.exception("tunnel audit emit failed: %s", action)


def emit_op_event(
    audit_emit: AuditEmit,
    action: str,
    *,
    system_id: int,
    operation_id: Optional[int],
    op_type: Optional[str] = None,
    tunnel_session_id: Optional[str] = None,
    outcome: str = "success",
    reason: Optional[str] = None,
    duration_ms: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit an op.* event with the standard correlation fields."""
    context: Dict[str, Any] = {}
    if operation_id is not None:
        context["operation_id"] = operation_id
    if op_type is not None:
        context["op_type"] = op_type
    if tunnel_session_id is not None:
        context["tunnel_session_id"] = tunnel_session_id
    if reason is not None:
        context["reason"] = reason
    if duration_ms is not None:
        context["duration_ms"] = duration_ms
    if extra:
        context.update(extra)
    target_id = f"op:{operation_id}" if operation_id is not None else str(system_id)
    try:
        audit_emit(
            action=action,
            outcome=outcome,
            target_kind="system",
            target_system_id=system_id,
            target_id=target_id,
            context=context,
        )
    except Exception:  # pylint: disable=broad-except
        logger.exception("op audit emit failed: %s", action)
