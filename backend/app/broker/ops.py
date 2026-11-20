"""PRA-151 task #16: operation lifecycle + per-op nonce manager.

The OperationManager is the seam between "backend wants to run X on a
host" and "agent dials a per-op WSS, attaches, and streams". It owns:

* nonce minting (raw token only in transit; SHA-256 hash stored)
* per-agent limits (concurrent ops, in-flight nonces)
* op state machine
* dispatching ``op_request`` + ``op_nonce`` over the agent's existing
  control WSS via the registry
* ``op_cancel`` flow (backend-initiated; non-terminal until the agent
  acknowledges with ``op_complete(cancelled)`` or the cancel timeout
  fires)
* clean teardown of orphan ops when a control tunnel disconnects or is
  replaced

Real op execution (exec, pty, file) is NOT implemented here — the
manager just bridges the WS to per-op asyncio queues. Callers
(eventually the main backend; for #16 the tests) drive ops by reading
``op.inbound`` and writing to ``op.outbound``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from websockets.exceptions import ConnectionClosed
from websockets.legacy.server import WebSocketServerProtocol

from .audit import (
    OP_CANCEL_REQUESTED,
    OP_COMPLETED,
    OP_REQUESTED,
    TUNNEL_EVICTED,
    AuditEmit,
    default_audit_emit,
    emit_op_event,
    emit_tunnel_event,
)
from .protocol import Frame
from .registry import AgentRegistry, TunnelEntry

logger = logging.getLogger(__name__)


class OperationState(str, Enum):
    PENDING_NONCE = "pending_nonce"
    ATTACHED = "attached"
    CANCELLING = "cancelling"  # op_cancel sent, waiting for agent op_complete
    COMPLETED = "completed"
    ERRORED = "errored"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


TERMINAL_STATES = frozenset(
    {
        OperationState.COMPLETED,
        OperationState.ERRORED,
        OperationState.CANCELLED,
        OperationState.EXPIRED,
    }
)


# --------- exceptions ------------------------------------------------------


class OperationError(Exception):
    """Base class for caller-facing op failures."""


class NoActiveTunnel(OperationError):
    pass


class ConcurrentOpsExceeded(OperationError):
    pass


class NonceLimitExceeded(OperationError):
    pass


class NonceInvalid(OperationError):
    """Lookup failure or already-redeemed."""


class NonceExpired(OperationError):
    pass


class OpNotFound(OperationError):
    pass


class AgentNotAuthorized(OperationError):
    """The committed identity state no longer authorizes this agent (or it
    could not be verified). ``code`` is a short reason; ``unverifiable`` marks
    the fail-closed case where the state could not be read."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

    @property
    def unverifiable(self) -> bool:
        return self.code == REASON_UNVERIFIABLE


# Reason code for a status lookup that failed or timed out. Treated as "not
# authorized": the broker never assumes an agent is still allowed.
REASON_UNVERIFIABLE = "identity_unverifiable"

# Termination vocabulary reported for an op interrupted by eviction.
TERMINATION_CONFIRMED = "confirmed"  # agent verified the process group is gone
TERMINATION_NOT_STARTED = "not_started"  # no process was ever started
TERMINATION_UNCONFIRMED = "unconfirmed"  # outcome of the process is unknown
TERMINATION_NOT_APPLICABLE = "not_applicable"  # op has no process
_PROCESS_OP_TYPES = frozenset({"exec", "pty"})


# --------- data ------------------------------------------------------------


@dataclass
class Operation:
    operation_id: int
    system_id: int
    # The control tunnel's session id at the moment of dispatch. Used
    # to scope cleanup so a displaced tunnel's late teardown does NOT
    # nuke ops dispatched on the replacement tunnel for the same
    # system_id.
    tunnel_session_id: str
    op_type: str
    params: dict
    state: OperationState
    created_at_monotonic: float
    nonce_expires_at_monotonic: float
    inbound: "asyncio.Queue[Frame]" = field(default_factory=asyncio.Queue)
    outbound: "asyncio.Queue[Frame]" = field(default_factory=asyncio.Queue)
    completion: "asyncio.Future" = field(default=None)  # type: ignore[assignment]
    # WSS this op is attached to (set in op_handler after op_attach).
    attached_ws: Optional[WebSocketServerProtocol] = None
    # When the manager initiated cancel; used for the cancel timeout.
    cancel_requested_at_monotonic: Optional[float] = None
    outcome: Optional[str] = None
    error: Optional[dict] = None
    # Top-level op_complete fields beyond outcome/error. The agent's
    # success message carries exit_code + duration_ms here (PRA-152
    # task #4 op_complete shape); without preserving them the
    # internal exec endpoint can't surface them to AgentTransport.
    # Keys are populated from the routed op_complete msg in
    # ``_route_op_complete``; unknown agents that send extra fields
    # have them captured too without code changes.
    result_metadata: Optional[dict] = None
    # When True, ``_terminalize`` skips injecting a ``None`` sentinel
    # into ``op.inbound``. Streaming endpoints (PRA-153 file_get)
    # set this so the pump doesn't exit prematurely when control-WSS
    # op_complete arrives ahead of the per-op WSS having delivered
    # all FILE Data + CLOSE frames. Those endpoints own EOF via their
    # own protocol-level signal (FILE CLOSE → body_queue None) and
    # tear the pump down themselves when the body iterator finishes.
    skip_terminal_sentinel: bool = False
    # Set when eviction interrupts this op. Terminalization then reports
    # ``agent_revoked`` / ``agent_revoked_unconfirmed`` plus ``termination``.
    revocation_reason: Optional[str] = None
    termination: Optional[str] = None
    # True when the agent echoed ``await_ready`` in op_attach and so will not
    # start work until the broker sends op_ready.
    agent_gated: bool = False


# --------- manager ---------------------------------------------------------


class OperationManager:
    """Per-process op + nonce state. Single asyncio.Lock guards all
    mutations; the broker is single-process by design (PRA-151 listener
    decision)."""

    def __init__(
        self,
        registry: AgentRegistry,
        *,
        nonce_ttl_seconds: float = 30.0,
        max_inflight_nonces_per_agent: int = 32,
        max_concurrent_ops_per_agent: int = 16,
        cancel_ack_timeout_seconds: float = 10.0,
        evict_ack_timeout_seconds: float = 5.0,
        evict_total_timeout_seconds: float = 10.0,
        evict_io_timeout_seconds: float = 2.0,
        authorize_timeout_seconds: float = 5.0,
        audit_emit: Optional[AuditEmit] = None,
    ) -> None:
        self._registry = registry
        self._nonce_ttl = nonce_ttl_seconds
        self._max_nonces = max_inflight_nonces_per_agent
        self._max_concurrent = max_concurrent_ops_per_agent
        self._cancel_timeout = cancel_ack_timeout_seconds
        self._evict_ack_timeout = evict_ack_timeout_seconds
        self._evict_total_timeout = evict_total_timeout_seconds
        self._evict_io_timeout = evict_io_timeout_seconds
        # Entries whose eviction is still draining. They are no longer in the
        # registry (dispatch is fenced), but a retried signal must observe the
        # pending eviction rather than report no_session.
        self._draining: Dict[int, TunnelEntry] = {}
        self._authorize_timeout = authorize_timeout_seconds
        self._audit_emit: AuditEmit = audit_emit or default_audit_emit
        self._lock = asyncio.Lock()
        self._ops: Dict[int, Operation] = {}
        self._nonce_to_op: Dict[str, int] = {}  # SHA-256 hex -> operation_id
        self._next_id = 1

    # ----- public ---------

    async def create_and_dispatch(
        self,
        system_id: int,
        op_type: str,
        params: Optional[dict] = None,
        *,
        outbound_maxsize: int = 0,
        inbound_maxsize: int = 0,
        skip_terminal_sentinel: bool = False,
    ) -> Tuple[Operation, str]:
        """Create an op + nonce, push op_request and op_nonce to the
        agent over its control WSS. Returns (op, raw_nonce) so callers
        in tests can drive the agent side; in production the backend
        only keeps the op handle and the raw nonce never leaves this
        function (it travels straight to the agent over WSS).

        ``outbound_maxsize`` / ``inbound_maxsize`` bound the per-op
        queues (default 0 = unbounded). Callers streaming into the
        per-op WSS (PRA-153 file_put) bound outbound; callers
        streaming OUT of it to a slow consumer (PRA-153 file_get with
        a slow HTTP reader) bound inbound. The bridge ``_pump_inbound``
        / ``_pump_outbound`` use ``await put()`` / ``await get()`` so
        bounded queues automatically backpressure all the way to TCP.
        """
        params = params or {}
        tunnel = self._registry.get(system_id)
        if tunnel is None or tunnel.evicted:
            raise NoActiveTunnel(f"no control tunnel for system {system_id}")

        # Authority is the committed identity row, re-read per dispatch. A
        # status the broker cannot read is a refusal, never a pass.
        denied = await self.authorize_tunnel(tunnel)
        if denied is not None:
            raise AgentNotAuthorized(denied)

        async with self._lock:
            # Re-check under the lock: eviction sets ``evicted`` before it takes
            # this lock to collect ops, so an op registered here is either seen
            # by eviction or refused here.
            if self._registry.get(system_id) is not tunnel or tunnel.evicted:
                raise NoActiveTunnel(f"no control tunnel for system {system_id}")

            expired_during_sweep = self._enforce_limits_locked(system_id)

            op_id = self._next_id
            self._next_id += 1
            now = time.monotonic()
            op = Operation(
                operation_id=op_id,
                system_id=system_id,
                tunnel_session_id=tunnel.tunnel_session_id,
                op_type=op_type,
                params=dict(params),
                state=OperationState.PENDING_NONCE,
                created_at_monotonic=now,
                nonce_expires_at_monotonic=now + self._nonce_ttl,
                completion=asyncio.get_running_loop().create_future(),
                skip_terminal_sentinel=skip_terminal_sentinel,
            )
            # Replace inbound/outbound with bounded queues when
            # requested. Safe at this point: op is in PENDING_NONCE,
            # the agent has not dialed /agent/op yet (we haven't sent
            # op_request below), so no one is consuming the queues.
            if outbound_maxsize > 0:
                op.outbound = asyncio.Queue(maxsize=outbound_maxsize)
            if inbound_maxsize > 0:
                op.inbound = asyncio.Queue(maxsize=inbound_maxsize)
            raw_nonce = self._issue_nonce_locked(op)
            self._ops[op_id] = op

        # Audit-emit any ops that were swept by the lazy expiry pass.
        # Done outside the lock so a slow audit sink can't stall
        # legitimate dispatches.
        for stale in expired_during_sweep:
            self._emit_op_completed(stale, outcome="expired")

        # Send the two control messages outside the manager lock so a slow WS
        # doesn't block the manager, but inside the tunnel's send lock: eviction
        # takes the same lock to send op_cancel, so a cancel can never reach the
        # agent ahead of the op_request it refers to, and a dispatch that lost
        # the race to eviction sends nothing at all.
        try:
            async with tunnel.send_lock:
                if tunnel.evicted:
                    op.revocation_reason = tunnel.evict_reason or "not_active"
                    op.termination = TERMINATION_NOT_STARTED
                    await self._terminalize(
                        op, OperationState.ERRORED, error={"reason": "agent_revoked"}
                    )
                    raise AgentNotAuthorized("agent_not_active")
                await tunnel.ws.send(
                    json.dumps(
                        {
                            "type": "op_request",
                            "operation_id": op.operation_id,
                            "op_type": op.op_type,
                            "params": op.params,
                            "transport": "per_op_wss",
                            "nonce_expires_in_s": int(self._nonce_ttl),
                            "await_ready": True,
                        }
                    )
                )
                await tunnel.ws.send(
                    json.dumps(
                        {
                            "type": "op_nonce",
                            "operation_id": op.operation_id,
                            "nonce": raw_nonce,
                        }
                    )
                )
        except ConnectionClosed as e:
            # Tunnel died between the registry lookup and the send.
            # Clean up the op we just minted.
            await self._terminalize(
                op, OperationState.ERRORED, error={"reason": "tunnel_closed"}
            )
            raise NoActiveTunnel("control tunnel closed during dispatch") from e

        emit_op_event(
            self._audit_emit,
            OP_REQUESTED,
            system_id=op.system_id,
            operation_id=op.operation_id,
            op_type=op.op_type,
            tunnel_session_id=op.tunnel_session_id,
        )
        return op, raw_nonce

    async def reissue_nonce(self, operation_id: int) -> str:
        """Mint a fresh nonce for an op still in PENDING_NONCE.

        Invalidates the previous nonce (its hash is removed from the
        lookup table) atomically.
        """
        async with self._lock:
            op = self._ops.get(operation_id)
            if op is None:
                raise OpNotFound(f"op {operation_id} not found")
            if op.state != OperationState.PENDING_NONCE:
                raise OperationError(f"cannot reissue nonce in state {op.state.value}")
            self._purge_nonces_for_op_locked(op.operation_id)
            return self._issue_nonce_locked(op)

    async def redeem_nonce(self, raw_nonce: str, *, system_id: int) -> Operation:
        """One-shot nonce redemption. Caller is the /agent/op handler.

        Constant-time hash comparison; nonce bound to a specific
        system_id; operation must still be in PENDING_NONCE.
        """
        if not raw_nonce or not isinstance(raw_nonce, str):
            raise NonceInvalid("missing or non-string nonce")
        digest = self._hash(raw_nonce)
        expired_op: Optional[Operation] = None
        async with self._lock:
            op_id = self._nonce_to_op.get(digest)
            if op_id is None:
                raise NonceInvalid("nonce unknown or already redeemed")
            op = self._ops.get(op_id)
            if op is None:
                # Shouldn't happen but defend anyway.
                self._nonce_to_op.pop(digest, None)
                raise NonceInvalid("op vanished")
            if op.state != OperationState.PENDING_NONCE:
                raise NonceInvalid(f"op state {op.state.value}, not pending")
            if op.system_id != system_id:
                raise NonceInvalid("nonce bound to a different system_id")
            if time.monotonic() > op.nonce_expires_at_monotonic:
                self._purge_nonces_for_op_locked(op.operation_id)
                op.state = OperationState.EXPIRED
                self._resolve_locked(op, outcome="expired")
                expired_op = op
            else:
                # Constant-time compare (digest already matched the
                # dict lookup, but use compare_digest to keep the
                # timing predictable across paths).
                stored = self._reverse_lookup_locked(op_id)
                if stored is None or not hmac.compare_digest(stored, digest):
                    raise NonceInvalid("hash mismatch")
                self._purge_nonces_for_op_locked(op.operation_id)
                op.state = OperationState.ATTACHED
                return op

        # Outside the lock: emit the lifecycle event for the expired
        # op, then surface the failure to the caller.
        self._emit_op_completed(expired_op, outcome="expired")
        raise NonceExpired("nonce ttl elapsed")

    async def cancel(self, operation_id: int) -> Operation:
        """Backend-initiated cancel. Sends ``op_cancel`` over the agent's
        control WSS, marks state CANCELLING, and schedules a timeout
        fallback that forces CANCELLED + closes the per-op WSS if the
        agent never acknowledges with ``op_complete(cancelled)``."""
        async with self._lock:
            op = self._ops.get(operation_id)
            if op is None:
                raise OpNotFound(f"op {operation_id} not found")
            if op.state in TERMINAL_STATES:
                return op
            if op.state == OperationState.CANCELLING:
                return op
            tunnel = self._registry.get(op.system_id)
            op.state = OperationState.CANCELLING
            op.cancel_requested_at_monotonic = time.monotonic()

        # Send op_cancel + schedule fallback outside the lock.
        if tunnel is not None:
            try:
                await tunnel.ws.send(
                    json.dumps(
                        {
                            "type": "op_cancel",
                            "operation_id": op.operation_id,
                            "reason": "backend requested",
                        }
                    )
                )
            except ConnectionClosed:
                # Tunnel gone — fall straight to terminal cancellation.
                await self._terminalize(op, OperationState.CANCELLED)
                return op

        emit_op_event(
            self._audit_emit,
            OP_CANCEL_REQUESTED,
            system_id=op.system_id,
            operation_id=op.operation_id,
            op_type=op.op_type,
            tunnel_session_id=op.tunnel_session_id,
        )
        asyncio.create_task(
            self._cancel_timeout_watch(op),
            name=f"op_cancel_watch:{op.operation_id}",
        )
        return op

    async def complete(
        self,
        operation_id: int,
        *,
        outcome: str,
        error: Optional[dict] = None,
        result_metadata: Optional[dict] = None,
    ) -> Operation:
        """Called when the control WSS sees ``op_complete``, when the
        per-op WSS closes, or when an internal failure forces an op
        terminal. Idempotent — second call on a terminal op is a no-op.
        """
        async with self._lock:
            op = self._ops.get(operation_id)
            if op is None:
                raise OpNotFound(f"op {operation_id} not found")
            if op.state in TERMINAL_STATES:
                return op
            target = {
                "success": OperationState.COMPLETED,
                "completed": OperationState.COMPLETED,
                "cancelled": OperationState.CANCELLED,
                "error": OperationState.ERRORED,
            }.get(outcome, OperationState.ERRORED)
            self._purge_nonces_for_op_locked(op.operation_id)
            if result_metadata is not None:
                op.result_metadata = result_metadata

        await self._terminalize(op, target, outcome=outcome, error=error)
        return op

    async def terminalize_for_session(
        self, tunnel_session_id: str, *, reason: str = "tunnel_closed"
    ) -> List[Operation]:
        """Cleanup hook called when a specific control tunnel session
        dies or is replaced. Only ops dispatched on THAT
        ``tunnel_session_id`` are terminalised — guards against a
        displaced tunnel's late teardown nuking ops on the replacement
        tunnel for the same ``system_id``."""
        async with self._lock:
            victims = [
                op
                for op in self._ops.values()
                if op.tunnel_session_id == tunnel_session_id
                and op.state not in TERMINAL_STATES
            ]
            for op in victims:
                self._purge_nonces_for_op_locked(op.operation_id)

        for op in victims:
            await self._terminalize(
                op, OperationState.ERRORED, error={"reason": reason}
            )
        return victims

    # ----- identity authority + eviction ---------

    async def authorize_tunnel(self, entry: TunnelEntry) -> Optional[str]:
        """Re-read the committed identity state for ``entry``'s certificate.

        Returns ``None`` when still authorized, otherwise a reason code. A
        lookup that raises or exceeds the bound, or a session with no bound
        authority source, returns ``identity_unverifiable``: authority that
        cannot be confirmed is withheld.
        """
        check = entry.authorize
        if check is None:
            # No authority source bound to this session: nothing can confirm
            # the identity is still active, so authority is withheld.
            return REASON_UNVERIFIABLE
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(check), timeout=self._authorize_timeout
            )
        except Exception:  # pylint: disable=broad-except
            logger.warning(
                "identity status lookup failed for system_id=%s session=%s",
                entry.system_id,
                entry.tunnel_session_id,
                exc_info=True,
            )
            return REASON_UNVERIFIABLE

    async def confirm_start(self, op: Operation, ws: WebSocketServerProtocol) -> bool:
        """Release a gated agent to start work on an attached op.

        The agent starts nothing until ``op_ready`` arrives. Authority is
        re-read immediately before it is sent, and the op must still be a plain
        ATTACHED op on a live, non-evicted tunnel of the same session. Returns
        ``False`` (nothing sent) otherwise.
        """
        entry = self._registry.get(op.system_id)
        if (
            entry is None
            or entry.tunnel_session_id != op.tunnel_session_id
            or entry.evicted
        ):
            return False
        if await self.authorize_tunnel(entry) is not None:
            return False
        # The validator awaited above: the session may have been replaced or
        # evicted meanwhile. Only the exact session that owns the op may
        # release its start.
        if (
            self._registry.get(op.system_id) is not entry
            or entry.evicted
            or op.state != OperationState.ATTACHED
            or op.revocation_reason
        ):
            return False
        try:
            await ws.send(
                json.dumps({"type": "op_ready", "operation_id": op.operation_id})
            )
        except ConnectionClosed:
            return False
        return True

    async def evict_system(
        self,
        system_id: int,
        *,
        reason: str,
        expected_session_id: Optional[str] = None,
    ) -> dict:
        """Backend-signalled eviction. The signal is a hint, not an order: the
        broker re-reads authority and does nothing when the identity is
        authorized again (delayed or repeated signal after re-enable), or when
        ``expected_session_id`` names a session that is no longer current."""
        entry = self._registry.get(system_id)
        draining = self._draining.get(system_id)
        if draining is not None and (
            entry is None or draining.tunnel_session_id == expected_session_id
        ):
            entry = draining
        if entry is None:
            return {"result": "no_session", "system_id": system_id}
        if (
            expected_session_id is not None
            and entry.tunnel_session_id != expected_session_id
        ):
            return {
                "result": "stale_session",
                "system_id": system_id,
                "tunnel_session_id": entry.tunnel_session_id,
            }
        if not entry.evicted and await self.authorize_tunnel(entry) is None:
            return {
                "result": "not_evicted",
                "reason": "identity_authorized",
                "system_id": system_id,
                "tunnel_session_id": entry.tunnel_session_id,
            }
        return await self.evict_tunnel(entry, reason=reason)

    async def evict_tunnel(self, entry: TunnelEntry, *, reason: str) -> dict:
        """Tear down one tunnel session and interrupt its ops. Idempotent per
        session: concurrent and repeated callers share one eviction."""
        if entry.evict_task is None:
            # No await between the check and the flag: this is the
            # linearization point dispatch re-checks.
            entry.evicted = True
            entry.evict_reason = reason
            entry.evict_task = asyncio.create_task(
                self._evict_run(entry, reason),
                name=f"evict:{entry.system_id}:{entry.tunnel_session_id}",
            )
        return await asyncio.shield(entry.evict_task)

    async def _bounded(self, awaitable, timeout: Optional[float] = None) -> bool:
        """Await ``awaitable`` for at most ``timeout`` (default: the eviction
        I/O bound). Returns False on timeout or a dead socket."""
        try:
            await asyncio.wait_for(awaitable, timeout or self._evict_io_timeout)
            return True
        except (ConnectionClosed, OSError):
            return False

    @staticmethod
    def _abort_ws(ws: WebSocketServerProtocol) -> None:
        """Drop a socket without waiting on the peer or the write buffer."""
        with contextlib.suppress(Exception):
            transport = getattr(ws, "transport", None)
            if transport is not None:
                transport.abort()

    async def _evict_run(self, entry: TunnelEntry, reason: str) -> dict:
        """Evict one session within ``evict_total_timeout_seconds``.

        Dispatch is fenced the instant ``entry.evicted`` is set. Every step
        that can block on the peer (send lock, writes, close) is bounded, and
        the whole run has a hard deadline: past it the socket is aborted and
        every op that has not acknowledged is terminalized as unconfirmed. The
        entry stays in ``_draining`` until the run ends so a retried signal
        sees the pending eviction instead of ``no_session``.
        """
        session = entry.tunnel_session_id
        self._draining[entry.system_id] = entry
        timed_out = False
        # One teardown deadline for the transport work of every op and socket.
        deadline = time.monotonic() + self._evict_total_timeout
        try:
            await self._registry.unregister(entry.system_id, session)
            try:
                await asyncio.wait_for(
                    self._evict_steps(entry, reason, deadline),
                    self._evict_total_timeout,
                )
            except asyncio.TimeoutError:
                timed_out = True
                logger.warning(
                    "eviction deadline exceeded system_id=%s session=%s",
                    entry.system_id,
                    session,
                )
            if timed_out:
                self._abort_ws(entry.ws)
            # Whatever the steps left behind (deadline, blocked write, lock
            # held by a stalled sender) is terminalized as unconfirmed.
            victims = self._session_ops(session)
            for op in victims:
                if op.state not in TERMINAL_STATES:
                    op.revocation_reason = op.revocation_reason or reason
                    self._purge_nonces_nolock(op.operation_id)
                    await self._terminalize(
                        op,
                        OperationState.ERRORED,
                        error={"reason": "agent_revoked"},
                        deadline=deadline,
                    )
        finally:
            if self._draining.get(entry.system_id) is entry:
                del self._draining[entry.system_id]

        counts: Dict[str, int] = {}
        for op in victims:
            if not op.revocation_reason:
                continue
            key = op.termination or (
                "completed" if op.outcome in ("success", "completed") else "unknown"
            )
            counts[key] = counts.get(key, 0) + 1
        summary = {
            "result": "evicted",
            "system_id": entry.system_id,
            "tunnel_session_id": session,
            "reason": reason,
            "ops_interrupted": sum(counts.values()),
            "ops": counts,
        }
        if timed_out:
            summary["deadline_exceeded"] = True
        emit_tunnel_event(
            self._audit_emit,
            TUNNEL_EVICTED,
            system_id=entry.system_id,
            tunnel_session_id=session,
            reason=reason,
            extra={
                "ops_interrupted": summary["ops_interrupted"],
                "ops": counts,
                "deadline_exceeded": timed_out,
            },
        )
        logger.info(
            "tunnel evicted: system_id=%s session=%s reason=%s ops=%s timed_out=%s",
            entry.system_id,
            session,
            reason,
            counts,
            timed_out,
        )
        return summary

    def _session_ops(self, session: str) -> List[Operation]:
        return [op for op in self._ops.values() if op.tunnel_session_id == session]

    def _purge_nonces_nolock(self, op_id: int) -> None:
        # Synchronous (no await), so atomic with respect to other coroutines.
        self._purge_nonces_for_op_locked(op_id)

    async def _evict_steps(
        self, entry: TunnelEntry, reason: str, deadline: Optional[float] = None
    ) -> None:
        session = entry.tunnel_session_id
        async with self._lock:
            victims = [
                op
                for op in self._ops.values()
                if op.tunnel_session_id == session and op.state not in TERMINAL_STATES
            ]
            now = time.monotonic()
            for op in victims:
                op.revocation_reason = reason
                # Purging the nonce closes the data-channel race for ops that
                # have not attached: the nonce can no longer be redeemed.
                self._purge_nonces_for_op_locked(op.operation_id)
                if op.state in (OperationState.PENDING_NONCE, OperationState.ATTACHED):
                    op.state = OperationState.CANCELLING
                    op.cancel_requested_at_monotonic = now

        if victims:
            sent = await self._bounded(self._send_cancels(entry, victims, reason))
            if not sent:
                # A blocked write: no cancel can be trusted to have reached the
                # agent, so do not wait for acknowledgements that cannot come.
                self._abort_ws(entry.ws)
            futures = [op.completion for op in victims if op.completion is not None]
            if futures and sent:
                await asyncio.wait(futures, timeout=self._evict_ack_timeout)
            for op in victims:
                if op.state not in TERMINAL_STATES:
                    await self._terminalize(
                        op,
                        OperationState.ERRORED,
                        error={"reason": "agent_revoked"},
                        deadline=deadline,
                    )

        async def _goodbye() -> None:
            await entry.ws.send(json.dumps({"type": "bye", "reason": reason}))
            await entry.ws.close(code=1000, reason=f"agent_{reason}")

        if not await self._bounded(_goodbye()):
            self._abort_ws(entry.ws)

    @staticmethod
    async def _send_cancels(
        entry: TunnelEntry, victims: List[Operation], reason: str
    ) -> None:
        # op_cancel goes out under the tunnel send lock, after any op_request
        # that dispatch had already committed to sending.
        try:
            async with entry.send_lock:
                for op in victims:
                    if op.state in TERMINAL_STATES:
                        # Dispatch lost the race and never sent the
                        # op_request; there is nothing to cancel.
                        continue
                    await entry.ws.send(
                        json.dumps(
                            {
                                "type": "op_cancel",
                                "operation_id": op.operation_id,
                                "reason": f"agent_{reason}",
                            }
                        )
                    )
        except (ConnectionClosed, OSError):
            logger.info(
                "eviction: tunnel already gone before op_cancel system_id=%s",
                entry.system_id,
            )

    @staticmethod
    def _revocation_error(op: Operation, outcome: str, error: Optional[dict]) -> dict:
        """Error body for an op interrupted by eviction. The termination value
        is only ever ``confirmed`` / ``not_started`` when the agent said so (or
        the broker never sent the op); everything else is ``unconfirmed``."""
        agent_reported = op.result_metadata is not None
        termination = op.termination
        if termination is None:
            if op.op_type in _PROCESS_OP_TYPES:
                said = (op.result_metadata or {}).get("termination")
                termination = (
                    said
                    if agent_reported
                    and said in (TERMINATION_CONFIRMED, TERMINATION_NOT_STARTED)
                    else TERMINATION_UNCONFIRMED
                )
            else:
                termination = (
                    TERMINATION_NOT_APPLICABLE
                    if agent_reported
                    else TERMINATION_UNCONFIRMED
                )
            op.termination = termination
        reason = (
            "agent_revoked_unconfirmed"
            if termination == TERMINATION_UNCONFIRMED
            else "agent_revoked"
        )
        body = {
            "reason": reason,
            "cause": op.revocation_reason,
            "termination": termination,
        }
        if isinstance(error, dict) and error.get("reason") not in (None, reason):
            body["agent_reason"] = error.get("reason")
        return body

    def get(self, operation_id: int) -> Optional[Operation]:
        return self._ops.get(operation_id)

    def for_system(self, system_id: int) -> List[Operation]:
        return [op for op in self._ops.values() if op.system_id == system_id]

    # ----- internal -------

    def _hash(self, raw_nonce: str) -> str:
        return hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()

    def _issue_nonce_locked(self, op: Operation) -> str:
        """Mint a raw token, store its hash, return the raw token.
        Caller MUST hold ``self._lock``."""
        raw = secrets.token_urlsafe(32)
        digest = self._hash(raw)
        self._nonce_to_op[digest] = op.operation_id
        op.nonce_expires_at_monotonic = time.monotonic() + self._nonce_ttl
        return raw

    def _purge_nonces_for_op_locked(self, op_id: int) -> None:
        """Remove every nonce hash whose value is this op_id. Caller
        MUST hold ``self._lock``."""
        stale = [d for d, oid in self._nonce_to_op.items() if oid == op_id]
        for d in stale:
            del self._nonce_to_op[d]

    def _reverse_lookup_locked(self, op_id: int) -> Optional[str]:
        for d, oid in self._nonce_to_op.items():
            if oid == op_id:
                return d
        return None

    def _expire_pending_locked(self, system_id: int) -> List[Operation]:
        """Lazily flip TTL-elapsed PENDING_NONCE ops to EXPIRED so they
        stop counting against per-agent limits. PENDING_NONCE ops have
        no attached WSS, so no socket close is needed — pure state +
        nonce-table mutation. Caller MUST hold ``self._lock``.

        Returns the list of ops just expired so the caller can emit
        ``OP_COMPLETED`` audit events AFTER releasing the lock — the
        emitter must never be invoked while holding the manager lock.
        """
        expired: List[Operation] = []
        now = time.monotonic()
        for op in self._ops.values():
            if (
                op.system_id == system_id
                and op.state == OperationState.PENDING_NONCE
                and now > op.nonce_expires_at_monotonic
            ):
                self._purge_nonces_for_op_locked(op.operation_id)
                op.state = OperationState.EXPIRED
                self._resolve_locked(op, outcome="expired")
                expired.append(op)
        return expired

    def _enforce_limits_locked(self, system_id: int) -> List[Operation]:
        # Sweep stale pending ops first so an agent that never dialed
        # /agent/op for prior ops doesn't block new ones forever.
        # Returns the swept ops so callers can emit lifecycle audit
        # events after releasing the lock.
        expired = self._expire_pending_locked(system_id)
        nonces = sum(
            1
            for op in self._ops.values()
            if op.system_id == system_id and op.state == OperationState.PENDING_NONCE
        )
        if nonces >= self._max_nonces:
            raise NonceLimitExceeded(
                f"system {system_id} has {nonces} in-flight nonces; max {self._max_nonces}"
            )
        live = sum(
            1
            for op in self._ops.values()
            if op.system_id == system_id and op.state not in TERMINAL_STATES
        )
        if live >= self._max_concurrent:
            raise ConcurrentOpsExceeded(
                f"system {system_id} has {live} live ops; max {self._max_concurrent}"
            )
        return expired

    def _emit_op_completed(self, op: Operation, *, outcome: str) -> None:
        """Emit OP_COMPLETED for an already-terminalised op. Safe to
        call outside the lock: pure read of op fields + audit emit
        (which is itself try/excepted)."""
        duration_ms = int((time.monotonic() - op.created_at_monotonic) * 1000)
        emit_op_event(
            self._audit_emit,
            OP_COMPLETED,
            system_id=op.system_id,
            operation_id=op.operation_id,
            op_type=op.op_type,
            tunnel_session_id=op.tunnel_session_id,
            outcome=outcome,
            duration_ms=duration_ms,
        )

    def _resolve_locked(
        self,
        op: Operation,
        *,
        outcome: str,
        error: Optional[dict] = None,
    ) -> None:
        """Resolve the op's completion future. Caller MUST hold the
        lock."""
        op.outcome = outcome
        op.error = error
        if op.completion is not None and not op.completion.done():
            op.completion.set_result((outcome, error))

    async def _terminalize(
        self,
        op: Operation,
        new_state: OperationState,
        *,
        outcome: Optional[str] = None,
        error: Optional[dict] = None,
        deadline: Optional[float] = None,
    ) -> None:
        """Atomic transition to a terminal state. Closes the attached
        per-op WSS if any, resolves the completion future, and unblocks
        anyone reading from ``op.inbound`` by pushing a sentinel
        ``None`` (queue consumers must handle ``None`` as 'done')."""
        async with self._lock:
            if op.state in TERMINAL_STATES:
                return
            if op.revocation_reason and new_state != OperationState.COMPLETED:
                error = self._revocation_error(op, outcome or new_state.value, error)
            op.state = new_state
            if outcome is None:
                outcome = new_state.value
            self._resolve_locked(op, outcome=outcome, error=error)
            ws = op.attached_ws
            op.attached_ws = None
            duration_ms = int((time.monotonic() - op.created_at_monotonic) * 1000)
            audit_outcome = {
                OperationState.COMPLETED: "success",
                OperationState.CANCELLED: "cancelled",
                OperationState.ERRORED: "error",
                OperationState.EXPIRED: "expired",
            }.get(new_state, "error")

        # The terminal audit event is emitted as soon as the state is final and
        # before anything that can wait, so cancellation of this coroutine can
        # neither lose it nor repeat it (a terminal op is never re-entered).
        emit_op_event(
            self._audit_emit,
            OP_COMPLETED,
            system_id=op.system_id,
            operation_id=op.operation_id,
            op_type=op.op_type,
            tunnel_session_id=op.tunnel_session_id,
            outcome=audit_outcome,
            duration_ms=duration_ms,
            reason=(error or {}).get("reason") if isinstance(error, dict) else None,
            extra=(
                {"termination": op.termination}
                if op.revocation_reason and op.termination
                else None
            ),
        )

        # Sentinel outside the lock. Streaming ops opt out
        # of the terminal sentinel; see Operation.skip_terminal_sentinel.
        if not op.skip_terminal_sentinel:
            try:
                op.inbound.put_nowait(None)  # type: ignore[arg-type]
            except asyncio.QueueFull:
                pass
        if ws is not None:
            await self._close_data_socket(ws, new_state.value, deadline)

    async def _close_data_socket(
        self,
        ws: WebSocketServerProtocol,
        state: str,
        deadline: Optional[float],
    ) -> None:
        """Close a per-op socket within the I/O bound and any shared deadline.
        The socket is detached from the op already, so if this is cancelled or
        the wait expires the transport is aborted rather than left open."""
        timeout = self._evict_io_timeout
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            self._abort_ws(ws)
            return
        try:
            await asyncio.wait_for(ws.close(code=1000, reason=f"op_{state}"), timeout)
        except (ConnectionClosed, RuntimeError):
            pass
        except asyncio.TimeoutError:
            self._abort_ws(ws)
        except asyncio.CancelledError:
            self._abort_ws(ws)
            raise

    async def _cancel_timeout_watch(self, op: Operation) -> None:
        try:
            await asyncio.sleep(self._cancel_timeout)
        except asyncio.CancelledError:
            return
        # Still in CANCELLING after the wait? Force terminal.
        if op.state == OperationState.CANCELLING:
            logger.warning(
                "op cancel timeout: op=%s system=%s; forcing CANCELLED",
                op.operation_id,
                op.system_id,
            )
            await self._terminalize(op, OperationState.CANCELLED, outcome="cancelled")


# Module-level singleton, lazily bound. Initialised by app.broker.main
# after the registry exists; tests inject their own.
default_manager: Optional[OperationManager] = None


def init_default_manager(registry: AgentRegistry, **kwargs) -> OperationManager:
    global default_manager
    default_manager = OperationManager(registry, **kwargs)
    return default_manager
