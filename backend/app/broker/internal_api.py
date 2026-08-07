"""Broker internal HTTP API (PRA-153).

Exposes a FastAPI app the main backend calls to (a) query the
in-memory ``AgentRegistry`` (tunnel health) and (b) dispatch ops
onto live tunnels. Per the PRA-153 design lock, the backend MUST
NOT import the broker registry directly; it goes through this HTTP
boundary so multi-process / cross-host deployment stays available
later without rearchitecting callers.

This API is bound to the Docker network hostname only and should
NEVER be exposed to operators or the public internet. PRA-180
BROKER-01 added a shared-secret bearer (see ``internal_auth``) on
top of the docker-network trust boundary: production wiring in
``main.py`` requires a valid ``x-praxis-internal-auth`` header so a
foothold on another backend-net container cannot dispatch agent ops.

Routes:
    GET  /internal/agent/health/{system_id}    (slice #1)
    POST /internal/agent/ops/exec              (slice #3a)
    POST /internal/agent/ops/file_get          (slice #3a)
    POST /internal/agent/ops/file_put          (slice #3a)

PTY (WS endpoint) is intentionally NOT included — agent-backed
PTY is deferred from PRA-153 #3 until effective_login switching is
designed (sudo -Hiu / runuser); see slice-3 design lock.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from typing import AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from .internal_auth import INTERNAL_AUTH_HEADER, tokens_match
from .ops import (
    ConcurrentOpsExceeded,
    NoActiveTunnel,
    NonceLimitExceeded,
    Operation,
    OperationManager,
    OperationState,
    OpNotFound,
)
from .protocol import (
    DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
    HEARTBEAT_DEAD_SECONDS,
    Channel,
    Frame,
    FrameOp,
)
from .registry import AgentRegistry, default_registry

logger = logging.getLogger(__name__)

# Hard cap on synchronous broker → agent exec time. Per the PRA-153
# slice-3 lock, anything longer than this should go through the job
# queue, not a request/response transport call. 5 minutes is enough
# for `apt-get update`, `systemctl status`, etc., without becoming
# a vector for half-hour-long stuck HTTP connections.
EXEC_HARD_CAP_SECONDS = 300.0

# PRA-155 #2b-a: facts ops are local /proc reads + a short cloud
# probe. They MUST complete fast or fail loudly — a stuck facts call
# would otherwise pile up under the scheduler. Keep this tighter than
# the exec cap so a bad agent / network partition is detected quickly.
FACTS_HARD_CAP_SECONDS = 30.0


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an int; using default %d", name, raw, default)
        return default
    if value <= 0:
        logger.warning("%s=%r is not positive; using default %d", name, raw, default)
        return default
    return value


# PRA-228 BROKER-03: cap total captured exec output (stdout+stderr bytes). Exec
# is already time-capped (EXEC_HARD_CAP_SECONDS), but a fast command emitting a
# huge stream would otherwise accumulate unbounded in broker memory before the
# time cap fires. When the cap is crossed the op is cancelled and a bounded
# ``exec_output_too_large`` error is returned instead of the (partial) output.
# Env-overridable for operators who legitimately need larger synchronous output.
EXEC_OUTPUT_MAX_BYTES = _int_env(
    "PRAXIS_BROKER_EXEC_OUTPUT_MAX_BYTES", 10 * 1024 * 1024
)

# Bound how long we'll wait for the agent to dial /agent/op after
# the broker dispatches op_request + op_nonce. If the agent never
# attaches (offline mid-dispatch, network partition), the op times
# out at this point rather than waiting the full exec cap.
ATTACH_TIMEOUT_SECONDS = 15.0

# PRA-339: hard ceiling on how many broker log records /internal/logs will
# return in one call. The ring buffer is already bounded to this size, so this
# just stops a caller asking for more than the buffer can hold.
MAX_INTERNAL_LOG_RECORDS = 5000

# How often the op-completion wait checks for a stale request
# (caller HTTP disconnect). Quicker than the cap so we don't keep
# the agent busy after the requester has gone away.
DISCONNECT_POLL_SECONDS = 0.5

# Max time we'll wait for the agent's file_get header to arrive
# after the per-op WSS attach. The agent normally produces the
# header in milliseconds, but this needs to absorb scheduler /
# network jitter under load — too short and a valid transfer that
# saw op_complete first would 502, which is the bug we're paving
# over. 30s is generous enough that any agent that hasn't produced
# a header by then is genuinely stuck.
HEADER_TIMEOUT_SECONDS = 30.0


# -------- request schemas --------


class ExecRequest(BaseModel):
    system_id: int = Field(..., gt=0)
    cmd: str = Field(..., min_length=1)
    args: list[str] = Field(default_factory=list)
    cwd: Optional[str] = None
    env: Optional[dict[str, str]] = None
    # base64-encoded stdin to forward to the agent's child via
    # ChannelStdin frames + CLOSE.
    stdin_b64: Optional[str] = None
    # 0 = no caller-side timeout (broker still enforces hard cap).
    timeout_s: float = Field(default=0.0, ge=0.0)


class FactsRequest(BaseModel):
    system_id: int = Field(..., gt=0)


class FileGetRequest(BaseModel):
    system_id: int = Field(..., gt=0)
    path: str = Field(..., min_length=1)
    max_bytes: int = Field(default=0, ge=0)


# -------- helpers --------


async def _wait_for_attach(op: Operation, timeout: float) -> None:
    """Block until the op is no longer in PENDING_NONCE.

    Per the OperationManager state machine, ATTACHED means the agent
    dialed /agent/op and redeemed the nonce; only after that can we
    push frames into ``op.outbound`` and expect the bridge to deliver
    them.
    """
    deadline = time.monotonic() + timeout
    while op.state == OperationState.PENDING_NONCE:
        if time.monotonic() > deadline:
            raise asyncio.TimeoutError(f"op {op.operation_id} never attached")
        await asyncio.sleep(0.05)


def _busy_response() -> JSONResponse:
    """PRA-228: per-agent op/nonce limit hit. Return a bounded, retryable 429
    instead of letting the limit exception surface as a raw 500."""
    return JSONResponse(
        status_code=429,
        content={"outcome": "error", "error": {"reason": "broker_busy"}},
    )


async def _drain_op_until_complete(
    op: Operation,
    request: Request,
    *,
    cap_seconds: float,
    on_frame,
    cancel,
    abort_event: Optional[asyncio.Event] = None,
) -> Operation:
    """Wait for ``op.completion`` while collecting inbound frames and
    watching for caller disconnect.

    ``on_frame`` is called for each frame off ``op.inbound``. ``cancel``
    is called (with the operation_id) when:
        - caller HTTP disconnects mid-flight
        - the cap_seconds window expires

    Returns the (now terminal) Operation. The caller inspects
    ``op.outcome`` / ``op.error`` for the JSON response.

    Important sequencing: we spawn the frame pump first, wait for
    completion, then drain whatever frames the pump still has in
    flight. Order matters because the bridge can put data frames AND
    set completion in the same scheduler tick — if we returned
    immediately on completion.done() we'd lose those frames.
    """

    pump_done_naturally = asyncio.Event()

    async def _frame_pump() -> None:
        try:
            while True:
                frame = await op.inbound.get()
                if frame is None:  # bridge / fake sentinel
                    return
                # on_frame may be sync OR async — async lets file_get
                # back-pressure when its body queue is full.
                result = on_frame(frame)
                if asyncio.iscoroutine(result):
                    await result
        finally:
            pump_done_naturally.set()

    pump_task = asyncio.create_task(
        _frame_pump(), name=f"int_op_pump:{op.operation_id}"
    )

    deadline = time.monotonic() + cap_seconds
    while not op.completion.done():
        if abort_event is not None and abort_event.is_set():
            logger.warning(
                "op=%s aborted by caller cap; cancelling agent op",
                op.operation_id,
            )
            await cancel(op.operation_id)
            try:
                await asyncio.wait_for(op.completion, timeout=5.0)
            except asyncio.TimeoutError:
                pass
            break
        if await request.is_disconnected():
            logger.info(
                "op=%s caller HTTP disconnected; cancelling agent op",
                op.operation_id,
            )
            await cancel(op.operation_id)
            try:
                await asyncio.wait_for(op.completion, timeout=5.0)
            except asyncio.TimeoutError:
                pass
            break
        if time.monotonic() > deadline:
            logger.warning(
                "op=%s exceeded broker cap %.1fs; cancelling",
                op.operation_id,
                cap_seconds,
            )
            await cancel(op.operation_id)
            try:
                await asyncio.wait_for(op.completion, timeout=5.0)
            except asyncio.TimeoutError:
                pass
            break
        try:
            await asyncio.wait_for(
                asyncio.shield(op.completion),
                timeout=DISCONNECT_POLL_SECONDS,
            )
        except asyncio.TimeoutError:
            continue

    # Op is terminal. Give the pump a brief window to finish draining
    # any frames that landed before completion fired. If the bridge
    # never sends a sentinel (which is normal in production — only
    # the fake puts one), cancel the pump after the window.
    try:
        await asyncio.wait_for(pump_done_naturally.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        pass
    if not pump_task.done():
        pump_task.cancel()
        try:
            await pump_task
        except (asyncio.CancelledError, Exception):  # pylint: disable=broad-except
            pass

    return op


def _spawn_logged_cancel(cancel_fn, operation_id: int) -> None:
    """Spawn a fire-and-forget cancel that logs failures.

    The header-timeout response returns 504 immediately without
    awaiting the cancel because production OperationManager.cancel
    just marks the op CANCELLING and schedules an async fallback.
    Without this wrapper, OpNotFound (op already terminal) or any
    transport error inside cancel would surface as "Task exception
    was never retrieved" warnings in broker logs.
    """

    async def _run() -> None:
        try:
            await cancel_fn(operation_id)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(
                "fire-and-forget cancel for op=%s raised: %s", operation_id, exc
            )

    asyncio.create_task(_run(), name=f"int_op_cancel_bg:{operation_id}")


def _outcome_json(op: Operation, **extra) -> dict:
    """Serialise op terminal state into the API response shape."""
    return {
        "outcome": op.outcome or "error",
        "operation_id": op.operation_id,
        "error": op.error,
        **extra,
    }


# -------- shared-secret auth (PRA-180 BROKER-01) --------


class _InternalAuthMiddleware:
    """ASGI middleware enforcing the shared-secret header on every request.

    Implemented as raw ASGI (not ``BaseHTTPMiddleware``) so it short-circuits
    unauthorized requests before the route runs and never interferes with the
    streaming request/response bodies used by file_get / file_put.
    """

    def __init__(self, app, expected_token: str) -> None:
        self.app = app
        self._expected = expected_token
        self._header = INTERNAL_AUTH_HEADER.encode("latin-1")

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        presented: Optional[str] = None
        for name, value in scope.get("headers") or ():
            if name == self._header:
                presented = value.decode("latin-1")
                break
        if not tokens_match(presented, self._expected):
            response = JSONResponse(
                status_code=401,
                content={"outcome": "error", "error": {"reason": "unauthorized"}},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


# -------- app builder --------


def build_internal_app(
    registry: AgentRegistry | None = None,
    manager: OperationManager | None = None,
    *,
    auth_token: Optional[str] = None,
) -> FastAPI:
    """Build the internal FastAPI app bound to ``registry`` + ``manager``.

    Tests inject an ad-hoc registry + a stub manager to drive op
    flows without spinning up a real tunnel + agent. Production
    wiring uses ``default_registry`` and the live OperationManager
    via ``main.py``.

    ``auth_token`` (PRA-180 BROKER-01): when set, every request must carry a
    matching ``x-praxis-internal-auth`` header or it is rejected with ``401``.
    ``None`` (the default) leaves the API unauthenticated — production wiring in
    ``main.py`` always passes a derived token, while op-flow unit tests that
    aren't exercising auth keep the historical no-auth behavior.
    """
    if registry is None:
        registry = default_registry

    app = FastAPI(
        title="Praxis Agent Broker — internal",
        # Hide schema/docs by default; this isn't a public API.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Allow the manager to be set after build so main.py can pass the
    # live one without circular-import gymnastics. Tests pass theirs
    # at build time.
    app.state.manager = manager

    # PRA-180 BROKER-01: enforce the shared-secret header when configured.
    if auth_token:
        app.add_middleware(_InternalAuthMiddleware, expected_token=auth_token)

    @app.get("/internal/agent/health/{system_id}")
    async def agent_health(system_id: int) -> dict:
        entry = registry.get(system_id)
        if entry is None:
            return {
                "system_id": system_id,
                "state": "unregistered",
                "tunnel_session_id": None,
                "since_seconds": None,
                "last_heartbeat_age_seconds": None,
                # PRA-155 #2b-b: capabilities is the per-tunnel set the
                # broker accepted at handshake. Returned here so the
                # transport-selection layer can gate auto-mode fallback
                # on whether the agent actually advertises the op_type
                # the caller wants (facts, eventually pty/etc).
                "capabilities": [],
            }
        now = time.monotonic()
        age = now - entry.last_recv_monotonic
        connected_age = now - entry.connected_at_monotonic
        state = "healthy" if age <= HEARTBEAT_DEAD_SECONDS else "stale"
        return {
            "system_id": system_id,
            "state": state,
            "capabilities": list(entry.capabilities or []),
            "tunnel_session_id": entry.tunnel_session_id,
            "since_seconds": connected_age,
            "last_heartbeat_age_seconds": age,
        }

    @app.get("/internal/logs")
    async def broker_logs(
        since_epoch: Optional[float] = None, limit: Optional[int] = None
    ) -> dict:
        """PRA-339: recent broker log records for the admin support bundle.

        Reads the in-process ring buffer (installed in ``main.main``). Returns
        raw records; the backend redacts them at bundle-build time, matching the
        backend log-buffer flow. Auth is the internal shared-secret middleware
        that already wraps every route on this app. ``limit`` is clamped so a
        caller can't ask for an unbounded dump (the buffer itself is bounded)."""
        from app.core.log_buffer import (  # pylint: disable=import-outside-toplevel
            get_log_buffer,
        )

        buf = get_log_buffer()
        if buf is None:
            return {"installed": False, "records": []}
        if limit is None or limit > MAX_INTERNAL_LOG_RECORDS:
            limit = MAX_INTERNAL_LOG_RECORDS
        records = buf.records(since_epoch=since_epoch, limit=limit)
        return {"installed": True, "records": records}

    @app.post("/internal/agent/ops/exec")
    async def agent_exec(req: ExecRequest, request: Request):
        mgr: OperationManager = app.state.manager
        if mgr is None:  # pragma: no cover - production wiring
            raise HTTPException(500, "broker manager not initialised")

        params = {"cmd": req.cmd, "args": req.args}
        if req.cwd is not None:
            params["cwd"] = req.cwd
        if req.env is not None:
            params["env"] = req.env
        # Cap timeout_s at the broker hard cap so a misconfigured
        # caller can't drag us past it.
        cap = (
            min(req.timeout_s, EXEC_HARD_CAP_SECONDS)
            if req.timeout_s > 0
            else EXEC_HARD_CAP_SECONDS
        )
        if req.timeout_s > 0:
            params["timeout_s"] = req.timeout_s

        try:
            op, _nonce = await mgr.create_and_dispatch(req.system_id, "exec", params)
        except NoActiveTunnel:
            return JSONResponse(
                status_code=503,
                content={
                    "outcome": "error",
                    "error": {"reason": "transport_unavailable"},
                },
            )
        except (ConcurrentOpsExceeded, NonceLimitExceeded):
            return _busy_response()

        try:
            await _wait_for_attach(op, ATTACH_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            try:
                await mgr.cancel(op.operation_id)
            except OpNotFound:
                pass
            return JSONResponse(
                status_code=504,
                content={
                    "outcome": "error",
                    "error": {"reason": "agent_attach_timeout"},
                },
            )

        # If caller supplied stdin, push it now and CLOSE on stdin.
        if req.stdin_b64:
            try:
                stdin_bytes = base64.b64decode(req.stdin_b64)
            except Exception:  # pylint: disable=broad-except
                await mgr.cancel(op.operation_id)
                raise HTTPException(400, "stdin_b64 not valid base64")
            await op.outbound.put(
                Frame(
                    op=FrameOp.DATA,
                    channel=Channel.STDIN,
                    flags=0,
                    payload=stdin_bytes,
                )
            )
            await op.outbound.put(
                Frame(op=FrameOp.CLOSE, channel=Channel.STDIN, flags=0, payload=b"")
            )

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        output_total = 0
        output_exceeded = asyncio.Event()

        def _accumulate(frame: Frame) -> None:
            nonlocal output_total
            if frame.op != FrameOp.DATA:
                return
            if frame.channel == Channel.STDOUT:
                chunks = stdout_chunks
            elif frame.channel == Channel.STDERR:
                chunks = stderr_chunks
            else:
                return
            # PRA-228 BROKER-03: bound captured output. Once over the cap, stop
            # appending (so memory can't grow past ~cap + one in-flight frame)
            # and signal the drain loop to cancel the agent op early.
            if output_exceeded.is_set():
                return
            payload = bytes(frame.payload)
            output_total += len(payload)
            if output_total > EXEC_OUTPUT_MAX_BYTES:
                output_exceeded.set()
                return
            chunks.append(payload)

        op = await _drain_op_until_complete(
            op,
            request,
            cap_seconds=cap,
            on_frame=_accumulate,
            cancel=mgr.cancel,
            abort_event=output_exceeded,
        )

        # PRA-228 BROKER-03: if output blew the cap, return a bounded error
        # (no captured command output in the body) rather than the truncated
        # stream. The op was cancelled by the drain loop's abort path.
        if output_exceeded.is_set():
            return JSONResponse(
                status_code=413,
                content={
                    "outcome": "error",
                    "error": {
                        "reason": "exec_output_too_large",
                        "limit_bytes": EXEC_OUTPUT_MAX_BYTES,
                    },
                },
            )

        # exit_code + duration_ms travel as TOP-LEVEL fields on the
        # agent's op_complete (PRA-152 task #4 op_complete shape) —
        # _route_op_complete in handlers.py captures them into
        # op.result_metadata. Reading from op.error here would only
        # work for outcomes the agent considers errors.
        meta = op.result_metadata or {}
        return {
            "outcome": op.outcome or "error",
            "operation_id": op.operation_id,
            "exit_code": meta.get("exit_code") if op.outcome == "success" else None,
            "stdout_b64": base64.b64encode(b"".join(stdout_chunks)).decode("ascii"),
            "stderr_b64": base64.b64encode(b"".join(stderr_chunks)).decode("ascii"),
            "duration_ms": meta.get("duration_ms"),
            "error": op.error if op.outcome != "success" else None,
        }

    @app.post("/internal/agent/ops/file_get")
    async def agent_file_get(req: FileGetRequest, request: Request):
        mgr: OperationManager = app.state.manager
        if mgr is None:  # pragma: no cover
            raise HTTPException(500, "broker manager not initialised")

        params: dict = {"path": req.path}
        if req.max_bytes > 0:
            params["max_bytes"] = req.max_bytes

        try:
            # Bounded inbound queue: if the HTTP response consumer is
            # slow, body_queue.put() blocks → on_frame awaits → frame
            # pump pauses → op.inbound fills → bridge _pump_inbound
            # blocks on its await put() → WSS reads stop → TCP
            # backpressure to the agent. Without this, a fast agent
            # producing a large file faster than the backend client
            # reads can pile the whole download in broker memory.
            # skip_terminal_sentinel=True: success-path EOF is owned
            # by the FILE CLOSE frame, not the manager's terminal
            # None push. Without this, op_complete arriving on the
            # control WSS before the per-op pump has delivered FILE
            # CLOSE could inject a None ahead of remaining file
            # frames and truncate (or hang) the response.
            op, _nonce = await mgr.create_and_dispatch(
                req.system_id,
                "file_get",
                params,
                inbound_maxsize=4,
                skip_terminal_sentinel=True,
            )
        except NoActiveTunnel:
            return JSONResponse(
                status_code=503,
                content={
                    "outcome": "error",
                    "error": {"reason": "transport_unavailable"},
                },
            )
        except (ConcurrentOpsExceeded, NonceLimitExceeded):
            return _busy_response()

        try:
            await _wait_for_attach(op, ATTACH_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            try:
                await mgr.cancel(op.operation_id)
            except OpNotFound:
                pass
            return JSONResponse(
                status_code=504,
                content={
                    "outcome": "error",
                    "error": {"reason": "agent_attach_timeout"},
                },
            )

        # Streaming lifecycle (deliberately NOT using
        # _drain_op_until_complete here): that helper has a 2-second
        # pump-cancel window that's safe for exec accumulators but
        # can truncate a download under backpressure — when the HTTP
        # consumer is slow, the frame pump is legitimately blocked on
        # body_queue.put() and we MUST NOT cancel it. Instead, the
        # body iterator drives teardown: pump runs until the body
        # iter is fully consumed (or aborts via _StreamFailure), then
        # the iter's finally cancels everything.
        #
        # Header (size, mode) lands as a ChannelControl Data frame
        # before any ChannelFile bytes per the PRA-152 file primitive.
        # Once we start writing the response body we cannot downgrade
        # to a JSON error — post-header failures surface as the body
        # iterator raising _StreamFailure, aborting the response.
        header_evt = asyncio.Event()
        header_holder: dict = {}
        # Bounded body queue: AWAITED puts so a slow HTTP consumer
        # back-pressures the on_frame coroutine, which in turn pauses
        # the inbound bridge pump (op.inbound is also bounded above).
        body_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=4)

        class _StreamFailure(Exception):
            """Sentinel pushed onto body_queue to abort the stream
            mid-flight when the op fails after the header has gone
            out. Caught and re-raised by _body_iter."""

            def __init__(self, reason: str) -> None:
                super().__init__(reason)
                self.reason = reason

        async def _on_frame(frame: Frame) -> None:
            if frame.channel == Channel.CONTROL and frame.op == FrameOp.DATA:
                try:
                    header_holder.update(json.loads(frame.payload.decode("utf-8")))
                except Exception:  # pylint: disable=broad-except
                    header_holder["_bad_header"] = True
                header_evt.set()
                return
            if frame.channel == Channel.FILE and frame.op == FrameOp.DATA:
                await body_queue.put(bytes(frame.payload))
                return
            if frame.channel == Channel.FILE and frame.op == FrameOp.CLOSE:
                await body_queue.put(None)
                return

        # Pump runs forever until either:
        #   - it sees a sentinel None on op.inbound (only the test
        #     fake produces this), or
        #   - the body iterator's finally cancels it
        async def _frame_pump() -> None:
            while True:
                frame = await op.inbound.get()
                if frame is None:
                    return
                await _on_frame(frame)

        # Watcher waits for op.completion (or caller disconnect, or
        # the broker hard cap). On SUCCESS the watcher MUST NOT
        # enqueue anything — clean EOF is the pump's responsibility
        # via the FILE CLOSE frame from the agent. If the watcher
        # raced ahead and put None directly, a backpressured pump
        # could still be parked on body_queue.put(chunk) for unsent
        # FILE Data frames; None could end up between the chunk and
        # CLOSE in the queue and produce a clean-but-truncated 200.
        # Only the failure paths publish a sentinel (_StreamFailure)
        # because in those cases there are no more frames coming.
        async def _watch_completion() -> None:
            deadline = time.monotonic() + EXEC_HARD_CAP_SECONDS
            while not op.completion.done():
                if await request.is_disconnected():
                    await mgr.cancel(op.operation_id)
                    try:
                        await asyncio.wait_for(op.completion, timeout=5.0)
                    except asyncio.TimeoutError:
                        pass
                    break
                if time.monotonic() > deadline:
                    await mgr.cancel(op.operation_id)
                    try:
                        await asyncio.wait_for(op.completion, timeout=5.0)
                    except asyncio.TimeoutError:
                        pass
                    break
                try:
                    await asyncio.wait_for(
                        asyncio.shield(op.completion),
                        timeout=DISCONNECT_POLL_SECONDS,
                    )
                except asyncio.TimeoutError:
                    continue
            # On error after the header has gone out, abort the body
            # mid-flight. On success, do NOT touch body_queue — the
            # pump handles EOF when it processes the FILE CLOSE.
            if header_evt.is_set() and op.outcome != "success":
                reason = (op.error or {}).get("reason", "op_stream_closed")
                await body_queue.put(_StreamFailure(reason))

        pump_task = asyncio.create_task(
            _frame_pump(), name=f"int_op_pump:{op.operation_id}"
        )
        watch_task = asyncio.create_task(
            _watch_completion(), name=f"int_op_watch:{op.operation_id}"
        )

        # Pre-header wait: race the header arriving against (a) the
        # watcher resolving with a NON-success outcome, and (b) a
        # protocol-level header timeout. SUCCESS completion alone is
        # NOT a pre-header failure signal — it's a normal scheduler
        # ordering when the agent's op_complete (control WSS) reaches
        # the broker before the per-op frame pump has processed the
        # header (which is already sitting on op.inbound). For that
        # case we just keep waiting for the header.
        wait_header = asyncio.create_task(header_evt.wait())

        async def _wait_for_failure() -> None:
            await asyncio.shield(watch_task)
            if op.outcome != "success":
                return
            # Success completion alone never resolves this — the
            # header timeout below is the only catch for the (very
            # rare) case where a "successful" op produced no header.
            await asyncio.Event().wait()

        async def _wait_for_header_timeout() -> None:
            await asyncio.sleep(HEADER_TIMEOUT_SECONDS)

        wait_failure = asyncio.create_task(
            _wait_for_failure(), name=f"int_op_failwait:{op.operation_id}"
        )
        wait_timeout = asyncio.create_task(
            _wait_for_header_timeout(), name=f"int_op_hdrto:{op.operation_id}"
        )
        try:
            done_set, _pending = await asyncio.wait(
                {wait_header, wait_failure, wait_timeout},
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for t in (wait_header, wait_failure, wait_timeout):
                if not t.done():
                    t.cancel()
        # Distinguish "agent failed pre-header" from "agent never
        # sent a header within the timeout". Both produce no body
        # but should report different reasons.
        header_timeout_fired = wait_timeout in done_set

        if not header_evt.is_set():
            # Two distinct cases:
            #   header_timeout_fired — agent never produced a header
            #       within HEADER_TIMEOUT_SECONDS. Fire-and-forget
            #       the cancel (production manager.cancel just marks
            #       the op CANCELLING and schedules a fallback; it
            #       does NOT resolve op.completion synchronously, so
            #       awaiting watch_task here would extend the 30s
            #       header timeout to ~40s by default). Tear down
            #       background tasks immediately and return 504.
            #   else — op completed with non-success outcome before
            #       any header. watch_task is already done; surface
            #       op.outcome / op.error as 502.
            if header_timeout_fired:
                # Fire-and-forget cancel; manager cleans up async.
                # Wrap so OpNotFound / transport errors don't become
                # "Task exception was never retrieved" warnings.
                _spawn_logged_cancel(mgr.cancel, op.operation_id)
                pump_task.cancel()
                if not watch_task.done():
                    watch_task.cancel()
                return JSONResponse(
                    status_code=504,
                    content={
                        "outcome": "error",
                        "error": {"reason": "header_timeout"},
                    },
                )
            # wait_failure won — watch_task already resolved with the
            # outcome we want to surface.
            await watch_task
            pump_task.cancel()
            try:
                await pump_task
            except (asyncio.CancelledError, Exception):  # pylint: disable=broad-except
                pass
            return JSONResponse(status_code=502, content=_outcome_json(op))
        if header_holder.get("_bad_header"):
            await mgr.cancel(op.operation_id)
            await watch_task
            pump_task.cancel()
            try:
                await pump_task
            except (asyncio.CancelledError, Exception):  # pylint: disable=broad-except
                pass
            return JSONResponse(
                status_code=502,
                content={"outcome": "error", "error": {"reason": "bad_header"}},
            )

        async def _body_iter() -> AsyncIterator[bytes]:
            try:
                while True:
                    chunk = await body_queue.get()
                    if chunk is None:
                        return
                    if isinstance(chunk, _StreamFailure):
                        raise chunk
                    yield chunk
            finally:
                # Body fully consumed (or aborted) — now safe to tear
                # down the pump + watcher. Watcher already enqueued
                # its sentinel; pump may be parked on op.inbound.get()
                # so it has to be cancelled.
                pump_task.cancel()
                try:
                    await pump_task
                except (
                    asyncio.CancelledError,
                    Exception,
                ):  # pylint: disable=broad-except
                    pass
                if not watch_task.done():
                    watch_task.cancel()
                    try:
                        await watch_task
                    except (
                        asyncio.CancelledError,
                        Exception,
                    ):  # pylint: disable=broad-except
                        pass

        size = header_holder.get("size", 0)
        mode = header_holder.get("mode", "")
        return StreamingResponse(
            _body_iter(),
            media_type="application/octet-stream",
            headers={
                "X-Praxis-File-Size": str(size),
                "X-Praxis-File-Mode": str(mode),
            },
        )

    @app.post("/internal/agent/ops/file_put")
    async def agent_file_put(request: Request):
        mgr: OperationManager = app.state.manager
        if mgr is None:  # pragma: no cover
            raise HTTPException(500, "broker manager not initialised")

        # Required headers carry the metadata.
        try:
            system_id = int(request.headers["x-praxis-system-id"])
            path = request.headers["x-praxis-file-path"]
        except (KeyError, ValueError) as e:
            raise HTTPException(400, f"missing/invalid header: {e}")

        mode_str = request.headers.get("x-praxis-file-mode")
        overwrite = request.headers.get("x-praxis-overwrite", "false").lower() == "true"
        max_bytes = int(request.headers.get("x-praxis-max-bytes", "0"))
        declared_size = int(request.headers.get("x-praxis-declared-size", "0"))

        params: dict = {"path": path, "overwrite": overwrite}
        if mode_str:
            params["mode"] = mode_str
        if max_bytes > 0:
            params["max_bytes"] = max_bytes

        try:
            # Bounded outbound queue → put() blocks when the per-op
            # WSS bridge can't drain fast enough → the upstream HTTP
            # body read pauses → TCP backpressure walks back to the
            # client. Without this, a fast HTTP upload can pile
            # ~1MiB-each frames into op.outbound while the agent /
            # WSS slowly drains, blowing broker memory.
            op, _nonce = await mgr.create_and_dispatch(
                system_id, "file_put", params, outbound_maxsize=4
            )
        except NoActiveTunnel:
            return JSONResponse(
                status_code=503,
                content={
                    "outcome": "error",
                    "error": {"reason": "transport_unavailable"},
                },
            )
        except (ConcurrentOpsExceeded, NonceLimitExceeded):
            return _busy_response()

        try:
            await _wait_for_attach(op, ATTACH_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            try:
                await mgr.cancel(op.operation_id)
            except OpNotFound:
                pass
            return JSONResponse(
                status_code=504,
                content={
                    "outcome": "error",
                    "error": {"reason": "agent_attach_timeout"},
                },
            )

        # Send the file_put header on ChannelControl first, then
        # stream HTTP body chunks → ChannelFile Data frames. Per the
        # slice-3 lock the broker MUST NOT buffer the upload; we
        # forward chunks as they arrive with a max-bytes counter.
        await op.outbound.put(
            Frame(
                op=FrameOp.DATA,
                channel=Channel.CONTROL,
                flags=0,
                payload=json.dumps(
                    {"type": "file_header", "size": declared_size}
                ).encode("utf-8"),
            )
        )

        bytes_written = 0
        chunk_cap = DEFAULT_MAX_FRAME_PAYLOAD_BYTES
        try:
            async for chunk in request.stream():
                if not chunk:
                    continue
                # Re-chunk if the HTTP client gives us larger pieces
                # than a single frame can carry.
                view = memoryview(chunk)
                while view:
                    piece, view = bytes(view[:chunk_cap]), view[chunk_cap:]
                    bytes_written += len(piece)
                    if max_bytes and bytes_written > max_bytes:
                        await mgr.cancel(op.operation_id)
                        return JSONResponse(
                            status_code=413,
                            content={
                                "outcome": "error",
                                "error": {"reason": "too_large"},
                            },
                        )
                    await op.outbound.put(
                        Frame(
                            op=FrameOp.DATA,
                            channel=Channel.FILE,
                            flags=0,
                            payload=piece,
                        )
                    )
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("file_put: HTTP body read failed: %s", e)
            await mgr.cancel(op.operation_id)
            return JSONResponse(
                status_code=502,
                content={
                    "outcome": "error",
                    "error": {"reason": "client_disconnected"},
                },
            )

        # Signal end-of-file to the agent.
        await op.outbound.put(
            Frame(op=FrameOp.CLOSE, channel=Channel.FILE, flags=0, payload=b"")
        )

        # Now wait for the agent's op_complete.
        op = await _drain_op_until_complete(
            op,
            request,
            cap_seconds=EXEC_HARD_CAP_SECONDS,
            on_frame=lambda _f: None,
            cancel=mgr.cancel,
        )
        if op.outcome == "success":
            return {"outcome": "success", "bytes_written": bytes_written}
        return JSONResponse(
            status_code=502,
            content=_outcome_json(op, bytes_written=bytes_written),
        )

    @app.post("/internal/agent/ops/facts")
    async def agent_facts(req: FactsRequest, request: Request):
        """PRA-155 #2b-a: dispatch op_type='facts' on the agent's
        control tunnel and return the inline facts payload from
        op_complete.

        Wire shape (from agent op_facts.go runFacts): the agent's
        op_complete carries top-level ``facts`` and ``partial_errors``
        fields, which ``_route_op_complete`` captures into
        ``op.result_metadata`` automatically. We don't expect any
        per-op WSS frames; the agent doesn't send any.

        Error vocabulary mirrors the existing exec/file_get patterns:
            503 transport_unavailable        no live tunnel
            504 agent_attach_timeout         agent never dialed /agent/op
            504 facts_timeout                op_complete didn't arrive
                                             within FACTS_HARD_CAP_SECONDS
            502 op_error                     op_complete reported error /
                                             cancelled outcome
        """
        mgr: OperationManager = app.state.manager
        if mgr is None:  # pragma: no cover - production wiring
            raise HTTPException(500, "broker manager not initialised")

        try:
            op, _nonce = await mgr.create_and_dispatch(req.system_id, "facts", {})
        except NoActiveTunnel:
            return JSONResponse(
                status_code=503,
                content={
                    "outcome": "error",
                    "error": {"reason": "transport_unavailable"},
                },
            )
        except (ConcurrentOpsExceeded, NonceLimitExceeded):
            return _busy_response()

        try:
            await _wait_for_attach(op, ATTACH_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            try:
                await mgr.cancel(op.operation_id)
            except OpNotFound:
                pass
            return JSONResponse(
                status_code=504,
                content={
                    "outcome": "error",
                    "error": {"reason": "agent_attach_timeout"},
                },
            )

        # No frame draining — facts is inline-only on op_complete.
        # _drain_op_until_complete with a no-op on_frame is the right
        # primitive (it also handles caller disconnect + the cap).
        op = await _drain_op_until_complete(
            op,
            request,
            cap_seconds=FACTS_HARD_CAP_SECONDS,
            on_frame=lambda _f: None,
            cancel=mgr.cancel,
        )

        meta = op.result_metadata or {}
        if op.outcome == "success":
            facts = meta.get("facts") if isinstance(meta.get("facts"), dict) else None
            partial = (
                meta.get("partial_errors")
                if isinstance(meta.get("partial_errors"), list)
                else []
            )
            if facts is None:
                # Success without inline facts is a protocol violation —
                # an older agent that still runs the stub for op_type=
                # "facts" would land here. Surface as 502 so the caller
                # doesn't ingest an empty row as a healthy poll.
                return JSONResponse(
                    status_code=502,
                    content={
                        "outcome": "error",
                        "error": {"reason": "missing_inline_facts"},
                    },
                )
            return {
                "outcome": "success",
                "operation_id": op.operation_id,
                "facts": facts,
                "partial_errors": partial,
            }

        # ``cancelled`` here means _drain_op_until_complete hit our cap
        # or the caller disconnected; either way the agent didn't
        # report on time. Map to 504 so the refresh endpoint can
        # surface "agent didn't respond" distinct from a real op
        # error. Other terminal outcomes are agent-reported failures
        # → 502.
        if op.outcome == "cancelled":
            return JSONResponse(
                status_code=504,
                content={"outcome": "error", "error": {"reason": "facts_timeout"}},
            )
        return JSONResponse(status_code=502, content=_outcome_json(op))

    return app
