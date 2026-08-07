"""Agent transport implementation (PRA-153 slice #3b).

Wraps a ``BrokerClient`` so each Transport method translates to one
broker internal op call. Stays thin — the broker owns sequencing,
backpressure, cancellation, and per-op WSS bridging. AgentTransport's
job is just to map BrokerClient outcomes back into the
Transport-shaped CommandResult / FileGetStream / FilePutStream and
the right TransportError subclass on failure.

PTY is intentionally NOT implemented (raises TransportUnsupported)
per the PRA-153 #3 design lock — agent-backed PTY sessions wait for
effective_login switching to be designed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Optional

from app.services.broker_client import (
    BrokerClient,
    BrokerError,
    BrokerExecResult,
    BrokerFileGetStream,
)

from .base import (
    CommandResult,
    FileCloseFn,
    FileGetStream,
    FilePutStream,
    PtySession,
    Transport,
    TransportError,
    TransportUnavailable,
    TransportUnsupported,
)

logger = logging.getLogger(__name__)


class AgentTransport(Transport):
    """Routes Transport ops over the broker → agent dispatch path.

    Bound to one ``System`` instance. The factory builds a fresh
    AgentTransport per-request; the ``BrokerClient`` is shared so
    httpx connection pooling carries across.
    """

    name = "agent"

    def __init__(self, system, broker_client: BrokerClient) -> None:
        self.system = system
        self.broker_client = broker_client

    async def run_command(
        self,
        cmd: list[str],
        *,
        stdin: Optional[bytes] = None,
        timeout_seconds: Optional[float] = None,
    ) -> CommandResult:
        if not cmd:
            raise TransportError("agent: cmd must be a non-empty list")
        argv = list(cmd)
        try:
            result: BrokerExecResult = await self.broker_client.exec(
                self.system.id,
                argv[0],
                args=argv[1:],
                stdin=stdin,
                timeout_s=timeout_seconds or 0.0,
            )
        except BrokerError as exc:
            raise _broker_error_to_transport(exc) from exc

        if result.outcome != "success":
            reason = (result.error or {}).get("reason", "agent_error")
            raise TransportError(f"agent: exec returned {result.outcome}/{reason}")

        return CommandResult(
            exit_code=int(result.exit_code) if result.exit_code is not None else -1,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=int(result.duration_ms)
            if result.duration_ms is not None
            else 0,
        )

    async def open_pty(self, *_args, **_kwargs) -> PtySession:
        # PRA-153 #3 design lock: agent PTY waits for effective_login
        # switching design (sudo -Hiu / runuser). Until then a
        # fleet-role-authorized session must NOT route to a root
        # shell on the agent. Force-agent for sessions surfaces here.
        raise TransportUnsupported(
            "agent: PTY sessions deferred — use SSH transport for interactive shells"
        )

    async def open_file_get(self, path: str) -> FileGetStream:
        try:
            stream: BrokerFileGetStream = await self.broker_client.file_get(
                self.system.id, path
            )
        except BrokerError as exc:
            raise _broker_error_to_transport(exc) from exc

        # Wrap the broker stream into the Transport-shaped FileGetStream.
        # The body iterator surfaces BrokerError mid-stream as
        # TransportError(reason=op_stream_closed).
        async def _chunks() -> AsyncIterator[bytes]:
            try:
                async for chunk in stream.iter_bytes():
                    yield chunk
            except BrokerError as exc:
                raise _broker_error_to_transport(exc) from exc

        async def _close() -> None:
            await stream.__aexit__(None, None, None)

        # Parse the mode header into an int when present (the
        # agent emits e.g. "0o644"); 0 is a sane default for SFTP
        # callers that just want the bytes.
        try:
            mode_int = int(stream.mode, 8) if stream.mode else 0
        except ValueError:
            mode_int = 0

        return FileGetStream(
            size=stream.size,
            mode=mode_int,
            chunks=_chunks(),
            close=_close,
        )

    async def open_file_put(
        self,
        path: str,
        *,
        size: int,
        mode: int = 0o600,
        overwrite: bool = False,
    ) -> FilePutStream:
        # The broker streams bytes from the request body. We need to
        # plumb caller writes into an async iterator that httpx can
        # consume. A bounded queue + producer/consumer pattern gives
        # the caller backpressure when the broker / agent is slow.
        chunk_q: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=4)
        result_holder: dict = {}
        error_holder: dict = {}

        async def _body() -> AsyncIterator[bytes]:
            while True:
                item = await chunk_q.get()
                if item is None:
                    return
                yield item

        async def _runner() -> None:
            try:
                result = await self.broker_client.file_put(
                    self.system.id,
                    path,
                    _body(),
                    declared_size=size,
                    mode=f"{mode:o}" if mode else None,
                    overwrite=overwrite,
                )
                result_holder["result"] = result
            except BrokerError as exc:
                error_holder["error"] = exc
            except Exception as exc:  # pylint: disable=broad-except
                error_holder["error"] = BrokerError("transport_error", str(exc))

        runner_task = asyncio.create_task(_runner(), name="agent_file_put_runner")

        async def _put_or_runner_error(item: Optional[bytes]) -> None:
            """Race chunk_q.put against runner_task completion.

            If the runner exits early (broker 503 / attach timeout /
            etc.) without draining the queue, a bounded chunk_q.put
            would block forever waiting for a consumer that's gone.
            Wake the writer immediately so the caller sees
            TransportError instead of hanging.
            """
            if error_holder.get("error") is not None:
                raise _broker_error_to_transport(error_holder["error"])
            put_task = asyncio.ensure_future(chunk_q.put(item))
            done, _pending = await asyncio.wait(
                {put_task, runner_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if put_task in done:
                # Normal path: queue accepted the chunk.
                return
            # Runner finished first → producer must abort. Cancel
            # the pending put so we don't leak a coroutine.
            put_task.cancel()
            try:
                await put_task
            except (asyncio.CancelledError, Exception):  # pylint: disable=broad-except
                pass
            if error_holder.get("error") is not None:
                raise _broker_error_to_transport(error_holder["error"])
            # Runner returned cleanly with no error captured — also
            # an early exit; raise a generic transport error so the
            # caller doesn't keep writing into a closed sink.
            raise TransportError("agent: file_put runner exited before body finished")

        async def _write(chunk: bytes) -> None:
            await _put_or_runner_error(chunk)

        async def _finish() -> None:
            await _put_or_runner_error(None)
            # _put_or_runner_error returned without raising, so the
            # runner is still alive (or just finished cleanly with the
            # None sentinel we just enqueued). Wait for it to finish.
            if not runner_task.done():
                await runner_task
            if error_holder.get("error") is not None:
                raise _broker_error_to_transport(error_holder["error"])

        return FilePutStream(write=_write, finish=_finish)


# PRA-228 TRANSPORT-01: caller-visible transport errors are built from the
# stable reason vocabulary, not the raw BrokerError detail (which can carry the
# internal broker URL, connection internals, or stack-ish exception text). The
# reason code is retained in the message so operators/audit stay actionable; the
# full detail is logged server-side only.
_REASON_MESSAGES = {
    "transport_unavailable": "agent transport is unavailable",
    "broker_unreachable": "agent broker is unreachable",
    "agent_attach_timeout": "agent did not attach in time",
    "header_timeout": "agent did not send a file header in time",
    "facts_timeout": "agent facts collection timed out",
    "exec_output_too_large": "command output exceeded the broker size limit",
    "op_stream_closed": "agent transfer stream closed early",
    "broker_busy": "agent broker is at capacity; retry shortly",
    "too_large": "transfer exceeded the size limit",
}


def _broker_error_to_transport(exc: BrokerError) -> TransportError:
    """Map BrokerError reasons → the right Transport exception type.

    The audit / UI layers key off the exception class, so this
    mapping is the single source of truth for what counts as
    "tunnel unavailable" vs a generic transport failure.
    """
    reason = exc.reason
    if exc.detail:
        # Keep the raw detail for operators, out of the caller-visible message.
        logger.warning(
            "agent transport op failed: reason=%s detail=%s", reason, exc.detail
        )
    message = _REASON_MESSAGES.get(reason, "agent transport error")
    text = f"agent: {message} ({reason})"
    if reason == "transport_unavailable":
        return TransportUnavailable(text)
    return TransportError(text)
