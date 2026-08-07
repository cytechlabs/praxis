"""In-process session runtime registry (PRA-140 + PRA-148 fanout).

Holds live paramiko PTY channels keyed by session_id. The REST endpoint
that opens a session creates a ``SessionRuntime`` and registers it here.
WebSocket handlers retrieve it and ``attach`` as subscribers.

PRA-140 single-subscriber path is now a degenerate case of PRA-148
multi-subscriber fanout: any number of subscribers can attach with a
mode (``owner`` | ``observe`` | ``participate``); output bytes are
broadcast to every subscriber's queue, and writes from any
``owner``/``participate`` subscriber are multiplexed into the PTY.

Lives in-process — the runtime is bound to a specific paramiko transport
and cannot be shared across workers. PRA-141 recording taps in via
``add_consumer``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Literal, Optional

import paramiko

logger = logging.getLogger(__name__)


SubscriberMode = Literal["owner", "observe", "participate"]


@dataclass
class Subscriber:
    """A single attached WebSocket consumer of a session's output stream."""

    sid: int
    loop: asyncio.AbstractEventLoop
    out_queue: "asyncio.Queue[Optional[bytes]]"
    username: str
    mode: SubscriberMode
    joined_at: datetime = field(default_factory=datetime.utcnow)
    # PRA-148: cheap rate-limit token for session.moderator_write audits
    last_write_audit_at: float = 0.0


class SessionRuntime:
    """Wraps a single paramiko ``invoke_shell`` channel with multi-subscriber fanout."""

    def __init__(
        self,
        session_id: int,
        transport: paramiko.Transport,
        channel: paramiko.Channel,
        max_expires_at: datetime,
    ) -> None:
        self.session_id = session_id
        self.transport = transport
        self.channel = channel
        self.max_expires_at = max_expires_at
        self.closed = threading.Event()
        self.last_activity = time.monotonic()
        self._lock = threading.Lock()

        self._subscribers: Dict[int, Subscriber] = {}
        self._next_sid = 1
        self._reader: Optional[threading.Thread] = None
        self._consumers: List[Callable[[bytes], None]] = []
        self._on_close: Optional[Callable[[int, str], None]] = None

    # ----------------------------------------------------- consumer hooks

    def add_consumer(self, fn: Callable[[bytes], None]) -> None:
        """Register an extra byte sink (used by PRA-141 recording)."""
        with self._lock:
            self._consumers.append(fn)

    def set_on_close(self, fn: Callable[[int, str], None]) -> None:
        self._on_close = fn

    # ---------------------------------------------------- lifecycle

    def attach(
        self,
        loop: asyncio.AbstractEventLoop,
        out_queue: "asyncio.Queue[Optional[bytes]]",
        *,
        username: str = "",
        mode: SubscriberMode = "owner",
    ) -> int:
        """Register a subscriber. Returns its ``sid`` for later ``detach``.

        The reader thread starts on the first attach and runs until
        ``close()``; subsequent attaches just join the fanout.
        """
        with self._lock:
            sid = self._next_sid
            self._next_sid += 1
            sub = Subscriber(
                sid=sid,
                loop=loop,
                out_queue=out_queue,
                username=username,
                mode=mode,
            )
            self._subscribers[sid] = sub
            need_reader = self._reader is None
        if need_reader:
            t = threading.Thread(
                target=self._read_loop,
                name=f"session-{self.session_id}-reader",
                daemon=True,
            )
            with self._lock:
                self._reader = t
            t.start()
        return sid

    def detach(self, sid: int) -> None:
        """Remove a subscriber. Sends EOF to its queue but leaves the PTY open."""
        with self._lock:
            sub = self._subscribers.pop(sid, None)
        if sub is None:
            return
        try:
            sub.loop.call_soon_threadsafe(sub.out_queue.put_nowait, None)
        except RuntimeError:
            pass

    def list_subscribers(self) -> List[Dict[str, object]]:
        """Snapshot of attached subscribers (used by GET /sessions/{id})."""
        with self._lock:
            subs = list(self._subscribers.values())
        return [
            {
                "sid": s.sid,
                "username": s.username,
                "mode": s.mode,
                "joined_at": s.joined_at.isoformat() + "Z",
            }
            for s in subs
        ]

    def _read_loop(self) -> None:
        try:
            while not self.closed.is_set():
                if self.channel.closed or self.channel.eof_received:
                    break
                if self.channel.recv_ready():
                    try:
                        data = self.channel.recv(4096)
                    except Exception as e:  # pylint: disable=broad-except
                        logger.warning("session %d recv: %s", self.session_id, e)
                        break
                    if not data:
                        break
                    self.last_activity = time.monotonic()
                    self._dispatch(data)
                else:
                    time.sleep(0.02)
        finally:
            self._dispatch_eof()
            if self._on_close is not None:
                try:
                    self._on_close(self.session_id, "remote_eof")
                except Exception as e:  # pylint: disable=broad-except
                    logger.warning("on_close cb raised: %s", e)

    def _dispatch(self, data: bytes) -> None:
        with self._lock:
            subs = list(self._subscribers.values())
            consumers = list(self._consumers)
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(sub.out_queue.put_nowait, data)
            except RuntimeError:
                pass  # loop closed
        for c in consumers:
            try:
                c(data)
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("consumer raised: %s", e)

    def _dispatch_eof(self) -> None:
        self.closed.set()
        with self._lock:
            subs = list(self._subscribers.values())
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(sub.out_queue.put_nowait, None)
            except RuntimeError:
                pass

    # -------------------------------------------------- client ops

    def write(self, data: bytes, *, sid: Optional[int] = None) -> None:
        """Send ``data`` into the remote PTY (from owner / participant input).

        ``sid`` identifies the writing subscriber so callers can rate-limit
        per-subscriber audit events. Observers must not reach this method —
        the WS handler enforces that before calling.
        """
        if self.closed.is_set() or self.channel.closed:
            return
        try:
            self.channel.send(data)
            self.last_activity = time.monotonic()
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("session %d send: %s", self.session_id, e)
        # Mark the subscriber's audit timestamp so the WS handler can decide
        # whether to emit a fresh session.moderator_write event. We do this
        # here to keep the rate-limit logic colocated with the actual write.
        if sid is not None:
            with self._lock:
                sub = self._subscribers.get(sid)
            if sub is not None:
                sub.last_write_audit_at = max(sub.last_write_audit_at, time.monotonic())

    def resize(self, cols: int, rows: int) -> None:
        if self.closed.is_set() or self.channel.closed:
            return
        try:
            self.channel.resize_pty(width=cols, height=rows)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("session %d resize: %s", self.session_id, e)

    def close(self, reason: str = "client_close") -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            self.channel.close()
        except Exception:  # pylint: disable=broad-except
            pass
        try:
            self.transport.close()
        except Exception:  # pylint: disable=broad-except
            pass
        # Flush EOF to every subscriber
        with self._lock:
            subs = list(self._subscribers.values())
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(sub.out_queue.put_nowait, None)
            except RuntimeError:
                pass
        if self._on_close is not None:
            try:
                self._on_close(self.session_id, reason)
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("on_close cb raised: %s", e)


# ----------------------------------------------------------- registry


_registry: Dict[int, SessionRuntime] = {}
_registry_lock = threading.Lock()


def register(runtime: SessionRuntime) -> None:
    with _registry_lock:
        _registry[runtime.session_id] = runtime


def get(session_id: int) -> Optional[SessionRuntime]:
    with _registry_lock:
        return _registry.get(session_id)


def drop(session_id: int) -> None:
    with _registry_lock:
        _registry.pop(session_id, None)


def list_active() -> List[SessionRuntime]:
    with _registry_lock:
        return list(_registry.values())
