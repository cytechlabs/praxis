"""Bounded in-memory ring buffer of recent backend log records (PRA-310).

Backend logs stream to stdout (docker logs / journald); the app cannot read the
container's own log file. To make "recent backend logs" available to the admin
support bundle without shipping logs anywhere, a bounded ring-buffer handler is
attached to the root logger at startup. It is inherently size-bounded (a fixed-length
deque), single-worker (the supported 1.0 model), and thread-safe. Records are
redacted when the bundle is built, not here.
"""

from __future__ import annotations

import collections
import logging
import threading
from typing import Dict, List, Optional

_DEFAULT_CAPACITY = 5000

_FORMATTER = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")


class RingBufferLogHandler(logging.Handler):
    """A logging handler that retains the most recent ``capacity`` records."""

    def __init__(self, capacity: int = _DEFAULT_CAPACITY):
        super().__init__()
        self._buf: "collections.deque[Dict]" = collections.deque(maxlen=capacity)
        self._lock = threading.Lock()
        self.setFormatter(_FORMATTER)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "ts": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": self.format(record),
            }
            with self._lock:
                self._buf.append(entry)
        except Exception:  # pragma: no cover - logging must never raise
            self.handleError(record)

    def records(
        self, since_epoch: Optional[float] = None, limit: Optional[int] = None
    ) -> List[Dict]:
        with self._lock:
            items = list(self._buf)
        if since_epoch is not None:
            items = [r for r in items if r["ts"] >= since_epoch]
        if limit is not None and len(items) > limit:
            items = items[-limit:]
        return items


_handler: Optional[RingBufferLogHandler] = None
_install_lock = threading.Lock()


def install_log_buffer(
    capacity: int = _DEFAULT_CAPACITY, level: int = logging.INFO
) -> RingBufferLogHandler:
    """Attach the ring buffer to the root logger. Idempotent — repeated calls return
    the already-installed handler without adding a second one.

    Self-healing: if a later ``logging.basicConfig()`` / logging reconfiguration
    has detached our handler from the root logger, re-attach it. Without this a
    reconfig after install would silently stop feeding the buffer and the support
    bundle's log section would go empty — a bug that only shows up when install
    order and a later basicConfig interleave (PRA-339)."""
    global _handler  # pylint: disable=global-statement
    with _install_lock:
        root = logging.getLogger()
        if _handler is not None:
            if _handler not in root.handlers:
                root.addHandler(_handler)
            return _handler
        handler = RingBufferLogHandler(capacity=capacity)
        handler.setLevel(level)
        root.addHandler(handler)
        _handler = handler
        return handler


def get_log_buffer() -> Optional[RingBufferLogHandler]:
    """The installed ring buffer, or None if not installed (e.g. in a bare import)."""
    return _handler
