"""In-memory ``AgentRegistry`` for connected tunnels (PRA-151 task #15).

Process-local. The broker listener is single-process by design (see the
PRA-151 listener-strategy decision in ``project_m13_design_decisions``);
sharing the registry across multiple workers is out of scope for M13.

A ``TunnelEntry`` is created only after a successful hello/welcome
handshake. Duplicate ``system_id`` semantics: newest valid tunnel wins,
the displaced tunnel is sent ``{"type":"bye","reason":"replaced"}`` and
closed cleanly.

All locking is asyncio-only.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from websockets.legacy.server import WebSocketServerProtocol

from .tls import PeerIdentity

logger = logging.getLogger(__name__)


@dataclass
class TunnelEntry:
    """One connected agent's tunnel state.

    ``last_recv_monotonic`` and ``last_heartbeat_sent_monotonic`` use
    ``time.monotonic()`` so wall-clock skew or DST jumps don't break
    liveness. ``last_db_write_monotonic`` lets the heartbeat path
    throttle DB writes for ``System.agent_last_seen_at``.
    """

    system_id: int
    tunnel_session_id: str
    ws: WebSocketServerProtocol
    identity: PeerIdentity
    capabilities: List[str]
    agent_version: str
    connected_at_monotonic: float = field(default_factory=time.monotonic)
    last_recv_monotonic: float = field(default_factory=time.monotonic)
    last_heartbeat_sent_monotonic: float = 0.0
    last_db_write_monotonic: float = 0.0


class AgentRegistry:
    """Process-local map of ``system_id`` -> ``TunnelEntry``."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._by_system: Dict[int, TunnelEntry] = {}

    async def register(self, entry: TunnelEntry) -> Optional[TunnelEntry]:
        """Insert ``entry`` and return the displaced predecessor (if any).

        The caller is responsible for sending the ``bye`` and closing the
        displaced tunnel; the registry only owns the bookkeeping so the
        socket-level work stays in the handler.
        """
        async with self._lock:
            displaced = self._by_system.get(entry.system_id)
            self._by_system[entry.system_id] = entry
            if displaced is not None:
                logger.info(
                    "duplicate tunnel for system_id=%s — newest wins (old session=%s, new session=%s)",
                    entry.system_id,
                    displaced.tunnel_session_id,
                    entry.tunnel_session_id,
                )
            return displaced

    async def unregister(self, system_id: int, tunnel_session_id: str) -> bool:
        """Remove the entry only if its ``tunnel_session_id`` matches.

        Guards against the race where a newer tunnel for the same
        ``system_id`` has already replaced this one — the older
        coroutine's cleanup must not evict the newer entry.
        """
        async with self._lock:
            current = self._by_system.get(system_id)
            if current is None or current.tunnel_session_id != tunnel_session_id:
                return False
            del self._by_system[system_id]
            return True

    def get(self, system_id: int) -> Optional[TunnelEntry]:
        """Snapshot read — no lock; callers must tolerate stale reads.

        Mutations are async-locked, so a concurrent register/unregister
        may have just finished even when this returns.
        """
        return self._by_system.get(system_id)

    def all(self) -> List[TunnelEntry]:
        """Snapshot list of currently connected tunnels."""
        return list(self._by_system.values())

    def __len__(self) -> int:
        return len(self._by_system)


# Module-level singleton shared by every handler in this process. The
# broker listener is single-process by design (PRA-151 listener
# decision); a module global is the right shape until/unless we cluster.
default_registry = AgentRegistry()
