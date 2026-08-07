"""Transport factory (PRA-153 slices #1 + #3b + #3c).

Resolves ``System.transport_preference`` against broker tunnel
health to pick the right transport. The mapping is:

    pref=ssh                    -> SSHTransport (always)
    pref=auto + agent healthy   -> AgentTransport
    pref=auto + agent down      -> SSHTransport (graceful fallback)
    pref=agent + agent healthy  -> AgentTransport
    pref=agent + agent down     -> raise TransportUnavailable

Per the PRA-153 lock, ``pref=agent`` NEVER falls back to SSH. Force
means force; the audit ledger should reflect what actually happened.

Slice #3b ships a real ``AgentTransport``; slice #3c ships a real
``SSHTransport``. The stub classes remain importable for tests that
want a no-op transport.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from .agent import AgentTransport
from .base import Transport, TransportUnavailable
from .ssh import SSHTransport

if TYPE_CHECKING:  # pragma: no cover
    from app.db.models import System
    from app.services.broker_client import BrokerClient
    from app.services.ssh_service import SSHService

logger = logging.getLogger(__name__)


async def get_transport(
    system: "System",
    broker_client: "BrokerClient",
    ssh_service: Optional["SSHService"] = None,
) -> Transport:
    """Return the right transport for ``system`` per its preference.

    ``ssh_service`` is required when the resolution lands on the
    SSH path (forced ssh, or auto fallback). Callers that only ever
    use ``pref=agent`` may pass None — but passing it
    unconditionally is the safer pattern. Raises ``TransportError``
    if SSH is the chosen transport and ``ssh_service`` is missing,
    since the resolver has already committed to that path.

    Raises ``TransportUnavailable`` only when ``transport_preference
    == "agent"`` and the broker reports the tunnel as not healthy.
    """
    pref = (system.transport_preference or "auto").lower()

    if pref == "ssh":
        logger.debug(
            "transport: system_id=%s pref=ssh -> SSHTransport (forced)",
            system.id,
        )
        return _ssh(system, ssh_service)

    health = await broker_client.health(system.id)

    if pref == "agent":
        if not health.is_usable:
            logger.warning(
                "transport: system_id=%s pref=agent + tunnel %s -> raising TransportUnavailable",
                system.id,
                health.state,
            )
            raise TransportUnavailable(
                f"system {system.id}: transport_preference=agent but tunnel state={health.state}"
            )
        logger.debug(
            "transport: system_id=%s pref=agent + tunnel healthy -> AgentTransport",
            system.id,
        )
        return AgentTransport(system, broker_client)

    # auto
    if health.is_usable:
        logger.debug(
            "transport: system_id=%s pref=auto + tunnel healthy -> AgentTransport",
            system.id,
        )
        return AgentTransport(system, broker_client)
    logger.debug(
        "transport: system_id=%s pref=auto + tunnel %s -> SSHTransport (fallback)",
        system.id,
        health.state,
    )
    return _ssh(system, ssh_service)


def _ssh(system, ssh_service) -> Transport:
    if ssh_service is None:
        # Resolver has already committed to SSH; if the caller didn't
        # plumb an SSHService, that's a programmer error worth a hard
        # failure. Surfaces via TransportUnavailable so the audit
        # ledger gets a row instead of a silent traceback.
        raise TransportUnavailable(
            f"system {system.id}: SSH transport selected but no SSHService provided"
        )
    return SSHTransport(system, ssh_service)
