"""Transport abstraction (PRA-153 slice #1).

Two implementations land in slice #3:
    SSHTransport — wraps the existing paramiko-backed connection.
    AgentTransport — dispatches over the per-op WSS via the broker.

Slice #1 only ships:
    - the abstract Transport base class + per-op return shapes
    - TransportUnavailable / TransportUnsupported exceptions
    - get_transport() factory that resolves System.transport_preference
      against broker tunnel health
    - stub Transport implementations whose op methods raise
      NotImplementedError. Callers don't go through the factory yet,
      so no behavior change ships in slice #1.
"""

from .agent import AgentTransport
from .base import (
    AgentTransportStub,
    CommandResult,
    FileGetStream,
    FilePutStream,
    PtySession,
    SSHTransportStub,
    Transport,
    TransportError,
    TransportUnavailable,
    TransportUnsupported,
)
from .factory import get_transport
from .ssh import SSHTransport

__all__ = [
    "AgentTransport",
    "AgentTransportStub",
    "CommandResult",
    "FileGetStream",
    "FilePutStream",
    "PtySession",
    "SSHTransport",
    "SSHTransportStub",
    "Transport",
    "TransportError",
    "TransportUnavailable",
    "TransportUnsupported",
    "get_transport",
]
