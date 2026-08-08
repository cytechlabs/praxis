"""Transport abstract base + return shapes (PRA-153 slice #1).

Two implementations land in slice #3 (SSHTransport, AgentTransport).
This module defines the contract both must honour.

Per the PRA-153 design lock:
    - run_command  is high-level + sync (returns one CommandResult)
    - open_pty     is streaming (used by SessionRuntime)
    - file get/put are streaming
    - directory ops (list/stat/mkdir/unlink) are NOT in this
      abstraction. SSH callers keep using paramiko.SFTP for those.
      Forced-agent callers asking for them get TransportUnsupported.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import AsyncIterator, Optional, Protocol

# ---- exceptions ----


class TransportError(Exception):
    """Base for transport errors so callers can `except TransportError`."""


class TransportUnavailable(TransportError):
    """Raised when ``transport_preference=agent`` but no healthy tunnel.

    Per the PRA-153 lock, force-agent NEVER falls back to SSH. This
    surfaces to callers with a clear failure mode so the audit
    record reflects what the operator actually asked for.
    """


class TransportUnsupported(TransportError):
    """Raised when the chosen transport doesn't support the requested op.

    Example: ``transport_preference=agent`` with a directory listing
    request (agent has no list_dir primitive in M13). Auto/SSH
    paths route directory ops over SSH; forced-agent fails loudly.
    """


# ---- return shapes ----


@dataclass
class CommandResult:
    """Outcome of ``Transport.run_command``.

    ``exit_code`` is the child process's exit code; ``-1`` is
    reserved for "killed by signal, exit code unknown" (matches
    paramiko + Go agent semantics).
    """

    exit_code: int
    stdout: bytes
    stderr: bytes
    duration_ms: int


# Concrete async callable types. PRA-153 lock: these are real
# signatures (not `object` placeholders) even though slice #3
# defers PTY wiring — having sharp contracts in place reduces
# surprises later when the SessionRuntime / PtyDriver work lands.

# Inbound bytes from the remote side (PTY output, file body chunks).
RecvIterator = AsyncIterator[bytes]


class PtySendChannel(Protocol):
    """Push raw bytes into the remote PTY's stdin."""

    async def __call__(self, data: bytes) -> None: ...  # noqa: E701


class PtyResizeFn(Protocol):
    """Resize the remote PTY (TIOCSWINSZ on the agent side)."""

    async def __call__(self, rows: int, cols: int) -> None: ...  # noqa: E701


class PtySignalFn(Protocol):
    """Send a signal name (``"INT"`` / ``"TERM"`` / ``"QUIT"`` / ``"HUP"``)."""

    async def __call__(self, name: str) -> None: ...  # noqa: E701


class PtyCloseFn(Protocol):
    """Tear down the PTY session and release the underlying transport."""

    async def __call__(self) -> None: ...  # noqa: E701


@dataclass
class PtySession:
    """Streaming handle for an interactive PTY session.

    Concrete implementations layer on top of paramiko's invoke_shell()
    or the agent's ChannelPty frames. SessionRuntime owns the higher-
    level orchestration (recording, idle timeout, etc.) and consumes
    this stream.

    Note: agent-backed PTY sessions are deferred from PRA-153 #3 —
    they require an effective_login switching design (sudo -Hiu /
    runuser) so a fleet-role-authorized user's session doesn't end up
    as a root shell. SSH-backed PtySession is the only implementation
    that ships in slice #3.
    """

    recv: RecvIterator
    send: PtySendChannel
    resize: PtyResizeFn
    signal: PtySignalFn
    close: PtyCloseFn


class FileWriteFn(Protocol):
    """Push the next chunk of a file_put body."""

    async def __call__(self, chunk: bytes) -> None: ...  # noqa: E701


class FileCloseFn(Protocol):
    """Finalize / close a file stream."""

    async def __call__(self) -> None: ...  # noqa: E701


@dataclass
class FileGetStream:
    """Streaming handle for ``Transport.open_file_get``.

    Mirrors the agent's file_get framing: a header (size, mode) up
    front, then bytes. SSH implementation reconstructs this shape
    from sftp stat + open. ``chunks`` may raise ``TransportError``
    mid-iteration if the underlying transport fails after streaming
    has begun (per the slice-#3 file_get post-header error contract).
    """

    size: int
    mode: int
    chunks: RecvIterator
    close: FileCloseFn


@dataclass
class FilePutStream:
    """Streaming handle for ``Transport.open_file_put``.

    Caller pushes bytes via ``write`` then ``finish``. Mirrors the
    agent's file_put framing (header up front, bytes after, atomic
    rename on close).
    """

    write: FileWriteFn
    finish: FileCloseFn


# ---- abstract base ----


class Transport(abc.ABC):
    """Contract every transport implements.

    Per the PRA-153 lock, the abstraction is operation-shaped (not
    raw byte streams) so most callers can stay simple. The streaming
    methods are escape hatches for the genuinely-streaming use cases
    (SessionRuntime, large file transfer).
    """

    # Identifier the audit / UI layers tag every operation with.
    # Concrete classes set this to "ssh" or "agent".
    name: str = "abstract"

    @abc.abstractmethod
    async def run_command(
        self,
        cmd: list[str],
        *,
        stdin: Optional[bytes] = None,
        timeout_seconds: Optional[float] = None,
    ) -> CommandResult:
        """Run a one-shot non-PTY command. Returns the full result."""

    @abc.abstractmethod
    async def open_pty(
        self,
        cmd: list[str],
        *,
        term: str = "xterm-256color",
        rows: int = 24,
        cols: int = 80,
    ) -> PtySession:
        """Open a streaming PTY session."""

    @abc.abstractmethod
    async def open_file_get(self, path: str) -> FileGetStream:
        """Stream the contents of a remote regular file."""

    @abc.abstractmethod
    async def open_file_put(
        self,
        path: str,
        *,
        size: int,
        mode: int = 0o600,
        overwrite: bool = False,
    ) -> FilePutStream:
        """Stream bytes into a remote file (atomic on the agent path)."""


# ---- stub implementations (slice #1 only) ----


class _StubTransport(Transport):
    """Slice #1 stub.

    The factory returns these so callers can wire through the
    abstraction now; the actual op methods land in slice #3 when we
    refactor SSHService / SessionRuntime / file_transfer_service.
    Calling any op method on a stub raises NotImplementedError so
    accidental early integration fails loudly.
    """

    async def run_command(self, *_a, **_k):  # pragma: no cover - slice #3 fills this
        raise NotImplementedError(f"{self.name} transport not yet wired (slice #3)")

    async def open_pty(self, *_a, **_k):  # pragma: no cover
        raise NotImplementedError(f"{self.name} transport not yet wired (slice #3)")

    async def open_file_get(self, *_a, **_k):  # pragma: no cover
        raise NotImplementedError(f"{self.name} transport not yet wired (slice #3)")

    async def open_file_put(self, *_a, **_k):  # pragma: no cover
        raise NotImplementedError(f"{self.name} transport not yet wired (slice #3)")


class SSHTransportStub(_StubTransport):
    """Slice #3 will replace this with paramiko-backed implementation."""

    name = "ssh"

    def __init__(self, system) -> None:
        self.system = system


class AgentTransportStub(_StubTransport):
    """Slice #3 will replace this with broker-mediated agent ops."""

    name = "agent"

    def __init__(self, system, broker_client) -> None:
        self.system = system
        self.broker_client = broker_client
