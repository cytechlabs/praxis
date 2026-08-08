"""SSH transport implementation (PRA-153 slice #3c).

Wraps the existing paramiko-backed ``SSHService`` so each Transport
method translates to a paramiko call, run on a worker thread via
``asyncio.to_thread`` so the event loop never blocks on synchronous
network I/O.

Per the PRA-153 design lock:
    - SSHService internals are NOT refactored. SSHTransport just
      borrows ``SSHService.get_connection(system_id)`` to acquire a
      pooled paramiko.SSHClient.
    - This is a feature-complete transport: run_command, open_pty,
      open_file_get, open_file_put all work over SSH/SFTP.
    - Directory ops (list/stat/mkdir/unlink) intentionally stay out
      of the Transport abstraction — file_transfer_service routes
      those directly through SSH for both ssh and auto preferences,
      and raises TransportUnsupported for forced-agent.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import AsyncIterator, Optional

import paramiko

from .base import (
    CommandResult,
    FileGetStream,
    FilePutStream,
    PtySession,
    Transport,
    TransportError,
)

logger = logging.getLogger(__name__)

# Read chunk size used when streaming a remote file via SFTP. Same
# 32 KiB chunk the agent's file_get loop uses, so callers see
# similar pacing on either transport.
SFTP_CHUNK_BYTES = 32 * 1024


class SSHTransport(Transport):
    """Routes Transport ops over the existing paramiko-backed SSHService.

    Bound to one ``System`` instance. Reuses the pooled SSHClient so
    repeated transport calls against the same host don't pay the TCP
    + handshake cost each time.
    """

    name = "ssh"

    def __init__(self, system, ssh_service) -> None:
        self.system = system
        self.ssh_service = ssh_service

    # ---- helpers ----

    async def _client(self) -> paramiko.SSHClient:
        """Acquire a paramiko client off the SSHService pool.

        ``get_connection`` does pooling + reachability checks
        synchronously; offload to a thread so the event loop is free.
        """

        def _sync():
            client, _is_new = self.ssh_service.get_connection(self.system.id)
            return client

        return await asyncio.to_thread(_sync)

    # ---- run_command ----

    async def run_command(
        self,
        cmd: list[str],
        *,
        stdin: Optional[bytes] = None,
        timeout_seconds: Optional[float] = None,
    ) -> CommandResult:
        if not cmd:
            raise TransportError("ssh: cmd must be a non-empty list")
        client = await self._client()
        # paramiko exec_command takes a single string; quote each
        # argv member to preserve word boundaries.
        cmd_str = " ".join(_shell_quote(arg) for arg in cmd)

        def _sync() -> CommandResult:
            t0 = time.monotonic()
            try:
                stdin_io, stdout_io, stderr_io = client.exec_command(
                    cmd_str,
                    timeout=timeout_seconds
                    if timeout_seconds and timeout_seconds > 0
                    else None,
                )
                if stdin is not None:
                    stdin_io.write(stdin)
                    stdin_io.flush()
                stdin_io.close()
                stdout = stdout_io.read()
                stderr = stderr_io.read()
                exit_code = stdout_io.channel.recv_exit_status()
            except paramiko.SSHException as exc:
                raise TransportError(f"ssh: exec failed: {exc}") from exc
            except OSError as exc:
                raise TransportError(f"ssh: socket error: {exc}") from exc
            duration_ms = int((time.monotonic() - t0) * 1000)
            return CommandResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )

        return await asyncio.to_thread(_sync)

    # ---- open_pty ----

    async def open_pty(
        self,
        cmd: list[str],
        *,
        term: str = "xterm-256color",
        rows: int = 24,
        cols: int = 80,
    ) -> PtySession:
        """Open an interactive shell via paramiko.invoke_shell.

        ``cmd`` is currently advisory — paramiko's invoke_shell launches
        the user's default login shell as configured server-side. A
        future slice can route ``cmd`` via ``exec_command(get_pty=True)``
        for non-shell PTY ops, but the current SessionRuntime use case
        always wants a login shell.
        """
        _ = cmd  # see docstring
        client = await self._client()

        def _open_channel():
            try:
                channel = client.invoke_shell(term=term, width=cols, height=rows)
            except paramiko.SSHException as exc:
                raise TransportError(f"ssh: invoke_shell failed: {exc}") from exc
            return channel

        channel = await asyncio.to_thread(_open_channel)
        return _build_paramiko_pty_session(channel)

    # ---- file ops via SFTP ----

    async def open_file_get(self, path: str) -> FileGetStream:
        client = await self._client()

        def _stat_open():
            sftp = None
            handle = None
            try:
                sftp = client.open_sftp()
                attrs = sftp.stat(path)
                handle = sftp.open(path, "rb")
                handle.prefetch()
                return sftp, handle, int(attrs.st_size or 0), int(attrs.st_mode or 0)
            except FileNotFoundError as exc:
                _safe_close(handle, sftp)
                raise TransportError(f"ssh: not_found: {path}") from exc
            except PermissionError as exc:
                _safe_close(handle, sftp)
                raise TransportError(f"ssh: denied: {path}") from exc
            except paramiko.SSHException as exc:
                _safe_close(handle, sftp)
                raise TransportError(f"ssh: open_sftp failed: {exc}") from exc
            except OSError as exc:
                _safe_close(handle, sftp)
                raise TransportError(f"ssh: sftp stat/open: {exc}") from exc

        sftp, handle, size, mode = await asyncio.to_thread(_stat_open)

        async def _chunks() -> AsyncIterator[bytes]:
            while True:
                try:
                    chunk = await asyncio.to_thread(handle.read, SFTP_CHUNK_BYTES)
                except (paramiko.SSHException, OSError) as exc:
                    # Mid-transfer SSH/SFTP failure must surface as
                    # TransportError so callers + audit see the same
                    # vocabulary as AgentTransport's op_stream_closed.
                    await asyncio.to_thread(_safe_close, handle, sftp)
                    raise TransportError(f"ssh: read failed mid-stream: {exc}") from exc
                if not chunk:
                    return
                yield chunk

        async def _close() -> None:
            await asyncio.to_thread(_safe_close, handle, sftp)

        return FileGetStream(
            size=size,
            mode=mode & 0o7777,
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
        _ = size  # SFTP doesn't need declared size
        client = await self._client()

        def _open():
            sftp = None
            handle = None
            try:
                sftp = client.open_sftp()
                if not overwrite:
                    try:
                        sftp.stat(path)
                    except FileNotFoundError:
                        pass  # absence is what we want
                    else:
                        # Path exists and overwrite=False; fall through
                        # to the unified close-on-error branch below.
                        raise _ExistsError(path)
                handle = sftp.open(path, "wb")
                handle.set_pipelined(True)
                return sftp, handle
            except _ExistsError as exc:
                _safe_close(handle, sftp)
                raise TransportError(f"ssh: exists: {exc}") from exc
            except paramiko.SSHException as exc:
                _safe_close(handle, sftp)
                raise TransportError(f"ssh: open_sftp failed: {exc}") from exc
            except OSError as exc:
                _safe_close(handle, sftp)
                raise TransportError(f"ssh: sftp open: {exc}") from exc

        sftp, handle = await asyncio.to_thread(_open)

        async def _write(chunk: bytes) -> None:
            try:
                await asyncio.to_thread(handle.write, chunk)
            except (paramiko.SSHException, OSError) as exc:
                await asyncio.to_thread(_safe_close, handle, sftp)
                raise TransportError(f"ssh: write failed mid-stream: {exc}") from exc

        async def _finish() -> None:
            def _sync():
                try:
                    handle.close()
                    # Apply mode after close; paramiko opens 0o600 by
                    # default. Honour explicit non-default modes.
                    if mode and mode != 0o600:
                        sftp.chmod(path, mode & 0o7777)
                except (paramiko.SSHException, OSError) as exc:
                    _safe_close(None, sftp)
                    raise TransportError(f"ssh: finish failed: {exc}") from exc
                finally:
                    _safe_close(None, sftp)

            await asyncio.to_thread(_sync)

        return FilePutStream(write=_write, finish=_finish)


# ---- helpers ----


class _ExistsError(Exception):
    """Internal sentinel for the overwrite=False existing-path
    branch in open_file_put. Lets the unified except block close
    the SFTP session before raising the public TransportError.
    """


def _safe_close(handle, sftp) -> None:
    """Best-effort close on an SFTP handle and/or session.

    Used in error paths so a partial open doesn't leak SFTP channels
    on the pooled SSHClient. Either argument may be None. Exceptions
    during close are swallowed because the caller is already raising
    or returning a more important error.
    """
    if handle is not None:
        try:
            handle.close()
        except Exception:  # pylint: disable=broad-except
            pass
    if sftp is not None:
        try:
            sftp.close()
        except Exception:  # pylint: disable=broad-except
            pass


def _shell_quote(s: str) -> str:
    """Single-quote a shell argument so embedded specials are literal.

    paramiko exec_command takes a string; without quoting, args with
    spaces or shell metacharacters would split or expand. We keep it
    POSIX-shell-safe (single quotes; embedded single-quote becomes
    ``'\\''``).
    """
    if not s:
        return "''"
    if all(c.isalnum() or c in "@%+=:,./-_" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _build_paramiko_pty_session(channel: paramiko.Channel) -> PtySession:
    """Wrap a paramiko Channel into a PtySession.

    Reads/writes are blocking syscalls under the hood; we offload via
    ``asyncio.to_thread``. SessionRuntime drives this via the
    PtyDriver interface in its slice; right now it's not called by
    anything in slice #3c (sessions stay SSH-only and use paramiko
    directly), but the contract is here for the next slice to consume.
    """

    async def _recv() -> AsyncIterator[bytes]:
        loop = asyncio.get_running_loop()
        while True:
            chunk = await loop.run_in_executor(None, channel.recv, 4096)
            if not chunk:
                return
            yield chunk

    async def _send(data: bytes) -> None:
        await asyncio.to_thread(channel.send, data)

    async def _resize(rows: int, cols: int) -> None:
        await asyncio.to_thread(channel.resize_pty, cols, rows, 0, 0)

    async def _signal(name: str) -> None:
        # paramiko has Channel.send_signal but server support varies.
        # If unsupported, log and continue — same advisory semantics as
        # the agent's pty_signal control frame.
        def _sync():
            try:
                channel.send_signal(name)
            except (AttributeError, paramiko.SSHException) as exc:
                logger.debug("ssh pty signal %s ignored: %s", name, exc)

        await asyncio.to_thread(_sync)

    async def _close() -> None:
        await asyncio.to_thread(channel.close)

    return PtySession(
        recv=_recv(),
        send=_send,
        resize=_resize,
        signal=_signal,
        close=_close,
    )
