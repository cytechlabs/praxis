"""PRA-153 #3c: SSHTransport tests.

Drives SSHTransport against a fully-mocked paramiko stack — no real
SSH server needed. Verifies the Transport interface translates to
the right paramiko calls and packages results into the
CommandResult / FileGetStream / FilePutStream shapes.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from unittest.mock import MagicMock

import paramiko
import pytest

from app.services.transport import CommandResult, SSHTransport, TransportError


@dataclass
class _SystemStub:
    id: int


def _ssh_service(client) -> MagicMock:
    """Build an SSHService stub whose get_connection returns ``client``."""
    svc = MagicMock()
    svc.get_connection.return_value = (client, False)
    return svc


def _client_with_exec(stdout: bytes, stderr: bytes, exit_code: int) -> MagicMock:
    """Build a paramiko-shaped client whose exec_command returns the
    given streams. The channel ``recv_exit_status`` returns the
    requested exit code."""
    client = MagicMock(spec=paramiko.SSHClient)

    stdin_io = MagicMock()
    stdout_io = MagicMock()
    stdout_io.read.return_value = stdout
    stdout_io.channel.recv_exit_status.return_value = exit_code
    stderr_io = MagicMock()
    stderr_io.read.return_value = stderr

    client.exec_command.return_value = (stdin_io, stdout_io, stderr_io)
    return client


# ---- run_command ----


@pytest.mark.asyncio
async def test_run_command_happy_path():
    client = _client_with_exec(b"hello\n", b"", 0)
    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    result = await t.run_command(["echo", "hello"])
    assert isinstance(result, CommandResult)
    assert result.exit_code == 0
    assert result.stdout == b"hello\n"
    assert result.stderr == b""
    # exec_command should have received the joined argv.
    args, _kwargs = client.exec_command.call_args
    assert args[0] == "echo hello"


@pytest.mark.asyncio
async def test_run_command_nonzero_exit_returned_as_command_result():
    """SSHTransport returns a CommandResult with the actual exit code;
    nonzero is a successful TRANSPORT result. The command-ledger
    nonzero->failed mapping happens upstream in slice #3d."""
    client = _client_with_exec(b"", b"oops\n", 2)
    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    result = await t.run_command(["false"])
    assert result.exit_code == 2
    assert result.stderr == b"oops\n"


@pytest.mark.asyncio
async def test_run_command_quotes_args_with_specials():
    """argv joining must single-quote args with shell metacharacters
    so paramiko's exec_command (which takes a single string) doesn't
    word-split or expand them."""
    client = _client_with_exec(b"", b"", 0)
    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    await t.run_command(["echo", "hello world", "with $vars"])
    cmd_str = client.exec_command.call_args.args[0]
    assert cmd_str == "echo 'hello world' 'with $vars'"


@pytest.mark.asyncio
async def test_run_command_forwards_stdin():
    client = _client_with_exec(b"input\n", b"", 0)
    stdin_io = client.exec_command.return_value[0]
    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    await t.run_command(["cat"], stdin=b"input\n")
    stdin_io.write.assert_called_once_with(b"input\n")
    stdin_io.flush.assert_called_once()


@pytest.mark.asyncio
async def test_run_command_paramiko_exception_raises_transport_error():
    client = MagicMock(spec=paramiko.SSHClient)
    client.exec_command.side_effect = paramiko.SSHException("connection lost")
    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    with pytest.raises(TransportError) as exc:
        await t.run_command(["echo"])
    assert "connection lost" in str(exc.value)


@pytest.mark.asyncio
async def test_run_command_empty_cmd_raises():
    t = SSHTransport(_SystemStub(id=7), _ssh_service(MagicMock()))
    with pytest.raises(TransportError):
        await t.run_command([])


# ---- file_get via SFTP ----


@pytest.mark.asyncio
async def test_file_get_streams_via_sftp():
    body = b"hello sftp"
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    handle = MagicMock()
    # First read returns body, second read returns b'' (EOF).
    handle.read.side_effect = [body, b""]
    sftp.open.return_value = handle
    sftp.stat.return_value = MagicMock(st_size=len(body), st_mode=0o100644)
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    stream = await t.open_file_get("/etc/hosts")
    assert stream.size == len(body)
    assert stream.mode == 0o644
    received = b""
    async for chunk in stream.chunks:
        received += chunk
    await stream.close()
    assert received == body
    handle.close.assert_called_once()
    sftp.close.assert_called_once()


@pytest.mark.asyncio
async def test_file_get_not_found_raises_transport_error():
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    sftp.stat.side_effect = FileNotFoundError("no such file")
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    with pytest.raises(TransportError) as exc:
        await t.open_file_get("/missing")
    assert "not_found" in str(exc.value)


@pytest.mark.asyncio
async def test_file_get_permission_denied_raises_transport_error():
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    sftp.stat.side_effect = PermissionError("denied")
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    with pytest.raises(TransportError) as exc:
        await t.open_file_get("/root/secret")
    assert "denied" in str(exc.value)
    # The SFTP session must be closed when stat fails so
    # repeated not-found/denied attempts don't leak SFTP channels on
    # the pooled SSHClient.
    sftp.close.assert_called_once()


@pytest.mark.asyncio
async def test_file_get_closes_handle_when_prefetch_fails():
    """Stat succeeds + open succeeds, then prefetch fails.
    Both the handle and the SFTP session must be closed before the
    exception bubbles."""
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    handle = MagicMock()
    handle.prefetch.side_effect = paramiko.SSHException("server busy")
    sftp.open.return_value = handle
    sftp.stat.return_value = MagicMock(st_size=10, st_mode=0o100644)
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    with pytest.raises(TransportError):
        await t.open_file_get("/etc/hosts")
    handle.close.assert_called_once()
    sftp.close.assert_called_once()


@pytest.mark.asyncio
async def test_file_get_mid_stream_read_failure_raises_transport_error():
    """A paramiko/OSError mid-iter must surface as
    TransportError (matching AgentTransport's op_stream_closed
    contract), not as a raw paramiko exception that breaks caller
    error handling."""
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    handle = MagicMock()
    # Yield one chunk then explode.
    handle.read.side_effect = [b"part", paramiko.SSHException("link down")]
    sftp.open.return_value = handle
    sftp.stat.return_value = MagicMock(st_size=999, st_mode=0o100644)
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    stream = await t.open_file_get("/etc/hosts")
    received = b""
    with pytest.raises(TransportError) as exc:
        async for chunk in stream.chunks:
            received += chunk
    assert "link down" in str(exc.value)
    # Best-effort close still fired so the channel isn't leaked.
    handle.close.assert_called_once()
    sftp.close.assert_called_once()


# ---- file_put via SFTP ----


@pytest.mark.asyncio
async def test_file_put_writes_via_sftp():
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    handle = MagicMock()
    sftp.stat.side_effect = FileNotFoundError()  # path doesn't exist
    sftp.open.return_value = handle
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    stream = await t.open_file_put("/tmp/x", size=5, mode=0o644)
    await stream.write(b"hello")
    await stream.finish()
    handle.write.assert_called_with(b"hello")
    handle.close.assert_called_once()
    # mode != 0o600 → chmod after close
    sftp.chmod.assert_called_with("/tmp/x", 0o644)
    sftp.close.assert_called_once()


@pytest.mark.asyncio
async def test_file_put_overwrite_false_refuses_existing():
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    sftp.stat.return_value = MagicMock(st_size=10)  # path exists
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    with pytest.raises(TransportError) as exc:
        await t.open_file_put("/tmp/x", size=5, overwrite=False)
    assert "exists" in str(exc.value)
    # SFTP session must be closed when refusing existing
    # path so repeated overwrite-blocked attempts don't leak channels.
    sftp.close.assert_called_once()


@pytest.mark.asyncio
async def test_file_put_closes_session_when_open_fails():
    """sftp.open fails after a successful open_sftp — the SFTP
    session itself must still be closed."""
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    sftp.stat.side_effect = FileNotFoundError()  # path doesn't exist
    sftp.open.side_effect = paramiko.SSHException("permission denied")
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    with pytest.raises(TransportError):
        await t.open_file_put("/tmp/x", size=5, overwrite=True)
    sftp.close.assert_called_once()


@pytest.mark.asyncio
async def test_file_put_mid_stream_write_failure_raises_transport_error():
    """A paramiko/OSError mid-write must surface as
    TransportError, not as a raw paramiko exception."""
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    handle = MagicMock()
    handle.write.side_effect = paramiko.SSHException("link down")
    sftp.stat.side_effect = FileNotFoundError()
    sftp.open.return_value = handle
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    stream = await t.open_file_put("/tmp/x", size=5, overwrite=True)
    with pytest.raises(TransportError) as exc:
        await stream.write(b"hello")
    assert "link down" in str(exc.value)
    # Best-effort close still fired.
    handle.close.assert_called_once()
    sftp.close.assert_called_once()


@pytest.mark.asyncio
async def test_file_put_overwrite_true_replaces_existing():
    client = MagicMock(spec=paramiko.SSHClient)
    sftp = MagicMock()
    sftp.stat.return_value = MagicMock(st_size=10)  # path exists
    handle = MagicMock()
    sftp.open.return_value = handle
    client.open_sftp.return_value = sftp

    t = SSHTransport(_SystemStub(id=7), _ssh_service(client))
    stream = await t.open_file_put("/tmp/x", size=5, overwrite=True)
    await stream.write(b"replaced")
    await stream.finish()
    handle.write.assert_called_with(b"replaced")
    handle.close.assert_called_once()
