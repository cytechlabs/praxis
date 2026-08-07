"""PRA-159 #3: host_etc_writer unit tests.

Covers the durability primitive extracted from PRA-158
``mirror_host_trust``:

  * privilege_prefix branches on transport.name (sudo -n / agent direct)
  * ensure_parent_dir command shape
  * write_managed_file two-step: install /dev/stdin → tmp, mv -f
  * write_managed_file failure path: orphan tmp cleanup
  * remove_managed_file: rm -f, idempotent
  * list_managed_files: sh -c glob, empty list on no-match
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services import host_etc_writer
from app.services.host_etc_writer import (
    ensure_parent_dir,
    list_managed_files,
    privilege_prefix,
    remove_managed_file,
    write_managed_file,
)


def _make_transport(name: str = "ssh", *, run_outcomes=None):
    """Return a MagicMock transport with an async ``run_command``.

    ``run_outcomes`` is a list of MagicMock results (one per call);
    defaults to all-success.
    """
    t = MagicMock()
    t.name = name
    calls: list = []
    outcomes = list(run_outcomes or [])

    async def _run(argv, *, stdin=None, timeout_seconds=None):
        calls.append({"argv": list(argv), "stdin": stdin})
        if outcomes:
            return outcomes.pop(0)
        return MagicMock(exit_code=0, stderr=b"", stdout=b"")

    t.run_command = _run
    t._calls = calls
    return t


def test_privilege_prefix_ssh():
    t = MagicMock(name="ssh")
    t.name = "ssh"
    assert privilege_prefix(t) == ["sudo", "-n"]


def test_privilege_prefix_agent_no_prefix():
    t = MagicMock()
    t.name = "agent"
    assert privilege_prefix(t) == []


@pytest.mark.asyncio
async def test_ensure_parent_dir_uses_install_d():
    transport = _make_transport()
    res = await ensure_parent_dir(transport, parent="/etc/apt/keyrings")
    assert res.ok
    assert transport._calls[0]["argv"] == [
        "sudo",
        "-n",
        "install",
        "-d",
        "-m",
        "0755",
        "-o",
        "root",
        "-g",
        "root",
        "/etc/apt/keyrings",
    ]


@pytest.mark.asyncio
async def test_ensure_parent_dir_agent_no_sudo():
    transport = _make_transport(name="agent")
    res = await ensure_parent_dir(transport, parent="/etc/yum.repos.d")
    assert res.ok
    assert transport._calls[0]["argv"][:1] != ["sudo"]
    assert transport._calls[0]["argv"][0] == "install"


@pytest.mark.asyncio
async def test_write_managed_file_two_step_success():
    transport = _make_transport()
    res = await write_managed_file(
        transport,
        path="/etc/foo/bar.conf",
        body=b"hello\n",
        mode="0600",
    )
    assert res.ok
    assert res.path == "/etc/foo/bar.conf"
    assert len(transport._calls) == 2

    # Step 1: install /dev/stdin -> tmp
    assert transport._calls[0]["argv"] == [
        "sudo",
        "-n",
        "install",
        "-m",
        "0600",
        "-o",
        "root",
        "-g",
        "root",
        "/dev/stdin",
        "/etc/foo/bar.conf.praxis-tmp",
    ]
    assert transport._calls[0]["stdin"] == b"hello\n"

    # Step 2: mv -f tmp -> final
    assert transport._calls[1]["argv"] == [
        "sudo",
        "-n",
        "mv",
        "-f",
        "/etc/foo/bar.conf.praxis-tmp",
        "/etc/foo/bar.conf",
    ]


@pytest.mark.asyncio
async def test_write_managed_file_install_failure_attempts_orphan_cleanup():
    install_fail = MagicMock(exit_code=1, stderr=b"disk full", stdout=b"")
    cleanup_ok = MagicMock(exit_code=0, stderr=b"", stdout=b"")
    transport = _make_transport(run_outcomes=[install_fail, cleanup_ok])

    res = await write_managed_file(transport, path="/etc/foo/bar.conf", body=b"x")
    assert not res.ok
    assert "disk full" in res.error_text
    # 2 calls: failed install + best-effort rm -f cleanup.
    assert len(transport._calls) == 2
    assert transport._calls[1]["argv"] == [
        "sudo",
        "-n",
        "rm",
        "-f",
        "/etc/foo/bar.conf.praxis-tmp",
    ]


@pytest.mark.asyncio
async def test_write_managed_file_mv_failure_preserves_final():
    install_ok = MagicMock(exit_code=0, stderr=b"", stdout=b"")
    mv_fail = MagicMock(exit_code=1, stderr=b"perm denied", stdout=b"")
    transport = _make_transport(run_outcomes=[install_ok, mv_fail])

    res = await write_managed_file(transport, path="/etc/foo", body=b"x")
    assert not res.ok
    assert "perm denied" in res.error_text
    # 2 calls: install (success) + mv (failure). NO additional rm.
    assert len(transport._calls) == 2


@pytest.mark.asyncio
async def test_write_managed_file_transport_raises():
    transport = MagicMock()
    transport.name = "ssh"

    async def _raise(*_a, **_k):
        raise OSError("connection reset")

    transport.run_command = _raise
    res = await write_managed_file(transport, path="/etc/x", body=b"x")
    assert not res.ok
    assert "connection reset" in res.error_text


@pytest.mark.asyncio
async def test_remove_managed_file_idempotent():
    transport = _make_transport()
    res = await remove_managed_file(transport, path="/etc/foo")
    assert res.ok
    assert transport._calls[0]["argv"] == [
        "sudo",
        "-n",
        "rm",
        "-f",
        "/etc/foo",
    ]


@pytest.mark.asyncio
async def test_list_managed_files_returns_basenames():
    listing = MagicMock(
        exit_code=0,
        stderr=b"",
        stdout=b"/etc/yum.repos.d/praxis-profile-prod.repo\n"
        b"/etc/yum.repos.d/praxis-profile-stage.repo\n",
    )
    transport = _make_transport(run_outcomes=[listing])

    res = await list_managed_files(
        transport,
        dir_path="/etc/yum.repos.d",
        prefix="praxis-profile-",
    )
    assert res.ok
    assert res.paths == [
        "/etc/yum.repos.d/praxis-profile-prod.repo",
        "/etc/yum.repos.d/praxis-profile-stage.repo",
    ]
    # Confirms we ship the glob via $1 (no string interpolation).
    argv = transport._calls[0]["argv"]
    assert "sh" in argv
    assert "-c" in argv
    assert "/etc/yum.repos.d/praxis-profile-" in argv


@pytest.mark.asyncio
async def test_list_managed_files_empty_glob_is_ok():
    """``ls`` returning rc=0 with empty stdout (the ``|| true``
    branch on unmatched glob) maps to ``ok=True paths=[]``."""
    listing = MagicMock(exit_code=0, stderr=b"", stdout=b"")
    transport = _make_transport(run_outcomes=[listing])
    res = await list_managed_files(
        transport, dir_path="/etc/apt/sources.list.d", prefix="praxis-profile-"
    )
    assert res.ok
    assert res.paths == []


@pytest.mark.asyncio
async def test_list_managed_files_rejects_empty_prefix():
    transport = _make_transport()
    res = await list_managed_files(transport, dir_path="/etc", prefix="")
    assert not res.ok
    assert "non-empty" in res.error_text
    # No transport call made.
    assert transport._calls == []
