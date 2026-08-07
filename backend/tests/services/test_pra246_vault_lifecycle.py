"""PRA-246: the Vault container lifecycle follows the Vault SERVER process.

These are deterministic shell-lifecycle tests around ``vault/scripts/startup.sh``.
They use fake ``vault`` and ``init-vault.sh`` commands (no real Vault server) to
prove the startup contract:

- startup waits for ``vault status`` readiness before running init;
- init failure exits nonzero and does not fall into an infinite keepalive;
- the Vault process exiting causes startup (PID 1) to exit with Vault's code;
- SIGTERM is forwarded to the child Vault process.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest

_STARTUP = Path(
    os.environ.get("PRAXIS_VAULT_STARTUP_SH")
    or Path(__file__).resolve().parents[3] / "vault" / "scripts" / "startup.sh"
)

if not _STARTUP.exists():  # pragma: no cover - only when repo root isn't mounted
    pytest.skip(
        "vault/scripts/startup.sh not found (repo root not available)",
        allow_module_level=True,
    )

# A fake `vault`: `server` blocks until a crash file appears (or SIGTERM), and
# `status` reports "not ready" until it has been polled FAKE_READY_AFTER times.
_FAKE_VAULT = """#!/bin/sh
STATE="$FAKE_STATE"
case "$1" in
  server)
    echo "$$" > "$STATE/vault_pid"
    : > "$STATE/server_started"
    trap 'echo term > "$STATE/vault_term"; exit 143' TERM INT
    while [ ! -e "$STATE/crash" ]; do sleep 0.1; done
    exit "${FAKE_VAULT_EXIT:-0}"
    ;;
  status)
    n=0
    [ -f "$STATE/status_n" ] && n=$(cat "$STATE/status_n")
    n=$((n + 1))
    echo "$n" > "$STATE/status_n"
    if [ "$n" -ge "${FAKE_READY_AFTER:-2}" ]; then
      : > "$STATE/ready"
      exit 0
    fi
    exit 1
    ;;
  *)
    exit 0
    ;;
esac
"""

# A fake init script: fails loudly if run before Vault reported ready, otherwise
# records that it ran and exits with FAKE_INIT_RC.
_FAKE_INIT = """#!/bin/sh
STATE="$FAKE_STATE"
if [ ! -e "$STATE/ready" ]; then
  : > "$STATE/init_before_ready"
  echo "init ran before vault ready" >&2
  exit 3
fi
: > "$STATE/init_ran"
exit "${FAKE_INIT_RC:-0}"
"""


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _harness(tmp_path: Path, **fake_env: str):
    """Build the fake command harness and return (popen_args, env, state_dir)."""
    state = tmp_path / "state"
    state.mkdir()
    binp = tmp_path / "bin"
    binp.mkdir()
    # PRA-311: the bundled runtime is OpenBao; startup.sh drives it via `bao`.
    _write_exec(binp / "bao", _FAKE_VAULT)
    fake_init = tmp_path / "init-vault.sh"
    _write_exec(fake_init, _FAKE_INIT)

    env = dict(os.environ)
    env["PATH"] = f"{binp}{os.pathsep}{env['PATH']}"
    env["FAKE_STATE"] = str(state)
    env["VAULT_INIT_SCRIPT"] = str(fake_init)
    env["VAULT_READY_TIMEOUT"] = "20"
    env.update(fake_env)
    return ["sh", str(_STARTUP)], env, state


def _wait_for(path: Path, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return True
        time.sleep(0.05)
    return False


def _cleanup(proc, state: Path) -> None:
    if proc.poll() is None:
        (state / "crash").touch()  # let the fake vault loop exit
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_startup_waits_for_readiness_before_init(tmp_path):
    # Vault is "not ready" for the first two status polls, ready on the third.
    args, env, state = _harness(tmp_path, FAKE_READY_AFTER="3", FAKE_INIT_RC="0")
    proc = subprocess.Popen(
        args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        assert _wait_for(state / "init_ran"), "init never ran"
        # init only runs after readiness -> the fake init never hit its
        # before-ready guard.
        assert not (state / "init_before_ready").exists()
        # After a successful init, startup is supervising Vault (final wait),
        # NOT exited and NOT in a fake keepalive.
        assert proc.poll() is None
    finally:
        _cleanup(proc, state)


def test_init_failure_exits_nonzero_and_kills_vault(tmp_path):
    args, env, state = _harness(tmp_path, FAKE_READY_AFTER="2", FAKE_INIT_RC="1")
    proc = subprocess.Popen(
        args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        # Must exit (no infinite tail) and nonzero on init failure.
        rc = proc.wait(timeout=20)
        assert rc != 0
        # Vault was terminated rather than left running.
        assert _wait_for(state / "vault_term", timeout=5)
    finally:
        _cleanup(proc, state)


def test_vault_process_exit_propagates_exit_code(tmp_path):
    args, env, state = _harness(
        tmp_path, FAKE_READY_AFTER="2", FAKE_INIT_RC="0", FAKE_VAULT_EXIT="7"
    )
    proc = subprocess.Popen(
        args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        assert _wait_for(state / "init_ran"), "init never ran"
        # Simulate a Vault crash; startup's final `wait` must surface its code.
        (state / "crash").touch()
        rc = proc.wait(timeout=20)
        assert rc == 7
    finally:
        _cleanup(proc, state)


def test_sigterm_is_forwarded_to_vault(tmp_path):
    args, env, state = _harness(tmp_path, FAKE_READY_AFTER="2", FAKE_INIT_RC="0")
    proc = subprocess.Popen(
        args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        assert _wait_for(state / "init_ran"), "init never ran"
        assert proc.poll() is None  # supervising Vault
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=20)
        # The child Vault process received the forwarded SIGTERM.
        assert _wait_for(state / "vault_term", timeout=5)
        assert rc is not None  # startup actually exited
    finally:
        _cleanup(proc, state)
