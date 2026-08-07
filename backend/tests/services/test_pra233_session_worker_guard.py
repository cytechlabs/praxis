"""PRA-233 — 1.0 single-worker invariant for interactive SSH sessions.

Two concerns:

1. ``scripts/assert_session_worker_safety.sh`` — the production boot guard that
   fails fast when ``UVICORN_WORKERS > 1`` without the explicit unsupported
   override. Exercised in isolation via subprocess (no full prod entrypoint).
2. The process-local session runtime registry — a session opened in one worker's
   memory is not visible to another. A registry miss is exactly the condition
   the ``/sessions/{id}/ws`` attach path reports as "runtime missing" (HTTP 410
   / WS close 4410), which is why multi-worker is unsafe.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from app.services import session_runtime as rt_registry
from app.services.session_runtime import SessionRuntime

GUARD = (
    Path(__file__).resolve().parents[2] / "scripts" / "assert_session_worker_safety.sh"
)


def _run_guard(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(GUARD)],
        env={"PATH": "/usr/bin:/bin", **env},
        capture_output=True,
        text=True,
        check=False,
    )


# ------------------------------------------------------- guard: allowed


def test_guard_script_exists_and_executable():
    assert GUARD.is_file(), f"missing guard script at {GUARD}"


def test_guard_allows_default_unset():
    # No UVICORN_WORKERS set → defaults to 1 → allowed.
    assert _run_guard({}).returncode == 0


def test_guard_allows_single_worker():
    assert _run_guard({"UVICORN_WORKERS": "1"}).returncode == 0


def test_guard_allows_multiworker_with_override():
    res = _run_guard({"UVICORN_WORKERS": "4", "ALLOW_UNSAFE_MULTIWORKER_SESSIONS": "1"})
    assert res.returncode == 0


# ------------------------------------------------------- guard: rejected


def test_guard_rejects_multiworker_without_override():
    res = _run_guard({"UVICORN_WORKERS": "2"})
    assert res.returncode == 1
    # Actionable message names the invariant + the override.
    assert "UVICORN_WORKERS=2 is unsupported" in res.stderr
    assert "ALLOW_UNSAFE_MULTIWORKER_SESSIONS=1" in res.stderr


def test_guard_rejects_override_set_to_other_value():
    # Only the literal "1" opts in; anything else must still fail.
    res = _run_guard(
        {"UVICORN_WORKERS": "2", "ALLOW_UNSAFE_MULTIWORKER_SESSIONS": "true"}
    )
    assert res.returncode == 1


def test_guard_rejects_non_integer_workers():
    res = _run_guard({"UVICORN_WORKERS": "abc"})
    assert res.returncode == 1
    assert "positive integer" in res.stderr


def test_guard_rejects_zero_workers():
    res = _run_guard({"UVICORN_WORKERS": "0"})
    assert res.returncode == 1


# --------------------------------------- runtime registry: attach miss


def _mk_runtime(session_id: int) -> SessionRuntime:
    transport = MagicMock()
    channel = MagicMock()
    channel.closed = False
    channel.eof_received = False
    channel.recv_ready = MagicMock(return_value=False)
    return SessionRuntime(
        session_id=session_id,
        transport=transport,
        channel=channel,
        max_expires_at=datetime.utcnow() + timedelta(hours=1),
    )


def test_runtime_missing_when_never_registered():
    # A worker that never opened the session sees no runtime — the exact
    # condition the WS attach path reports as "runtime missing".
    assert rt_registry.get(999_233_001) is None


def test_runtime_visible_only_while_registered():
    rt = _mk_runtime(999_233_002)
    rt_registry.register(rt)
    try:
        assert rt_registry.get(999_233_002) is rt
    finally:
        rt_registry.drop(999_233_002)
    # After drop (mirrors close, or a different process), the lookup misses —
    # this is why cross-worker attach fails and 1.0 stays single-worker.
    assert rt_registry.get(999_233_002) is None
