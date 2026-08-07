"""Mirror sync engines (PRA-157 #2a/#3).

A ``SyncEngine`` runs the upstream-fetch + work/-staging step for one
mirror. The orchestrator (``mirror_sync.service.perform_sync_for_mirror``)
calls it after pre-sync gates pass, then promotes ``work/`` →
``live/``, builds the manifest, and finalizes the run row.

  * ``DebSyncEngine`` (debmirror) — slice #2a.
  * ``RpmSyncEngine`` (dnf reposync + createrepo_c) — slice #3.

Both share ``_run_subprocess`` for the fetch-tool invocation pattern
(capture stdout/stderr, bound runaway processes via timeout, surface
missing-binary errors clearly, capture diagnostic tail on failure).
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Protocol, Sequence

logger = logging.getLogger(__name__)

# Tail bytes of stdout/stderr captured into ``error_text`` on
# subprocess failure. Both apt and dnf mirror tools are verbose; the
# tail is the diagnostic that matters.
ERROR_TAIL_BYTES = 8 * 1024


@dataclass(frozen=True)
class SyncResult:
    ok: bool
    error_text: Optional[str] = None  # populated when ok=False


class SyncEngine(Protocol):
    """Protocol every package-family sync engine implements.

    Engines write into ``work/``; promotion to ``live/`` is the
    orchestrator's job. Engines do NOT touch ``mirror_sync_runs`` or
    ``mirror_repos`` rows — that's also the orchestrator's job. This
    keeps engines pure (subprocess + filesystem) and unit-testable
    without the DB.
    """

    def sync(self, mirror, work_dir) -> SyncResult:  # noqa: ANN001
        """Pull upstream content into ``work_dir`` (a Path). Returns
        a ``SyncResult`` with ``ok=True`` on subprocess success,
        ``ok=False`` and ``error_text`` populated on failure.
        """
        ...

    def estimate_sync_bytes(self, mirror) -> Optional[int]:  # noqa: ANN001
        """Best-effort size estimate for the upcoming sync, in bytes.
        Returns ``None`` if no estimate is available (first sync,
        upstream introspection failed, etc.). The orchestrator's
        free-space gate falls through to a per-mirror conservative
        path when this returns ``None``.
        """
        ...


def engine_for(mirror) -> SyncEngine:  # noqa: ANN001
    """Dispatch on ``mirror.package_family``."""
    if mirror.package_family == "deb":
        from .deb import DebSyncEngine

        return DebSyncEngine()
    if mirror.package_family == "rpm":
        from .rpm import RpmSyncEngine

        return RpmSyncEngine()
    raise NotImplementedError(
        f"no SyncEngine for package_family={mirror.package_family!r}"
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def decode_string_list(raw: Optional[str], field_name: str) -> List[str]:
    """Decode a JSON-text column (``components`` / ``architectures``)
    into a ``list[str]``. Both deb and rpm mirrors store these the
    same way; this is the shared decoder.

    Raises ``ValueError`` if the column doesn't parse as a JSON array
    of strings — caller turns that into a sync failure with
    ``error_text='argv build failed: ...'``.
    """
    if raw is None or raw == "":
        return []
    try:
        decoded = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{field_name} is not valid JSON: {exc}") from exc
    if not isinstance(decoded, list) or not all(
        isinstance(item, str) for item in decoded
    ):
        raise ValueError(f"{field_name} must be a JSON array of strings")
    return decoded


def _run_subprocess(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    missing_binary_msg: str,
    label: str,
    cwd: Optional[str] = None,
    env_overrides: Optional[dict] = None,
) -> SyncResult:
    """Run an external mirror tool and shape its outcome into a
    ``SyncResult``.

    ``label`` appears in error messages (e.g. ``"debmirror"`` /
    ``"dnf reposync"``) so an operator inspecting ``error_text`` can
    tell which step failed without correlating to the call site.

    ``cwd`` is the working directory to launch the subprocess in.
    Optional; when omitted, inherits the parent's cwd. Some tools
    write transient state into cwd regardless of explicit output
    options; isolating cwd to a mirror-owned scratch dir prevents
    pollution of ``/app`` and shared-state contention between
    concurrent syncs.

    ``env_overrides`` merges into a copy of ``os.environ`` and is
    passed as the subprocess env. Used by the rpm engine to point
    ``HOME`` at the mirror's dnf-state directory because ``dnf``
    creates ``.rpmdb/`` under ``$HOME`` (not cwd) on first run, and
    the praxis user's HOME is ``/app`` in production (PRA-157 #6-a).

    Both engines pass ``capture_output=True`` so we can capture the
    last ``ERROR_TAIL_BYTES`` of output on rc != 0.
    """
    import os

    env = None
    if env_overrides is not None:
        env = os.environ.copy()
        env.update(env_overrides)

    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            cwd=cwd,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return SyncResult(
            ok=False,
            error_text=f"{label} exceeded {timeout_seconds}s timeout",
        )
    except FileNotFoundError:
        return SyncResult(ok=False, error_text=missing_binary_msg)

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or b"")[-ERROR_TAIL_BYTES:]
        return SyncResult(
            ok=False,
            error_text=(
                f"{label} exited with rc={proc.returncode}; "
                f"tail: {tail.decode('utf-8', errors='replace')}"
            ),
        )

    return SyncResult(ok=True)
