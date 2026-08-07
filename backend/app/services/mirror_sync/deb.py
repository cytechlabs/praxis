"""DebSyncEngine — debmirror subprocess wrapper for apt mirrors
(PRA-157 #2a).

debmirror is the standard apt-mirror tool from Debian/Ubuntu repos
(installed via ``Dockerfile.prod`` in this slice). Its argument shape:

    debmirror <target_dir> \\
        --host=archive.ubuntu.com \\
        --root=/ubuntu \\
        --dist=jammy \\
        --section=main,universe \\
        --arch=amd64 \\
        --method=http \\
        --no-source --i18n --getcontents \\
        --ignore-release-gpg                # PRA-158 wires real keyring

For PRA-157 #2a, ``verify_upstream_signature`` on the
``mirror_repos`` row maps to whether ``--ignore-release-gpg`` is
passed; PRA-158 will replace this with real upstream-key plumbing
via Vault.

Estimate: returns ``None`` for v1 — debmirror has no clean dry-run
that gives an upfront size. The orchestrator's disk gate handles
the no-estimate path (``estimate_unavailable=True`` flag on the run
row, conservative per-mirror fallback if a budget is set). A future
improvement can cache the prior successful run's ``byte_count`` as
an estimate.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from . import SyncResult, _run_subprocess, decode_string_list

logger = logging.getLogger(__name__)

# Subprocess timeout in seconds. debmirror's wall-time on a real
# Ubuntu mirror is hours on a cold sync; cap at 6h to bound runaway
# subprocesses without breaking legitimate large initial syncs.
DEBMIRROR_TIMEOUT_SECONDS = 6 * 60 * 60

_MISSING_DEBMIRROR_MSG = (
    "debmirror not found on PATH — Dockerfile must " "install the 'debmirror' package"
)


class DebSyncEngine:
    def sync(self, mirror, work_dir: Path) -> SyncResult:  # noqa: ANN001
        try:
            argv = _build_debmirror_argv(mirror, work_dir)
        except ValueError as exc:
            return SyncResult(ok=False, error_text=f"argv build failed: {exc}")

        work_dir.mkdir(parents=True, exist_ok=True)
        logger.info("debmirror starting for %s: %s", mirror.slug, " ".join(argv))

        return _run_subprocess(
            argv,
            timeout_seconds=DEBMIRROR_TIMEOUT_SECONDS,
            missing_binary_msg=_MISSING_DEBMIRROR_MSG,
            label="debmirror",
        )

    def estimate_sync_bytes(self, mirror) -> Optional[int]:  # noqa: ANN001
        # v1: no upfront estimate. Disk gate falls through to the
        # estimate-unavailable path. Future: cache last successful
        # run's byte_count as a rough estimate.
        return None


def _build_debmirror_argv(mirror, work_dir: Path) -> List[str]:  # noqa: ANN001
    parsed = urlparse(mirror.upstream_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"upstream_url={mirror.upstream_url!r} missing scheme or host")
    method = parsed.scheme  # http | https | rsync | ftp
    host = parsed.netloc
    root = parsed.path or "/"

    components = decode_string_list(mirror.components, "components")
    architectures = decode_string_list(mirror.architectures, "architectures")

    if not architectures:
        raise ValueError("at least one architecture is required")

    argv: List[str] = [
        "debmirror",
        str(work_dir),
        f"--host={host}",
        f"--root={root}",
        f"--dist={mirror.distribution}",
        f"--method={method}",
        "--no-source",
        "--i18n",
        "--getcontents",
        # ``--progress`` keeps subprocess output structured for the
        # capture path. Earlier drafts also passed ``--nothreads``;
        # that flag isn't valid in the version of debmirror we ship
        # (Debian Bookworm) — it would ABORT the subprocess. Caught
        # by the PRA-157 #6 real-debmirror integration test.
        "--progress",
    ]

    if components:
        argv.append(f"--section={','.join(components)}")

    argv.append(f"--arch={','.join(architectures)}")

    if not mirror.verify_upstream_signature:
        # PRA-158 wires Vault-backed keyring; until then the
        # column controls whether debmirror enforces upstream-Release
        # GPG verification.
        argv.append("--ignore-release-gpg")

    return argv


# Module-level re-export for back-compat with existing tests that
# import _decode_string_list from app.services.mirror_sync.deb.
_decode_string_list = decode_string_list
