"""RpmSyncEngine — dnf reposync subprocess wrapper for rpm/dnf
mirrors (PRA-157 #3).

``dnf reposync`` from ``dnf-plugins-core`` is the standard rpm
mirror tool. Argument shape::

    dnf reposync \\
        --releasever=praxis \\
        --repofrompath=<slug>,<upstream_url> \\
        --repo=<slug> \\
        --download-metadata \\
        --norepopath \\
        --delete \\
        -p <work_dir> \\
        -a <arch1> -a <arch2> ...
        [--nogpgcheck]              # PRA-158 wires real keyring

``--releasever`` is set to a sentinel because dnf refuses to start
without one when running outside a configured host. The upstream URL
should be fully resolved to a concrete release before reaching us
(the caller doesn't substitute ``$releasever``); this is just to
satisfy dnf's preflight.

``--download-metadata`` keeps upstream's ``repodata/`` as
authoritative — v1 doesn't run ``createrepo_c`` to regenerate. If
operators report inconsistencies (filtered packages, dropped arches),
a follow-up slice can add a post-sync ``createrepo_c`` step.

Estimate: returns ``None`` for v1 — same shape as DebSyncEngine.
The orchestrator's disk gate handles the no-estimate path.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional

from . import SyncResult, _run_subprocess, decode_string_list

logger = logging.getLogger(__name__)

# dnf reposync wall-time on a real CentOS/Fedora mirror is hours on
# a cold sync. 6h matches DebSyncEngine.
DNF_REPOSYNC_TIMEOUT_SECONDS = 6 * 60 * 60

# dnf refuses to start without --releasever; sentinel value used
# only to satisfy preflight (the upstream URL is already
# fully-resolved, so $releasever expansion never happens).
RELEASEVER_SENTINEL = "praxis"

# DNF expands ``$releasever`` / ``$basearch`` / ``$arch`` (and
# similar) in repo URLs. Our contract is that operators paste
# already-release-resolved URLs — an unresolved variable would
# either expand against the sentinel + container env (fetching the
# wrong path) or 404 opaquely. Reject loudly at argv-build instead.
_DNF_REPO_VAR_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")

# When an operator specifies binary architectures for an RPM mirror,
# implicitly include ``noarch`` because normal RPM repos rely
# heavily on architecture-independent packages and ``dnf reposync``
# does NOT make ``noarch`` implicit under ``-a`` filtering. Without
# this, a x86_64-only mirror would download metadata that references
# absent noarch RPMs.
_NOARCH = "noarch"

_MISSING_DNF_MSG = (
    "dnf not found on PATH — Dockerfile must install the "
    "'dnf' and 'dnf-plugins-core' packages"
)


class RpmSyncEngine:
    def sync(self, mirror, work_dir: Path) -> SyncResult:  # noqa: ANN001
        try:
            argv = _build_dnf_reposync_argv(mirror, work_dir)
        except ValueError as exc:
            return SyncResult(ok=False, error_text=f"argv build failed: {exc}")

        work_dir.mkdir(parents=True, exist_ok=True)

        # PRA-157 #6-a: dnf creates ``.rpmdb/`` and other transient
        # state under ``$HOME`` on first invocation (not cwd, despite
        # what the file's appearance in cwd-style locations might
        # suggest). The praxis user's HOME is ``/app`` in
        # production, which would mean every RPM sync writes shared
        # rpmdb state into the application root and concurrent RPM
        # syncs would contend on it. Pin both cwd and HOME to a
        # mirror-owned dnf-state/ directory siblings to work/ so:
        #   * production /app stays clean
        #   * distinct RPM mirrors don't share rpmdb state
        #   * the side-effect dir isn't promoted into live/ (rsync
        #     work/ → live/ won't touch its sibling)
        # Derived from work_dir.parent (== mirror_repo_root(slug))
        # rather than mirror_paths.dnf_state_dir(slug) so the engine
        # stays pure with respect to its parameters: no os.getenv
        # mid-sync. Mocked unit tests pass tmp_path/work and stay
        # off /data; mirror_paths.dnf_state_dir(slug) remains the
        # canonical name for external callers.
        state_dir = work_dir.parent / "dnf-state"
        state_dir.mkdir(parents=True, exist_ok=True)

        logger.info("dnf reposync starting for %s: %s", mirror.slug, " ".join(argv))

        return _run_subprocess(
            argv,
            timeout_seconds=DNF_REPOSYNC_TIMEOUT_SECONDS,
            missing_binary_msg=_MISSING_DNF_MSG,
            label="dnf reposync",
            cwd=str(state_dir),
            env_overrides={"HOME": str(state_dir)},
        )

    def estimate_sync_bytes(self, mirror) -> Optional[int]:  # noqa: ANN001
        # v1: no upfront estimate. Same as DebSyncEngine.
        return None


def _build_dnf_reposync_argv(mirror, work_dir: Path) -> List[str]:  # noqa: ANN001
    upstream = (mirror.upstream_url or "").strip()
    if not upstream:
        raise ValueError("upstream_url is required")
    if not upstream.lower().startswith(("http://", "https://", "ftp://")):
        raise ValueError(
            f"upstream_url={upstream!r} must be http://, https://, or ftp:// "
            "for dnf reposync"
        )

    unresolved = _DNF_REPO_VAR_RE.findall(upstream)
    if unresolved:
        raise ValueError(
            f"upstream_url={upstream!r} contains unresolved DNF repo "
            f"variable(s) {sorted(set(unresolved))}. RPM mirrors must use a "
            "release-resolved URL — substitute the concrete release/arch "
            "before saving the mirror."
        )

    architectures = decode_string_list(mirror.architectures, "architectures")
    if not architectures:
        raise ValueError("at least one architecture is required")

    # Normal RPM repos rely on noarch packages. Append it implicitly
    # if the operator only specified binary arches; preserve order
    # otherwise. De-dup defensively against an operator who already
    # listed it.
    archs_with_noarch: List[str] = list(architectures)
    if _NOARCH not in archs_with_noarch:
        archs_with_noarch.append(_NOARCH)

    repoid = mirror.slug

    argv: List[str] = [
        "dnf",
        "reposync",
        f"--releasever={RELEASEVER_SENTINEL}",
        f"--repofrompath={repoid},{upstream}",
        f"--repo={repoid}",
        "--download-metadata",
        "--norepopath",
        "--delete",
        "-p",
        str(work_dir),
    ]

    # ``-a`` is repeatable per arch in dnf reposync.
    for arch in archs_with_noarch:
        argv.extend(["-a", arch])

    if not mirror.verify_upstream_signature:
        # PRA-158 wires Vault-backed RPM-key trust; until then the
        # column controls whether dnf enforces upstream-repodata
        # GPG verification.
        argv.append("--nogpgcheck")

    return argv
