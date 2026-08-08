"""Shared host ``/etc/...`` writer with the PRA-158 durability protocol
(PRA-159 slice #3 refactor).

Two callers compose this module:

  * ``mirror_host_trust.install_mirror_trust_on_host`` — writes the
    public-key trust bundle into ``/etc/apt/keyrings/...`` or
    ``/etc/pki/rpm-gpg/...``. Originally PRA-158 #3-d/#3-e territory;
    refactored here in slice #3 so source-list writes share one
    durability primitive.
  * ``content_profile_apply.apply_content_profile_to_host`` — writes
    per-profile source-list / .repo files into
    ``/etc/apt/sources.list.d/...``, ``/etc/apt/auth.conf.d/...``, or
    ``/etc/yum.repos.d/...``.

Locked semantics (carried forward from PRA-158 #3-d/#3-e):

  * ``sudo -n`` on SSH transports — noninteractive, fails fast on
    password-required sudoers, never hangs / eats stdin. Hosts whose
    sudoers requires a password are NOT supported in v1; operators
    must configure NOPASSWD for the praxis target paths.
  * Agent transport: no privilege prefix (PRA-153 lock — agent runs
    as root v1).
  * Two-step durability for every write:
      1. ``install -m <mode> -o root -g root /dev/stdin <FINAL>.praxis-tmp``
         — body via stdin to a same-directory tmp. Final path
         untouched; ``install`` is NOT a contractual atomic temp+rename
         for updating an existing file.
      2. ``mv -f <FINAL>.praxis-tmp <FINAL>`` — atomic rename swap.
    On step-1 failure, best-effort ``rm -f`` cleans the orphan tmp;
    failure of cleanup itself is logged, never re-raised. On step-2
    failure, FINAL is preserved at last-good and the tmp is left for
    forensics.
  * Removal: ``rm -f <FINAL>``. ``rm -f`` returns 0 even when the
    target is absent, so ``ok=True`` is the legitimate idempotent
    response — operators can re-call apply without seeing spurious
    failures from already-removed files.
  * Listing: ``ls <dir>/<prefix>*`` returning basenames matching
    the prefix. Empty (not error) when the glob is unmatched —
    we can't tell "dir empty" from "no matches" reliably across
    shells, and either case is "no managed files."

Return shapes are simple dataclasses so callers can build their own
domain results (HostInstallResult / ApplyResult / ...) on top.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------


@dataclass
class WriteResult:
    """Outcome of a single managed-file write."""

    ok: bool
    path: Optional[str] = None
    error_text: Optional[str] = None


@dataclass
class RemoveResult:
    """Outcome of a single managed-file removal.

    ``rm -f`` is idempotent — ``ok=True`` covers both "file removed"
    and "file was already absent."
    """

    ok: bool
    path: Optional[str] = None
    error_text: Optional[str] = None


@dataclass
class ListResult:
    """Outcome of a managed-file directory listing."""

    ok: bool
    paths: List[str] = field(default_factory=list)
    error_text: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def privilege_prefix(transport) -> List[str]:
    """Argv prefix for privileged commands on this transport.

    SSH: ``["sudo", "-n"]`` (noninteractive sudo). Agent: ``[]`` (agent runs as root per the PRA-153 lock).
    Hosts whose credential is already root see ``sudo -n`` as a
    transparent no-op so the SSH branch covers both cases.
    """
    if getattr(transport, "name", None) == "agent":
        return []
    return ["sudo", "-n"]


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


async def ensure_parent_dir(
    transport, *, parent: str, mode: str = "0755"
) -> WriteResult:
    """``install -d -m <mode> -o root -g root <parent>``.

    Creates the parent dir if missing; sets mode + ownership in one
    syscall. ``install -d`` is idempotent — re-running on an existing
    correctly-permissioned dir is a no-op.
    """
    prefix = privilege_prefix(transport)
    return await _run_simple(
        transport,
        [*prefix, "install", "-d", "-m", mode, "-o", "root", "-g", "root", parent],
        label=f"install -d {parent}",
        result_path=parent,
    )


async def write_managed_file(
    transport, *, path: str, body: bytes, mode: str = "0644"
) -> WriteResult:
    """Two-step durability write.

    1. ``install -m <mode> -o root -g root /dev/stdin <path>.praxis-tmp``
    2. ``mv -f <path>.praxis-tmp <path>``

    On step-1 failure, best-effort ``rm -f`` cleans the orphan tmp;
    on step-2 failure FINAL is preserved at last-good (no further
    cleanup attempted — operator may want to inspect the tmp).
    """
    prefix = privilege_prefix(transport)
    tmp = f"{path}.praxis-tmp"

    # Step 1: write body to tmp via privileged install.
    install_res = await _run_simple(
        transport,
        [
            *prefix,
            "install",
            "-m",
            mode,
            "-o",
            "root",
            "-g",
            "root",
            "/dev/stdin",
            tmp,
        ],
        label=f"install {tmp}",
        stdin=body,
        result_path=path,
    )
    if not install_res.ok:
        # Best-effort orphan cleanup. Failure here is logged, never
        # re-raised — the original install error carries the
        # operator-actionable signal.
        try:
            await transport.run_command([*prefix, "rm", "-f", tmp])
        except Exception as cleanup_err:  # pylint: disable=broad-except
            logger.warning(
                "host_etc_writer: orphan tmp cleanup failed path=%s: %s",
                tmp,
                cleanup_err,
            )
        return install_res

    # Step 2: atomic rename swap. If this fails, FINAL is preserved
    # (never partially overwritten); tmp is left for forensics.
    return await _run_simple(
        transport,
        [*prefix, "mv", "-f", tmp, path],
        label=f"mv {tmp} -> {path}",
        result_path=path,
    )


async def remove_managed_file(transport, *, path: str) -> RemoveResult:
    """``sudo -n rm -f <path>`` — idempotent.

    ``rm -f`` returns 0 when the target is absent, so a re-apply that
    re-removes a file isn't a failure from the orchestrator's
    perspective.
    """
    prefix = privilege_prefix(transport)
    try:
        result = await transport.run_command([*prefix, "rm", "-f", path])
    except Exception as exc:  # pylint: disable=broad-except
        return RemoveResult(
            ok=False,
            path=path,
            error_text=f"rm -f {path} transport: {exc}",
        )
    if result.exit_code != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        return RemoveResult(
            ok=False,
            path=path,
            error_text=(
                f"rm -f {path} failed (rc={result.exit_code}): "
                f"{stderr or '<no stderr>'}"
            ),
        )
    return RemoveResult(ok=True, path=path)


async def list_managed_files(transport, *, dir_path: str, prefix: str) -> ListResult:
    """List basenames in ``<dir_path>`` matching ``<prefix>*``.

    Wraps ``ls -1`` in a small shell snippet so the shell handles
    glob expansion AND the empty-glob case ("nothing to list, exit
    0"). We can't directly invoke a shell argv with the privilege
    prefix, so we wrap with ``sh -c`` and pass the glob literal as
    ``$1`` to keep argv injection-safe.

    Empty list (ok=True, paths=[]) covers both:
      * directory missing → glob unmatched → empty
      * directory present but no matching files → empty

    Both states mean "no managed files" from the orchestrator's
    perspective; the apply path treats them identically.
    """
    if not prefix:
        return ListResult(ok=False, error_text="prefix must be non-empty")
    priv = privilege_prefix(transport)
    glob_literal = f"{dir_path.rstrip('/')}/{prefix}"
    # Use ``sh -c '... "$1"' _ <glob>`` so $1 is the only expansion
    # surface; we don't string-interpolate the glob into the shell
    # body. ``ls -1`` outputs one path per line. ``2>/dev/null`` and
    # ``|| true`` collapse the unmatched-glob exit-1 into success
    # with empty output.
    sh_body = 'ls -1 "$1"* 2>/dev/null || true'
    try:
        result = await transport.run_command(
            [*priv, "sh", "-c", sh_body, "_", glob_literal]
        )
    except Exception as exc:  # pylint: disable=broad-except
        return ListResult(
            ok=False,
            error_text=f"list {glob_literal}* transport: {exc}",
        )
    if result.exit_code != 0:
        # The ``|| true`` should swallow ls's exit-1; any non-zero
        # here means sh itself failed (sudo denied, sh missing, etc).
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        return ListResult(
            ok=False,
            error_text=(
                f"list {glob_literal}* failed (rc={result.exit_code}): "
                f"{stderr or '<no stderr>'}"
            ),
        )
    out = result.stdout.decode("utf-8", errors="replace")
    paths = [line.strip() for line in out.splitlines() if line.strip()]
    return ListResult(ok=True, paths=paths)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _run_simple(
    transport,
    argv: List[str],
    *,
    label: str,
    stdin: Optional[bytes] = None,
    result_path: Optional[str] = None,
) -> WriteResult:
    try:
        result = await transport.run_command(argv, stdin=stdin)
    except Exception as exc:  # pylint: disable=broad-except
        return WriteResult(
            ok=False,
            path=result_path,
            error_text=f"{label} transport: {exc}",
        )
    if result.exit_code != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        return WriteResult(
            ok=False,
            path=result_path,
            error_text=(
                f"{label} failed (rc={result.exit_code}): " f"{stderr or '<no stderr>'}"
            ),
        )
    return WriteResult(ok=True, path=result_path)
