"""Confinement rules for local-file audit sinks.

A ``file`` audit sink appends newline-delimited JSON to a path an administrator
supplies through the API. Those targets are relative paths beneath a single
operator-approved root directory (``AUDIT_FILE_SINK_ROOT``, default
``/data/praxis/audit-sinks``). Nothing outside that root is reachable through a
sink, so a sink cannot be turned into an arbitrary-write primitive against the
control plane's own runtime files.

Every filesystem step here is taken with directory descriptors and no-follow
opens, starting from a descriptor on the filesystem root. Paths are never
resolved before the policy is enforced and are never reopened by name, so a
symlink anywhere in the configured root or the target cannot redirect a read or
a write, and no time-of-check to time-of-use window exists between validation
and the append.

Two entry points share that machinery, so the create/update boundary and the
delivery boundary cannot drift:

* ``validate`` checks root policy, target shape, and every component of the
  target that already exists. It runs when a sink is created or updated.
* ``append_line`` repeats all of it and then performs the confined append,
  creating missing intermediate directories in place.

The root is read from the environment on every call, so operator configuration
takes effect on restart without any import-time frozen value.

Targets that do not satisfy these rules fail closed. A sink row that predates
the confinement rules keeps its stored target and stays visible; its deliveries
fail with a bounded error until an administrator replaces the target with a
relative path.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import List, Optional, Tuple

ROOT_ENV = "AUDIT_FILE_SINK_ROOT"
DEFAULT_ROOT = "/data/praxis/audit-sinks"

# Runtime and control locations that must never hold sink output, even when an
# operator points the root at one. The root is rejected when it names one of
# these or anything beneath one.
_FORBIDDEN_ROOTS = (
    "/app",
    "/boot",
    "/dev",
    "/etc",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/vault",
)

_DIR_MODE = 0o750
_FILE_MODE = 0o640

# Operator-supplied values are echoed back in errors that reach the API and the
# delivery row, so cap how much of a 1 KiB target can be repeated.
_MAX_ECHO = 120

# Confined access needs POSIX no-follow directory descriptors. Without them
# there is no way to pin traversed components, so both entry points fail rather
# than falling back to a resolve-then-open sequence that a symlink swap can beat.
_HAS_NOFOLLOW_DIRFD = hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")

_ROOT_SCOPE = "audit file sink root"
_TARGET_SCOPE = "file sink target"


class FileSinkTargetError(ValueError):
    """A file sink root or target is not usable under the confinement rules."""


def _echo(value: str) -> str:
    """A bounded, quoted rendering of an operator-supplied value for errors."""
    text = value if len(value) <= _MAX_ECHO else value[:_MAX_ECHO] + "..."
    return repr(text)


def _require_posix_support() -> None:
    if not _HAS_NOFOLLOW_DIRFD:
        raise FileSinkTargetError(
            "confined file sink access requires a POSIX runtime with no-follow "
            "directory descriptors"
        )


# ---------------------------------------------------------------- root policy


def root_components() -> Tuple[str, ...]:
    """Return the path components of the configured root after policy checks.

    Reads ``AUDIT_FILE_SINK_ROOT`` on each call and falls back to
    ``DEFAULT_ROOT``. The value is inspected literally: symlinks are never
    resolved away before the policy is applied, and the components returned here
    are the exact sequence the no-follow walk descends. Raises
    ``FileSinkTargetError`` when the configured value is not an absolute path,
    is the filesystem root, contains a ``.`` or ``..`` segment, or names a
    sensitive runtime location.
    """
    raw = os.getenv(ROOT_ENV, "").strip() or DEFAULT_ROOT
    if not raw.startswith("/"):
        raise FileSinkTargetError(
            f"audit file sink root must be an absolute path (got {_echo(raw)})"
        )
    parts = tuple(p for p in raw.split("/") if p)
    if not parts:
        raise FileSinkTargetError(
            "audit file sink root must not be the filesystem root"
        )
    for part in parts:
        if part in (".", ".."):
            raise FileSinkTargetError(
                "audit file sink root must not contain '.' or '..' segments "
                f"(got {_echo(raw)})"
            )
    lexical = "/" + "/".join(parts)
    for forbidden in _FORBIDDEN_ROOTS:
        if lexical == forbidden or lexical.startswith(forbidden + "/"):
            raise FileSinkTargetError(
                f"audit file sink root must not be under {forbidden} "
                f"(got {_echo(lexical)})"
            )
    return parts


def configured_root() -> Path:
    """The policy-checked root directory as written by the operator.

    Reported in errors and documentation. It is deliberately NOT resolved:
    enforcement happens by walking these components with no-follow opens, so a
    symlinked root or root ancestor is refused rather than followed.
    """
    return Path("/" + "/".join(root_components()))


# -------------------------------------------------------------- target policy


def validate_target(target: str) -> Tuple[str, ...]:
    """Return the path components of a usable relative file sink target.

    Raises ``FileSinkTargetError`` for anything that is not a plain relative
    path naming a file: absolute paths, empty or whitespace-only values,
    directory-only values, ``.`` and ``..`` segments, repeated or trailing
    separators, and embedded NUL bytes.
    """
    if not isinstance(target, str) or not target.strip():
        raise FileSinkTargetError(
            "file sink target must be a relative path under the audit file "
            "sink root, for example exports/audit.jsonl"
        )
    if "\x00" in target:
        raise FileSinkTargetError("file sink target must not contain NUL bytes")
    if target.startswith("/"):
        raise FileSinkTargetError(
            f"file sink target must be relative, not absolute (got {_echo(target)})"
        )
    parts = target.split("/")
    for part in parts:
        if not part:
            raise FileSinkTargetError(
                "file sink target must not contain an empty path segment or a "
                f"trailing separator (got {_echo(target)})"
            )
        if part in (".", ".."):
            raise FileSinkTargetError(
                "file sink target must not contain '.' or '..' segments "
                f"(got {_echo(target)})"
            )
    return tuple(parts)


# ------------------------------------------------------- no-follow traversal


def _symlink_error(scope: str, name: str) -> FileSinkTargetError:
    return FileSinkTargetError(
        f"{scope} component {_echo(name)} is a symlink; sink paths must "
        "contain only real directories and a real file"
    )


def _is_symlink(parent_fd: Optional[int], name: str) -> bool:
    """Whether *name* inside *parent_fd* is a symlink right now.

    Used only to word a rejection accurately. The decision to reject was already
    made by a failed no-follow open, so a racing change here can at worst
    produce the more generic message.
    """
    if parent_fd is None:
        return False
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode)


def _map_component_error(
    scope: str, name: str, exc: OSError, parent_fd: Optional[int] = None
) -> Optional[FileSinkTargetError]:
    """Translate an open failure that means "this component is not allowed" into
    a target error. Returns ``None`` for ordinary filesystem failures (missing
    permissions, full disk) so they keep their original type and the caller's
    retry behavior.

    ``O_NOFOLLOW`` reports a symlink as ``ELOOP``, except when it is combined
    with ``O_DIRECTORY``, where Linux reports ``ENOTDIR`` because the symlink
    itself is not a directory. Both are rejections either way; the component is
    inspected so the message names the real reason.
    """
    if exc.errno == errno.ELOOP:
        return _symlink_error(scope, name)
    if exc.errno == errno.ENOTDIR:
        if _is_symlink(parent_fd, name):
            return _symlink_error(scope, name)
        return FileSinkTargetError(
            f"{scope} component {_echo(name)} is not a directory"
        )
    if exc.errno == errno.EISDIR:
        return FileSinkTargetError(f"{scope} {_echo(name)} is a directory, not a file")
    if exc.errno == errno.ENXIO:
        return FileSinkTargetError(f"{scope} {_echo(name)} is not a regular file")
    return None


def _open_child_dir(parent_fd: int, name: str, *, scope: str, create: bool) -> int:
    """Open *name* inside *parent_fd* as a directory without following symlinks.

    With ``create`` the directory is made when it does not exist yet; the create
    path never widens the guarantee, because the directory is reopened no-follow
    afterwards, so a symlink that won the race is rejected instead of traversed.
    Without ``create`` a missing component raises ``FileNotFoundError``.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
    except OSError as exc:
        mapped = _map_component_error(scope, name, exc, parent_fd)
        if mapped is not None:
            raise mapped from exc
        raise
    try:
        os.mkdir(name, _DIR_MODE, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        mapped = _map_component_error(scope, name, exc, parent_fd)
        if mapped is not None:
            raise mapped from exc
        raise


def _close_all(fds: List[int]) -> None:
    for fd in reversed(fds):
        try:
            os.close(fd)
        except OSError:
            pass


def _open_root(fds: List[int]) -> None:
    """Pin the configured root, one component at a time from the filesystem root.

    Appends every descriptor opened along the way to *fds* so the caller can
    close them. The filesystem root itself cannot be a symlink; every component
    below it is opened no-follow, so a symlinked root or root ancestor is
    refused. Missing components are created, which is what makes the default
    root usable on a first run.
    """
    parts = root_components()
    fds.append(os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
    for part in parts:
        fds.append(_open_child_dir(fds[-1], part, scope=_ROOT_SCOPE, create=True))


def _descend(fds: List[int], parts: Tuple[str, ...], *, create: bool) -> bool:
    """Open each directory in *parts* below ``fds[-1]``, no-follow.

    Returns ``True`` when the whole chain is open, ``False`` when a component
    does not exist and *create* is off (the rest of the target is missing, which
    is allowed: delivery creates it).
    """
    for part in parts:
        try:
            fds.append(
                _open_child_dir(fds[-1], part, scope=_TARGET_SCOPE, create=create)
            )
        except FileNotFoundError:
            return False
    return True


def _check_existing_leaf(parent_fd: int, name: str) -> None:
    """Reject an existing final component that is a symlink or is not a regular
    file. A missing final component is fine: delivery creates it."""
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise FileSinkTargetError(
            f"{_TARGET_SCOPE} {_echo(name)} is a symlink; sink paths must "
            "contain only real directories and a real file"
        )
    if not stat.S_ISREG(info.st_mode):
        raise FileSinkTargetError(
            f"{_TARGET_SCOPE} {_echo(name)} is not a regular file"
        )


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte of *data* to *fd*.

    ``os.write`` may accept fewer bytes than offered, which would leave a
    truncated record in the audit stream. A write that accepts nothing is
    treated as a failure so the delivery retries instead of spinning.
    """
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "audit file sink write made no progress")
        view = view[written:]


def _append_into(parent_fd: int, name: str, payload: str) -> None:
    """Append one newline-terminated record to *name* inside *parent_fd*.

    ``O_NOFOLLOW`` rejects an existing symlink at the final component,
    ``O_NONBLOCK`` keeps a FIFO from blocking the delivery worker before the
    type check, and the ``fstat`` confirms the descriptor is a regular file.
    """
    flags = (
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | os.O_CLOEXEC
    )
    try:
        fd = os.open(name, flags, _FILE_MODE, dir_fd=parent_fd)
    except OSError as exc:
        mapped = _map_component_error(_TARGET_SCOPE, name, exc, parent_fd)
        if mapped is not None:
            raise mapped from exc
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise FileSinkTargetError(
                f"{_TARGET_SCOPE} {_echo(name)} is not a regular file"
            )
        record = payload if payload.endswith("\n") else payload + "\n"
        _write_all(fd, record.encode("utf-8"))
    finally:
        os.close(fd)


# ------------------------------------------------------------- entry points


def validate(target: str) -> None:
    """Create/update time check.

    The root must satisfy policy and be reachable without traversing a symlink,
    and *target* must be a relative path beneath it whose already-existing
    components are real directories ending in a real file. Components that do
    not exist yet are allowed: delivery creates them. Raises
    ``FileSinkTargetError`` otherwise.
    """
    _require_posix_support()
    parts = validate_target(target)
    fds: List[int] = []
    try:
        _open_root(fds)
        if _descend(fds, parts[:-1], create=False):
            _check_existing_leaf(fds[-1], parts[-1])
    finally:
        _close_all(fds)


def append_line(target: str, payload: str) -> None:
    """Append *payload* as one newline-terminated record beneath the root.

    Repeats the full root and target check, then walks the target with pinned
    directory descriptors and no-follow opens so the write cannot land outside
    the root. Missing intermediate directories are created in place. Raises
    ``FileSinkTargetError`` when the root or the target is not usable and
    ``OSError`` for ordinary filesystem failures.
    """
    _require_posix_support()
    parts = validate_target(target)
    fds: List[int] = []
    try:
        _open_root(fds)
        _descend(fds, parts[:-1], create=True)
        _append_into(fds[-1], parts[-1], payload)
    finally:
        _close_all(fds)
