"""PRA-254: SSH uploads publish atomically and preserve existing files.

The old ``_upload_via_ssh`` opened the final destination with ``sftp.open(
remote_path, "wb")`` before the upload was known valid — so an oversize stream, a
client/iterator error, or a write/close failure could truncate or partially
replace an existing remote file. The fix streams into a unique sibling temp path,
enforces the cap while writing, closes the temp handle, and only then publishes
over ``remote_path`` with an atomic rename (``posix_rename`` preferred). Every
failure path removes the temp file and leaves the existing destination untouched.

These tests drive ``_upload_via_ssh`` against a fake SFTP that records opened
paths/modes, per-path bytes, rename/posix_rename calls, and removes. They prove:

- the final path is NEVER opened ``"wb"``;
- the temp path is a hidden sibling of the final path;
- on success the full content is published atomically, audit records size + sha,
  and no temp artifact lingers;
- on oversize / iterator error / write error / close error / rename error the
  existing destination content is preserved and the temp file is removed;
- audit is marked error (never success) on every failure.
"""

from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass, field
from typing import Dict, List
from unittest.mock import MagicMock, patch

import pytest

from app.services import file_transfer_service as fts


@dataclass
class _SystemStub:
    id: int = 7
    hostname: str = "host.test"
    transport_preference: str = "ssh"


class _FakeHandle:
    """A writable remote file handle used as a context manager. ``fail_on_write``
    and ``fail_on_close`` inject failures; bytes land in ``store[path]`` only on a
    clean close so a failed handle never publishes partial content."""

    def __init__(self, sftp: "_FakeSFTP", path: str):
        self._sftp = sftp
        self._path = path
        self._buf = bytearray()
        self.closed = False

    def write(self, chunk: bytes) -> None:
        if self._sftp.fail_on_write and len(self._buf) >= self._sftp.fail_on_write:
            raise OSError("simulated write failure")
        self._buf.extend(chunk)

    def close(self) -> None:
        if self.closed:
            return
        if self._sftp.fail_on_close:
            raise OSError("simulated close failure")
        self._sftp.store[self._path] = bytes(self._buf)
        self.closed = True

    def __enter__(self) -> "_FakeHandle":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        # Mirror a real file object: close runs on exit. If the body raised we
        # still attempt close, but never mask the original exception.
        try:
            self.close()
        except Exception:
            if exc_type is None:
                raise
        return False


@dataclass
class _FakeSFTP:
    """Records everything ``_upload_via_ssh`` does so tests can assert on it."""

    store: Dict[str, bytes] = field(default_factory=dict)
    opened: List[tuple] = field(default_factory=list)
    renames: List[tuple] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    fail_on_write: int = 0  # fail once this many bytes are buffered (0 = never)
    fail_on_close: bool = False
    fail_on_rename: bool = False

    def open(self, path: str, mode: str) -> _FakeHandle:
        self.opened.append((path, mode))
        return _FakeHandle(self, path)

    def posix_rename(self, src: str, dst: str) -> None:
        self._do_rename(src, dst)

    def rename(self, src: str, dst: str) -> None:
        self._do_rename(src, dst)

    def _do_rename(self, src: str, dst: str) -> None:
        self.renames.append((src, dst))
        if self.fail_on_rename:
            raise OSError("simulated rename failure")
        # Atomic replace: move src bytes onto dst.
        self.store[dst] = self.store.pop(src)

    def remove(self, path: str) -> None:
        self.removed.append(path)
        self.store.pop(path, None)


class _CtxSFTP:
    """Wraps a _FakeSFTP as the context manager _open_sftp yields."""

    def __init__(self, sftp: _FakeSFTP):
        self._sftp = sftp

    def __enter__(self) -> _FakeSFTP:
        return self._sftp

    def __exit__(self, *a) -> bool:
        return False


REMOTE = "/etc/app/config.yml"
EXISTING = b"OLD-EXISTING-CONTENT-must-survive"


def _run_upload(sftp: _FakeSFTP, chunks, remote_path: str = REMOTE):
    """Drive ``_upload_via_ssh`` with the given fake sftp and chunk iterator.
    Returns (result_or_None, audit_calls, raised_exc)."""
    audit = MagicMock()
    audit_calls: List[dict] = []

    def _capture_finish(db, row, **kwargs):
        audit_calls.append(kwargs)

    result = None
    raised = None
    with patch.object(fts, "_open_sftp", return_value=_CtxSFTP(sftp)), patch.object(
        fts, "_finish_audit", side_effect=_capture_finish
    ):
        try:
            result = fts._upload_via_ssh(
                MagicMock(),
                MagicMock(),
                _SystemStub(),
                "ops",
                remote_path,
                iter(chunks),
                audit,
            )
        except fts.FileTransferError as e:
            raised = e
    return result, audit_calls, raised


def _assert_temp_is_sibling(sftp: _FakeSFTP, remote_path: str) -> str:
    """The one written path must be a hidden sibling temp of remote_path, and the
    final path must never be opened at all. Returns the temp path."""
    modes = [m for _, m in sftp.opened]
    assert modes == ["wb"], f"exactly one wb open expected, got {sftp.opened}"
    tmp_path = sftp.opened[0][0]
    assert tmp_path != remote_path, "final destination must never be opened wb"
    assert posixpath.dirname(tmp_path) == posixpath.dirname(remote_path)
    assert posixpath.basename(tmp_path).startswith(".praxis-upload-")
    return tmp_path


def test_success_publishes_atomically_and_cleans_up():
    sftp = _FakeSFTP(store={REMOTE: EXISTING})
    body_chunks = [b"hello ", b"", b"brave ", b"new world"]
    body = b"".join(body_chunks)

    result, audit_calls, raised = _run_upload(sftp, body_chunks)

    assert raised is None
    tmp_path = _assert_temp_is_sibling(sftp, REMOTE)

    # Final path published with the FULL new content via an atomic rename.
    assert sftp.store[REMOTE] == body
    assert sftp.renames == [(tmp_path, REMOTE)]
    # No temp artifact lingers (rename consumed it; nothing removed on success).
    assert tmp_path not in sftp.store
    assert sftp.removed == []

    # Return shape + audit success with size + sha.
    assert result == {
        "remote_path": REMOTE,
        "size": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    assert len(audit_calls) == 1
    assert audit_calls[0]["status"] == "success"
    assert audit_calls[0]["size_bytes"] == len(body)
    assert audit_calls[0]["sha256"] == hashlib.sha256(body).hexdigest()


def test_success_uses_plain_rename_when_no_posix_rename():
    """When the server lacks the posix-rename extension, publish still happens via
    plain rename. Shadow the method with a non-callable instance attribute so the
    ``callable(getattr(...))`` guard takes the fallback branch."""
    sftp = _FakeSFTP(store={REMOTE: EXISTING})
    sftp.posix_rename = None  # type: ignore[assignment]
    body = b"published-via-plain-rename"
    result, audit_calls, raised = _run_upload(sftp, [body])

    assert raised is None
    tmp_path = _assert_temp_is_sibling(sftp, REMOTE)
    assert sftp.store[REMOTE] == body
    # rename() (not posix_rename) recorded the publish.
    assert sftp.renames == [(tmp_path, REMOTE)]
    assert audit_calls[0]["status"] == "success"


def test_oversize_preserves_destination_and_removes_temp():
    sftp = _FakeSFTP(store={REMOTE: EXISTING})
    with patch.object(fts, "MAX_TRANSFER_BYTES", 10):
        result, audit_calls, raised = _run_upload(sftp, [b"x" * 6, b"y" * 6, b"z" * 6])

    assert result is None
    assert isinstance(raised, fts.FileTransferError)
    assert "exceeded max size" in str(raised)
    tmp_path = _assert_temp_is_sibling(sftp, REMOTE)

    # Existing destination untouched; no rename; temp removed.
    assert sftp.store[REMOTE] == EXISTING
    assert sftp.renames == []
    assert sftp.removed == [tmp_path]
    assert tmp_path not in sftp.store
    assert audit_calls[0]["status"] == "error"


def test_iterator_failure_preserves_destination_and_removes_temp():
    sftp = _FakeSFTP(store={REMOTE: EXISTING})

    def _boom_iter():
        yield b"partial-"
        raise RuntimeError("client hung up mid-upload")

    result, audit_calls, raised = _run_upload(sftp, _boom_iter())

    assert result is None
    assert isinstance(raised, fts.FileTransferError)
    tmp_path = _assert_temp_is_sibling(sftp, REMOTE)
    assert sftp.store[REMOTE] == EXISTING
    assert sftp.renames == []
    assert sftp.removed == [tmp_path]
    assert audit_calls[0]["status"] == "error"


def test_write_failure_preserves_destination_and_removes_temp():
    sftp = _FakeSFTP(store={REMOTE: EXISTING}, fail_on_write=4)
    result, audit_calls, raised = _run_upload(sftp, [b"abcd", b"efgh"])

    assert result is None
    assert isinstance(raised, fts.FileTransferError)
    tmp_path = _assert_temp_is_sibling(sftp, REMOTE)
    assert sftp.store[REMOTE] == EXISTING
    assert sftp.renames == []
    assert sftp.removed == [tmp_path]
    assert audit_calls[0]["status"] == "error"


def test_close_failure_preserves_destination_and_removes_temp():
    sftp = _FakeSFTP(store={REMOTE: EXISTING}, fail_on_close=True)
    result, audit_calls, raised = _run_upload(sftp, [b"complete-body"])

    assert result is None
    assert isinstance(raised, fts.FileTransferError)
    tmp_path = _assert_temp_is_sibling(sftp, REMOTE)
    # Close failed => temp never landed in store, nothing published, temp removed.
    assert sftp.store[REMOTE] == EXISTING
    assert sftp.renames == []
    assert sftp.removed == [tmp_path]
    assert audit_calls[0]["status"] == "error"


def test_rename_failure_preserves_destination_and_removes_temp():
    sftp = _FakeSFTP(store={REMOTE: EXISTING}, fail_on_rename=True)
    result, audit_calls, raised = _run_upload(sftp, [b"fully-written-body"])

    assert result is None
    assert isinstance(raised, fts.FileTransferError)
    tmp_path = _assert_temp_is_sibling(sftp, REMOTE)

    # Rename was attempted but failed => existing destination preserved, temp
    # (which was fully written) removed, audit error.
    assert sftp.renames == [(tmp_path, REMOTE)]
    assert sftp.store[REMOTE] == EXISTING
    assert tmp_path not in sftp.store
    assert sftp.removed == [tmp_path]
    assert audit_calls[0]["status"] == "error"


def test_upload_to_new_path_still_atomic():
    """No pre-existing destination: success still goes temp -> atomic publish."""
    sftp = _FakeSFTP(store={})
    body = b"brand-new-file"
    result, audit_calls, raised = _run_upload(sftp, [body])

    assert raised is None
    tmp_path = _assert_temp_is_sibling(sftp, REMOTE)
    assert sftp.store[REMOTE] == body
    assert sftp.renames == [(tmp_path, REMOTE)]
    assert audit_calls[0]["status"] == "success"


def test_sibling_tmp_path_is_deterministic_shape():
    """Temp path generation is a hidden sibling in the same dir, unique per call."""
    p1 = fts._sibling_tmp_path("/var/lib/app/data.bin")
    p2 = fts._sibling_tmp_path("/var/lib/app/data.bin")
    assert p1 != p2, "temp paths must be unique per upload"
    for p in (p1, p2):
        assert posixpath.dirname(p) == "/var/lib/app"
        assert posixpath.basename(p).startswith(".praxis-upload-data.bin-")
        assert p.endswith(".tmp")
