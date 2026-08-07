"""DebSigningEngine — apt Release signing (PRA-158 #2b).

For each ``dists/<suite>/Release`` file under ``work/``, produces:

  * ``dists/<suite>/InRelease`` (clearsigned, body embedded between
    PGP cleartext armor headers and a PGP signature block — apt's
    preferred form).
  * ``dists/<suite>/Release.gpg`` (detached signature over the bytes
    of ``Release`` — fallback that older apt versions accept).

Both artifacts are emitted because some apt clients prefer one or
the other; emitting both gives the broadest support without forcing
a per-client decision.

``Packages`` files are NOT separately signed. Their integrity is
hash-anchored from ``Release`` (the ``Release`` file lists every
``Packages``/``Packages.gz`` checksum), so signing ``Release``
implicitly anchors the whole metadata tree.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .. import mirror_gpg
from . import SigningResult

logger = logging.getLogger(__name__)


class DebSigningEngine:
    """Sign apt repository metadata in-place under ``work_dir``."""

    def sign_native(
        self, work_dir: Path, key_fingerprint: str, gnupg_home: Path
    ) -> SigningResult:
        signed: list[Path] = []
        try:
            release_files = self._discover_release_files(work_dir)
        except OSError as exc:
            return SigningResult(
                ok=False,
                signed_files=signed,
                error_text=f"deb signing: walk failed: {exc}",
            )

        if not release_files:
            # No Release files at all = empty/aborted sync; nothing to
            # sign. Return ok with empty signed_files; orchestrator
            # decides whether that's a sync-level failure (it likely
            # is, but that's not the signing engine's call).
            return SigningResult(ok=True, signed_files=[])

        for release_path in release_files:
            try:
                body = release_path.read_bytes()
            except OSError as exc:
                return SigningResult(
                    ok=False,
                    signed_files=signed,
                    error_text=(f"deb signing: failed to read {release_path}: {exc}"),
                )

            try:
                inrelease_bytes = mirror_gpg.clearsign(
                    gnupg_home, key_fingerprint, body
                )
                detached_sig = mirror_gpg.detached_sign(
                    gnupg_home, key_fingerprint, body
                )
            except mirror_gpg.MirrorGPGError as exc:
                return SigningResult(
                    ok=False,
                    signed_files=signed,
                    error_text=(
                        f"deb signing: gpg failed for {release_path.parent}: {exc}"
                    ),
                )

            inrelease_path = release_path.parent / "InRelease"
            release_gpg_path = release_path.parent / "Release.gpg"
            try:
                # Atomic-ish per file: write to .tmp then rename. On a
                # mid-write crash the original (or absence) of
                # InRelease is preserved, never a half-written file.
                _atomic_write_bytes(inrelease_path, inrelease_bytes)
                signed.append(inrelease_path)
                _atomic_write_bytes(release_gpg_path, detached_sig)
                signed.append(release_gpg_path)
            except OSError as exc:
                return SigningResult(
                    ok=False,
                    signed_files=signed,
                    error_text=(
                        f"deb signing: failed to write signature beside "
                        f"{release_path}: {exc}"
                    ),
                )

        logger.info(
            "deb signing: produced %d signature artifacts under %s",
            len(signed),
            work_dir,
        )
        return SigningResult(ok=True, signed_files=signed)

    @staticmethod
    def _discover_release_files(work_dir: Path) -> list[Path]:
        """Find every ``Release`` file under ``work_dir/dists/`` (PRA-158 #2b).

        debmirror lays per-suite Release files at
        ``dists/<suite>/Release``. A multi-suite mirror has more than
        one; we sign all of them. Top-level ``Release`` files outside
        ``dists/`` (rare, typically Ubuntu metadata) are intentionally
        ignored — apt clients enforce signatures on per-suite Release
        only.
        """
        dists = work_dir / "dists"
        if not dists.is_dir():
            return []
        # Sort for deterministic order in tests + logs.
        return sorted(p for p in dists.rglob("Release") if p.is_file())


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` via a sibling ``.tmp`` + ``replace``.

    ``Path.replace`` is atomic on the same filesystem (single rename
    syscall). Live readers either see the prior file or the new one,
    never a half-written intermediate. Required because slice #2c's
    sign-current primitive runs against ``live/`` directly — the
    files we're rewriting may be served to clients concurrently.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
