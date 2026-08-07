"""RpmSigningEngine — yum/dnf repodata signing (PRA-158 #2b).

For each ``repodata/repomd.xml`` file under ``work/``, produces:

  * ``repodata/repomd.xml.asc`` (detached signature over the
    ``repomd.xml`` bytes — what dnf/yum verify when ``repo_gpgcheck=1``).
  * ``repodata/repomd.xml.key`` (public key copy in armored form —
    convenience for installers that expect to find the key beside the
    repodata).

``repomd.xml`` is the rpm equivalent of apt's ``Release``: it lists
checksums for every other repo metadata file (primary.xml.gz,
filelists.xml.gz, etc.), so signing it implicitly anchors the rest.

Locked terminology: do NOT sign individual ``primary.xml.gz`` files,
do NOT sign individual ``.rpm`` packages — both are out of scope for
PRA-158 (and individual rpm signing is the package builder's job, not
the mirror's).
"""

from __future__ import annotations

import logging
from pathlib import Path

from .. import mirror_gpg
from . import SigningResult
from .deb import _atomic_write_bytes

logger = logging.getLogger(__name__)


class RpmSigningEngine:
    """Sign rpm repository metadata in-place under ``work_dir``."""

    def sign_native(
        self, work_dir: Path, key_fingerprint: str, gnupg_home: Path
    ) -> SigningResult:
        signed: list[Path] = []
        try:
            repomd_files = self._discover_repomd_files(work_dir)
        except OSError as exc:
            return SigningResult(
                ok=False,
                signed_files=signed,
                error_text=f"rpm signing: walk failed: {exc}",
            )

        if not repomd_files:
            return SigningResult(ok=True, signed_files=[])

        # Export the public key once — same key signs every repomd
        # under this work_dir, so a single export covers them all.
        try:
            public_armored = mirror_gpg.export_public_armored(
                gnupg_home, key_fingerprint
            )
        except mirror_gpg.MirrorGPGError as exc:
            return SigningResult(
                ok=False,
                signed_files=signed,
                error_text=f"rpm signing: public-key export failed: {exc}",
            )

        for repomd_path in repomd_files:
            try:
                body = repomd_path.read_bytes()
            except OSError as exc:
                return SigningResult(
                    ok=False,
                    signed_files=signed,
                    error_text=(f"rpm signing: failed to read {repomd_path}: {exc}"),
                )

            try:
                detached_sig = mirror_gpg.detached_sign(
                    gnupg_home, key_fingerprint, body
                )
            except mirror_gpg.MirrorGPGError as exc:
                return SigningResult(
                    ok=False,
                    signed_files=signed,
                    error_text=(
                        f"rpm signing: gpg failed for {repomd_path.parent}: {exc}"
                    ),
                )

            asc_path = repomd_path.parent / "repomd.xml.asc"
            key_path = repomd_path.parent / "repomd.xml.key"
            try:
                _atomic_write_bytes(asc_path, detached_sig)
                signed.append(asc_path)
                _atomic_write_bytes(key_path, public_armored.encode("utf-8"))
                signed.append(key_path)
            except OSError as exc:
                return SigningResult(
                    ok=False,
                    signed_files=signed,
                    error_text=(
                        f"rpm signing: failed to write signature beside "
                        f"{repomd_path}: {exc}"
                    ),
                )

        logger.info(
            "rpm signing: produced %d signature artifacts under %s",
            len(signed),
            work_dir,
        )
        return SigningResult(ok=True, signed_files=signed)

    @staticmethod
    def _discover_repomd_files(work_dir: Path) -> list[Path]:
        """Find every ``repodata/repomd.xml`` under ``work_dir``.

        dnf reposync lays repodata per-repo at
        ``<repoid>/repodata/repomd.xml`` (or just ``repodata/repomd.xml``
        for single-repo mirrors). Walk the tree to catch both shapes.
        """
        if not work_dir.is_dir():
            return []
        return sorted(p for p in work_dir.rglob("repodata/repomd.xml") if p.is_file())
