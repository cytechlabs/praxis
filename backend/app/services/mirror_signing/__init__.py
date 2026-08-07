"""Signing engines for mirror native repository metadata (PRA-158 #2b).

A ``SigningEngine`` walks a sync's ``work/`` tree, finds the
package-family-native metadata files (apt's ``Release`` /
rpm's ``repodata/repomd.xml``), and produces the canonical
signature artifacts apt and dnf clients enforce. Engines are pure
functions over (work_dir, key_fingerprint, gnupg_home) — the
orchestrator (slice #2c) sets up the GNUPGHOME with the imported key
and tears it down; engines never touch Vault, the DB, or
``mirror_sync_runs``.

Locked terminology (project_pra158_design_locks.md):

  * **Apt:** sign ``dists/<suite>/Release`` by producing
    ``dists/<suite>/InRelease`` (clearsigned) AND
    ``dists/<suite>/Release.gpg`` (detached). ``Packages`` files are
    NOT separately GPG-signed; their integrity is hash-anchored from
    ``Release``.
  * **Rpm:** sign ``repodata/repomd.xml`` by producing
    ``repodata/repomd.xml.asc`` (detached). Also write
    ``repodata/repomd.xml.key`` as a public-key convenience copy
    (some installers expect to find it next to repodata).

Slice #2b ships these engines as pure functions; slice #2c plugs
them into the fence-ordered orchestrator (sign in ``work/`` BEFORE
``rsync work/ → live/``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Protocol

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SigningResult:
    """Outcome of a single ``SigningEngine.sign_native`` call.

    ``signed_files`` is for logging only — the orchestrator records
    which artifacts landed so a forensic ``error_text="signing failed
    after writing X"`` is possible. Engine implementations append
    files in the order they're written so a partial-failure log
    reads naturally.
    """

    ok: bool
    signed_files: List[Path] = field(default_factory=list)
    error_text: Optional[str] = None


class SigningEngine(Protocol):
    """Protocol every package-family signing engine implements."""

    def sign_native(
        self, work_dir: Path, key_fingerprint: str, gnupg_home: Path
    ) -> SigningResult:
        """Sign the native repo metadata files under ``work_dir``.

        Idempotent: if a previous run already wrote signature
        artifacts, overwrite them with fresh ones (the active key
        may have rotated). Returns a ``SigningResult`` carrying
        ``ok`` plus the list of files written.
        """
        ...


def engine_for(mirror) -> SigningEngine:  # noqa: ANN001
    """Dispatch on ``mirror.package_family``.

    Mirrors PRA-157's ``mirror_sync.engine_for`` shape — same lazy
    import pattern so the deb/rpm impls don't load when only the
    other family is in use.
    """
    if mirror.package_family == "deb":
        from .deb import DebSigningEngine

        return DebSigningEngine()
    if mirror.package_family == "rpm":
        from .rpm import RpmSigningEngine

        return RpmSigningEngine()
    raise NotImplementedError(
        f"no SigningEngine for package_family={mirror.package_family!r}"
    )
