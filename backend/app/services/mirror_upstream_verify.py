"""Pre-sync upstream signature verification gate (PRA-158 #4b).

Runs after the engine has populated ``work/`` and BEFORE the native
re-sign step. Builds a transient gpg keyring from
``mirror_upstream_keys`` and verifies the upstream archive signatures
already pulled to disk. Failure aborts the sync with run=failed and
fires ``mirror_upstream_signature_invalid``.

Locks (project_pra158_design_locks.md "Upstream signature verification"):

  * Gate fires only when ``mirror.verify_upstream_signature=True`` AND
    ``mirror.source_mode='upstream_sync'``. Imported-offline mirrors
    skip — they don't pull from upstream and have no upstream sigs to
    verify.
  * Apt: prefer ``InRelease`` (clearsigned, body inline). Fall back to
    ``Release.gpg`` + ``Release`` (detached). At least one signed
    artifact MUST exist per discovered ``dists/<suite>/`` — absence
    is itself a verification failure.
  * Rpm: ``repodata/repomd.xml`` + ``repodata/repomd.xml.asc`` per
    repo. Missing ``.asc`` is a verification failure.
  * Empty keyring (no rows in ``mirror_upstream_keys``) with
    ``verify_upstream_signature=True`` is a refused-sync condition —
    the operator opted in to verification but provided no anchors.

Why verify *after* the engine pull rather than before: the engine
already fetched everything to ``work/``; verifying on-disk artifacts
avoids a parallel HTTP fetch path. Bandwidth on a compromised
upstream is wasted, but the security-critical bit (refusing to
promote/sign) is preserved.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import mirror_gpg
from .mirror_upstream_key_service import MirrorUpstreamKeyService

logger = logging.getLogger(__name__)


@dataclass
class UpstreamVerifyResult:
    """Outcome of the pre-sync verification gate."""

    ok: bool
    verified_paths: List[Path] = field(default_factory=list)
    error_text: Optional[str] = None


def verify_upstream_signatures(
    db, mirror, work: Path
) -> UpstreamVerifyResult:  # noqa: ANN001
    """Verify upstream signatures already on disk under ``work/``.

    Returns ``ok=True`` when every discoverable suite/repo has a
    valid upstream signature against the DB-backed keyring. Returns
    ``ok=False`` on any verification failure or missing signed
    artifact. Caller (orchestrator) maps False to a failed run + the
    ``mirror_upstream_signature_invalid`` alert event.
    """
    keys = MirrorUpstreamKeyService(db).list_keys()
    if not keys:
        return UpstreamVerifyResult(
            ok=False,
            error_text=(
                "verify_upstream_signature=true but no upstream trust anchors "
                "are configured. Import upstream archive keys via "
                "POST /mirror-upstream-keys before enabling verification."
            ),
        )

    family = mirror.package_family
    if family == "deb":
        targets = _discover_deb_signed_artifacts(work)
        if not targets:
            return UpstreamVerifyResult(
                ok=False,
                error_text=(
                    "no signed apt metadata found under work/dists/ "
                    "(expected InRelease or Release+Release.gpg per suite)"
                ),
            )
    elif family == "rpm":
        targets = _discover_rpm_signed_artifacts(work)
        if not targets:
            return UpstreamVerifyResult(
                ok=False,
                error_text=(
                    "no signed rpm metadata found under work/ "
                    "(expected repodata/repomd.xml + repomd.xml.asc per repo)"
                ),
            )
    else:
        return UpstreamVerifyResult(
            ok=False,
            error_text=f"unsupported package_family={family!r}",
        )

    verified: List[Path] = []
    with mirror_gpg.ephemeral_gnupg_home() as home:
        for k in keys:
            try:
                mirror_gpg.import_armored_public(home, k.armored_public_key)
            except mirror_gpg.MirrorGPGError as exc:
                # An anchor row that won't import is operator-actionable.
                # Refuse the sync rather than silently dropping the key
                # from the keyring.
                return UpstreamVerifyResult(
                    ok=False,
                    error_text=(
                        f"upstream trust anchor {k.gpg_fingerprint} failed "
                        f"to load into the verification keyring: {exc}"
                    ),
                )

        for target in targets:
            if target.kind == "missing":
                return UpstreamVerifyResult(
                    ok=False,
                    verified_paths=verified,
                    error_text=(
                        f"upstream signature verification failed: "
                        f"{target.missing_context}"
                    ),
                )
            try:
                if target.kind == "clearsigned":
                    mirror_gpg.verify_clearsigned(home, target.signed_path)
                else:  # "detached"
                    mirror_gpg.verify_detached(
                        home, target.signed_path, target.body_path
                    )
            except mirror_gpg.MirrorGPGError as exc:
                return UpstreamVerifyResult(
                    ok=False,
                    verified_paths=verified,
                    error_text=(
                        f"upstream signature verification failed for "
                        f"{target.signed_path}: {exc}"
                    ),
                )
            verified.append(target.signed_path)

    logger.info(
        "upstream verify ok: mirror=%s package_family=%s verified=%d artifacts",
        mirror.slug,
        family,
        len(verified),
    )
    return UpstreamVerifyResult(ok=True, verified_paths=verified)


@dataclass(frozen=True)
class _VerifyTarget:
    """One signed artifact under work/ to verify, OR a sentinel for a
    discovered-but-unsigned suite/repo.

    ``kind`` is one of:
      * ``clearsigned`` — single file, body inline (apt InRelease)
      * ``detached`` — separate body + signature files (apt
        Release.gpg / rpm repomd.xml.asc)
      * ``missing`` — suite/repo present in work/ but has no signed
        upstream artifact. Caller turns this into a verification
        failure with a structured error message (
        per-suite enforcement, not whole-mirror).
    """

    kind: str
    signed_path: Path
    body_path: Optional[Path] = None
    missing_context: Optional[str] = None


def _discover_deb_signed_artifacts(work: Path) -> List[_VerifyTarget]:
    """Find one signed artifact per ``dists/<suite>/`` directory.

    Prefer ``InRelease`` over ``Release.gpg`` per the apt locked
    terminology — InRelease is what modern apt verifies. Fall back to
    ``Release`` + ``Release.gpg`` for older mirrors.

    Every observed suite directory must carry a signed
    artifact when verify_upstream_signature=true. A suite present in
    work/dists/ without InRelease and without Release+Release.gpg is
    a verification failure (returned as a ``missing`` target so the
    caller surfaces a structured error). Silently skipping unsigned
    suites would let unsigned bytes through to Praxis re-signing.
    """
    dists = work / "dists"
    if not dists.is_dir():
        return []

    targets: List[_VerifyTarget] = []
    for suite_dir in sorted(p for p in dists.iterdir() if p.is_dir()):
        inrelease = suite_dir / "InRelease"
        release = suite_dir / "Release"
        release_gpg = suite_dir / "Release.gpg"

        if inrelease.is_file():
            targets.append(_VerifyTarget(kind="clearsigned", signed_path=inrelease))
        elif release.is_file() and release_gpg.is_file():
            targets.append(
                _VerifyTarget(
                    kind="detached",
                    signed_path=release_gpg,
                    body_path=release,
                )
            )
        else:
            # Suite directory present but unsigned. Surface as a
            # structured failure — never silently skip.
            targets.append(
                _VerifyTarget(
                    kind="missing",
                    signed_path=inrelease,  # placeholder; not used for missing
                    missing_context=(
                        f"apt suite {suite_dir} has no signed upstream "
                        "artifact (expected InRelease or Release + Release.gpg)"
                    ),
                )
            )
    return targets


def _discover_rpm_signed_artifacts(work: Path) -> List[_VerifyTarget]:
    """Find ``repodata/repomd.xml`` + ``repomd.xml.asc`` per repo.

    A repodata directory without a ``repomd.xml.asc`` is treated as a
    verification failure (the corresponding ``mirror_repos`` row opted
    in to verification by setting ``verify_upstream_signature=true``).
    """
    if not work.is_dir():
        return []

    targets: List[_VerifyTarget] = []
    for repomd in sorted(work.rglob("repodata/repomd.xml")):
        if not repomd.is_file():
            continue
        asc = repomd.parent / "repomd.xml.asc"
        if not asc.is_file():
            # Repo present but unsigned — structured failure target,
            # mirrors the deb per-suite enforcement.
            targets.append(
                _VerifyTarget(
                    kind="missing",
                    signed_path=asc,
                    missing_context=(
                        f"rpm repo {repomd.parent} has no signed upstream "
                        "artifact (expected repodata/repomd.xml.asc)"
                    ),
                )
            )
            continue
        targets.append(
            _VerifyTarget(kind="detached", signed_path=asc, body_path=repomd)
        )
    return targets
