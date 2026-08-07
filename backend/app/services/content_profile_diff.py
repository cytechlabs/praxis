"""Profile-vs-profile package diff (PRA-159 slice #2).

Loads each profile's resolved mirror-entry set (via
``ContentProfileService.resolve_mirror_entries_for_profile``), opens
the manifest JSON for each entry's pinned-or-latest ok run, and
produces a structured ``{added, removed, changed}`` view at the
``(package, arch)`` level.

Locked semantics:
  * Manifest source: when ``pinned_run_id`` is set, that run's
    ``manifest_path`` is read; else the most recent ``status='ok'``
    run for the mirror. ``imported_offline`` mirrors that have at
    least one signed manifest behave the same way.
  * Missing manifest file → log warning, treat as empty package set
    for that entry. Diff continues; consumer sees fewer packages on
    that side. We do NOT fail the diff because a missing manifest
    is operational state (mirror not yet synced) and an empty
    source side is meaningful information.
  * Entry collation: a profile may compose multiple channels that
    each include a mirror; we collapse to one effective package set
    per profile. If two channels in the same profile pin the same
    mirror to different runs, the diff helper picks the LATEST run
    id deterministically (operator can verify via the resolved view).
  * Comparison key: ``(package_name, arch)`` because two arches of
    the same package legitimately coexist (amd64 + arm64). ``version``
    is the value being compared.
  * Output is plain dicts so the route layer can ``response_model``
    it without the service depending on Pydantic.

Out of scope for slice #2:
  * Diff against the live ``Packages``/``repodata`` of a candidate
    re-sync (would require re-running ``build_manifest`` against
    ``work/``).
  * Per-suite diff slicing (callers can post-filter by ``suite``
    field on entries if needed).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import MirrorRepo, MirrorSyncRun
from .content_profile_service import ContentProfileService, ResolvedMirrorEntry

logger = logging.getLogger(__name__)


PackageKey = Tuple[str, Optional[str]]  # (package_name, arch)


def compute_profile_diff(
    db: Session, *, from_profile_id: int, to_profile_id: int
) -> dict:
    """Return ``{added, removed, changed, summary}`` between two
    profiles.

    ``added``: ``(package, arch)`` present in ``to`` but not ``from``.
    ``removed``: present in ``from`` but not ``to``.
    ``changed``: present in both with different ``version`` strings.

    Each entry is shaped::

        {"package": "...", "arch": "amd64", "from_version": "1.0",
         "to_version": "1.1"}

    For ``added`` rows ``from_version`` is null; for ``removed`` rows
    ``to_version`` is null.

    NOTE: passing the same profile id on both sides at the *route*
    layer returns 400 (``GET /content-profiles/{id}/diff``); the
    service is permissive and would return all-empty arrays for
    that case. The 400 contract is the user-facing one — don't
    build against the service-level empty-diff behaviour.
    """
    service = ContentProfileService(db)
    from_entries = service.resolve_mirror_entries_for_profile(from_profile_id)
    to_entries = service.resolve_mirror_entries_for_profile(to_profile_id)

    from_pkgs = _build_package_index(db, from_entries)
    to_pkgs = _build_package_index(db, to_entries)

    added: List[dict] = []
    removed: List[dict] = []
    changed: List[dict] = []

    for key, to_version in to_pkgs.items():
        if key not in from_pkgs:
            added.append(_diff_row(key, None, to_version))
        elif from_pkgs[key] != to_version:
            changed.append(_diff_row(key, from_pkgs[key], to_version))
    for key, from_version in from_pkgs.items():
        if key not in to_pkgs:
            removed.append(_diff_row(key, from_version, None))

    # Deterministic sort so test assertions can compare directly.
    added.sort(key=lambda r: (r["package"], r.get("arch") or ""))
    removed.sort(key=lambda r: (r["package"], r.get("arch") or ""))
    changed.sort(key=lambda r: (r["package"], r.get("arch") or ""))

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
            "from_package_count": len(from_pkgs),
            "to_package_count": len(to_pkgs),
        },
    }


def compute_profile_manifest(db: Session, profile_id: int) -> dict:
    """Return a flat ``{packages, summary}`` view of one profile.

    Used by ``GET /content-profiles/{id}/manifest`` for inspection.
    Same package_index walk as the diff but without comparison.
    """
    service = ContentProfileService(db)
    entries = service.resolve_mirror_entries_for_profile(profile_id)
    pkg_index = _build_package_index(db, entries)
    packages = [
        {"package": name, "arch": arch, "version": version}
        for (name, arch), version in pkg_index.items()
    ]
    packages.sort(key=lambda r: (r["package"], r.get("arch") or ""))
    return {
        "packages": packages,
        "summary": {
            "package_count": len(pkg_index),
            "entry_count": len(entries),
        },
    }


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _build_package_index(
    db: Session, entries: List[ResolvedMirrorEntry]
) -> Dict[PackageKey, str]:
    """Walk each resolved entry's manifest, collapse to ``{(package,
    arch) -> version}``.

    Multiple entries can contribute to the same package key (e.g.
    a profile composes ``base`` and ``base-security`` of the same
    upstream); the LATEST run wins so the index reflects the
    "newest known version of this package" — matches the apt/dnf
    client behaviour where the highest-version index entry wins.
    """
    # Per-mirror dedup: choose one ok run per mirror_id for this
    # profile. If multiple entries reference the same mirror, prefer
    # the one with the highest pinned_run_id (or unpinned-latest if
    # none are pinned).
    chosen: Dict[int, Optional[int]] = {}  # mirror_id → run_id (or None for latest)
    for entry in entries:
        if entry.mirror_id not in chosen:
            chosen[entry.mirror_id] = entry.pinned_run_id
            continue
        existing = chosen[entry.mirror_id]
        # Prefer pinned over unpinned; among pinned, prefer larger id.
        if entry.pinned_run_id is None:
            continue
        if existing is None or (
            isinstance(existing, int) and entry.pinned_run_id > existing
        ):
            chosen[entry.mirror_id] = entry.pinned_run_id

    out: Dict[PackageKey, str] = {}
    for mirror_id, pin_run_id in chosen.items():
        manifest_path = _resolve_manifest_path(db, mirror_id, pin_run_id)
        if manifest_path is None:
            logger.warning(
                "no manifest available for mirror_id=%d pin=%s; "
                "treating as empty for diff",
                mirror_id,
                pin_run_id,
            )
            continue
        manifest = _read_manifest(manifest_path)
        if manifest is None:
            continue
        for pkg in manifest.get("files", []):
            name = pkg.get("package")
            if not name:
                # metadata file (Release / Packages.xz / repomd.xml)
                # — no package name, skip in diff view.
                continue
            arch = pkg.get("arch")
            version = pkg.get("version") or ""
            key: PackageKey = (name, arch)
            # Within the same manifest, last write wins on duplicate
            # (package, arch) — manifest is sorted-deterministic so
            # this behaviour is stable.
            out[key] = version
    return out


def _resolve_manifest_path(
    db: Session, mirror_id: int, pin_run_id: Optional[int]
) -> Optional[Path]:
    """Resolve the manifest file path for a mirror.

    Pinned: the referenced run's ``manifest_path``.
    Unpinned: most recent ``status='ok'`` run for the mirror.
    """
    if pin_run_id is not None:
        run = (
            db.query(MirrorSyncRun).filter(MirrorSyncRun.id == pin_run_id).one_or_none()
        )
    else:
        run = (
            db.query(MirrorSyncRun)
            .filter(
                MirrorSyncRun.mirror_repo_id == mirror_id,
                MirrorSyncRun.status == "ok",
            )
            .order_by(MirrorSyncRun.started_at.desc())
            .first()
        )
    if run is None or not run.manifest_path:
        return None
    return Path(run.manifest_path)


def _read_manifest(path: Path) -> Optional[dict]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        logger.warning("manifest file missing on disk: %s", path)
        return None
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("failed to read manifest %s: %s", path, exc)
        return None


def _diff_row(
    key: PackageKey, from_version: Optional[str], to_version: Optional[str]
) -> dict:
    name, arch = key
    return {
        "package": name,
        "arch": arch,
        "from_version": from_version,
        "to_version": to_version,
    }
