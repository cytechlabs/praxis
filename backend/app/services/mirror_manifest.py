"""Manifest builder for the mirror engine (PRA-157 #2a).

After a successful sync's work/ → live/ promotion, walks ``live/``
and produces a JSON manifest of every file: filename, sha256, size,
plus parsed package metadata (name/version/arch) for ``.deb`` and
``.rpm`` files.

Manifest is the spine PRA-158 will sign and PRA-160's airgap
importer will key off — keep the format stable and well-documented.
``MANIFEST_FORMAT_VERSION`` bumps when the schema changes in a
breaking way; readers should accept unknown fields.

**Hash semantics.** The on-disk JSON includes some volatile fields
(``run_id``, ``generated_at``, ``mirror_slug``) for forensics — an
operator inspecting ``snapshots/<run_id>.manifest.json`` should be
able to see which run produced it and when. But ``manifest_sha256``
is the content fingerprint that PRA-158 signs and PRA-160 uses as
the bundle index, so it MUST be stable across syncs of identical
bytes. ``manifest_sha256`` therefore hashes a **content-only view**
(``MANIFEST_CONTENT_FIELDS``) — the format version, package family,
and the deterministically-sorted file list. Two ok runs over the
same upstream content produce the same ``manifest_sha256``;
``serialize_manifest`` still writes the full manifest including
volatile fields for the on-disk JSON.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from .mirror_paths import live_dir, snapshot_manifest_path, snapshots_dir

logger = logging.getLogger(__name__)

MANIFEST_FORMAT_VERSION = "v1"
MANIFEST_HASH_BUF_BYTES = 1024 * 1024  # 1 MiB read chunks

# Fields that contribute to ``manifest_sha256``. Excludes volatile
# run metadata (run_id, generated_at, mirror_slug) so identical
# content produces identical hashes regardless of which sync run
# observed it. PRA-158 signing and PRA-160 bundle indexing both
# rely on this hash being a *content* fingerprint, not a run-row
# fingerprint.
MANIFEST_CONTENT_FIELDS = (
    "praxis_mirror_manifest",
    "package_family",
    "byte_count",
    "package_count",
    "files",
)

# debmirror lays files into the standard apt pool layout. .deb names
# follow `<package>_<version>_<arch>.deb`. ``<version>`` may itself
# contain underscores in epoch-style notation, but the trailing two
# underscores always precede arch and version respectively. Right-
# split is the right tool.
_DEB_FILENAME_RE = re.compile(
    r"^(?P<package>[^_]+)_(?P<version>.+)_(?P<arch>[^_]+)\.deb$"
)


@dataclass(frozen=True)
class ManifestFile:
    filename: str  # path relative to live_dir(slug)
    sha256: str
    size: int
    package: Optional[str]
    version: Optional[str]
    arch: Optional[str]


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(MANIFEST_HASH_BUF_BYTES), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_deb_filename(
    name: str,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (package, version, arch) parsed from a .deb filename, or
    (None, None, None) if the filename doesn't match the canonical
    pattern. Index/metadata files (Release, Packages.xz, etc.) parse
    as no-package — that's the signal callers can use to count
    "package files vs index files."
    """
    if not name.endswith(".deb"):
        return None, None, None
    m = _DEB_FILENAME_RE.match(name)
    if not m:
        return None, None, None
    return m.group("package"), m.group("version"), m.group("arch")


def _parse_rpm_filename(
    name: str,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (package, version, arch) parsed from an RPM filename.

    RPM filenames follow ``<name>-<version>-<release>.<arch>.rpm``.
    The package ``name`` may itself contain dashes (e.g.
    ``python3-foo``); ``version`` and ``release`` typically don't.
    Right-anchored split parses correctly: arch is the last
    dot-segment before ``.rpm``, then the trailing two dashes
    delimit ``release`` and ``version``, and ``name`` is whatever's
    left.

    The returned ``version`` field is the joined ``version-release``
    so it matches what users see in ``dnf info`` output. NEVRA
    epoch is rare in filenames (it lives in repodata) and not
    parsed here.

    Index/metadata files (``repodata/repomd.xml``, ``.xml.gz``, etc.)
    parse as no-package.
    """
    if not name.endswith(".rpm") or name.endswith(".src.rpm"):
        # Source RPMs are skipped — Praxis mirrors binary content;
        # source-RPM lifecycle is a future concern.
        return None, None, None
    stem = name[:-4]  # strip .rpm
    if "." not in stem:
        return None, None, None
    rest, arch = stem.rsplit(".", 1)
    if not arch or "-" not in rest:
        return None, None, None
    rest, release = rest.rsplit("-", 1)
    if not release or "-" not in rest:
        return None, None, None
    package, version = rest.rsplit("-", 1)
    if not package or not version:
        return None, None, None
    return package, f"{version}-{release}", arch


def build_manifest(
    *,
    slug: str,
    run_id: int,
    package_family: str,
    root: Optional[Path] = None,
) -> dict:
    """Walk ``live_dir(slug)`` and produce the manifest dict (not yet
    serialized). Files sorted by filename for deterministic
    ``manifest_sha256``.

    For .deb files (package_family='deb') the per-file metadata
    fields ``package``/``version``/``arch`` are populated; for index/
    metadata files like ``Release`` and ``Packages.xz`` they remain
    ``None``. ``package_count`` counts only files with a non-null
    ``package`` (i.e. real package files, not metadata).
    """
    target = root if root is not None else live_dir(slug)
    if not target.exists():
        return _empty_manifest(slug, run_id, package_family)

    files: List[ManifestFile] = []
    total_bytes = 0
    package_count = 0

    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(target)).replace("\\", "/")
        size = path.stat().st_size
        sha = _sha256_of_file(path)

        package = version = arch = None
        if package_family == "deb":
            package, version, arch = _parse_deb_filename(path.name)
        elif package_family == "rpm":
            package, version, arch = _parse_rpm_filename(path.name)
        if package is not None:
            package_count += 1

        files.append(
            ManifestFile(
                filename=rel,
                sha256=sha,
                size=size,
                package=package,
                version=version,
                arch=arch,
            )
        )
        total_bytes += size

    return {
        "praxis_mirror_manifest": MANIFEST_FORMAT_VERSION,
        "mirror_slug": slug,
        "run_id": run_id,
        "package_family": package_family,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "byte_count": total_bytes,
        "package_count": package_count,
        "files": [
            {
                "filename": f.filename,
                "sha256": f.sha256,
                "size": f.size,
                "package": f.package,
                "version": f.version,
                "arch": f.arch,
            }
            for f in files
        ],
    }


def _empty_manifest(slug: str, run_id: int, package_family: str) -> dict:
    return {
        "praxis_mirror_manifest": MANIFEST_FORMAT_VERSION,
        "mirror_slug": slug,
        "run_id": run_id,
        "package_family": package_family,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "byte_count": 0,
        "package_count": 0,
        "files": [],
    }


def serialize_manifest(manifest: dict) -> bytes:
    """Canonical JSON bytes of the FULL manifest (with volatile
    fields). Used for the on-disk ``snapshots/<run_id>.manifest.json``
    write so an operator inspecting the file can see run_id /
    generated_at.

    Do NOT use this for hashing — see ``manifest_sha256`` /
    ``serialize_manifest_content``.
    """
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def serialize_manifest_content(manifest: dict) -> bytes:
    """Canonical JSON bytes of the content-only view. This is what
    ``manifest_sha256`` hashes and what PRA-158 will sign — strips
    volatile run metadata so identical content over two runs
    produces identical bytes.
    """
    content = {k: manifest[k] for k in MANIFEST_CONTENT_FIELDS if k in manifest}
    return json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_sha256(manifest: dict) -> str:
    """Content fingerprint of the manifest. Stable across runs of
    identical bytes (excludes ``run_id``, ``generated_at``,
    ``mirror_slug``).
    """
    return hashlib.sha256(serialize_manifest_content(manifest)).hexdigest()


def write_manifest(manifest: dict, slug: str, run_id: int) -> Path:
    """Write the canonical-JSON manifest under ``snapshots/`` and
    return the path. Caller records this path on the
    ``mirror_sync_runs`` row.
    """
    snapshots_dir(slug).mkdir(parents=True, exist_ok=True)
    path = snapshot_manifest_path(slug, run_id)
    path.write_bytes(serialize_manifest(manifest))
    return path
