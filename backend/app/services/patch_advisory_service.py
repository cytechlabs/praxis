"""Native distribution advisory ingestion + storage (PRA-163 slices 1+2).

Metadata-only. No package-manager execution, no live network fetch,
no plan generation, no preflight, no probes, no reboot/rollback,
no mirror rebuild/re-sign, no airgap changes.

Slice 1 (advisory storage + native-source import foundation):

* Normalizes per-source-kind raw payloads into a canonical
  advisory shape (`normalize_ubuntu_usn`, `normalize_redhat_updateinfo`,
  `normalize_debian_security`).
* Computes a deterministic ``digest`` from the canonical-JSON raw
  payload.
* Upserts advisory rows by ``(source_kind, source_advisory_id)`` —
  if the digest is unchanged the row is left alone (true no-op,
  no audit, counted as ``unchanged``); if the digest changed the
  row is refreshed and ``patch_advisory.refreshed`` fires; if the
  row is new ``patch_advisory.imported`` fires.
* Replaces the advisory's fixed-package set on every refresh
  (delete-then-insert by ``advisory_id``).
* Records a single :class:`PatchAdvisoryImport` row per call with
  imported/refreshed/unchanged/error counts and per-payload error
  details.

Slice 2 (host-applicability resolver):

* ``compute_host_applicability(db, system_id)`` joins
  ``HostFacts.distro_id_facts`` / ``HostFacts.distro_release`` and
  ``Package.name`` / ``Package.installed_version`` against Slice 1
  ``patch_advisory_fixed_packages`` rows. Per-host replace-all keeps
  the materialized row set in
  ``patch_advisory_host_applicability`` deterministic.
* Distro-release alias map (``_RELEASE_ALIASES``) bridges Ubuntu
  codenames (``jammy``/``noble``/...) ↔ versions (``22.04``/...) and
  Debian codenames (``bookworm``/...) ↔ majors. RHEL matches on
  major version segment.
* Local ``_compare_versions`` is a numeric-segment heuristic with
  optional epoch (``:`` prefix) handling — fixture-defensible for
  PRA-163 USN/DSA/RHSA shapes; documented as a known limitation if
  PRA-164 needs full distro-native comparison.
* ``recompute_after_advisory_import`` is the targeted fanout —
  collect ``(distro_id, distro_release, package_name)`` tuples
  touched by imported/refreshed advisories and recompute only the
  hosts whose facts and installed packages intersect those targets.
  Wired into ``import_advisories`` after audit emit so a digest-equal
  no-op import does not trigger applicability churn.
* ``patch_advisory.applicable_recomputed`` audit fires per host
  only when the row delta is non-zero.

Design locks (carry-forward from PRA-161/PRA-162):

* Local exception class so this service stays independent.
* ``safe_emit`` audit emission with no ``db=`` argument so it opens
  its own ``SessionLocal`` per ``feedback_safe_emit_session_boundary.md``.
* Audit happens AFTER the service's own commit. No audit on
  digest-equal or row-delta-zero no-ops.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from ..db.models import (
    HostFacts,
    Package,
    PatchAdvisory,
    PatchAdvisoryFixedPackage,
    PatchAdvisoryHostApplicability,
    PatchAdvisoryImport,
    System,
    User,
)
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local exception class
# ---------------------------------------------------------------------------


class PatchAdvisoryError(ValueError):
    """Raised when a payload normalization or import is rejected for
    semantic reasons (unknown source_kind, invalid vocabulary, missing
    required field, unknown actor, etc.).

    Subclasses ``ValueError`` so route layers (when added in Slice 4)
    can map the family to HTTP 422.
    """


# ---------------------------------------------------------------------------
# Audit event-type strings
# ---------------------------------------------------------------------------

AUDIT_PATCH_ADVISORY_IMPORTED = "patch_advisory.imported"
AUDIT_PATCH_ADVISORY_REFRESHED = "patch_advisory.refreshed"
AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED = "patch_advisory.applicable_recomputed"


# ---------------------------------------------------------------------------
# Vocabularies (must mirror DB CHECK constraints in the migration)
# ---------------------------------------------------------------------------

SOURCE_KIND_UBUNTU_USN = "ubuntu_usn"
SOURCE_KIND_DEBIAN_SECURITY = "debian_security"
SOURCE_KIND_REDHAT_UPDATEINFO = "redhat_updateinfo"
VALID_SOURCE_KINDS = {
    SOURCE_KIND_UBUNTU_USN,
    SOURCE_KIND_DEBIAN_SECURITY,
    SOURCE_KIND_REDHAT_UPDATEINFO,
}

ADVISORY_CLASS_SECURITY = "security"
ADVISORY_CLASS_BUGFIX = "bugfix"
ADVISORY_CLASS_ENHANCEMENT = "enhancement"
ADVISORY_CLASS_OTHER = "other"
VALID_ADVISORY_CLASSES = {
    ADVISORY_CLASS_SECURITY,
    ADVISORY_CLASS_BUGFIX,
    ADVISORY_CLASS_ENHANCEMENT,
    ADVISORY_CLASS_OTHER,
}

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_NEGLIGIBLE = "negligible"
SEVERITY_UNKNOWN = "unknown"
VALID_SEVERITIES = {
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_NEGLIGIBLE,
    SEVERITY_UNKNOWN,
}

DISTRO_FAMILY_DEBIAN = "debian"
DISTRO_FAMILY_RHEL = "rhel"
VALID_DISTRO_FAMILIES = {DISTRO_FAMILY_DEBIAN, DISTRO_FAMILY_RHEL}

IMPORT_STATUS_SUCCESS = "success"
IMPORT_STATUS_PARTIAL = "partial"
IMPORT_STATUS_FAILED = "failed"
VALID_IMPORT_STATUSES = {
    IMPORT_STATUS_SUCCESS,
    IMPORT_STATUS_PARTIAL,
    IMPORT_STATUS_FAILED,
}


# ---------------------------------------------------------------------------
# Severity normalization map
# ---------------------------------------------------------------------------
#
# Native sources use overlapping but distinct severity vocabularies:
#
# * Ubuntu USN: "Critical", "High", "Medium", "Low", "Negligible".
# * Debian security tracker: "important", "high", "medium", "low".
# * Red Hat updateinfo / dnf: "Critical", "Important", "Moderate", "Low".
#
# Normalize to the canonical set so PRA-164 plan generation sees one
# vocabulary regardless of upstream source.

_SEVERITY_ALIASES: Dict[str, str] = {
    # USN / generic
    "critical": SEVERITY_CRITICAL,
    "high": SEVERITY_HIGH,
    "medium": SEVERITY_MEDIUM,
    "moderate": SEVERITY_MEDIUM,
    "low": SEVERITY_LOW,
    "negligible": SEVERITY_NEGLIGIBLE,
    "important": SEVERITY_HIGH,  # Red Hat / Debian
    "none": SEVERITY_NEGLIGIBLE,
    "unknown": SEVERITY_UNKNOWN,
    "unspecified": SEVERITY_UNKNOWN,
    "": SEVERITY_UNKNOWN,
}


def normalize_severity(value: Any) -> str:
    """Map a native severity string to the canonical vocabulary.

    Unrecognized values fall through to ``unknown`` rather than
    raising — operators can still see the raw value via the JSONB
    ``raw`` column on the advisory row.
    """
    if value is None:
        return SEVERITY_UNKNOWN
    key = str(value).strip().lower()
    return _SEVERITY_ALIASES.get(key, SEVERITY_UNKNOWN)


# ---------------------------------------------------------------------------
# Canonical payload shape
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class CanonicalAdvisoryPayload:
    """Source-neutral advisory shape consumed by :func:`import_advisories`.

    Per-source-kind ``normalize_*`` helpers turn a raw native dict into
    one or more of these. ``raw`` retains the original payload as JSONB
    so the source-of-truth context is never lost.
    """

    source_kind: str
    source_advisory_id: str
    advisory_class: str
    severity: str
    title: str
    distro_family: str
    summary: Optional[str] = None
    published_at: Optional[datetime] = None
    source_updated_at: Optional[datetime] = None
    cve_ids: Optional[List[str]] = None
    external_refs: Optional[List[str]] = None
    raw: Optional[Dict[str, Any]] = None
    fixed_packages: List[Dict[str, Any]] = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# Payload validation + digest
# ---------------------------------------------------------------------------


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # Accept "Z" and bare datetimes; reject silently to None on
        # malformed values rather than dying mid-import.
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return datetime.fromisoformat(s)
        except ValueError:
            return None
    return None


def _validate_payload(payload: CanonicalAdvisoryPayload) -> None:
    if payload.source_kind not in VALID_SOURCE_KINDS:
        raise PatchAdvisoryError(
            f"source_kind={payload.source_kind!r} not in {sorted(VALID_SOURCE_KINDS)}"
        )
    if not payload.source_advisory_id or not isinstance(
        payload.source_advisory_id, str
    ):
        raise PatchAdvisoryError("source_advisory_id is required")
    if len(payload.source_advisory_id) > 128:
        raise PatchAdvisoryError("source_advisory_id exceeds 128 characters")
    if payload.advisory_class not in VALID_ADVISORY_CLASSES:
        raise PatchAdvisoryError(
            f"advisory_class={payload.advisory_class!r} not in "
            f"{sorted(VALID_ADVISORY_CLASSES)}"
        )
    if payload.severity not in VALID_SEVERITIES:
        raise PatchAdvisoryError(
            f"severity={payload.severity!r} not in {sorted(VALID_SEVERITIES)}"
        )
    if payload.distro_family not in VALID_DISTRO_FAMILIES:
        raise PatchAdvisoryError(
            f"distro_family={payload.distro_family!r} not in "
            f"{sorted(VALID_DISTRO_FAMILIES)}"
        )
    if not payload.title or not isinstance(payload.title, str):
        raise PatchAdvisoryError("title is required")
    if len(payload.title) > 512:
        raise PatchAdvisoryError("title exceeds 512 characters")

    seen: set = set()
    for entry in payload.fixed_packages:
        if not isinstance(entry, dict):
            raise PatchAdvisoryError("fixed_packages entries must be dicts")
        for key in ("distro_id", "distro_release", "package_name"):
            v = entry.get(key)
            if not v or not isinstance(v, str):
                raise PatchAdvisoryError(
                    f"fixed_packages entry missing required string {key!r}"
                )
        key_tuple = (
            entry["distro_id"],
            entry["distro_release"],
            entry["package_name"],
        )
        if key_tuple in seen:
            raise PatchAdvisoryError(f"duplicate fixed_packages target {key_tuple!r}")
        seen.add(key_tuple)


def _compute_digest(raw: Optional[Dict[str, Any]]) -> str:
    """Sha256 of canonical-JSON ``raw`` payload, hex-encoded.

    ``sort_keys=True`` makes the digest deterministic across dict
    iteration orders. ``default=str`` is a defensive fallback for
    any non-JSON-serializable values that snuck into ``raw``.
    """
    blob = json.dumps(raw if raw is not None else {}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Per-source-kind normalizers
# ---------------------------------------------------------------------------
#
# Each accepts a single raw payload dict and returns one
# CanonicalAdvisoryPayload. Real callers (future fetcher slices) will
# stream native payloads through these. Keep them small and pure.


def normalize_ubuntu_usn(raw: Dict[str, Any]) -> CanonicalAdvisoryPayload:
    """Normalize a single Ubuntu USN payload.

    Expected raw shape (mirrors ``ubuntu.com/security/notices`` JSON):

        {
          "id": "USN-7234-1",
          "title": "OpenSSL vulnerabilities",
          "summary": "...",
          "cves": ["CVE-2024-1234"],
          "references": ["https://..."],
          "published": "2026-04-12T00:00:00Z",
          "release_packages": {
            "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
            "noble": [{"name": "openssl", "version": "3.0.13-0ubuntu1"}],
          },
        }
    """
    if not isinstance(raw, dict):
        raise PatchAdvisoryError("ubuntu_usn payload must be a dict")
    advisory_id = raw.get("id")
    if not advisory_id:
        raise PatchAdvisoryError("ubuntu_usn payload missing 'id'")

    fixed: List[Dict[str, Any]] = []
    release_packages = raw.get("release_packages")
    if release_packages is None:
        release_packages = {}
    if not isinstance(release_packages, dict):
        raise PatchAdvisoryError(
            "ubuntu_usn 'release_packages' must be a dict release→[pkg]"
        )
    for release, pkgs in release_packages.items():
        if not isinstance(pkgs, list):
            continue
        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            if not name:
                continue
            fixed.append(
                {
                    "distro_id": "ubuntu",
                    "distro_release": str(release),
                    "package_name": str(name),
                    "fixed_version": pkg.get("version"),
                }
            )

    return CanonicalAdvisoryPayload(
        source_kind=SOURCE_KIND_UBUNTU_USN,
        source_advisory_id=str(advisory_id),
        advisory_class=ADVISORY_CLASS_SECURITY,  # USNs are security advisories
        severity=normalize_severity(raw.get("severity")),
        title=str(raw.get("title") or advisory_id),
        summary=raw.get("summary"),
        distro_family=DISTRO_FAMILY_DEBIAN,
        published_at=_parse_dt(raw.get("published")),
        source_updated_at=_parse_dt(raw.get("updated") or raw.get("published")),
        cve_ids=list(raw.get("cves") or []) or None,
        external_refs=list(raw.get("references") or []) or None,
        raw=raw,
        fixed_packages=fixed,
    )


def normalize_debian_security(raw: Dict[str, Any]) -> CanonicalAdvisoryPayload:
    """Normalize a single Debian Security Advisory payload (DSA / DLA).

    Expected raw shape (mirrors Debian security tracker per-DSA JSON):

        {
          "id": "DSA-5512-1",
          "title": "openssl - security update",
          "description": "...",
          "cves": ["CVE-2024-1234"],
          "date": "2026-04-12",
          "releases": {
            "bookworm": {
              "fixed_version": "3.0.13-1~deb12u1",
              "packages": ["openssl"]
            }
          }
        }
    """
    if not isinstance(raw, dict):
        raise PatchAdvisoryError("debian_security payload must be a dict")
    advisory_id = raw.get("id")
    if not advisory_id:
        raise PatchAdvisoryError("debian_security payload missing 'id'")

    fixed: List[Dict[str, Any]] = []
    releases = raw.get("releases")
    if releases is None:
        releases = {}
    if not isinstance(releases, dict):
        raise PatchAdvisoryError(
            "debian_security 'releases' must be a dict release→info"
        )
    for release, info in releases.items():
        if not isinstance(info, dict):
            continue
        version = info.get("fixed_version")
        for pkg in info.get("packages") or []:
            if not pkg:
                continue
            fixed.append(
                {
                    "distro_id": "debian",
                    "distro_release": str(release),
                    "package_name": str(pkg),
                    "fixed_version": version,
                }
            )

    return CanonicalAdvisoryPayload(
        source_kind=SOURCE_KIND_DEBIAN_SECURITY,
        source_advisory_id=str(advisory_id),
        advisory_class=ADVISORY_CLASS_SECURITY,
        severity=normalize_severity(raw.get("severity")),
        title=str(raw.get("title") or advisory_id),
        summary=raw.get("description") or raw.get("summary"),
        distro_family=DISTRO_FAMILY_DEBIAN,
        published_at=_parse_dt(raw.get("date") or raw.get("published")),
        source_updated_at=_parse_dt(raw.get("updated") or raw.get("date")),
        cve_ids=list(raw.get("cves") or []) or None,
        external_refs=list(raw.get("references") or []) or None,
        raw=raw,
        fixed_packages=fixed,
    )


# Red Hat updateinfo "type" → canonical advisory_class.
_RHSA_TYPE_TO_CLASS: Dict[str, str] = {
    "security": ADVISORY_CLASS_SECURITY,
    "bugfix": ADVISORY_CLASS_BUGFIX,
    "enhancement": ADVISORY_CLASS_ENHANCEMENT,
    "newpackage": ADVISORY_CLASS_OTHER,
}


def normalize_redhat_updateinfo(raw: Dict[str, Any]) -> CanonicalAdvisoryPayload:
    """Normalize a single dnf/yum updateinfo entry (RHSA/RHBA/RHEA).

    Expected raw shape (mirrors ``updateinfo.xml`` parsed to dict):

        {
          "id": "RHSA-2024:1234",
          "type": "security",        # security|bugfix|enhancement|newpackage
          "severity": "Important",
          "title": "Important: openssl security update",
          "description": "...",
          "issued": "2026-04-12",
          "updated": "2026-04-13",
          "release": "9",            # major release; falls back to per-pkg
          "distro_id": "rhel",       # optional; defaults to 'rhel'
          "references": [
            {"type": "cve", "id": "CVE-2024-1234", "href": "https://..."},
            {"type": "self", "href": "https://..."}
          ],
          "packages": [
            {
              "name": "openssl",
              "version": "3.0.7-25.el9_3",
              "release": "9"   # optional per-pkg release override
            }
          ]
        }
    """
    if not isinstance(raw, dict):
        raise PatchAdvisoryError("redhat_updateinfo payload must be a dict")
    advisory_id = raw.get("id")
    if not advisory_id:
        raise PatchAdvisoryError("redhat_updateinfo payload missing 'id'")

    rhsa_type = str(raw.get("type") or "").strip().lower()
    advisory_class = _RHSA_TYPE_TO_CLASS.get(rhsa_type, ADVISORY_CLASS_OTHER)

    distro_id = str(raw.get("distro_id") or "rhel")
    default_release = raw.get("release")

    fixed: List[Dict[str, Any]] = []
    for pkg in raw.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        if not name:
            continue
        rel = pkg.get("release") or default_release
        if not rel:
            # Skip packages with no release context — the index demands it.
            continue
        fixed.append(
            {
                "distro_id": distro_id,
                "distro_release": str(rel),
                "package_name": str(name),
                "fixed_version": pkg.get("version"),
            }
        )

    cves: List[str] = []
    external: List[str] = []
    for ref in raw.get("references") or []:
        if isinstance(ref, dict):
            ref_type = (ref.get("type") or "").lower()
            if ref_type == "cve" and ref.get("id"):
                cves.append(str(ref["id"]))
            href = ref.get("href")
            if href:
                external.append(str(href))
        elif isinstance(ref, str):
            external.append(ref)

    return CanonicalAdvisoryPayload(
        source_kind=SOURCE_KIND_REDHAT_UPDATEINFO,
        source_advisory_id=str(advisory_id),
        advisory_class=advisory_class,
        severity=normalize_severity(raw.get("severity")),
        title=str(raw.get("title") or advisory_id),
        summary=raw.get("description") or raw.get("summary"),
        distro_family=DISTRO_FAMILY_RHEL,
        published_at=_parse_dt(raw.get("issued") or raw.get("published")),
        source_updated_at=_parse_dt(raw.get("updated") or raw.get("issued")),
        cve_ids=cves or None,
        external_refs=external or None,
        raw=raw,
        fixed_packages=fixed,
    )


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------


def get_advisory(db: Session, advisory_id: int) -> Optional[PatchAdvisory]:
    return db.query(PatchAdvisory).filter(PatchAdvisory.id == advisory_id).first()


def get_advisory_by_source(
    db: Session, *, source_kind: str, source_advisory_id: str
) -> Optional[PatchAdvisory]:
    return (
        db.query(PatchAdvisory)
        .filter(
            PatchAdvisory.source_kind == source_kind,
            PatchAdvisory.source_advisory_id == source_advisory_id,
        )
        .first()
    )


def list_advisories(
    db: Session,
    *,
    source_kind: Optional[str] = None,
    advisory_class: Optional[str] = None,
    severity: Optional[str] = None,
    distro_family: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[PatchAdvisory]:
    """List advisories newest-first by ``source_updated_at`` (then id)."""
    q = db.query(PatchAdvisory)
    if source_kind is not None:
        q = q.filter(PatchAdvisory.source_kind == source_kind)
    if advisory_class is not None:
        q = q.filter(PatchAdvisory.advisory_class == advisory_class)
    if severity is not None:
        q = q.filter(PatchAdvisory.severity == severity)
    if distro_family is not None:
        q = q.filter(PatchAdvisory.distro_family == distro_family)
    return (
        q.order_by(
            PatchAdvisory.source_updated_at.desc().nullslast(),
            PatchAdvisory.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )


def list_fixed_packages(
    db: Session, advisory_id: int
) -> List[PatchAdvisoryFixedPackage]:
    return (
        db.query(PatchAdvisoryFixedPackage)
        .filter(PatchAdvisoryFixedPackage.advisory_id == advisory_id)
        .order_by(
            PatchAdvisoryFixedPackage.distro_id.asc(),
            PatchAdvisoryFixedPackage.distro_release.asc(),
            PatchAdvisoryFixedPackage.package_name.asc(),
        )
        .all()
    )


def list_import_runs(
    db: Session,
    *,
    source_kind: Optional[str] = None,
    limit: int = 50,
) -> List[PatchAdvisoryImport]:
    q = db.query(PatchAdvisoryImport)
    if source_kind is not None:
        q = q.filter(PatchAdvisoryImport.source_kind == source_kind)
    return (
        q.order_by(PatchAdvisoryImport.started_at.desc(), PatchAdvisoryImport.id.desc())
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Core import
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ImportOutcome:
    """Per-payload outcome returned by :func:`import_advisories`.

    ``action`` is one of ``imported`` / ``refreshed`` / ``unchanged`` /
    ``error``. Caller maps these into the ``PatchAdvisoryImport`` row's
    counts; tests inspect them directly.
    """

    source_advisory_id: str
    action: str
    advisory_id: Optional[int] = None
    error: Optional[str] = None


def _replace_fixed_packages(
    db: Session,
    advisory: PatchAdvisory,
    entries: Iterable[Dict[str, Any]],
) -> None:
    """Delete-then-insert the advisory's fixed-package set.

    Replace-all is intentional: per-row diff would have to handle
    add/remove/version-change for every (distro_id, release, package)
    tuple. Replace-all is one DELETE + N INSERTs and keeps the model
    free of stale rows.
    """
    db.query(PatchAdvisoryFixedPackage).filter(
        PatchAdvisoryFixedPackage.advisory_id == advisory.id
    ).delete(synchronize_session=False)
    for entry in entries:
        db.add(
            PatchAdvisoryFixedPackage(
                advisory_id=advisory.id,
                distro_id=entry["distro_id"],
                distro_release=entry["distro_release"],
                package_name=entry["package_name"],
                fixed_version=entry.get("fixed_version"),
            )
        )


def _emit_advisory_audit(
    *,
    action: str,
    advisory: PatchAdvisory,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    fixed_count: int,
) -> None:
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_advisory",
        target_id=str(advisory.id),
        context={
            "source_kind": advisory.source_kind,
            "source_advisory_id": advisory.source_advisory_id,
            "advisory_class": advisory.advisory_class,
            "severity": advisory.severity,
            "fixed_packages": fixed_count,
        },
    )


def import_advisories(
    db: Session,
    *,
    source_kind: str,
    payloads: List[CanonicalAdvisoryPayload],
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> Tuple[PatchAdvisoryImport, List[ImportOutcome]]:
    """Import a batch of canonical advisory payloads.

    All payloads must declare the same ``source_kind`` as the
    enclosing import run; mismatches raise before any DB write.
    Per-payload errors are captured into the run's ``error_details``
    rather than aborting the entire batch — partial imports leave the
    successful rows in place and the run is recorded with status
    ``partial``.
    """
    if source_kind not in VALID_SOURCE_KINDS:
        raise PatchAdvisoryError(
            f"source_kind={source_kind!r} not in {sorted(VALID_SOURCE_KINDS)}"
        )
    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchAdvisoryError(
            f"actor_user_id={actor_user_id} does not reference a user"
        )
    for p in payloads:
        if p.source_kind != source_kind:
            raise PatchAdvisoryError(
                f"payload source_kind={p.source_kind!r} does not match "
                f"run source_kind={source_kind!r}"
            )

    started_at = datetime.utcnow()
    outcomes: List[ImportOutcome] = []
    audit_queue: List[Tuple[str, PatchAdvisory, int]] = []
    touched_targets: Set[Tuple[str, str, str]] = set()

    for payload in payloads:
        try:
            _validate_payload(payload)
        except PatchAdvisoryError as err:
            outcomes.append(
                ImportOutcome(
                    source_advisory_id=str(payload.source_advisory_id or ""),
                    action="error",
                    error=str(err),
                )
            )
            continue

        digest = _compute_digest(payload.raw)
        existing = (
            db.query(PatchAdvisory)
            .filter(
                PatchAdvisory.source_kind == payload.source_kind,
                PatchAdvisory.source_advisory_id == payload.source_advisory_id,
            )
            .first()
        )

        if existing is None:
            advisory = PatchAdvisory(
                source_kind=payload.source_kind,
                source_advisory_id=payload.source_advisory_id,
                advisory_class=payload.advisory_class,
                severity=payload.severity,
                title=payload.title,
                summary=payload.summary,
                distro_family=payload.distro_family,
                published_at=payload.published_at,
                source_updated_at=payload.source_updated_at,
                cve_ids=payload.cve_ids,
                external_refs=payload.external_refs,
                raw=payload.raw,
                digest=digest,
            )
            db.add(advisory)
            db.flush()  # need advisory.id for fixed_packages FK
            _replace_fixed_packages(db, advisory, payload.fixed_packages)
            outcomes.append(
                ImportOutcome(
                    source_advisory_id=payload.source_advisory_id,
                    action="imported",
                    advisory_id=advisory.id,
                )
            )
            audit_queue.append(
                (
                    AUDIT_PATCH_ADVISORY_IMPORTED,
                    advisory,
                    len(payload.fixed_packages),
                )
            )
            for entry in payload.fixed_packages:
                touched_targets.add(
                    (
                        entry["distro_id"],
                        entry["distro_release"],
                        entry["package_name"],
                    )
                )
        elif existing.digest == digest:
            outcomes.append(
                ImportOutcome(
                    source_advisory_id=payload.source_advisory_id,
                    action="unchanged",
                    advisory_id=existing.id,
                )
            )
        else:
            # Capture OLD targets BEFORE _replace_fixed_packages drops
            # them so the Slice 2 fanout visits hosts that were only
            # affected by the prior target set (refresh that
            # removes/replaces a release/package would otherwise leave
            # those hosts' applicability rows stale — the FK is SET
            # NULL on the dropped fixed_package row, so the
            # applicability row survives with stale state until the
            # next recompute touches that host).
            old_targets = (
                db.query(
                    PatchAdvisoryFixedPackage.distro_id,
                    PatchAdvisoryFixedPackage.distro_release,
                    PatchAdvisoryFixedPackage.package_name,
                )
                .filter(PatchAdvisoryFixedPackage.advisory_id == existing.id)
                .all()
            )
            for distro_id, distro_release, package_name in old_targets:
                touched_targets.add((distro_id, distro_release, package_name))

            existing.advisory_class = payload.advisory_class
            existing.severity = payload.severity
            existing.title = payload.title
            existing.summary = payload.summary
            existing.distro_family = payload.distro_family
            existing.published_at = payload.published_at
            existing.source_updated_at = payload.source_updated_at
            existing.cve_ids = payload.cve_ids
            existing.external_refs = payload.external_refs
            existing.raw = payload.raw
            existing.digest = digest
            _replace_fixed_packages(db, existing, payload.fixed_packages)
            outcomes.append(
                ImportOutcome(
                    source_advisory_id=payload.source_advisory_id,
                    action="refreshed",
                    advisory_id=existing.id,
                )
            )
            audit_queue.append(
                (
                    AUDIT_PATCH_ADVISORY_REFRESHED,
                    existing,
                    len(payload.fixed_packages),
                )
            )
            for entry in payload.fixed_packages:
                touched_targets.add(
                    (
                        entry["distro_id"],
                        entry["distro_release"],
                        entry["package_name"],
                    )
                )

    imported_count = sum(1 for o in outcomes if o.action == "imported")
    refreshed_count = sum(1 for o in outcomes if o.action == "refreshed")
    unchanged_count = sum(1 for o in outcomes if o.action == "unchanged")
    error_count = sum(1 for o in outcomes if o.action == "error")
    error_details: Optional[List[Dict[str, Any]]] = None
    if error_count:
        error_details = [
            {"source_advisory_id": o.source_advisory_id, "error": o.error}
            for o in outcomes
            if o.action == "error"
        ]

    if error_count == 0:
        status = IMPORT_STATUS_SUCCESS
    elif imported_count or refreshed_count or unchanged_count:
        status = IMPORT_STATUS_PARTIAL
    else:
        status = IMPORT_STATUS_FAILED

    finished_at = datetime.utcnow()
    run = PatchAdvisoryImport(
        source_kind=source_kind,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        imported_count=imported_count,
        refreshed_count=refreshed_count,
        unchanged_count=unchanged_count,
        error_count=error_count,
        error_details=error_details,
        created_by=actor_user_id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    # Audit AFTER commit, no db= per safe_emit session boundary rule.
    for action, advisory, fixed_count in audit_queue:
        _emit_advisory_audit(
            action=action,
            advisory=advisory,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            fixed_count=fixed_count,
        )

    # Slice 2: targeted host-applicability recompute fanout.
    # Only fires when imported/refreshed advisories actually touched
    # distro/release/package targets — digest-equal no-op imports
    # leave touched_targets empty.
    if touched_targets:
        try:
            recompute_after_advisory_import(
                db,
                touched_targets,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
            )
        except Exception as exc:  # pylint: disable=broad-except
            # Applicability recompute is a follow-on optimization; never
            # let it fail the import that already committed. Operators
            # can trigger a manual recompute if needed.
            logger.warning(
                "applicability recompute after advisory import failed: %s", exc
            )

    return run, outcomes


# ---------------------------------------------------------------------------
# Slice 2: host-applicability resolver
# ---------------------------------------------------------------------------


# Applicability state vocabulary (mirrors the DB CHECK constraint).
APPLICABILITY_STATE_APPLICABLE = "applicable"
APPLICABILITY_STATE_FIXED = "fixed"
APPLICABILITY_STATE_NOT_APPLICABLE = "not_applicable"
APPLICABILITY_STATE_UNKNOWN = "unknown"
VALID_APPLICABILITY_STATES = {
    APPLICABILITY_STATE_APPLICABLE,
    APPLICABILITY_STATE_FIXED,
    APPLICABILITY_STATE_NOT_APPLICABLE,
    APPLICABILITY_STATE_UNKNOWN,
}


# Distro release alias map: native sources use either codenames
# (Ubuntu USN: ``jammy``/``noble``; Debian DSA: ``bookworm``) or
# version numbers (Ubuntu host facts: ``22.04``; Debian host facts:
# ``12``). The resolver matches a fixed-package target's release
# against a host's release if either string appears in the other's
# alias set. RHEL major-version matching is handled separately
# (``9.3`` host vs ``9`` source) because RHEL releases use a
# major.minor scheme.
_RELEASE_ALIASES: Dict[Tuple[str, str], Set[str]] = {
    # Ubuntu codename ↔ version
    ("ubuntu", "16.04"): {"16.04", "xenial"},
    ("ubuntu", "xenial"): {"16.04", "xenial"},
    ("ubuntu", "18.04"): {"18.04", "bionic"},
    ("ubuntu", "bionic"): {"18.04", "bionic"},
    ("ubuntu", "20.04"): {"20.04", "focal"},
    ("ubuntu", "focal"): {"20.04", "focal"},
    ("ubuntu", "22.04"): {"22.04", "jammy"},
    ("ubuntu", "jammy"): {"22.04", "jammy"},
    ("ubuntu", "24.04"): {"24.04", "noble"},
    ("ubuntu", "noble"): {"24.04", "noble"},
    # Debian codename ↔ version
    ("debian", "10"): {"10", "buster"},
    ("debian", "buster"): {"10", "buster"},
    ("debian", "11"): {"11", "bullseye"},
    ("debian", "bullseye"): {"11", "bullseye"},
    ("debian", "12"): {"12", "bookworm"},
    ("debian", "bookworm"): {"12", "bookworm"},
    ("debian", "13"): {"13", "trixie"},
    ("debian", "trixie"): {"13", "trixie"},
}


def _release_matches(distro_id: str, host_release: str, source_release: str) -> bool:
    """Decide whether a host release equates to a source release for
    advisory applicability.

    * Exact string equality always matches.
    * For ``ubuntu``/``debian`` the bidirectional codename↔version map
      makes ``jammy`` equivalent to ``22.04``, ``bookworm`` equivalent
      to ``12``, etc.
    * For ``rhel`` the leading major-version segment is compared
      (``9.3`` host equates to ``9`` source).
    * Unknown distro_ids fall back to exact equality.
    """
    if not host_release or not source_release:
        return False
    if host_release == source_release:
        return True
    aliases = _RELEASE_ALIASES.get((distro_id, host_release))
    if aliases and source_release in aliases:
        return True
    aliases = _RELEASE_ALIASES.get((distro_id, source_release))
    if aliases and host_release in aliases:
        return True
    if distro_id == "rhel":
        host_major = host_release.split(".", 1)[0]
        source_major = source_release.split(".", 1)[0]
        if host_major and host_major == source_major:
            return True
    return False


# Numeric-segment comparator for fixture-defensible ordering.
# Limitations (documented for PRA-164): epoch (``1:3.0.7``) is compared
# as a leading integer; non-numeric pre-release suffixes (``rc1``,
# ``beta``) are stripped; Debian-style revision (``-1~deb12u1``)
# reduces to its remaining digits. Sufficient for the USN/DSA/RHSA
# fixture shapes; PRA-164 may need a distro-native comparator.

_VERSION_TOKEN_RE = re.compile(r"\d+")


def _parse_version_segments(version: str) -> Optional[Tuple[int, List[int]]]:
    """Return ``(epoch, [int_segments])`` or ``None`` if unparseable."""
    if not version or not isinstance(version, str):
        return None
    epoch_part, _, rest = version.partition(":")
    if rest:
        try:
            epoch = int(epoch_part)
        except ValueError:
            return None
        body = rest
    else:
        epoch = 0
        body = epoch_part
    tokens = _VERSION_TOKEN_RE.findall(body)
    if not tokens:
        return None
    try:
        segments = [int(t) for t in tokens]
    except ValueError:  # pragma: no cover - regex guarantees digits
        return None
    return epoch, segments


def _compare_versions(a: str, b: str) -> Optional[int]:
    """Return -1/0/1 (a vs b), or None when either side is unparseable.

    Pads the shorter segment list with zeros so ``3.0.2`` and
    ``3.0.2.0`` compare equal.
    """
    parsed_a = _parse_version_segments(a)
    parsed_b = _parse_version_segments(b)
    if parsed_a is None or parsed_b is None:
        return None
    epoch_a, segs_a = parsed_a
    epoch_b, segs_b = parsed_b
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    width = max(len(segs_a), len(segs_b))
    padded_a = segs_a + [0] * (width - len(segs_a))
    padded_b = segs_b + [0] * (width - len(segs_b))
    if padded_a < padded_b:
        return -1
    if padded_a > padded_b:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Resolver result shape
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ApplicabilityResult:
    """Outcome of one ``compute_host_applicability`` call.

    ``host_facts_missing`` is set when the host has no
    ``HostFacts.distro_id_facts`` — the resolver writes zero rows in
    that case but still emits the audit so operators can see the host
    is unresolvable.

    ``rows_added`` / ``rows_updated`` / ``rows_removed`` count the
    delta against pre-existing rows so an idempotent recompute
    (zero delta) suppresses audit emission.
    """

    system_id: int
    counts: Dict[str, int] = dataclasses.field(default_factory=dict)
    rows_added: int = 0
    rows_updated: int = 0
    rows_removed: int = 0
    advisories_touched: int = 0
    host_facts_missing: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.rows_added or self.rows_updated or self.rows_removed)


# ---------------------------------------------------------------------------
# Internal classification helper
# ---------------------------------------------------------------------------


def _classify(
    *, installed_version: Optional[str], required_version: Optional[str]
) -> Tuple[str, Optional[str]]:
    """Return ``(state, reason)`` for one (host, fixed_package_target).

    Caller has already established that the package is installed on
    the host. ``required_version`` is the source's published fix
    (may be ``None`` for advisories with no fix yet).
    """
    if not installed_version:
        return APPLICABILITY_STATE_UNKNOWN, "installed_version missing"
    if required_version is None:
        return APPLICABILITY_STATE_APPLICABLE, "no published fix"
    cmp_result = _compare_versions(installed_version, required_version)
    if cmp_result is None:
        return APPLICABILITY_STATE_UNKNOWN, "version compare failed"
    if cmp_result >= 0:
        return APPLICABILITY_STATE_FIXED, None
    return APPLICABILITY_STATE_APPLICABLE, None


# ---------------------------------------------------------------------------
# Core resolver
# ---------------------------------------------------------------------------


def compute_host_applicability(
    db: Session,
    system_id: int,
    *,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    emit_audit: bool = True,
) -> ApplicabilityResult:
    """Materialize the applicability state for one host.

    Reads only stored DB metadata: ``System``, ``HostFacts``,
    ``Package``, and Slice 1's advisory tables. Never calls a package
    manager, runs a probe, opens an SSH session, or fetches over
    the network.

    Replace-all per host: the resolver computes the desired row set
    against the host's pre-existing applicability rows, deletes
    obsolete rows, inserts new rows, updates rows whose state /
    versions / reason / fixed_package_id changed, and commits. If
    the row delta is zero, no audit is emitted.

    ``actor_user_id`` is informational for audit context — the
    resolver does not enforce actor identity (recompute is allowed
    from internal hooks without an operator).
    """
    if db.query(System.id).filter(System.id == system_id).first() is None:
        raise PatchAdvisoryError(f"system_id={system_id} does not reference a system")

    facts = db.query(HostFacts).filter(HostFacts.system_id == system_id).one_or_none()
    existing_rows = (
        db.query(PatchAdvisoryHostApplicability)
        .filter(PatchAdvisoryHostApplicability.system_id == system_id)
        .all()
    )

    if facts is None or not facts.distro_id_facts or not facts.distro_release:
        # Host has no usable facts. Drop any stale applicability rows
        # (the host's distro/release may have become unknown since the
        # last recompute) so operators see a clean slate.
        result = ApplicabilityResult(
            system_id=system_id,
            counts={s: 0 for s in VALID_APPLICABILITY_STATES},
            host_facts_missing=True,
        )
        if existing_rows:
            for row in existing_rows:
                db.delete(row)
            result.rows_removed = len(existing_rows)
            db.commit()
        # Audit only when there's a real delta. A host that was already
        # unresolvable and stays unresolvable is a no-op.
        if emit_audit and result.changed:
            _emit_applicable_recomputed(
                system_id=system_id,
                result=result,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
            )
        if result.changed:
            _recompute_advisory_smart_groups(db)
        return result

    distro_id = facts.distro_id_facts
    host_release = facts.distro_release

    installed: Dict[str, str] = {}
    pkg_rows = (
        db.query(Package.name, Package.installed_version)
        .filter(Package.system_id == system_id)
        .all()
    )
    for name, version in pkg_rows:
        installed[name] = version or ""

    # Pull all fixed-package targets for the host's distro and filter
    # by release alias in Python — the alias logic is non-trivial
    # enough that pushing it into SQL would either need a join table
    # or a CASE expression that's harder to maintain than the
    # in-memory filter.
    candidate_targets = (
        db.query(PatchAdvisoryFixedPackage)
        .filter(PatchAdvisoryFixedPackage.distro_id == distro_id)
        .all()
    )

    # Desired row map: (advisory_id, package_name) → row data. Dedupe
    # by (advisory_id, package_name) so an advisory that lists the
    # same package under multiple aliased releases (rare) produces
    # one row, preferring the exact-release match over alias matches.
    desired: Dict[Tuple[int, str], Dict[str, Any]] = {}
    advisories_touched: Set[int] = set()

    for target in candidate_targets:
        if not _release_matches(distro_id, host_release, target.distro_release):
            continue
        key = (target.advisory_id, target.package_name)
        installed_version = installed.get(target.package_name)
        if installed_version is not None:
            state, reason = _classify(
                installed_version=installed_version,
                required_version=target.fixed_version,
            )
            row_installed = installed_version or None
        else:
            state = APPLICABILITY_STATE_NOT_APPLICABLE
            reason = "package not installed"
            row_installed = None

        existing_desired = desired.get(key)
        prefer_exact = target.distro_release == host_release
        if existing_desired is not None and not prefer_exact:
            continue

        desired[key] = {
            "advisory_id": target.advisory_id,
            "package_name": target.package_name,
            "fixed_package_id": target.id,
            "installed_version": row_installed,
            "required_version": target.fixed_version,
            "state": state,
            "reason": reason,
        }
        advisories_touched.add(target.advisory_id)

    existing_map: Dict[Tuple[int, str], PatchAdvisoryHostApplicability] = {
        (row.advisory_id, row.package_name): row for row in existing_rows
    }
    desired_keys = set(desired.keys())
    existing_keys = set(existing_map.keys())

    rows_added = 0
    rows_updated = 0
    rows_removed = 0
    now = datetime.utcnow()

    for key in existing_keys - desired_keys:
        db.delete(existing_map[key])
        rows_removed += 1

    for key in desired_keys - existing_keys:
        d = desired[key]
        db.add(
            PatchAdvisoryHostApplicability(
                system_id=system_id,
                advisory_id=d["advisory_id"],
                fixed_package_id=d["fixed_package_id"],
                package_name=d["package_name"],
                installed_version=d["installed_version"],
                required_version=d["required_version"],
                state=d["state"],
                reason=d["reason"],
                evaluated_at=now,
            )
        )
        rows_added += 1

    for key in desired_keys & existing_keys:
        d = desired[key]
        row = existing_map[key]
        if (
            row.fixed_package_id != d["fixed_package_id"]
            or row.installed_version != d["installed_version"]
            or row.required_version != d["required_version"]
            or row.state != d["state"]
            or row.reason != d["reason"]
        ):
            row.fixed_package_id = d["fixed_package_id"]
            row.installed_version = d["installed_version"]
            row.required_version = d["required_version"]
            row.state = d["state"]
            row.reason = d["reason"]
            row.evaluated_at = now
            rows_updated += 1

    counts = {s: 0 for s in VALID_APPLICABILITY_STATES}
    for d in desired.values():
        counts[d["state"]] += 1

    result = ApplicabilityResult(
        system_id=system_id,
        counts=counts,
        rows_added=rows_added,
        rows_updated=rows_updated,
        rows_removed=rows_removed,
        advisories_touched=len(advisories_touched),
    )

    if result.changed:
        db.commit()
        if emit_audit:
            _emit_applicable_recomputed(
                system_id=system_id,
                result=result,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
            )
        _recompute_advisory_smart_groups(db)
    # No-op recompute → no audit, no commit, no smart-group recompute.
    return result


def _recompute_advisory_smart_groups(db: Session) -> None:
    """Lazy hook into smart_group_service after applicability rows
    actually change.

    Imported at call time so this module stays free of a hard
    dependency on smart_group_service (which already lazy-imports
    *this* module inside ``compute_advisory_index``). Exceptions are
    swallowed and logged — smart-group cache staleness is a
    background-sweep concern, not a reason to fail the resolver
    that already committed (mirrors the
    ``_recompute_ring_smart_groups`` pattern in patch_ring_service).
    """
    try:
        from . import smart_group_service  # pylint: disable=import-outside-toplevel

        smart_group_service.recompute_advisory_groups(db)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("recompute_advisory_groups follow-on failed: %s", exc)


def _emit_applicable_recomputed(
    *,
    system_id: int,
    result: ApplicabilityResult,
    actor_user_id: Optional[int],
    actor_username: Optional[str],
    actor_ip: Optional[str],
) -> None:
    safe_emit(
        action=AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_system_id=system_id,
        target_kind="system",
        target_id=str(system_id),
        context={
            "counts": result.counts,
            "rows_added": result.rows_added,
            "rows_updated": result.rows_updated,
            "rows_removed": result.rows_removed,
            "advisories_touched": result.advisories_touched,
            "host_facts_missing": result.host_facts_missing,
        },
    )


# ---------------------------------------------------------------------------
# Targeted recompute fanout (advisory-import driven)
# ---------------------------------------------------------------------------


def recompute_after_advisory_import(
    db: Session,
    touched_targets: Iterable[Tuple[str, str, str]],
    *,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> List[ApplicabilityResult]:
    """Recompute applicability only for hosts whose facts and installed
    packages intersect ``touched_targets`` from a Slice 1 import.

    ``touched_targets`` is an iterable of
    ``(distro_id, distro_release, package_name)`` tuples drawn from
    the imported/refreshed advisories' fixed-package set.

    The fanout is intentionally narrow — never the whole fleet —
    because per-host recompute is non-trivial and most advisories
    affect a small slice of hosts. A host is recomputed iff:

    * ``HostFacts.distro_id_facts`` matches one of the touched
      ``distro_id`` values, AND
    * ``HostFacts.distro_release`` aliases to one of the touched
      ``distro_release`` values for the matching distro_id, AND
    * the host has at least one installed ``Package.name`` matching
      one of the touched ``package_name`` values.

    Returns the per-host :class:`ApplicabilityResult`s for hosts the
    resolver actually visited.
    """
    targets = list(touched_targets)
    if not targets:
        return []

    distro_ids: Set[str] = {t[0] for t in targets}
    package_names: Set[str] = {t[2] for t in targets}
    releases_by_distro: Dict[str, Set[str]] = {}
    for distro_id, release, _pkg in targets:
        releases_by_distro.setdefault(distro_id, set()).add(release)

    candidate_systems = (
        db.query(System.id, HostFacts.distro_id_facts, HostFacts.distro_release)
        .join(HostFacts, HostFacts.system_id == System.id)
        .filter(HostFacts.distro_id_facts.in_(distro_ids))
        .filter(HostFacts.distro_release.isnot(None))
        .all()
    )

    affected_system_ids: List[int] = []
    for system_id, host_distro, host_release in candidate_systems:
        candidate_releases = releases_by_distro.get(host_distro, set())
        if not any(
            _release_matches(host_distro, host_release, r) for r in candidate_releases
        ):
            continue
        # Only recompute if the host has at least one of the touched
        # packages installed — saves work for hosts that match the
        # distro but don't carry any of the touched packages.
        has_package = (
            db.query(Package.id)
            .filter(Package.system_id == system_id)
            .filter(Package.name.in_(package_names))
            .first()
            is not None
        )
        if has_package:
            affected_system_ids.append(system_id)

    results: List[ApplicabilityResult] = []
    for system_id in affected_system_ids:
        results.append(
            compute_host_applicability(
                db,
                system_id,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
            )
        )
    return results


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------


def list_host_advisories(
    db: Session,
    system_id: int,
    *,
    state: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> List[PatchAdvisoryHostApplicability]:
    q = db.query(PatchAdvisoryHostApplicability).filter(
        PatchAdvisoryHostApplicability.system_id == system_id
    )
    if state is not None:
        if state not in VALID_APPLICABILITY_STATES:
            raise PatchAdvisoryError(
                f"state={state!r} not in {sorted(VALID_APPLICABILITY_STATES)}"
            )
        q = q.filter(PatchAdvisoryHostApplicability.state == state)
    return (
        q.order_by(
            PatchAdvisoryHostApplicability.advisory_id.asc(),
            PatchAdvisoryHostApplicability.package_name.asc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )


def count_host_advisories_by_state(db: Session, system_id: int) -> Dict[str, int]:
    """Return ``{state: count}`` for one host across all states.

    Always includes a key for every state in
    :data:`VALID_APPLICABILITY_STATES` so callers can render zero
    counts without a lookup miss.
    """
    counts = {s: 0 for s in VALID_APPLICABILITY_STATES}
    rows = (
        db.query(PatchAdvisoryHostApplicability.state)
        .filter(PatchAdvisoryHostApplicability.system_id == system_id)
        .all()
    )
    for (state,) in rows:
        if state in counts:
            counts[state] += 1
    return counts


def count_fleet_applicable_by_severity(
    db: Session, scope_system_ids: Optional[Set[int]] = None
) -> Dict[str, Any]:
    """Return fleet-wide counts of ``state='applicable'`` advisory rows
    grouped by severity AND by advisory_class (PRA-163 Slice 4).

    Used by the dashboard tile and the ``GET /patch/advisories/counts``
    route. Always returns one entry per
    :data:`VALID_SEVERITIES` and per :data:`VALID_ADVISORY_CLASSES`
    (defaulting to zero) so the operator UI can render the full grid
    without a lookup miss.

    Distinct host counts AT a severity / class are intentionally NOT
    de-duplicated — one host with three applicable critical advisories
    contributes 3 to ``severity['critical']``. Operators wanting "hosts
    with at least one critical applicable advisory" should use the
    Slice 3 ``advisory.applicable_critical_count > 0`` smart-group
    predicate instead.

    PRA-281: ``scope_system_ids`` constrains the applicability rows to the
    caller's fleet scope. ``None`` = tenant-wide (admin); an explicit set is an
    allow-list; an empty set yields all-zero counts, so an out-of-scope host's
    applicability never contributes to (or is revealed by) the fleet counts.
    """
    severity_counts: Dict[str, int] = {s: 0 for s in VALID_SEVERITIES}
    class_counts: Dict[str, int] = {c: 0 for c in VALID_ADVISORY_CLASSES}
    if scope_system_ids is not None and not scope_system_ids:
        # Empty scope: no accessible systems, so no applicability contributes.
        return {"severity": severity_counts, "advisory_class": class_counts, "total": 0}
    query = (
        db.query(
            PatchAdvisory.severity,
            PatchAdvisory.advisory_class,
        )
        .join(
            PatchAdvisoryHostApplicability,
            PatchAdvisoryHostApplicability.advisory_id == PatchAdvisory.id,
        )
        .filter(PatchAdvisoryHostApplicability.state == APPLICABILITY_STATE_APPLICABLE)
    )
    if scope_system_ids is not None:
        query = query.filter(
            PatchAdvisoryHostApplicability.system_id.in_(scope_system_ids)
        )
    rows = query.all()
    total = 0
    for severity, advisory_class in rows:
        total += 1
        if severity in severity_counts:
            severity_counts[severity] += 1
        if advisory_class in class_counts:
            class_counts[advisory_class] += 1
    return {
        "severity": severity_counts,
        "advisory_class": class_counts,
        "total": total,
    }
