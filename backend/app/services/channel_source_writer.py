"""Source-list generator for content profiles (PRA-159 slice #3).

Pure function: given a resolved profile, its fan-out of mirror
entries, the per-mirror serve credentials, and the public serve
base URL, produce the list of files Praxis will write to the host.

Locked file matrix per profile:

  * **deb**: TWO files
      * ``/etc/apt/sources.list.d/praxis-profile-<slug>.list`` — mode
        0644, root:root. World-readable; contains ONLY URLs +
        ``signed-by=`` references, no secrets.
      * ``/etc/apt/auth.conf.d/praxis-profile-<slug>.conf`` — mode
        0600, root:root. Per-mirror ``machine`` entries with
        ``login praxis`` and the bearer in the ``password`` slot.
        Apt natively reads ``auth.conf.d`` and matches longest URL
        prefix, so a profile composing N mirrors produces N entries.

  * **rpm**: ONE file
      * ``/etc/yum.repos.d/praxis-profile-<slug>.repo`` — mode 0600,
        root:root. dnf has no out-of-band auth file; ``username=`` /
        ``password=`` go inline in the .repo. The whole file is
        0600 because it carries credentials, not because the rest of
        the file is sensitive.

Naming lock:
  * Filename prefix is **``praxis-profile-``** (NOT ``praxis-channel-``)
    because the file describes the host's effective profile config,
    not a channel. The orchestrator's "list managed files" step
    matches this prefix to discover files to keep / remove.
  * Repo stanza id (rpm) is ``praxis-<profile-slug>-<mirror-slug>``
    so it sorts predictably when an operator runs ``dnf repolist``
    and is unambiguous if they have multiple Praxis profiles
    layered (which slice #3 doesn't allow but a future slice might).

NOT in scope here:
  * Actually writing the files (orchestrator territory — slice #3's
    ``content_profile_apply.py`` calls ``host_etc_writer``).
  * Issuing serve credentials (orchestrator pre-step calls
    ``MirrorServeCredentialService.issue``).
  * Validating that the host's package_family matches the profile —
    apply orchestrator does that earlier.

This module is purely string composition + path naming so it's
unit-testable without any transport / DB.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .content_profile_service import ResolvedMirrorEntry

logger = logging.getLogger(__name__)


# Matched-prefix glob the apply orchestrator uses to find Praxis-managed
# files. Anything NOT starting with this prefix is operator territory
# and Praxis must never touch it.
MANAGED_FILENAME_PREFIX = "praxis-profile-"

DEB_SOURCES_DIR = "/etc/apt/sources.list.d"
DEB_AUTH_DIR = "/etc/apt/auth.conf.d"
RPM_REPOS_DIR = "/etc/yum.repos.d"

# Username slot for HTTP Basic on the serve endpoint. The route
# enforces this exact value (PRA-159 slice #2-a) so
# generated host config has a single self-describing marker.
BASIC_AUTH_USERNAME = "praxis"


@dataclass(frozen=True)
class FileSpec:
    """One file Praxis will write to the host."""

    path: str
    body: bytes
    mode: str  # "0600" or "0644"


def compute_source_files(
    *,
    profile_slug: str,
    package_family: str,
    entries: Sequence[ResolvedMirrorEntry],
    serve_credentials: Dict[int, str],
    serve_base_url: str,
    key_fingerprints_by_mirror_id: Optional[Dict[int, List[str]]] = None,
) -> List[FileSpec]:
    """Render a profile into ``FileSpec`` records.

    ``serve_credentials`` is a ``mirror_id -> bearer_plaintext`` map
    the orchestrator builds by issuing credentials before calling
    here. Missing entries raise ``KeyError`` so a forgotten issue
    surfaces loud, not as a silent half-config.

    ``serve_base_url`` is the externally-reachable Praxis base URL
    (e.g. ``https://praxis.example.com``). The serve route URL for a
    given mirror is ``<base>/mirrors/<mirror_slug>/serve``.

    ``key_fingerprints_by_mirror_id`` maps each mirror to the
    fingerprints currently in its trust bundle (active +
    pending_cutover + rotating_out). For rpm the writer emits one
    explicit ``gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-<slug>-<fp8>``
    line per fingerprint — dnf treats ``gpgkey`` as a list of URL/file
    references, NOT a shell glob, so the slice #3 first cut's
    ``...-*`` wildcard wouldn't have worked.
    For deb the trust bundle is one concatenated file (PRA-158
    naming) so ``signed-by=`` doesn't need fingerprints. Required
    for rpm; ignored for deb. KeyError on a missing rpm entry to
    keep the failure mode explicit.

    Empty entry list returns ``[]`` — the orchestrator handles this
    case (no managed files needed) without writing anything.
    """
    if not entries:
        return []

    base = serve_base_url.rstrip("/")
    fingerprints = key_fingerprints_by_mirror_id or {}

    if package_family == "deb":
        return _compute_deb_files(profile_slug, entries, serve_credentials, base)
    if package_family == "rpm":
        return _compute_rpm_files(
            profile_slug, entries, serve_credentials, base, fingerprints
        )
    raise ValueError(f"unsupported package_family={package_family!r}")


# ---------------------------------------------------------------------------
# deb
# ---------------------------------------------------------------------------


def _compute_deb_files(
    profile_slug: str,
    entries: Sequence[ResolvedMirrorEntry],
    serve_credentials: Dict[int, str],
    base: str,
) -> List[FileSpec]:
    sources_path = f"{DEB_SOURCES_DIR}/{MANAGED_FILENAME_PREFIX}{profile_slug}.list"
    auth_path = f"{DEB_AUTH_DIR}/{MANAGED_FILENAME_PREFIX}{profile_slug}.conf"

    sources_lines = [
        "# Managed by Praxis — do not edit.",
        f"# Profile: {profile_slug}",
        f"# Bearer credentials live in {auth_path} (mode 0600).",
        "",
    ]
    for entry in entries:
        # ``signed-by=`` references the trust bundle PRA-158 installs.
        # File name is locked at PRA-158 #3c:
        #   /etc/apt/keyrings/praxis-mirror-<slug>.asc
        signed_by = f"/etc/apt/keyrings/praxis-mirror-{entry.mirror_slug}.asc"
        url = _serve_url(base, entry.mirror_slug)
        components = " ".join(entry.components) if entry.components else "main"
        sources_lines.append(
            f"deb [signed-by={signed_by}] {url} {entry.suite} {components}"
        )
    sources_lines.append("")  # trailing newline
    sources_body = "\n".join(sources_lines).encode("utf-8")

    # Dedup auth blocks by mirror_id: a profile
    # composing multiple suites of the same mirror produces N deb
    # source lines but only ONE machine block — apt's auth.conf is
    # keyed by URL prefix, so duplicating the same machine entry N
    # times would just be redundant. ``dict.setdefault`` preserves
    # the first entry seen for each mirror_id while keeping the
    # iteration order stable across Python's insertion-ordered dict.
    auth_lines = [
        "# Managed by Praxis — do not edit.",
        f"# Profile: {profile_slug}",
        "",
    ]
    seen_mirror_ids: Dict[int, ResolvedMirrorEntry] = {}
    for entry in entries:
        seen_mirror_ids.setdefault(entry.mirror_id, entry)
    for entry in seen_mirror_ids.values():
        token = serve_credentials[entry.mirror_id]
        # apt's auth.conf supports either bare hostname OR URL
        # prefix in the ``machine`` field; URL prefix matches the
        # most-specific entry, so per-mirror creds work cleanly even
        # when the same host serves N mirrors.
        machine_url = _machine_url_for_apt(base, entry.mirror_slug)
        auth_lines.append(f"machine {machine_url}")
        auth_lines.append(f"  login {BASIC_AUTH_USERNAME}")
        auth_lines.append(f"  password {token}")
        auth_lines.append("")
    auth_body = "\n".join(auth_lines).encode("utf-8")

    return [
        FileSpec(path=sources_path, body=sources_body, mode="0644"),
        FileSpec(path=auth_path, body=auth_body, mode="0600"),
    ]


# ---------------------------------------------------------------------------
# rpm
# ---------------------------------------------------------------------------


def _compute_rpm_files(
    profile_slug: str,
    entries: Sequence[ResolvedMirrorEntry],
    serve_credentials: Dict[int, str],
    base: str,
    fingerprints_by_mirror_id: Dict[int, List[str]],
) -> List[FileSpec]:
    repo_path = f"{RPM_REPOS_DIR}/{MANAGED_FILENAME_PREFIX}{profile_slug}.repo"

    chunks: List[str] = []
    chunks.append("# Managed by Praxis — do not edit.")
    chunks.append(f"# Profile: {profile_slug}")
    chunks.append("# This file is mode 0600 root because it carries bearer creds.")
    chunks.append("")

    # Dedup stanzas by mirror_id: rpm has no
    # per-suite concept in the .repo stanza — ``baseurl`` is one URL
    # per repo. Multi-suite composition for an rpm mirror collapses
    # to a single stanza. ``dict.setdefault`` preserves the first
    # entry seen for each mirror_id; later entries (different
    # ``suite_override`` values) are dropped from rpm output.
    seen_mirror_ids: Dict[int, ResolvedMirrorEntry] = {}
    for entry in entries:
        seen_mirror_ids.setdefault(entry.mirror_id, entry)

    for entry in seen_mirror_ids.values():
        token = serve_credentials[entry.mirror_id]
        url = _serve_url(base, entry.mirror_slug)
        # PRA-158 #3c installs one file per fingerprint in
        # /etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-<slug>-<fp8>.
        # dnf treats the ``gpgkey`` value as a list of URL/file
        # references — NOT a shell-expanded glob. We emit one explicit
        # ``file://...-<fp8>`` reference per fingerprint,
        # whitespace-continued so dnf parses them
        # as a multi-value list. KeyError on missing/empty so a
        # forgotten fingerprint surfaces loud, not as a silent
        # gpgcheck-fail at the host.
        fps = fingerprints_by_mirror_id.get(entry.mirror_id)
        if not fps:
            raise KeyError(
                f"missing rpm gpgkey fingerprints for mirror_id="
                f"{entry.mirror_id} (slug={entry.mirror_slug!r})"
            )
        gpgkey_lines = [
            f"file:///etc/pki/rpm-gpg/RPM-GPG-KEY-PRAXIS-MIRROR-"
            f"{entry.mirror_slug}-{fp[:8].lower()}"
            for fp in fps
        ]
        # dnf accepts whitespace-continued multi-value gpgkey:
        #   gpgkey=file:///path/to/key1
        #          file:///path/to/key2
        # The leading whitespace on continuation lines is required.
        gpgkey_block = "\n       ".join(gpgkey_lines)

        stanza_id = f"praxis-{profile_slug}-{entry.mirror_slug}"
        chunks.append(f"[{stanza_id}]")
        chunks.append(
            f"name=Praxis profile {profile_slug} (mirror {entry.mirror_slug})"
        )
        chunks.append(f"baseurl={url}")
        chunks.append("enabled=1")
        chunks.append("gpgcheck=1")
        chunks.append(f"gpgkey={gpgkey_block}")
        chunks.append(f"username={BASIC_AUTH_USERNAME}")
        chunks.append(f"password={token}")
        chunks.append("")

    body = "\n".join(chunks).encode("utf-8")
    return [FileSpec(path=repo_path, body=body, mode="0600")]


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def _serve_url(base: str, mirror_slug: str) -> str:
    """Compose the externally-reachable serve URL for a mirror."""
    return f"{base}/mirrors/{mirror_slug}/serve"


def _machine_url_for_apt(base: str, mirror_slug: str) -> str:
    """Return the value apt's auth.conf ``machine`` field expects.

    apt strips the URL scheme on match, so we strip it here for
    readability; the longest-prefix match still works either way.
    """
    if base.startswith("https://"):
        host_and_path = base[len("https://") :]
    elif base.startswith("http://"):
        host_and_path = base[len("http://") :]
    else:
        host_and_path = base
    return f"{host_and_path}/mirrors/{mirror_slug}/serve"


# Useful for the orchestrator's diff step. Keeps the prefix lock in
# this module so the writer + apply orchestrator agree.
def managed_filenames(profile_slug: str, package_family: str) -> List[str]:
    """Return the basenames Praxis manages for ``profile_slug``.

    Used by the orchestrator's diff step: list managed files in
    each managed directory, compare to this set, write/keep/remove
    accordingly.
    """
    if package_family == "deb":
        return [
            f"{MANAGED_FILENAME_PREFIX}{profile_slug}.list",
            f"{MANAGED_FILENAME_PREFIX}{profile_slug}.conf",
        ]
    if package_family == "rpm":
        return [f"{MANAGED_FILENAME_PREFIX}{profile_slug}.repo"]
    raise ValueError(f"unsupported package_family={package_family!r}")


def managed_directories(package_family: str) -> List[str]:
    """Directories Praxis writes managed files to.

    Apply orchestrator scans these for ``praxis-profile-*`` files
    to discover obsolete files when an operator unsubscribes the
    host or moves it to a different profile.
    """
    if package_family == "deb":
        return [DEB_SOURCES_DIR, DEB_AUTH_DIR]
    if package_family == "rpm":
        return [RPM_REPOS_DIR]
    raise ValueError(f"unsupported package_family={package_family!r}")
