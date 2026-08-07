"""Content-profile apply orchestrator (PRA-159 slice #3).

Composes the slice #1 + #2 primitives into one host-targeted operation:

  1. Resolve the host's effective content (slice #1 + #2). If state is
     anything other than ``resolved`` — refuse loud (operator must
     fix the binding before Praxis writes /etc/...).
  2. Ensure the trust bundle is installed on the host for every
     mirror in the resolved entries (slice #2 — call
     ``install_mirror_trust_on_host`` for every mirror that doesn't
     have a fresh-enough ``host_mirror_trust`` row, or that has a
     row whose installed_fingerprints differ from the active set).
  3. Ensure a non-revoked, non-expired serve credential exists for
     every (host, mirror) — issue if missing (slice #2). The
     plaintext is captured in-memory only for source-list rendering;
     never persisted, never logged.
  4. Render the source-list / .repo / auth.conf files via the slice
     #3 ``channel_source_writer`` pure helper.
  5. Diff against the host's existing ``praxis-profile-*`` files via
     ``host_etc_writer.list_managed_files``; the orchestrator
     writes new + changed files and removes obsolete files (one a
     prior profile binding put on the host but the current
     resolution doesn't need any more).
  6. Audit emit ``host_content_profile.applied`` with file-write /
     file-remove counts + the credentials-issued count. Failure paths
     emit ``host_content_profile.apply_failed`` with the same shape +
     ``error_text``.

Locked refusal contract:
  * ``state != "resolved"`` → ``ApplyOutcome(state="refused_no_profile"|
    "refused_conflict")``. No /etc writes.
  * Trust install or credential issuance failure → bail with
    ``ApplyOutcome(state="failed")``. Files already written stay on
    the host (last-good); operator can re-run apply after fixing the
    underlying issue and idempotent re-run will reconcile.
  * File write failure mid-loop → bail. Earlier writes stay on the
    host; the next apply re-derives the desired set and reconciles.

NOT in scope here:
  * Auto-apply on subscription change (PRA-159 lock — explicit
    operator action only in v1).
  * Per-host transport_preference selection (we accept the transport
    the route handler builds via PRA-153's
    ``get_transport(host, broker, ssh_service=...)`` factory).
  * Rollback of partial writes (last-good preservation via the
    PRA-158 install + mv -f durability protocol is the v1 contract;
    the next apply reconciles).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from ..db.models import (
    ContentProfile,
    HostMirrorServeCredential,
    HostMirrorTrust,
    MirrorRepo,
    System,
)
from . import audit_event_service
from .channel_source_writer import (
    MANAGED_FILENAME_PREFIX,
    FileSpec,
    compute_source_files,
    managed_directories,
    managed_filenames,
)
from .content_profile_service import ContentProfileService, ResolvedMirrorEntry
from .host_etc_writer import (
    ensure_parent_dir,
    list_managed_files,
    remove_managed_file,
    write_managed_file,
)
from .mirror_host_trust import install_mirror_trust_on_host
from .mirror_serve_credential_service import MirrorServeCredentialService
from .mirror_signing_key_service import MirrorSigningKeyService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public env hook for the externally-reachable serve URL
# ---------------------------------------------------------------------------


class PublicServeUrlNotConfigured(Exception):
    """Raised when ``PRAXIS_PUBLIC_URL`` is unset and the orchestrator
    needs it to render apt/dnf config.
    """


def public_serve_base_url() -> str:
    """Externally-reachable Praxis base URL the host fetches mirrors
    from.

    Read from ``PRAXIS_PUBLIC_URL`` (no scheme/path coercion — operator
    sets the value they want apt/dnf to embed). Required: the
    orchestrator refuses to write host config when this is unset
    rather than embedding a placeholder that would silently fail at
    the host's next apt/dnf run. The route
    layer surfaces ``PublicServeUrlNotConfigured`` as
    ``state=failed`` with a clear error message.
    """
    raw = os.getenv("PRAXIS_PUBLIC_URL")
    if raw is None or not raw.strip():
        raise PublicServeUrlNotConfigured(
            "PRAXIS_PUBLIC_URL is not configured; apply refuses to write host "
            "source config without an externally-reachable base URL"
        )
    return raw.strip().rstrip("/")


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------


@dataclass
class ApplyOutcome:
    """Structured result of an apply attempt.

    ``state`` ∈
      * ``applied`` — files written / removed as needed; host config
        now matches the resolved profile.
      * ``noop`` — host has the resolved profile and no source files
        needed changes (re-apply on a clean host).
      * ``refused_no_profile`` — host has no effective profile;
        apply doesn't write or remove anything.
      * ``refused_conflict`` — multiple profiles tied at the
        winning tier; operator must resolve before apply runs.
      * ``failed`` — partial state possible; ``error_text`` carries
        the operator-actionable signal.
    """

    state: str
    profile_slug: Optional[str] = None
    written_paths: List[str] = field(default_factory=list)
    removed_paths: List[str] = field(default_factory=list)
    trust_installed_for_mirrors: List[str] = field(default_factory=list)
    credentials_issued_for_mirrors: List[str] = field(default_factory=list)
    error_text: Optional[str] = None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def apply_content_profile_to_host(
    db: Session,
    host: System,
    transport,
    *,
    serve_base_url: Optional[str] = None,
    actor_user_id: Optional[int] = None,
) -> ApplyOutcome:
    """End-to-end apply for one host. See module docstring for the
    locked sequence and refusal contract.
    """
    service = ContentProfileService(db)
    resolved = service.resolve_content_for_host(host.id)

    # Refusals don't need PRAXIS_PUBLIC_URL — they don't write or
    # remove anything. Check the URL only when we actually need to
    # render config (after refusal short-circuits).
    if resolved.state == "no_profile":
        outcome = ApplyOutcome(state="refused_no_profile")
        _emit_outcome(db, host, outcome, actor_user_id)
        return outcome

    if resolved.state == "conflict":
        outcome = ApplyOutcome(state="refused_conflict")
        _emit_outcome(db, host, outcome, actor_user_id)
        return outcome

    # Resolved → we're about to write; require PRAXIS_PUBLIC_URL
    # before any host-side work runs.
    if serve_base_url is None:
        try:
            base_url = public_serve_base_url()
        except PublicServeUrlNotConfigured as exc:
            outcome = ApplyOutcome(
                state="failed",
                profile_slug=resolved.profile.profile_slug
                if resolved.profile is not None
                else None,
                error_text=str(exc),
            )
            _emit_outcome(
                db,
                host,
                outcome,
                actor_user_id,
                profile_id=(
                    resolved.profile.profile_id
                    if resolved.profile is not None
                    else None
                ),
            )
            return outcome
    else:
        base_url = serve_base_url.rstrip("/")

    assert resolved.profile is not None  # narrowed by state == "resolved"
    profile_slug = resolved.profile.profile_slug
    profile_id = resolved.profile.profile_id

    # Refetch the ContentProfile so we know the package_family even
    # when ``resolved.entries`` is empty (a live profile with no
    # channels, or whose channels are all soft-deleted, is legal).
    # The orchestrator treats an empty resolved
    # set as "desired = no managed files" and just removes obsolete
    # on-host files for the profile's package_family.
    profile_row = (
        db.query(ContentProfile).filter(ContentProfile.id == profile_id).one_or_none()
    )
    if profile_row is None:
        outcome = ApplyOutcome(
            state="failed",
            profile_slug=profile_slug,
            error_text=(
                f"profile {profile_id} disappeared between resolution and "
                "apply (race) — re-run apply"
            ),
        )
        _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
        return outcome
    package_family = profile_row.package_family

    # Step 2: ensure trust bundle on host for every distinct mirror
    # in the resolved entries. Multiple entries may share a mirror
    # (multi-suite composition) so dedup by mirror_id.
    distinct_mirrors: Dict[int, ResolvedMirrorEntry] = {}
    for entry in resolved.entries:
        distinct_mirrors.setdefault(entry.mirror_id, entry)

    key_service = MirrorSigningKeyService(db)
    trust_installed_for: List[str] = []
    fingerprints_by_mirror_id: Dict[int, List[str]] = {}
    for mirror_id, entry in distinct_mirrors.items():
        needs_install, mirror = _needs_trust_install(db, host.id, mirror_id)
        if mirror is None:
            outcome = ApplyOutcome(
                state="failed",
                profile_slug=profile_slug,
                error_text=(
                    f"mirror {mirror_id} disappeared between resolution and "
                    "trust install (race) — re-run apply after the resolver "
                    "stabilises"
                ),
            )
            _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
            return outcome
        if needs_install:
            result = await install_mirror_trust_on_host(db, mirror, host, transport)
            if not result.ok:
                outcome = ApplyOutcome(
                    state="failed",
                    profile_slug=profile_slug,
                    trust_installed_for_mirrors=trust_installed_for,
                    error_text=(
                        f"trust install failed for mirror {mirror.slug}: "
                        f"{result.error_text}"
                    ),
                )
                _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
                return outcome
            trust_installed_for.append(mirror.slug)

        # Capture only the fingerprints the orchestrator GUARANTEES
        # are installed on the host — that's active + pending_cutover
        # (see ``_needs_trust_install``). rotating_out keys are
        # explicitly allowed to be missing from the host's
        # installed_fingerprints set, so emitting a gpgkey reference
        # to one would point at a file Praxis didn't ensure exists. The
        # writer reuses this map for rpm only; deb concatenates everything
        # into one signed-by file.
        bundle = key_service.bundle_public_keys(mirror_id)
        fingerprints_by_mirror_id[mirror_id] = [
            k.gpg_fingerprint
            for k in bundle
            if k.status in ("active", "pending_cutover")
        ]

    # Step 3: issue NEW serve credentials for every distinct mirror,
    # but DO NOT revoke any prior active credentials yet. The host
    # keeps using its old bearer until step 5 lands the new
    # auth.conf / .repo file. We only revoke the prior creds in
    # step 8, AFTER all writes succeed. A
    # failure between steps 3 and 8 leaves the host's last-good
    # package access intact.
    cred_service = MirrorServeCredentialService(db)
    plaintext_by_mirror: Dict[int, str] = {}
    creds_issued_for: List[str] = []
    new_credential_id_by_mirror: Dict[int, int] = {}
    for mirror_id, entry in distinct_mirrors.items():
        try:
            issued = cred_service.issue(host_id=host.id, mirror_id=mirror_id)
        except Exception as exc:  # pylint: disable=broad-except
            outcome = ApplyOutcome(
                state="failed",
                profile_slug=profile_slug,
                trust_installed_for_mirrors=trust_installed_for,
                credentials_issued_for_mirrors=creds_issued_for,
                error_text=(
                    f"credential issue failed for mirror {entry.mirror_slug}: " f"{exc}"
                ),
            )
            _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
            return outcome
        plaintext_by_mirror[mirror_id] = issued.plaintext
        new_credential_id_by_mirror[mirror_id] = issued.credential_id
        creds_issued_for.append(entry.mirror_slug)

    # Step 4: render desired files. ``package_family`` came from the
    # ContentProfile row above so empty-entries profiles still have
    # a valid family for the file-matrix locks (deb: .list+.conf;
    # rpm: .repo).
    desired_files: List[FileSpec] = compute_source_files(
        profile_slug=profile_slug,
        package_family=package_family,
        entries=resolved.entries,
        serve_credentials=plaintext_by_mirror,
        serve_base_url=base_url,
        key_fingerprints_by_mirror_id=fingerprints_by_mirror_id,
    )
    desired_paths = {fs.path for fs in desired_files}

    # Step 5a: ensure every managed directory exists before listing
    # or writing. list_managed_files treats a
    # missing dir as empty, so we'd otherwise pass the diff step
    # and then fail on the first install /dev/stdin <missing>/...
    # No-op on hosts that already have the dirs (most do); the
    # ``install -d`` is idempotent.
    for managed_dir in managed_directories(package_family):
        ensure_res = await ensure_parent_dir(transport, parent=managed_dir)
        if not ensure_res.ok:
            outcome = ApplyOutcome(
                state="failed",
                profile_slug=profile_slug,
                trust_installed_for_mirrors=trust_installed_for,
                credentials_issued_for_mirrors=creds_issued_for,
                error_text=(f"ensure {managed_dir} failed: {ensure_res.error_text}"),
            )
            _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
            return outcome

    # Step 5b: diff against on-host managed files. Any praxis-profile-*
    # file NOT in the desired set is obsolete (operator changed
    # profile, removed a channel, or unsubscribed the host).
    obsolete_paths: List[str] = []
    for managed_dir in managed_directories(package_family):
        listing = await list_managed_files(
            transport, dir_path=managed_dir, prefix=MANAGED_FILENAME_PREFIX
        )
        if not listing.ok:
            outcome = ApplyOutcome(
                state="failed",
                profile_slug=profile_slug,
                trust_installed_for_mirrors=trust_installed_for,
                credentials_issued_for_mirrors=creds_issued_for,
                error_text=(
                    f"list managed files in {managed_dir} failed: "
                    f"{listing.error_text}"
                ),
            )
            _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
            return outcome
        for full_path in listing.paths:
            if full_path not in desired_paths:
                obsolete_paths.append(full_path)

    # Step 6: write new + changed (we always re-write to keep the
    # apply path simple — every write goes through the install +
    # mv -f durability primitive so re-writing identical bytes is
    # cheap-ish AND fixes drift if the file was edited on-host).
    written_paths: List[str] = []
    for spec in desired_files:
        result = await write_managed_file(
            transport, path=spec.path, body=spec.body, mode=spec.mode
        )
        if not result.ok:
            outcome = ApplyOutcome(
                state="failed",
                profile_slug=profile_slug,
                trust_installed_for_mirrors=trust_installed_for,
                credentials_issued_for_mirrors=creds_issued_for,
                written_paths=written_paths,
                error_text=(f"write {spec.path} failed: {result.error_text}"),
            )
            _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
            return outcome
        written_paths.append(spec.path)

    # Step 7: remove obsolete files. ``rm -f`` is idempotent so a
    # mid-list race (file vanished) isn't a failure.
    removed_paths: List[str] = []
    for path in obsolete_paths:
        result = await remove_managed_file(transport, path=path)
        if not result.ok:
            outcome = ApplyOutcome(
                state="failed",
                profile_slug=profile_slug,
                trust_installed_for_mirrors=trust_installed_for,
                credentials_issued_for_mirrors=creds_issued_for,
                written_paths=written_paths,
                removed_paths=removed_paths,
                error_text=f"remove {path} failed: {result.error_text}",
            )
            _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
            return outcome
        removed_paths.append(path)

    # Step 8: host writes succeeded; NOW revoke
    # any prior active credentials for each (host, mirror). Up to
    # this point the prior bearer was still valid so a failed apply
    # would have left package access working. From here, only the
    # new bearer authenticates.
    for mirror_id, new_cred_id in new_credential_id_by_mirror.items():
        cred_service.revoke_other_active_for_pair(
            host_id=host.id, mirror_id=mirror_id, except_id=new_cred_id
        )

    outcome = ApplyOutcome(
        state="applied" if (written_paths or removed_paths) else "noop",
        profile_slug=profile_slug,
        written_paths=written_paths,
        removed_paths=removed_paths,
        trust_installed_for_mirrors=trust_installed_for,
        credentials_issued_for_mirrors=creds_issued_for,
    )
    _emit_outcome(db, host, outcome, actor_user_id, profile_id=profile_id)
    return outcome


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _needs_trust_install(
    db: Session, host_id: int, mirror_id: int
) -> tuple[bool, Optional[MirrorRepo]]:
    """Decide whether the trust bundle needs (re)installing for this
    (host, mirror).

    Reinstall is needed when:
      * No ``host_mirror_trust`` row exists for the pair.
      * The row's ``installed_fingerprints`` is missing the mirror's
        current ``active`` fingerprint OR a ``pending_cutover``
        fingerprint. Pre-installing pending_cutover keys means the
        next rotation cutover doesn't strand the host: once the operator runs cutover, the host already
        has the new active key in its keyring, so apt/dnf trust
        continues uninterrupted.

    Returns the ``MirrorRepo`` row alongside so the caller can pass
    it straight into ``install_mirror_trust_on_host`` without an
    extra fetch.
    """
    mirror = (
        db.query(MirrorRepo)
        .filter(MirrorRepo.id == mirror_id, MirrorRepo.deleted_at.is_(None))
        .one_or_none()
    )
    if mirror is None:
        return True, None

    row = (
        db.query(HostMirrorTrust)
        .filter(
            HostMirrorTrust.host_id == host_id,
            HostMirrorTrust.mirror_id == mirror_id,
        )
        .one_or_none()
    )
    if row is None:
        return True, mirror

    # Look up the mirror's current active + pending_cutover
    # fingerprints. Both must be present in the host's installed
    # set; rotating_out is allowed to be missing (those keys are
    # being phased out and don't gate apply).
    key_service = MirrorSigningKeyService(db)
    bundle = key_service.bundle_public_keys(mirror_id)
    required_fps = [
        k.gpg_fingerprint for k in bundle if k.status in ("active", "pending_cutover")
    ]
    if not required_fps:
        # Mirror has no active key — install primitive will fail loud
        # with a clear error; let the orchestrator try and surface the
        # reason rather than papering over it here.
        return True, mirror

    installed = set(row.installed_fingerprints or [])
    if any(fp not in installed for fp in required_fps):
        return True, mirror
    return False, mirror


def _active_credential(
    db: Session, host_id: int, mirror_id: int
) -> Optional[HostMirrorServeCredential]:
    now = datetime.utcnow()
    return (
        db.query(HostMirrorServeCredential)
        .filter(
            HostMirrorServeCredential.host_id == host_id,
            HostMirrorServeCredential.mirror_id == mirror_id,
            HostMirrorServeCredential.revoked_at.is_(None),
            HostMirrorServeCredential.expires_at > now,
        )
        .one_or_none()
    )


def _emit_outcome(
    db: Session,
    host: System,
    outcome: ApplyOutcome,
    actor_user_id: Optional[int],
    *,
    profile_id: Optional[int] = None,
) -> None:
    """Audit emit on the same session as the mutation. The apply
    surface only mutates serve_credential rows + writes files; the
    file writes are not in DB so there's no cross-session boundary
    issue (PRA-158 ``safe_emit``-on-fresh-session rule applies to
    state transitions; apply rows describe a completed multi-step
    op, not a single state transition).
    """
    action = (
        "host_content_profile.applied"
        if outcome.state in ("applied", "noop")
        else (
            "host_content_profile.refused"
            if outcome.state.startswith("refused_")
            else "host_content_profile.apply_failed"
        )
    )
    audit_event_service.emit(
        db,
        action=action,
        target_kind="system",
        target_id=str(host.id),
        context={
            "hostname": host.hostname,
            "profile_slug": outcome.profile_slug,
            "profile_id": profile_id,
            "outcome_state": outcome.state,
            "written_count": len(outcome.written_paths),
            "removed_count": len(outcome.removed_paths),
            "trust_installed_count": len(outcome.trust_installed_for_mirrors),
            "credentials_issued_count": len(outcome.credentials_issued_for_mirrors),
            "actor_user_id": actor_user_id,
            "error_text": outcome.error_text,
        },
    )
